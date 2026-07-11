#!/usr/bin/env python3
"""Bounded context helpers for Ask-AI.

The helpers in this module are deliberately provider-independent and use only
the Python standard library.  They provide a conservative pre-flight estimate;
the provider remains the final authority on token counts.

Message metadata understood by :func:`fit_messages_to_budget`:

``context_pin``
    Keep the message intact.  A group containing a pinned message is kept
    intact as well.
``context_group``
    Treat all messages with the same value as one atomic retention unit.  This
    is useful for assistant tool-call/tool-result pairs.
``context_trimmable``
    Allow balanced head/tail truncation of this message's string ``content``.
``context_kind``
    Human-readable kind included in the returned audit information.

System messages and the newest user message (the current question) are always
trusted/pinned, regardless of metadata.  No trusted content is silently
truncated or omitted.
"""

from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence, Tuple


DENSE_CHARS_PER_TOKEN = 3.5
MESSAGE_OVERHEAD_TOKENS = 8
DEFAULT_OUTPUT_RESERVE_TOKENS = 8_192
DEFAULT_SAFETY_TOKENS = 8_192
MIN_CONTEXT_WINDOW_TOKENS = 8_000
MAX_CONTEXT_WINDOW_TOKENS = 2_000_000
UNKNOWN_CLOUD_CONTEXT_WINDOW = 128_000
OLLAMA_CONTEXT_WINDOW = 32_000

_ENV_WINDOW_KEYS = (
    "AI_CONTEXT_WINDOW_TOKENS",
    "ASK_AI_CONTEXT_WINDOW_TOKENS",
    "ASK_AI_CONTEXT_WINDOW",
)
_TRUNCATION_MARKER = "\n[...context truncated to fit model budget...]\n"
_HEADING_RE = re.compile(
    r"^(?:"
    r"#{1,6}\s+\S|"
    r"={3,}\s*\S*|"
    r"-{3,}\s*\S+|"
    r"@[A-Za-z0-9_.:-]+(?:\s|$)|"
    r"(?:ROLE|DEVICE|SOURCE|CHUNK|SECTION|OBSERVATION|EVIDENCE)\s*[:#]"
    r")",
    re.IGNORECASE,
)


class ContextBudgetError(ValueError):
    """Raised when trusted context cannot fit the configured input budget."""

    def __init__(
        self,
        message: str,
        *,
        required_tokens: Optional[int] = None,
        budget_tokens: Optional[int] = None,
        required_indexes: Optional[Sequence[int]] = None,
    ) -> None:
        super().__init__(message)
        self.required_tokens = required_tokens
        self.budget_tokens = budget_tokens
        self.required_indexes = tuple(required_indexes or ())


def _coerce_integer(value: Any, *, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError("%s must be an integer" % name)
    try:
        text = str(value).strip().replace(",", "").replace("_", "")
        result = int(text)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError("%s must be an integer" % name) from exc
    return result


def _clamped_window(value: Any, *, name: str) -> int:
    parsed = _coerce_integer(value, name=name)
    return max(MIN_CONTEXT_WINDOW_TOKENS, min(MAX_CONTEXT_WINDOW_TOKENS, parsed))


def _catalog_context_window(model: str, provider: Optional[str]) -> int:
    model_name = str(model or "").strip().lower()
    provider_name = str(provider or "").strip().lower()
    route = "/".join(value for value in (provider_name, model_name) if value)

    # A local gateway controls its own loaded model settings.  Do not infer a
    # cloud-sized context merely because an Ollama alias contains "gpt".
    if "ollama" in route or provider_name in {"local", "localhost"}:
        return OLLAMA_CONTEXT_WINDOW

    # Current 1M-window Anthropic models, matched by substring so both direct
    # names and bedrock-/vendor-prefixed routes resolve identically.  Unknown
    # Claude aliases (including haiku-4-5) keep the conservative 200K rule.
    if any(
        name in route
        for name in (
            "claude-opus-4-8",
            "claude-opus-4-7",
            "claude-opus-4-6",
            "claude-sonnet-5",
            "claude-sonnet-4-6",
            "claude-fable-5",
        )
    ):
        return 1_000_000
    if any(name in route for name in ("claude", "sonnet", "haiku", "opus")):
        return 200_000

    # Gemini 2.x and 3.x routes used by Ask-AI advertise a one-million-token
    # input window.  Future/unknown Gemini aliases retain the cloud fallback.
    if re.search(r"(?:^|[/_-])gemini[-_ ]?[23](?:[.\-_/]|$)", route):
        return 1_000_000

    if "gpt-4o" in route:
        return 128_000

    # Current GPT-5 catalog aliases.  Match specific variants before the
    # generic family fallback because their deployed windows differ.
    if "gpt-5.5" in route:
        return 1_100_000 if "openai" in provider_name or route.startswith("openai/") else 1_000_000
    if "gpt-5.4-mini" in route:
        return 400_000
    if "gpt-5.4" in route:
        return 1_000_000
    if "gpt-5.3-codex" in route:
        return 200_000
    if "gpt-5.2-codex" in route or "gpt-5-codex" in route:
        return 400_000
    if "gpt-5.1-codex-mini" in route:
        return 30_000
    if "gpt-5.1-codex" in route:
        return 500_000
    if "gpt-5" in route:
        return 400_000

    if "sonar" in route:
        return 128_000
    return UNKNOWN_CLOUD_CONTEXT_WINDOW


def _resolve_context_window(
    model: str,
    *,
    provider: Optional[str] = None,
    override: Optional[Any] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Tuple[int, str]:
    # CGI configuration exports optional overrides as an empty string when
    # unset; treat that exactly like no explicit override.
    if override is not None and str(override).strip():
        return _clamped_window(override, name="context window override"), "explicit"

    environment = os.environ if environ is None else environ
    for key in _ENV_WINDOW_KEYS:
        raw = environment.get(key)
        if raw is None or not str(raw).strip():
            continue
        try:
            return _clamped_window(raw, name=key), "environment:%s" % key
        except ValueError:
            # A malformed process environment must not disable the safety
            # mechanism.  Fall through to the conservative catalog value.
            continue

    return _catalog_context_window(model, provider), "catalog"


def model_context_window(
    model: str,
    *,
    provider: Optional[str] = None,
    override: Optional[Any] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> int:
    """Return a provider/model-aware context window in tokens.

    An explicit override wins over ``AI_CONTEXT_WINDOW_TOKENS`` (and the
    backwards-compatible ``ASK_AI_CONTEXT_WINDOW*`` aliases).  All overrides
    are clamped to 8K..2M tokens. Unknown cloud routes use 128K; Ollama/local
    routes use 32K.
    """

    return _resolve_context_window(
        model, provider=provider, override=override, environ=environ
    )[0]


def context_input_budget(
    model: str,
    *,
    provider: Optional[str] = None,
    output_reserve_tokens: Any = DEFAULT_OUTPUT_RESERVE_TOKENS,
    safety_tokens: Any = DEFAULT_SAFETY_TOKENS,
    window_override: Optional[Any] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> int:
    """Return usable input tokens after response reserve and safety room."""

    window = model_context_window(
        model, provider=provider, override=window_override, environ=environ
    )
    output_reserve = _coerce_integer(
        output_reserve_tokens, name="output reserve"
    )
    safety = _coerce_integer(safety_tokens, name="safety tokens")
    if output_reserve < 0 or safety < 0:
        raise ValueError("output reserve and safety tokens must be non-negative")
    budget = window - output_reserve - safety
    if budget <= 0:
        raise ContextBudgetError(
            "context window %d leaves no input room after output reserve %d "
            "and safety %d" % (window, output_reserve, safety),
            budget_tokens=budget,
        )
    return budget


def _content_text_for_estimate(content: Any) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    try:
        return json.dumps(
            content,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, OverflowError):
        return str(content)


def estimate_content_tokens(content: Any) -> int:
    """Conservatively estimate tokens for ASCII and dense non-ASCII text.

    Network output is normally ASCII, where real BPE tokenizers average about
    3.5-4 characters/token even for dense structured text; 3.5 keeps the
    estimate on the conservative side. CJK and emoji can consume one or
    multiple tokens per Unicode code point, so count them at two tokens each
    instead of treating them like English prose.
    """

    text = _content_text_for_estimate(content)
    if not text:
        return 0
    ascii_chars = sum(1 for character in text if ord(character) < 128)
    non_ascii_chars = len(text) - ascii_chars
    return int(math.ceil(ascii_chars / DENSE_CHARS_PER_TOKEN)) + non_ascii_chars * 2


def estimate_message_tokens(message: Mapping[str, Any]) -> int:
    return estimate_content_tokens(message.get("content")) + MESSAGE_OVERHEAD_TOKENS


def estimate_messages_tokens(messages: Sequence[Mapping[str, Any]]) -> int:
    return sum(estimate_message_tokens(message) for message in messages)


def balanced_context_truncate(
    text: str,
    max_chars: int,
    marker: str = _TRUNCATION_MARKER,
) -> str:
    """Truncate a string while retaining equally sized head and tail slices."""

    value = str(text or "")
    limit = max(0, int(max_chars))
    if len(value) <= limit:
        return value
    if limit == 0:
        return ""

    note = str(marker or "")
    if len(note) + 2 > limit:
        # There is no room to identify truncation, but keeping both ends is
        # still more useful than a one-sided hard cut.
        head = (limit + 1) // 2
        return value[:head] + value[-(limit - head):] if limit - head else value[:head]

    room = limit - len(note)
    head = (room + 1) // 2
    tail = room - head
    return value[:head] + note + (value[-tail:] if tail else "")


def _is_heading_line(line: str) -> bool:
    stripped = str(line or "").strip()
    return bool(stripped and len(stripped) <= 512 and _HEADING_RE.match(stripped))


@dataclass(frozen=True)
class SemanticChunk:
    """One chunk plus its exact, non-overlapping source range.

    ``repeated_heading`` is supplemental context and never belongs to the
    source range.  Joining ``source_text`` across chunks reconstructs the
    original byte-for-byte at the Python string level.
    """

    index: int
    start: int
    end: int
    source_text: str
    repeated_heading: str = ""

    @property
    def text(self) -> str:
        return self.repeated_heading + self.source_text

    def as_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "start": self.start,
            "end": self.end,
            "source_text": self.source_text,
            "repeated_heading": self.repeated_heading,
            "text": self.text,
        }


def _heading_ranges(text: str) -> List[Tuple[int, int, str]]:
    ranges: List[Tuple[int, int, str]] = []
    cursor = 0
    for line in text.splitlines(keepends=True):
        end = cursor + len(line)
        if _is_heading_line(line):
            ranges.append((cursor, end, line))
        cursor = end
    # splitlines(keepends=True) covers all source characters, including a
    # final line without a newline; an empty string simply has no headings.
    return ranges


def _active_heading(
    headings: Sequence[Tuple[int, int, str]],
    cursor: int,
    target_chars: int,
) -> str:
    active = ""
    for start, end, line in headings:
        if start == cursor:
            # This chunk already begins with its own heading. Repeating the
            # previous section heading would mislabel the new section.
            return ""
        if start > cursor:
            break
        if end <= cursor:
            active = line
    # A pathological heading should not consume the next chunk.  It remains
    # available in its original source range and is simply not repeated.
    if len(active) > target_chars // 3:
        return ""
    return active


def _semantic_cut(
    text: str,
    start: int,
    room: int,
    headings: Sequence[Tuple[int, int, str]],
) -> int:
    hard_end = min(len(text), start + max(1, room))
    if hard_end >= len(text):
        return len(text)
    floor = min(hard_end, start + max(1, int(room * 0.55)))

    heading_starts = [
        heading_start
        for heading_start, _heading_end, _line in headings
        if floor <= heading_start <= hard_end and heading_start > start
    ]
    if heading_starts:
        return max(heading_starts)

    paragraph = text.rfind("\n\n", floor, hard_end)
    if paragraph >= floor:
        return paragraph + 2
    line = text.rfind("\n", floor, hard_end)
    if line >= floor:
        return line + 1
    for separator in (" ", "\t"):
        boundary = text.rfind(separator, floor, hard_end)
        if boundary >= floor:
            return boundary + 1
    return hard_end


def semantic_chunks(text: str, target_chars: int) -> List[SemanticChunk]:
    """Split text at semantic boundaries without source gaps or overlaps.

    Preferred boundaries are headings, paragraphs, lines, then whitespace.
    Continuations may repeat only the active heading; that repetition is kept
    separately in :attr:`SemanticChunk.repeated_heading`.
    """

    source = str(text or "")
    target = int(target_chars)
    if target <= 0:
        raise ValueError("target_chars must be positive")
    if not source:
        return []
    if len(source) <= target:
        return [SemanticChunk(0, 0, len(source), source)]

    headings = _heading_ranges(source)
    result: List[SemanticChunk] = []
    cursor = 0
    while cursor < len(source):
        repeated_heading = _active_heading(headings, cursor, target)
        room = target - len(repeated_heading)
        if room < max(32, target // 4):
            repeated_heading = ""
            room = target
        end = _semantic_cut(source, cursor, room, headings)
        if end <= cursor:
            end = min(len(source), cursor + max(1, room))
        source_text = source[cursor:end]
        result.append(
            SemanticChunk(
                index=len(result),
                start=cursor,
                end=end,
                source_text=source_text,
                repeated_heading=repeated_heading,
            )
        )
        cursor = end

    return result


def reconstruct_semantic_source(chunks: Sequence[SemanticChunk]) -> str:
    """Validate source ranges and reconstruct the original without prefixes."""

    cursor = 0
    source: List[str] = []
    for chunk in chunks:
        if chunk.start != cursor or chunk.end < chunk.start:
            raise ValueError("semantic chunks contain a source gap or overlap at %d" % cursor)
        if len(chunk.source_text) != chunk.end - chunk.start:
            raise ValueError("semantic chunk source length does not match its range")
        source.append(chunk.source_text)
        cursor = chunk.end
    return "".join(source)


def strip_repeated_heading(chunk: SemanticChunk) -> str:
    """Return only the original source portion of a semantic chunk."""

    return chunk.source_text


def _message_kind(message: Mapping[str, Any]) -> str:
    value = message.get("context_kind") or message.get("role") or "message"
    return str(value)


def _group_key(message: Mapping[str, Any], index: int) -> Tuple[Any, ...]:
    value = message.get("context_group")
    if value is None:
        return ("message", index)
    try:
        hash(value)
        return ("group", type(value).__name__, value)
    except TypeError:
        try:
            rendered = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError, OverflowError):
            rendered = repr(value)
        return ("group-rendered", type(value).__name__, rendered)


def _allocate_chars(lengths: Sequence[int], char_budget: int) -> Optional[List[int]]:
    minimums = [min(length, 64) for length in lengths]
    if char_budget < sum(minimums):
        return None
    allocations = list(minimums)
    remaining = min(char_budget - sum(allocations), sum(lengths) - sum(allocations))
    while remaining > 0:
        capacities = [length - allocation for length, allocation in zip(lengths, allocations)]
        total_capacity = sum(capacities)
        if total_capacity <= 0:
            break
        additions = [
            min(capacity, int(remaining * capacity / total_capacity))
            for capacity in capacities
        ]
        if not any(additions):
            for position, capacity in enumerate(capacities):
                if capacity > 0:
                    additions[position] = 1
                    break
        consumed = min(remaining, sum(additions))
        for position, addition in enumerate(additions):
            if consumed <= 0:
                break
            actual = min(addition, consumed)
            allocations[position] += actual
            consumed -= actual
        remaining -= sum(additions)
    return allocations


def _balanced_truncate_to_tokens(text: str, token_budget: int) -> str:
    """Find the largest balanced character slice within an estimated token budget."""
    value = str(text or "")
    budget = max(0, int(token_budget))
    if estimate_content_tokens(value) <= budget:
        return value
    low, high = 0, len(value)
    best = ""
    while low <= high:
        middle = (low + high) // 2
        candidate = balanced_context_truncate(value, middle)
        if estimate_content_tokens(candidate) <= budget:
            best = candidate
            low = middle + 1
        else:
            high = middle - 1
    return best


def _fit_optional_group(
    indexes: Sequence[int],
    messages: Sequence[Mapping[str, Any]],
    available_tokens: int,
) -> Optional[Tuple[Dict[int, Mapping[str, Any]], List[int]]]:
    full_tokens = sum(estimate_message_tokens(messages[index]) for index in indexes)
    if full_tokens <= available_tokens:
        return ({index: messages[index] for index in indexes}, [])

    trimmable = [
        index
        for index in indexes
        if messages[index].get("context_trimmable") is True
        and isinstance(messages[index].get("content"), str)
        and len(messages[index].get("content") or "") > 0
    ]
    if not trimmable:
        return None

    fixed_tokens = MESSAGE_OVERHEAD_TOKENS * len(indexes)
    for index in indexes:
        if index not in trimmable:
            fixed_tokens += estimate_content_tokens(messages[index].get("content"))
    content_token_budget = available_tokens - fixed_tokens
    if content_token_budget <= 0:
        return None

    usable_content_tokens = max(0, content_token_budget)
    token_lengths = [
        estimate_content_tokens(messages[index].get("content") or "")
        for index in trimmable
    ]
    allocations = _allocate_chars(token_lengths, usable_content_tokens)
    if allocations is None:
        return None

    fitted: Dict[int, Mapping[str, Any]] = {
        index: messages[index] for index in indexes
    }
    truncated: List[int] = []
    for index, allocation, original_tokens in zip(
        trimmable, allocations, token_lengths
    ):
        if allocation >= original_tokens:
            continue
        replacement: MutableMapping[str, Any] = dict(messages[index])
        replacement["content"] = _balanced_truncate_to_tokens(
            str(messages[index].get("content") or ""), allocation
        )
        fitted[index] = replacement
        truncated.append(index)

    fitted_tokens = sum(estimate_message_tokens(fitted[index]) for index in indexes)
    if not truncated or fitted_tokens > available_tokens:
        return None
    return fitted, truncated


def _fit_info(
    *,
    model: str,
    provider: Optional[str],
    window: int,
    window_source: str,
    output_reserve: int,
    safety: int,
    budget: int,
    original_tokens: int,
    estimated_tokens: int,
    original_count: int,
    final_count: int,
    omitted_indexes: Sequence[int],
    truncated_indexes: Sequence[int],
    messages: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    omitted = list(sorted(omitted_indexes))
    truncated = list(sorted(truncated_indexes))
    return {
        "model": str(model or ""),
        "provider": str(provider or ""),
        "context_window_tokens": window,
        "window_source": window_source,
        "output_reserve_tokens": output_reserve,
        "safety_tokens": safety,
        "budget_tokens": budget,
        "input_budget_tokens": budget,
        "original_estimated_tokens": original_tokens,
        "original_tokens": original_tokens,
        "estimated_tokens": estimated_tokens,
        "final_estimated_tokens": estimated_tokens,
        "original_message_count": original_count,
        "final_message_count": final_count,
        "omitted_indexes": omitted,
        "omitted_kinds": [_message_kind(messages[index]) for index in omitted],
        "truncated_indexes": truncated,
        "truncated_kinds": [_message_kind(messages[index]) for index in truncated],
        "changed": bool(omitted or truncated),
    }


def fit_messages_to_budget(
    messages: Sequence[Mapping[str, Any]],
    model: str,
    *,
    provider: Optional[str] = None,
    output_reserve_tokens: Any = DEFAULT_OUTPUT_RESERVE_TOKENS,
    safety_tokens: Any = DEFAULT_SAFETY_TOKENS,
    window_override: Optional[Any] = None,
    environ: Optional[Mapping[str, str]] = None,
) -> Tuple[Sequence[Mapping[str, Any]], Dict[str, Any]]:
    """Fit messages into the model input budget without losing trusted data.

    Optional groups are considered newest-first.  A group is either retained
    whole, retained with only explicitly trimmable string observations
    balanced-truncated, or omitted whole.  Returned messages remain in their
    original order and all message metadata is retained.
    """

    for index, message in enumerate(messages):
        if not isinstance(message, Mapping):
            raise TypeError("message %d is not a mapping" % index)

    window, window_source = _resolve_context_window(
        model, provider=provider, override=window_override, environ=environ
    )
    output_reserve = _coerce_integer(
        output_reserve_tokens, name="output reserve"
    )
    safety = _coerce_integer(safety_tokens, name="safety tokens")
    if output_reserve < 0 or safety < 0:
        raise ValueError("output reserve and safety tokens must be non-negative")
    budget = window - output_reserve - safety
    if budget <= 0:
        raise ContextBudgetError(
            "context window %d leaves no input room after reserves" % window,
            budget_tokens=budget,
        )

    original_tokens = estimate_messages_tokens(messages)
    if original_tokens <= budget:
        return messages, _fit_info(
            model=model,
            provider=provider,
            window=window,
            window_source=window_source,
            output_reserve=output_reserve,
            safety=safety,
            budget=budget,
            original_tokens=original_tokens,
            estimated_tokens=original_tokens,
            original_count=len(messages),
            final_count=len(messages),
            omitted_indexes=[],
            truncated_indexes=[],
            messages=messages,
        )

    groups: Dict[Tuple[Any, ...], List[int]] = {}
    group_order: List[Tuple[Any, ...]] = []
    index_group: Dict[int, Tuple[Any, ...]] = {}
    for index, message in enumerate(messages):
        key = _group_key(message, index)
        if key not in groups:
            groups[key] = []
            group_order.append(key)
        groups[key].append(index)
        index_group[index] = key

    current_question = next(
        (
            index
            for index in range(len(messages) - 1, -1, -1)
            if str(messages[index].get("role") or "").lower() == "user"
        ),
        None,
    )
    required_indexes = {
        index
        for index, message in enumerate(messages)
        if str(message.get("role") or "").lower() == "system"
        or message.get("context_pin") is True
        or index == current_question
    }
    required_groups = {index_group[index] for index in required_indexes}
    required_indexes = {
        index for key in required_groups for index in groups[key]
    }
    required_tokens = sum(
        estimate_message_tokens(messages[index]) for index in required_indexes
    )
    if required_tokens > budget:
        kinds = ", ".join(
            "%d:%s" % (index, _message_kind(messages[index]))
            for index in sorted(required_indexes)
        )
        raise ContextBudgetError(
            "trusted pinned context requires about %d tokens but input budget "
            "is %d; refusing to truncate system/current/pinned content (%s)"
            % (required_tokens, budget, kinds),
            required_tokens=required_tokens,
            budget_tokens=budget,
            required_indexes=sorted(required_indexes),
        )

    kept: Dict[int, Mapping[str, Any]] = {
        index: messages[index] for index in required_indexes
    }
    truncated_indexes: List[int] = []
    used_tokens = required_tokens

    optional_groups = [key for key in group_order if key not in required_groups]
    optional_groups.sort(key=lambda key: max(groups[key]), reverse=True)
    for key in optional_groups:
        available = budget - used_tokens
        if available <= 0:
            break
        fitted = _fit_optional_group(groups[key], messages, available)
        if fitted is None:
            continue
        fitted_messages, truncated = fitted
        group_tokens = sum(
            estimate_message_tokens(fitted_messages[index])
            for index in groups[key]
        )
        if used_tokens + group_tokens > budget:
            continue
        kept.update(fitted_messages)
        truncated_indexes.extend(truncated)
        used_tokens += group_tokens

    omitted_indexes = [index for index in range(len(messages)) if index not in kept]
    result: List[Mapping[str, Any]] = [
        kept[index] for index in range(len(messages)) if index in kept
    ]
    estimated_tokens = estimate_messages_tokens(result)
    if estimated_tokens > budget:
        # This is an internal invariant, not a condition callers should have
        # to recover from.  Refuse rather than submit a known-oversize prompt.
        raise ContextBudgetError(
            "fitted context estimate %d unexpectedly exceeds budget %d"
            % (estimated_tokens, budget),
            required_tokens=required_tokens,
            budget_tokens=budget,
            required_indexes=sorted(required_indexes),
        )

    return result, _fit_info(
        model=model,
        provider=provider,
        window=window,
        window_source=window_source,
        output_reserve=output_reserve,
        safety=safety,
        budget=budget,
        original_tokens=original_tokens,
        estimated_tokens=estimated_tokens,
        original_count=len(messages),
        final_count=len(result),
        omitted_indexes=omitted_indexes,
        truncated_indexes=truncated_indexes,
        messages=messages,
    )


__all__ = [
    "ContextBudgetError",
    "DENSE_CHARS_PER_TOKEN",
    "SemanticChunk",
    "balanced_context_truncate",
    "context_input_budget",
    "estimate_content_tokens",
    "estimate_message_tokens",
    "estimate_messages_tokens",
    "fit_messages_to_budget",
    "model_context_window",
    "reconstruct_semantic_source",
    "semantic_chunks",
    "strip_repeated_heading",
]
