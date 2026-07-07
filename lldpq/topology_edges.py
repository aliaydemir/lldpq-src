#!/usr/bin/env python3
"""Shared topology-edge and LLDP-neighbor semantics for LLDPq.

The wiring report and both topology generators must interpret ``topology.dot``
the same way.  This module intentionally implements the small, point-to-point
subset LLDPq supports while accepting normal DOT conveniences such as quoted or
unquoted identifiers, comments, attributes, semicolons, and multiple statements
on one line.  Edge chains are parsed for an actionable diagnostic, but normal
point-to-point semantics reject their reused middle endpoint.

Every endpoint is a physical ``(device, interface)`` identity.  Reusing one in
more than one configured edge is therefore rejected instead of silently
inflating report totals.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
import re
import sys
from typing import Iterable, Iterator, Optional, Sequence


_KNOWN_HOST_SUFFIXES = (".cm.cluster", ".localdomain", ".local")
_LLDP_SEPARATOR_RE = re.compile(r"(?m)^-{20,}\s*$")


class TopologyError(ValueError):
    """Base class for topology input errors suitable for an operator."""


class TopologySyntaxError(TopologyError):
    """The DOT input contains an edge LLDPq cannot interpret."""


class TopologySemanticError(TopologyError):
    """The DOT input violates point-to-point topology semantics."""


@dataclass(frozen=True)
class TopologyEdge:
    left_device: str
    left_port: str
    right_device: str
    right_port: str
    line: int = 0
    column: int = 0

    def as_tuple(self) -> tuple[str, str, str, str]:
        return (
            self.left_device,
            self.left_port,
            self.right_device,
            self.right_port,
        )


@dataclass(frozen=True)
class LLDPNeighbor:
    local_port: str
    device: Optional[str]
    remote_port: Optional[str]


@dataclass(frozen=True)
class _Token:
    kind: str
    value: str
    line: int
    column: int
    quoted: bool = False


def normalize_hostname(name: Optional[str]) -> str:
    """Normalize harmless LLDP hostname decoration while preserving spelling."""
    value = str(name or "").strip().rstrip(".")
    while value:
        folded = value.casefold()
        matched = next(
            (suffix for suffix in _KNOWN_HOST_SUFFIXES if folded.endswith(suffix)),
            None,
        )
        if not matched:
            break
        value = value[: -len(matched)].rstrip(".")
    return value


class DeviceNameResolver:
    """Resolve DNS-style case/FQDN variants to one known canonical spelling.

    A generic FQDN is shortened only when its first label uniquely identifies a
    known name.  Thus ``leaf-01.example.test`` can match configured ``LEAF-01``
    without conflating ``leaf-01.site-a`` and ``leaf-01.site-b``.
    """

    def __init__(self, known_names: Iterable[str] = ()):
        names: list[str] = []
        seen: set[str] = set()
        for raw in known_names:
            value = str(raw or "").strip().rstrip(".")
            if not value:
                continue
            folded = value.casefold()
            if folded in seen:
                continue
            seen.add(folded)
            names.append(value)

        # An explicitly known short hostname is the preferred identity and
        # display spelling for all of its case/FQDN forms.  FQDN-only names that
        # merely share a first label remain distinct, which avoids merging hosts
        # from different DNS domains accidentally.
        short_identities = {
            name.casefold() for name in names if "." not in name
        }
        self._canonical_by_key: dict[str, str] = {}
        self._exact_to_key: dict[str, str] = {}
        canonical_rank: dict[str, tuple[int, int]] = {}
        for position, name in enumerate(names):
            exact_key = name.casefold()
            short_key = name.split(".", 1)[0].casefold()
            normalized_key = normalize_hostname(name).casefold() or exact_key
            canonical_key = (
                short_key
                if "." in name and short_key in short_identities
                else normalized_key
            )
            self._exact_to_key[exact_key] = canonical_key

            # Prefer a literal short hostname over a suffix-decorated spelling,
            # irrespective of input order. Otherwise preserve the first known
            # spelling so configured names remain stable in reports and graphs.
            rank = (0 if "." not in name else 1, position)
            if canonical_key not in canonical_rank or rank < canonical_rank[canonical_key]:
                canonical_rank[canonical_key] = rank
                self._canonical_by_key[canonical_key] = name

        aliases: dict[str, set[str]] = {}
        for name in names:
            exact_key = name.casefold()
            canonical_key = self._exact_to_key[exact_key]
            candidates = {
                exact_key,
                canonical_key,
                name.split(".", 1)[0].casefold(),
            }
            for candidate in candidates:
                if candidate:
                    aliases.setdefault(candidate, set()).add(canonical_key)
        self._unique_aliases = {
            alias: next(iter(keys)) for alias, keys in aliases.items() if len(keys) == 1
        }

    def key(self, name: Optional[str]) -> str:
        raw = str(name or "").strip().rstrip(".")
        if not raw:
            return ""
        folded = raw.casefold()
        if folded in self._exact_to_key:
            return self._exact_to_key[folded]
        candidates = (
            normalize_hostname(raw).casefold(),
            raw.split(".", 1)[0].casefold(),
        )
        for candidate in candidates:
            canonical_key = self._unique_aliases.get(candidate)
            if canonical_key:
                return canonical_key
        return normalize_hostname(raw).casefold()

    def canonical(self, name: Optional[str]) -> str:
        raw = str(name or "").strip().rstrip(".")
        if not raw:
            return ""
        key = self.key(raw)
        # Preserve an unknown device's advertised spelling for diagnostics.  A
        # known FQDN/case variant still resolves to the configured canonical name.
        return self._canonical_by_key.get(key, raw)


def canonicalize_device_names(
    names: Iterable[str], authoritative_names: Iterable[str]
) -> set[str]:
    """Map name variants onto authoritative spellings without inventing aliases."""
    resolver = DeviceNameResolver(authoritative_names)
    canonical: set[str] = set()
    for name in names:
        resolved = resolver.canonical(name)
        if resolved:
            canonical.add(resolved)
    return canonical


def normalize_port_name(port: Optional[str]) -> str:
    """Normalize LLDP punctuation without changing case-sensitive interface IDs."""
    return str(port or "").strip().strip(",")


def port_key(port: Optional[str]) -> str:
    """Interface names remain case-sensitive on Linux and network operating systems."""
    return normalize_port_name(port)


def is_eth0(port: Optional[str]) -> bool:
    return normalize_port_name(port).casefold() == "eth0"


def _strip_device_prefix(port: str, known_device_names: Iterable[str]) -> str:
    best = ""
    folded_port = port.casefold()
    for raw_name in known_device_names:
        name = str(raw_name or "").strip().rstrip(".")
        for candidate in (name, normalize_hostname(name)):
            prefix = candidate + "-"
            if candidate and folded_port.startswith(prefix.casefold()) and len(prefix) > len(best):
                best = prefix
    return port[len(best) :] if best else port


def normalize_advertised_port(
    port_id: Optional[str],
    port_description: Optional[str],
    known_device_names: Iterable[str] = (),
) -> Optional[str]:
    """Select and normalize one remote interface from LLDP TLVs consistently."""
    candidate = normalize_port_name(port_id)
    if not candidate:
        description = str(port_description or "").strip()
        as_match = re.search(r"\bas\s+(\S+)", description, re.IGNORECASE)
        if as_match:
            candidate = normalize_port_name(as_match.group(1))
        elif description and not any(char.isspace() for char in description):
            candidate = normalize_port_name(description)
        else:
            # The aggregate report is whitespace-delimited.  A prose PortDescr
            # is not a safe interface identity and must remain explicitly unknown.
            candidate = ""
    if not candidate or candidate.upper().startswith("TLV"):
        return None
    return _strip_device_prefix(candidate, known_device_names)


def iter_lldp_neighbors(
    content: str,
    *,
    resolver: Optional[DeviceNameResolver] = None,
    known_device_names: Iterable[str] = (),
) -> Iterator[LLDPNeighbor]:
    """Yield normalized neighbor records from one ``lldpctl`` capture."""
    known_names = tuple(known_device_names)
    if resolver is None:
        resolver = DeviceNameResolver(known_names)
    for section in _LLDP_SEPARATOR_RE.split(content):
        interface_match = re.search(r"Interface:\s*([^\s,]+)", section, re.IGNORECASE)
        if not interface_match:
            continue
        sys_name_match = re.search(r"SysName:\s*([^\r\n]+)", section, re.IGNORECASE)
        port_id_match = re.search(
            r"PortID:\s+(?:ifname|ifalias)\s+(\S+)", section, re.IGNORECASE
        )
        port_description_match = re.search(
            r"PortDescr:\s*([^\r\n]+)", section, re.IGNORECASE
        )
        raw_device = sys_name_match.group(1).strip() if sys_name_match else ""
        # devices.yaml and the aggregate schema both require one hostname token.
        # Preserve the neighbor as Unknown in validation, but never serialize a
        # prose/malformed SysName into multiple report columns.
        device = (
            resolver.canonical(raw_device)
            if raw_device and not any(char.isspace() for char in raw_device)
            else None
        )
        prefix_names = tuple(
            name for name in (raw_device, device) if name
        )
        remote_port = normalize_advertised_port(
            port_id_match.group(1) if port_id_match else None,
            port_description_match.group(1) if port_description_match else None,
            prefix_names,
        )
        yield LLDPNeighbor(
            local_port=normalize_port_name(interface_match.group(1)),
            device=device or None,
            remote_port=remote_port,
        )


def _tokenize(content: str, source: str) -> list[_Token]:
    tokens: list[_Token] = []
    index = 0
    line = 1
    column = 1
    length = len(content)

    def advance(character: str) -> None:
        nonlocal line, column
        if character == "\n":
            line += 1
            column = 1
        else:
            column += 1

    while index < length:
        char = content[index]
        if char.isspace():
            advance(char)
            index += 1
            continue

        if char == "#":
            while index < length and content[index] != "\n":
                advance(content[index])
                index += 1
            continue
        if char == "/" and index + 1 < length and content[index + 1] == "/":
            while index < length and content[index] != "\n":
                advance(content[index])
                index += 1
            continue
        if char == "/" and index + 1 < length and content[index + 1] == "*":
            start_line, start_column = line, column
            advance(char)
            advance(content[index + 1])
            index += 2
            while index + 1 < length and content[index : index + 2] != "*/":
                advance(content[index])
                index += 1
            if index + 1 >= length:
                raise TopologySyntaxError(
                    f"{source}:{start_line}:{start_column}: unterminated block comment"
                )
            advance(content[index])
            advance(content[index + 1])
            index += 2
            continue

        start_line, start_column = line, column
        if char == '"':
            index += 1
            advance(char)
            value: list[str] = []
            while index < length:
                current = content[index]
                if current == '"':
                    advance(current)
                    index += 1
                    break
                if current == "\\":
                    if index + 1 >= length:
                        raise TopologySyntaxError(
                            f"{source}:{start_line}:{start_column}: unterminated quoted identifier"
                        )
                    escaped = content[index + 1]
                    advance(current)
                    advance(escaped)
                    index += 2
                    if escaped != "\n":
                        value.append(escaped)
                    continue
                if current in "\r\n":
                    raise TopologySyntaxError(
                        f"{source}:{start_line}:{start_column}: newline in quoted identifier"
                    )
                value.append(current)
                advance(current)
                index += 1
            else:
                raise TopologySyntaxError(
                    f"{source}:{start_line}:{start_column}: unterminated quoted identifier"
                )
            tokens.append(
                _Token("ID", "".join(value), start_line, start_column, quoted=True)
            )
            continue

        if char == "[":
            depth = 1
            index += 1
            advance(char)
            quoted = False
            escaped = False
            while index < length and depth:
                current = content[index]
                if quoted:
                    if escaped:
                        escaped = False
                    elif current == "\\":
                        escaped = True
                    elif current == '"':
                        quoted = False
                else:
                    if current == '"':
                        quoted = True
                    elif current == "[":
                        depth += 1
                    elif current == "]":
                        depth -= 1
                advance(current)
                index += 1
            if depth:
                raise TopologySyntaxError(
                    f"{source}:{start_line}:{start_column}: unterminated attribute list"
                )
            continue

        if content.startswith("--", index):
            tokens.append(_Token("EDGE", "--", start_line, start_column))
            advance("-")
            advance("-")
            index += 2
            continue
        if content.startswith("->", index):
            raise TopologySyntaxError(
                f"{source}:{start_line}:{start_column}: directed edges are unsupported; use '--'"
            )
        punctuation = {":": "COLON", ";": "SEMI", "{": "LBRACE", "}": "RBRACE", ",": "COMMA", "=": "EQUAL"}
        if char in punctuation:
            tokens.append(_Token(punctuation[char], char, start_line, start_column))
            advance(char)
            index += 1
            continue

        value: list[str] = []
        while index < length:
            current = content[index]
            if current.isspace() or current in '"#:;{}[],=':
                break
            if content.startswith("--", index) or content.startswith("//", index) or content.startswith("/*", index):
                break
            value.append(current)
            advance(current)
            index += 1
        if not value:
            raise TopologySyntaxError(
                f"{source}:{start_line}:{start_column}: unsupported character {char!r}"
            )
        tokens.append(_Token("ID", "".join(value), start_line, start_column))

    return tokens


def _parse_endpoint(tokens: Sequence[_Token], index: int):
    if index >= len(tokens) or tokens[index].kind != "ID":
        return None
    if index + 2 >= len(tokens) or tokens[index + 1].kind != "COLON" or tokens[index + 2].kind != "ID":
        return None
    device = tokens[index].value
    port_parts = [tokens[index + 2].value]
    cursor = index + 3
    # Preserve legacy unquoted port IDs containing colons.
    while cursor + 1 < len(tokens) and tokens[cursor].kind == "COLON" and tokens[cursor + 1].kind == "ID":
        port_parts.append(tokens[cursor + 1].value)
        cursor += 2
    port = ":".join(port_parts)
    if not device or not port:
        return None
    return device, port, cursor, tokens[index]


def _validate_braces(tokens: Sequence[_Token], source: str) -> None:
    cursor = 0
    if (cursor < len(tokens) and tokens[cursor].kind == "ID"
            and not tokens[cursor].quoted
            and tokens[cursor].value.casefold() == "strict"):
        cursor += 1
    if (cursor >= len(tokens) or tokens[cursor].kind != "ID"
            or tokens[cursor].quoted
            or tokens[cursor].value.casefold() != "graph"):
        raise TopologySyntaxError(
            f"{source}: topology.dot must start with an undirected 'graph' declaration"
        )
    cursor += 1
    if cursor < len(tokens) and tokens[cursor].kind == "ID":
        cursor += 1
    if cursor >= len(tokens) or tokens[cursor].kind != "LBRACE":
        token = tokens[cursor] if cursor < len(tokens) else None
        location = f":{token.line}:{token.column}" if token else ""
        raise TopologySyntaxError(
            f"{source}{location}: graph declaration must be followed by '{{'"
        )

    header_brace_index = cursor
    depth = 0
    closing_index = None
    for token_index, token in enumerate(tokens[header_brace_index:], header_brace_index):
        if token.kind == "LBRACE":
            depth += 1
        elif token.kind == "RBRACE":
            depth -= 1
            if depth < 0:
                raise TopologySyntaxError(
                    f"{source}:{token.line}:{token.column}: unmatched closing brace"
                )
            if depth == 0:
                closing_index = token_index
                break
    if depth:
        raise TopologySyntaxError(f"{source}: topology graph has unbalanced braces")
    if closing_index is None:
        raise TopologySyntaxError(f"{source}: topology graph is missing a closing brace")
    for token in tokens[closing_index + 1:]:
        if token.kind != "SEMI":
            raise TopologySyntaxError(
                f"{source}:{token.line}:{token.column}: content appears after the top-level graph"
            )


def validate_topology_semantics(
    edges: Sequence[TopologyEdge], *, source: str = "topology.dot"
) -> None:
    resolver = DeviceNameResolver(
        device for edge in edges for device in (edge.left_device, edge.right_device)
    )
    seen_edges: dict[tuple[tuple[str, str], tuple[str, str]], TopologyEdge] = {}
    seen_endpoints: dict[tuple[str, str], TopologyEdge] = {}
    for edge in edges:
        for label, value in (
            ("device", edge.left_device),
            ("interface", edge.left_port),
            ("device", edge.right_device),
            ("interface", edge.right_port),
        ):
            if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
                raise TopologySemanticError(
                    f"{source}:{edge.line}: topology {label} {value!r} contains "
                    "whitespace or control characters unsupported by LLDP reports"
                )
        left = (resolver.key(edge.left_device), port_key(edge.left_port))
        right = (resolver.key(edge.right_device), port_key(edge.right_port))
        if left == right:
            raise TopologySemanticError(
                f"{source}:{edge.line}: topology edge connects endpoint "
                f"{edge.left_device}:{edge.left_port} to itself"
            )
        edge_key = tuple(sorted((left, right)))
        previous_edge = seen_edges.get(edge_key)
        if previous_edge is not None:
            raise TopologySemanticError(
                f"{source}:{edge.line}: duplicate topology edge; first defined on "
                f"line {previous_edge.line}"
            )
        for endpoint, display in (
            (left, f"{edge.left_device}:{edge.left_port}"),
            (right, f"{edge.right_device}:{edge.right_port}"),
        ):
            previous = seen_endpoints.get(endpoint)
            if previous is not None:
                raise TopologySemanticError(
                    f"{source}:{edge.line}: endpoint {display} is reused; first used "
                    f"on line {previous.line}"
                )
            seen_endpoints[endpoint] = edge
        seen_edges[edge_key] = edge


def parse_topology_text(
    content: str,
    *,
    source: str = "topology.dot",
    validate_semantics: bool = True,
) -> list[TopologyEdge]:
    if not str(content or "").strip():
        raise TopologySyntaxError(f"{source}: topology.dot cannot be empty")
    tokens = _tokenize(content, source)
    _validate_braces(tokens, source)
    edges: list[TopologyEdge] = []
    consumed_edge_tokens: set[int] = set()
    consumed_endpoint_tokens: set[int] = set()
    index = 0
    while index < len(tokens):
        endpoint = _parse_endpoint(tokens, index)
        if endpoint is None:
            index += 1
            continue
        left_device, left_port, cursor, origin = endpoint
        if cursor >= len(tokens) or tokens[cursor].kind != "EDGE":
            index += 1
            continue
        consumed_endpoint_tokens.update(range(index, cursor))
        while cursor < len(tokens) and tokens[cursor].kind == "EDGE":
            consumed_edge_tokens.add(cursor)
            right = _parse_endpoint(tokens, cursor + 1)
            if right is None:
                token = tokens[cursor]
                raise TopologySyntaxError(
                    f"{source}:{token.line}:{token.column}: edge endpoint must be device:port"
                )
            right_device, right_port, next_cursor, _ = right
            consumed_endpoint_tokens.update(range(cursor + 1, next_cursor))
            edges.append(
                TopologyEdge(
                    left_device=left_device,
                    left_port=left_port,
                    right_device=right_device,
                    right_port=right_port,
                    line=origin.line,
                    column=origin.column,
                )
            )
            left_device, left_port = right_device, right_port
            cursor = next_cursor
        index = cursor

    for token_index, token in enumerate(tokens):
        if token.kind == "EDGE" and token_index not in consumed_edge_tokens:
            raise TopologySyntaxError(
                f"{source}:{token.line}:{token.column}: unsupported topology edge syntax"
            )
        if token.kind == "COLON" and token_index not in consumed_endpoint_tokens:
            raise TopologySyntaxError(
                f"{source}:{token.line}:{token.column}: device:port endpoint is not part of an edge"
            )
    if validate_semantics:
        validate_topology_semantics(edges, source=source)
    return edges


def parse_topology_file(
    path: str, *, validate_semantics: bool = True
) -> list[TopologyEdge]:
    with open(path, "r", encoding="utf-8") as handle:
        return parse_topology_text(
            handle.read(), source=os.path.abspath(path), validate_semantics=validate_semantics
        )


def _main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Validate LLDPq topology edge semantics")
    parser.add_argument("--validate-stdin", action="store_true")
    parser.add_argument("path", nargs="?")
    args = parser.parse_args(argv)
    if not args.validate_stdin and not args.path:
        parser.error("provide a topology path or --validate-stdin")
    try:
        if args.validate_stdin:
            edges = parse_topology_text(sys.stdin.read(), source="topology.dot")
        else:
            edges = parse_topology_file(args.path)
    except (OSError, TopologyError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"validated {len(edges)} topology edge(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
