#!/usr/bin/env python3
"""Contract tests for Ask-AI context budgeting and semantic chunking."""

import math
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "html"))

from ai_context import (  # noqa: E402
    ContextBudgetError,
    balanced_context_truncate,
    context_input_budget,
    estimate_content_tokens,
    estimate_messages_tokens,
    fit_messages_to_budget,
    model_context_window,
    reconstruct_semantic_source,
    semantic_chunks,
    strip_repeated_heading,
)


class ContextWindowTest(unittest.TestCase):
    def test_primary_model_windows_and_conservative_fallbacks(self):
        cases = {
            "aws/bedrock-claude-opus-4-8": 1_000_000,
            "aws/bedrock-claude-opus-4-7": 1_000_000,
            "claude/claude-opus-4-8": 1_000_000,
            "claude/claude-opus-4-7": 1_000_000,
            "claude/claude-opus-4-6": 1_000_000,
            "claude/claude-sonnet-4-6": 1_000_000,
            "claude/claude-fable-5": 1_000_000,
            "azure/anthropic/claude-sonnet-5": 1_000_000,
            "claude/claude-haiku-4-5": 200_000,
            "claude/claude-3-opus-unknown": 200_000,
            "gcp/google/gemini-2.5-pro": 1_000_000,
            "gcp/google/gemini-3.5-flash": 1_000_000,
            "openai/openai/gpt-4o": 128_000,
            "openai/openai/gpt-5.5": 1_100_000,
            "azure/openai/gpt-5.5": 1_000_000,
            "openai/openai/gpt-5.4": 1_000_000,
            "openai/openai/gpt-5.4-mini": 400_000,
            "openai/openai/gpt-5.3-codex": 200_000,
            "openai/openai/gpt-5.2-codex": 400_000,
            "unknown/cloud-model": 128_000,
        }
        for model, expected in cases.items():
            with self.subTest(model=model):
                self.assertEqual(
                    model_context_window(model, environ={}), expected
                )
        self.assertEqual(
            model_context_window("gpt-4o", provider="ollama", environ={}),
            32_000,
        )

    def test_explicit_and_environment_overrides_are_clamped(self):
        self.assertEqual(
            model_context_window(
                "unknown", override="4,096", environ={}
            ),
            8_000,
        )
        self.assertEqual(
            model_context_window(
                "unknown", override=9_000_000, environ={}
            ),
            2_000_000,
        )
        self.assertEqual(
            model_context_window("unknown", override="", environ={}),
            128_000,
        )
        environment = {
            "AI_CONTEXT_WINDOW_TOKENS": "256_000",
            "ASK_AI_CONTEXT_WINDOW_TOKENS": "384_000",
            "ASK_AI_CONTEXT_WINDOW": "512000",
        }
        self.assertEqual(
            model_context_window("unknown", environ=environment), 256_000
        )
        self.assertEqual(
            model_context_window(
                "unknown", override=300_000, environ=environment
            ),
            300_000,
        )
        self.assertEqual(
            model_context_window(
                "unknown",
                environ={"AI_CONTEXT_WINDOW_TOKENS": "not-a-number"},
            ),
            128_000,
        )

    def test_input_budget_subtracts_output_and_safety(self):
        self.assertEqual(
            context_input_budget(
                "unknown",
                window_override=100_000,
                output_reserve_tokens=12_000,
                safety_tokens=8_000,
                environ={},
            ),
            80_000,
        )
        with self.assertRaisesRegex(ContextBudgetError, "leaves no input room"):
            context_input_budget(
                "unknown",
                window_override=8_000,
                output_reserve_tokens=4_000,
                safety_tokens=4_000,
                environ={},
            )

    def test_dense_unicode_estimate_is_more_conservative_than_ascii(self):
        dense = "界🙂é" * 113
        self.assertEqual(estimate_content_tokens(dense), len(dense) * 2)
        self.assertEqual(estimate_content_tokens("a" * 113), math.ceil(113 / 3.5))
        messages = [{"role": "user", "content": dense}]
        self.assertEqual(
            estimate_messages_tokens(messages),
            len(dense) * 2 + 8,
        )


class TruncationAndChunkingTest(unittest.TestCase):
    def test_balanced_truncation_preserves_head_tail_and_limit(self):
        text = "HEAD-" + ("m" * 1000) + "-TAIL"
        result = balanced_context_truncate(text, 160)
        self.assertEqual(len(result), 160)
        self.assertTrue(result.startswith("HEAD-"))
        self.assertTrue(result.endswith("-TAIL"))
        self.assertIn("context truncated", result)

    def test_semantic_chunks_have_exact_nonoverlapping_source_ranges(self):
        text = (
            "# Interfaces\n"
            + "".join(
                "eth%d is up with counters %s\n" % (index, "x" * 45)
                for index in range(18)
            )
            + "\n## Routing\n"
            + "".join(
                "route %d via 10.0.0.%d %s\n" % (index, index, "y" * 35)
                for index in range(14)
            )
        )
        chunks = semantic_chunks(text, 240)
        self.assertGreater(len(chunks), 3)
        self.assertEqual(reconstruct_semantic_source(chunks), text)
        self.assertEqual("".join(strip_repeated_heading(c) for c in chunks), text)
        self.assertEqual(chunks[0].start, 0)
        self.assertEqual(chunks[-1].end, len(text))
        for previous, current in zip(chunks, chunks[1:]):
            self.assertEqual(previous.end, current.start)
        for chunk in chunks:
            self.assertLessEqual(len(chunk.text), 240)
            self.assertEqual(chunk.source_text, text[chunk.start:chunk.end])

    def test_repeated_heading_is_separate_and_is_the_only_added_context(self):
        heading = "## Optical ports\n"
        text = heading + "".join(
            "swp%d rx=-3.%d tx=-2.%d %s\n" % (index, index, index, "z" * 50)
            for index in range(15)
        )
        chunks = semantic_chunks(text, 180)
        continued = [chunk for chunk in chunks if chunk.repeated_heading]
        self.assertTrue(continued)
        for chunk in continued:
            self.assertEqual(chunk.repeated_heading, heading)
            self.assertEqual(chunk.text, heading + chunk.source_text)
            self.assertEqual(strip_repeated_heading(chunk), chunk.source_text)
        self.assertEqual(reconstruct_semantic_source(chunks), text)

    def test_chunk_starting_at_new_heading_never_repeats_previous_heading(self):
        text = (
            "# A\n" + ("a line\n" * 20)
            + "# B\n" + ("b line\n" * 20)
        )
        chunks = semantic_chunks(text, 40)
        section_b = next(
            chunk for chunk in chunks if chunk.source_text.startswith("# B")
        )
        self.assertEqual(section_b.repeated_heading, "")
        self.assertTrue(section_b.text.startswith("# B"))

    def test_paragraph_line_and_space_fallbacks_make_progress(self):
        paragraph_text = ("alpha\n\n" + "beta line\n") * 80
        paragraph_chunks = semantic_chunks(paragraph_text, 160)
        self.assertEqual(reconstruct_semantic_source(paragraph_chunks), paragraph_text)
        self.assertTrue(all(chunk.end > chunk.start for chunk in paragraph_chunks))

        unbroken = "🙂" * 1000
        hard_chunks = semantic_chunks(unbroken, 128)
        self.assertEqual(reconstruct_semantic_source(hard_chunks), unbroken)
        self.assertTrue(all(len(chunk.text) <= 128 for chunk in hard_chunks))

        tiny_chunks = semantic_chunks("abcdefghijklmnopqrstuvwxyz", 7)
        self.assertEqual(reconstruct_semantic_source(tiny_chunks), "abcdefghijklmnopqrstuvwxyz")
        self.assertTrue(all(len(chunk.text) <= 7 for chunk in tiny_chunks))
        with self.assertRaisesRegex(ValueError, "must be positive"):
            semantic_chunks("data", 0)


class MessageFittingTest(unittest.TestCase):
    @staticmethod
    def fit(messages, budget=3_000):
        # The minimum supported context override is 8K.  Select reserves so
        # the exact input budget used by each test remains easy to reason about.
        return fit_messages_to_budget(
            messages,
            "unknown/model",
            window_override=8_000,
            output_reserve_tokens=3_000,
            safety_tokens=5_000 - budget,
            environ={},
        )

    def test_under_budget_is_a_true_noop_for_objects_and_metadata(self):
        structured = [{"type": "text", "text": "hello"}]
        messages = [
            {
                "role": "system",
                "content": "rules",
                "custom": {"trusted": True},
            },
            {"role": "user", "content": structured, "request_id": "r1"},
        ]
        fitted, info = self.fit(messages, budget=2_000)
        self.assertIs(fitted, messages)
        self.assertIs(fitted[1]["content"], structured)
        self.assertEqual(fitted, messages)
        self.assertFalse(info["changed"])
        self.assertEqual(info["omitted_indexes"], [])
        self.assertEqual(info["truncated_indexes"], [])
        self.assertEqual(info["original_estimated_tokens"], info["estimated_tokens"])
        self.assertEqual(info["budget_tokens"], 2_000)

    def test_pinned_messages_and_their_group_companions_survive(self):
        messages = [
            {"role": "system", "content": "trusted rules"},
            {
                "role": "assistant",
                "content": "tool call " + ("a" * 700),
                "context_group": "critical-tool",
            },
            {
                "role": "tool",
                "content": "trusted result " + ("b" * 700),
                "context_group": "critical-tool",
                "context_pin": True,
                "context_kind": "pinned-result",
            },
            {"role": "assistant", "content": "old " + ("x" * 8000)},
            {"role": "user", "content": "What is wrong?"},
        ]
        fitted, info = self.fit(messages, budget=1_000)
        self.assertIn(messages[0], fitted)
        self.assertIn(messages[1], fitted)
        self.assertIn(messages[2], fitted)
        self.assertIn(messages[4], fitted)
        self.assertNotIn(messages[3], fitted)
        self.assertEqual(info["omitted_indexes"], [3])
        self.assertEqual(info["omitted_kinds"], ["assistant"])
        self.assertLessEqual(info["estimated_tokens"], info["budget_tokens"])

    def test_groups_are_never_orphaned_and_newest_groups_win(self):
        messages = [
            {"role": "system", "content": "rules"},
            {
                "role": "assistant",
                "content": "old-call " + ("a" * 2200),
                "context_group": "old",
            },
            {
                "role": "tool",
                "content": "old-result " + ("b" * 2200),
                "context_group": "old",
            },
            {
                "role": "assistant",
                "content": "new-call " + ("c" * 1200),
                "context_group": "new",
            },
            {
                "role": "tool",
                "content": "new-result " + ("d" * 1200),
                "context_group": "new",
            },
            {"role": "user", "content": "current question"},
        ]
        fitted, info = self.fit(messages, budget=1_300)
        self.assertNotIn(messages[1], fitted)
        self.assertNotIn(messages[2], fitted)
        self.assertIn(messages[3], fitted)
        self.assertIn(messages[4], fitted)
        self.assertEqual(info["omitted_indexes"], [1, 2])
        self.assertEqual(
            [message.get("context_group") for message in fitted if message.get("context_group")],
            ["new", "new"],
        )

    def test_only_explicitly_trimmable_observation_is_truncated(self):
        observation = "OBS-HEAD\n" + ("dense-data🙂" * 1800) + "\nOBS-TAIL"
        messages = [
            {"role": "system", "content": "rules", "context_trimmable": True},
            {
                "role": "user",
                "content": "old untrusted request " + ("q" * 5000),
                "context_kind": "old-question",
            },
            {
                "role": "tool",
                "content": observation,
                "context_trimmable": True,
                "context_kind": "fabric-observation",
                "source": "timeline",
            },
            {
                "role": "user",
                "content": "Correlate the current failures.",
                "context_trimmable": True,
            },
        ]
        fitted, info = self.fit(messages, budget=1_400)
        self.assertIs(fitted[0], messages[0])
        self.assertEqual(fitted[-1]["content"], messages[-1]["content"])
        self.assertNotIn(messages[1], fitted)
        trimmed = next(item for item in fitted if item.get("source") == "timeline")
        self.assertTrue(trimmed["content"].startswith("OBS-HEAD"))
        self.assertTrue(trimmed["content"].endswith("OBS-TAIL"))
        self.assertIn("context truncated", trimmed["content"])
        self.assertEqual(trimmed["context_kind"], "fabric-observation")
        self.assertTrue(trimmed["context_trimmable"])
        self.assertEqual(info["truncated_indexes"], [2])
        self.assertEqual(info["truncated_kinds"], ["fabric-observation"])
        self.assertEqual(info["omitted_indexes"], [1])
        self.assertTrue(info["changed"])
        self.assertLessEqual(info["estimated_tokens"], info["budget_tokens"])
        self.assertEqual(messages[2]["content"], observation)

    def test_unmarked_large_message_is_omitted_not_truncated(self):
        large = {"role": "tool", "content": "x" * 20_000, "tag": "unchanged"}
        messages = [
            {"role": "system", "content": "rules"},
            large,
            {"role": "user", "content": "question"},
        ]
        fitted, info = self.fit(messages, budget=700)
        self.assertNotIn(large, fitted)
        self.assertEqual(large["content"], "x" * 20_000)
        self.assertEqual(info["omitted_indexes"], [1])
        self.assertEqual(info["truncated_indexes"], [])

    def test_impossible_trusted_pinned_context_raises_clear_error(self):
        messages = [
            {
                "role": "system",
                "content": "s" * 8_000,
                "context_trimmable": True,
            },
            {
                "role": "tool",
                "content": "p" * 3_000,
                "context_pin": True,
                "context_kind": "trusted-evidence",
                "context_trimmable": True,
            },
            {"role": "user", "content": "current"},
        ]
        with self.assertRaises(ContextBudgetError) as captured:
            self.fit(messages, budget=1_000)
        error = captured.exception
        self.assertIn("trusted pinned context", str(error))
        self.assertIn("refusing to truncate", str(error))
        self.assertGreater(error.required_tokens, error.budget_tokens)
        self.assertEqual(error.required_indexes, (0, 1, 2))


if __name__ == "__main__":
    unittest.main()
