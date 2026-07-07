#!/usr/bin/env python3
"""Regression checks for the Device Details NVT tab."""

from html.parser import HTMLParser
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
DEVICE_HTML = ROOT / "html" / "device.html"
COMMANDS_HTML = ROOT / "html" / "commands.html"


class _TabParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tabs = []
        self.panels = {}

    def handle_starttag(self, tag, attrs) -> None:
        attributes = dict(attrs)
        if tag == "button" and attributes.get("role") == "tab":
            self.tabs.append(attributes)
        if tag == "div" and attributes.get("role") == "tabpanel":
            self.panels[attributes.get("id")] = attributes


def _css_rule(source: str, selector: str) -> str:
    match = re.search(rf"{re.escape(selector)}\s*\{{([^}}]*)\}}", source, re.DOTALL)
    if not match:
        raise AssertionError(f"Missing CSS rule: {selector}")
    return re.sub(r"\s+", " ", match.group(1)).strip()


def _color_map(block: str):
    return {
        int(code): color.lower()
        for code, color in re.findall(r"(\d+)\s*:\s*'([^']+)'", block)
    }


class DeviceDetailsNvtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.device = DEVICE_HTML.read_text(encoding="utf-8")
        cls.commands = COMMANDS_HTML.read_text(encoding="utf-8")

    def test_nvt_tab_is_between_optical_and_bgp_with_matching_panel(self) -> None:
        parser = _TabParser()
        parser.feed(self.device)
        tab_names = [tab.get("data-tab") for tab in parser.tabs]
        optical_index = tab_names.index("optical")
        self.assertEqual(tab_names[optical_index : optical_index + 3], ["optical", "nvt", "bgp"])

        nvt_tab = next(tab for tab in parser.tabs if tab.get("data-tab") == "nvt")
        self.assertEqual(nvt_tab.get("aria-controls"), "tab-nvt")
        self.assertEqual(nvt_tab.get("aria-selected"), "false")
        self.assertEqual(nvt_tab.get("tabindex"), "-1")
        self.assertEqual(parser.panels["tab-nvt"].get("aria-labelledby"), "tab-button-nvt")

    def test_nvt_uses_lazy_loading_and_exact_allowlisted_command(self) -> None:
        self.assertIn("else if (tabName === 'nvt' && !tabsLoaded.nvt)", self.device)
        self.assertIn("trackTabLoad('nvt', loadNvtOutput())", self.device)
        self.assertIn(
            "JSON.stringify({device: requestContext.device, command: 'nvt'})",
            self.device,
        )
        self.assertRegex(self.device, r"tabsLoaded\s*=\s*\{[^}]*\bnvt:\s*false")

    def test_nvt_palette_matches_commands_output(self) -> None:
        commands_match = re.search(r"const BASIC\s*=\s*\{(.*?)\};", self.commands, re.DOTALL)
        device_match = re.search(
            r"const NVT_ANSI_COLORS\s*=\s*Object\.freeze\(\{(.*?)\}\);",
            self.device,
            re.DOTALL,
        )
        self.assertIsNotNone(commands_match)
        self.assertIsNotNone(device_match)
        self.assertEqual(_color_map(device_match.group(1)), _color_map(commands_match.group(1)))

    def test_nvt_output_is_full_height_and_preserves_terminal_columns(self) -> None:
        rule = _css_rule(self.device, ".nvt-output")
        self.assertIn("max-height: none", rule)
        self.assertIn("overflow-y: visible", rule)
        self.assertIn("overflow-x: auto", rule)
        self.assertIn("white-space: pre", rule)
        self.assertNotIn("overflow-y: auto", rule)

    def test_nvt_renderer_preserves_safe_dom_and_stale_request_guards(self) -> None:
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
            self.assertNotIn(sink, self.device)
        self.assertIn("document.createTextNode(text)", self.device)
        self.assertIn("document.createDocumentFragment()", self.device)
        self.assertGreaterEqual(self.device.count("requestId !== nvtRequestId"), 2)
        self.assertIn(
            "!isCurrentDeviceRequest(requestContext.device, requestContext.generation)",
            self.device,
        )
        self.assertIn("if (nvtAbortController) nvtAbortController.abort()", self.device)

    def test_nvt_and_global_refresh_share_pending_operation_barriers(self) -> None:
        self.assertIn("let refreshAllPromise = null", self.device)
        self.assertIn("let nvtOperationPromise = null", self.device)
        self.assertIn(
            "const pendingRefresh = waitForGlobalRefresh ? refreshAllPromise : null",
            self.device,
        )
        self.assertIn("const pendingNvt = nvtOperationPromise", self.device)
        self.assertIn("await Promise.resolve(pendingNvt).catch(() => false)", self.device)
        self.assertIn(
            "loadNvtOutput(requestContext, { waitForGlobalRefresh: false })",
            self.device,
        )
        self.assertIn("if (refreshAllButton) refreshAllButton.disabled = true", self.device)
        self.assertIn("if (nvtRefreshButton) nvtRefreshButton.disabled = true", self.device)


if __name__ == "__main__":
    unittest.main()
