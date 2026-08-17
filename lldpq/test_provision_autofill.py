#!/usr/bin/env python3
"""Keeps browser autofill out of the Provision page's inputs.

An operator pressed "Add Pool" on a live server and the new card came up with
the logged-in account name sitting in DEFAULT LEASE TIME (sec).  Nothing in the
page writes a username into a numeric field, so the value came from the
browser's password manager.

Three properties keep it out, and each is pinned below because each is easy to
lose by accident:

1. The page must not put a password field in the same form scope as ordinary
   data inputs.  `provision.html` declares no `<form>` around most of its
   inputs, so every form-less input lands in the one implicit form the browser
   synthesises for the document.  A `type="password"` field in that implicit
   form is what makes a password manager treat the page as a sign-in form and
   look for a username slot among the surrounding text inputs — which is how an
   unrelated field gets filled.  Every password field therefore has to live in
   its own real `<form>`, leaving no credential anchor beside the data inputs.

2. Every input a browser can autofill must carry an `autocomplete` attribute.
   Chromium ignores `autocomplete="off"` for password-manager filling, so the
   attribute alone is not the fix — but it does suppress address and profile
   Autofill, and it is the project's convention.  The pool card matters most:
   its ten fields all come from one template, and `addDHCPPool()` injects a
   fresh set of empty inputs into the live DOM, which is exactly when a
   password manager rescans and fills.

3. The `:-webkit-autofill` override must stay, so a browser that fills anyway
   cannot repaint an input white or yellow on this dark page.

All of it is markup, so it is checked by reading the page rather than driving a
browser.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROVISION_HTML = (ROOT / "html" / "provision.html").read_text(encoding="utf-8")

POOL_FIELDS = ('name', 'subnet', 'netmask', 'range_start', 'range_end',
               'gateway', 'dns', 'domain', 'provision_url', 'lease_time')

# Types a browser fills.  checkbox/radio/file/hidden/button are never autofill
# targets, and an input with no type at all defaults to text.
FILLABLE_TYPES = frozenset((
    '', 'text', 'search', 'password', 'email', 'tel', 'url', 'number',
    'date', 'datetime-local', 'month', 'week', 'time',
))

AUTOFILL_CSS = (
    'input:-webkit-autofill',
    'input:-webkit-autofill:hover',
    'input:-webkit-autofill:focus',
    '-webkit-box-shadow: 0 0 0 1000px #1a1a1a inset !important',
    '-webkit-text-fill-color: #fff !important',
    'caret-color: #fff !important',
)


def _tag_at(html, start):
    """Return the tag starting at `start`, honouring quoted attribute values.

    An inline `onclick="if (a > b) ..."` puts a bare `>` inside a value, so the
    first `>` in the text is not reliably the end of the tag.
    """
    quote = None
    for index in range(start, len(html)):
        char = html[index]
        if quote:
            if char == quote:
                quote = None
        elif char in '"\'':
            quote = char
        elif char == '>':
            return html[start:index + 1]
    return html[start:]


def input_tags(html):
    """Every `<input>` in the page, literal or built inside a JS template."""
    found = []
    for match in re.finditer(r'<input\b', html, re.I):
        tag = _tag_at(html, match.start())
        found.append((html.count('\n', 0, match.start()) + 1, tag))
    return found


def tag_attr(tag, name):
    match = re.search(r'\b' + name + r'\s*=\s*"([^"]*)"', tag, re.I)
    return match.group(1) if match else None


def tag_type(tag):
    return (tag_attr(tag, 'type') or '').strip().lower()


def form_spans(html):
    """Character ranges covered by a real `<form>` element."""
    spans = []
    for match in re.finditer(r'<form\b', html, re.I):
        end = html.find('</form>', match.start())
        spans.append((match.start(), len(html) if end < 0 else end))
    return spans


class ProvisionAutofillTests(unittest.TestCase):
    """The Provision page, read as markup."""

    def test_every_fillable_input_declares_autocomplete(self):
        unprotected = [
            (line, tag[:120]) for line, tag in input_tags(PROVISION_HTML)
            if tag_type(tag) in FILLABLE_TYPES
            and tag_attr(tag, 'autocomplete') is None
        ]
        self.assertEqual(unprotected, [])

    def test_the_page_still_has_the_inputs_this_sweep_is_meant_to_cover(self):
        # Guards the sweep above against passing because a regex stopped
        # matching anything at all.
        fillable = [tag for _, tag in input_tags(PROVISION_HTML)
                    if tag_type(tag) in FILLABLE_TYPES]
        self.assertGreaterEqual(len(fillable), 15)

    def test_the_pool_card_template_protects_the_input_it_builds(self):
        template = PROVISION_HTML[
            PROVISION_HTML.index("function dhcpPoolCell("):
            PROVISION_HTML.index("function dhcpPoolCardHtml(")
        ]
        tags = input_tags(template)
        self.assertEqual(len(tags), 1, "one input per pool cell")
        self.assertEqual(tag_attr(tags[0][1], 'autocomplete'), 'off')

    def test_every_pool_field_goes_through_that_one_template(self):
        # The lease time field was the one that got filled, but all ten are
        # equally exposed, and they are only all protected because no card field
        # is built anywhere else.
        card = PROVISION_HTML[
            PROVISION_HTML.index("function dhcpPoolCardHtml("):
            PROVISION_HTML.index("function renderDHCPPoolCards(")
        ]
        self.assertEqual(input_tags(card), [])
        for field in POOL_FIELDS:
            self.assertIn("'" + field + "',", card, field)

    def test_no_password_field_shares_the_implicit_form_with_data_inputs(self):
        spans = form_spans(PROVISION_HTML)
        loose = []
        for match in re.finditer(r'<input\b', PROVISION_HTML, re.I):
            tag = _tag_at(PROVISION_HTML, match.start())
            if tag_type(tag) != 'password':
                continue
            if not any(start <= match.start() < end for start, end in spans):
                loose.append(PROVISION_HTML.count('\n', 0, match.start()) + 1)
        self.assertEqual(loose, [], "password field left in the implicit form")

    def test_the_password_field_refuses_a_remembered_credential(self):
        password = [tag for _, tag in input_tags(PROVISION_HTML)
                    if tag_type(tag) == 'password']
        self.assertEqual(len(password), 1)
        # "off" is ignored by Chromium's password manager; "new-password" is
        # the token it honours, and matches setup.html's key-push field.
        self.assertEqual(tag_attr(password[0], 'autocomplete'), 'new-password')

    def test_the_password_form_cannot_navigate_the_page(self):
        # The wrapper exists only to scope autofill.  Pressing Enter in the
        # field, or clicking the show/hide button, must not submit it.
        opener = '<form onsubmit="return false;"'
        self.assertIn(opener, PROVISION_HTML, "inert password form is missing")
        start = PROVISION_HTML.index(opener)
        form = PROVISION_HTML[start:PROVISION_HTML.index('</form>', start)]
        self.assertIn('id="ztpPassword"', form)
        self.assertIn('<button type="button"', form)

    def test_the_dark_theme_survives_an_autofill_that_happens_anyway(self):
        for fragment in AUTOFILL_CSS:
            self.assertIn(fragment, PROVISION_HTML, fragment)


if __name__ == "__main__":
    unittest.main()
