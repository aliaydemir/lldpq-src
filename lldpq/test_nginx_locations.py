#!/usr/bin/env python3
"""Nginx exact-location coverage for frontend-called .sh endpoints.

etc/nginx/sites-available/lldpq 404s every URI matching `\\.sh$` so CGI shell
sources are never served as static text. Frontend-called APIs work only
because each has an exact `location = /<name>.sh` block that outranks the
regex catch-all. Nothing enforced that invariant: adding a new CGI API and
forgetting the nginx block fails with a bare 404 only at deploy time. These
tests scan the frontend sources for referenced .sh endpoints and assert each
one has an exact-match location in the site config."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NGINX_SITE = ROOT / "etc" / "nginx" / "sites-available" / "lldpq"
HTML_DIR = ROOT / "html"

# A .sh name counts as an endpoint reference when it appears as a URL literal:
# preceded by a quote/backtick or a path slash and immediately followed by a
# query string or a closing quote — the shapes fetch()/XHR/href wiring uses
# (fetch('/fabric-api.sh?...'), apiFetchJson('search-api.sh?action=...')).
# Prose mentions like "runs collect-transceiver-fw.sh." do not match.
ENDPOINT_RE = re.compile(r"""['"`/]([A-Za-z0-9_-]+\.sh)(?=[?'"`])""")

# .sh names that match ENDPOINT_RE without being URLs this vhost must route.
# Every entry needs a reason; a new unrouted .sh reference must either get an
# exact nginx location or be consciously added here.
NON_ENDPOINTS = {
    # index.html/setup.html show operators the server-side upgrade command
    # ("cd ~/lldpq-src ... ./install.sh"); it is never fetched over HTTP.
    "install.sh",
    # provision.html deploys /etc/profile.d/motd.sh ONTO switches; the
    # string is a device-side destination path, not a web URL.
    "motd.sh",
}

# NOTE on cumulus-ztp.sh: it is a real HTTP endpoint (ONIE/ZTP clients fetch
# it as plain text, so it is deliberately served statically instead of via
# fcgiwrap) but it still has its own `location = /cumulus-ztp.sh` block, so
# it passes the generic exact-location assertion like the CGI APIs do.


def frontend_sources():
    return (
        sorted(HTML_DIR.glob("*.html"))
        + sorted(HTML_DIR.glob("*.js"))
        + sorted((HTML_DIR / "css").glob("*.js"))
    )


def referenced_endpoints():
    names = set()
    for path in frontend_sources():
        text = path.read_text(encoding="utf-8", errors="replace")
        names.update(ENDPOINT_RE.findall(text))
    return names


class NginxShLocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.conf = NGINX_SITE.read_text(encoding="utf-8")
        cls.referenced = referenced_endpoints()
        cls.exact_locations = set(
            re.findall(r"location\s*=\s*/([A-Za-z0-9._-]+\.sh)\s*\{", cls.conf)
        )

    def test_scan_still_finds_the_core_endpoints(self):
        # Guards the extraction regex itself: if it rots into matching
        # nothing, the coverage assertion below would pass vacuously.
        self.assertLessEqual(
            {"fabric-api.sh", "setup-api.sh", "search-api.sh", "ansible-api.sh"},
            self.referenced,
        )

    def test_sh_source_catchall_404_is_still_present(self):
        # The premise of the invariant: CGI shell sources must never be
        # served as static text, so the regex catch-all must stay.
        self.assertRegex(
            self.conf, r"location\s*~\s*\\\.sh\$\s*\{\s*return\s+404;"
        )

    def test_every_referenced_endpoint_has_an_exact_location(self):
        missing = sorted(
            self.referenced - NON_ENDPOINTS - self.exact_locations
        )
        self.assertFalse(
            missing,
            "frontend-referenced .sh endpoints without an exact "
            "`location = /<name>` block in etc/nginx/sites-available/lldpq "
            "(the `location ~ \\.sh$` catch-all will 404 them): "
            f"{missing}",
        )

    def test_every_referenced_endpoint_script_exists(self):
        # A location block pointing at a missing CGI is the same deploy-time
        # 404/502 class of failure as a missing location.
        missing = sorted(
            name for name in self.referenced - NON_ENDPOINTS
            if not (HTML_DIR / name).is_file()
        )
        self.assertFalse(
            missing,
            f"frontend-referenced .sh endpoints with no html/<name> script: {missing}",
        )

    def test_non_endpoint_allowlist_is_not_stale(self):
        # Keep the allowlist honest: drop entries once nothing matches them.
        stale = sorted(NON_ENDPOINTS - self.referenced)
        self.assertFalse(
            stale,
            f"NON_ENDPOINTS entries no longer referenced by any frontend source: {stale}",
        )


if __name__ == "__main__":
    unittest.main()
