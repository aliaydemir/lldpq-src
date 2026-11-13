#!/usr/bin/env python3
"""Session gate for the static data directories and the login rate limit.

etc/nginx/sites-available/lldpq used to serve /configs/ (every device's
running configuration), /hstr/ and /monitor-results/ with autoindex and no
session check, and /auth-api accepted any number of login attempts.

The site file cannot run off-box as shipped, so the contract is checked three
ways:
  - text: the file is parsed into its location blocks and a small model of
    nginx's location selection decides, for real URIs, whether the location
    that answers them sits behind the session gate;
  - the gate itself: auth-guard.sh is run directly, the way the auth_request
    subrequest runs it;
  - nginx, when installed: `nginx -t` on a rendered copy, and (opt-in, like
    the fcgiwrap socket test) a live nginx in front of a FastCGI stand-in.
"""

import http.client
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NGINX_SITE = ROOT / "etc" / "nginx" / "sites-available" / "lldpq"
HTML_DIR = ROOT / "html"
AUTH_GUARD = HTML_DIR / "auth-guard.sh"
AUTH_API = HTML_DIR / "auth-api.sh"
LOGIN_PAGE = HTML_DIR / "login.html"
README = ROOT / "README.md"

GATE_URI = "/lldpq-session-gate"
GATED_PREFIXES = ("/configs/", "/hstr/", "/monitor-results/")
GUARD_SESSIONS_LINE = 'LLDPQ_GUARD_SESSIONS_DIR="/var/lib/lldpq/sessions"'
TOKEN = "ab" * 32


# ── nginx site file model ───────────────────────────────────────────────────

class Block:
    def __init__(self, header):
        self.header = header
        self.statements = []
        self.blocks = []

    def walk(self):
        yield self
        for child in self.blocks:
            yield from child.walk()


def parse_nginx(text):
    """Blocks and statements; quoted strings and comments are opaque."""
    root = Block("")
    stack = [root]
    buffer = []
    index = 0
    while index < len(text):
        char = text[index]
        if char in "\"'":
            end = index + 1
            while text[end] != char:
                end += 2 if text[end] == "\\" else 1
            buffer.append(text[index:end + 1])
            index = end + 1
            continue
        if char == "#":
            index = text.find("\n", index)
            if index < 0:
                break
            continue
        if char == "{":
            block = Block(" ".join("".join(buffer).split()))
            stack[-1].blocks.append(block)
            stack.append(block)
            buffer = []
        elif char == "}":
            stack.pop()
            buffer = []
        elif char == ";":
            stack[-1].statements.append(" ".join("".join(buffer).split()))
            buffer = []
        else:
            buffer.append(char)
        index += 1
    return root


def split_location(header):
    parts = header.split()
    if len(parts) == 2:
        return "", parts[1]
    return parts[1], parts[2]


def locations_of(scope):
    return [
        (split_location(block.header), block)
        for block in scope.blocks if block.header.startswith("location ")
    ]


def location_regex(modifier, pattern):
    # PCRE named groups -> Python named groups.
    pattern = re.sub(r"\(\?<(?![=!])", "(?P<", pattern)
    return re.compile(pattern, re.IGNORECASE if modifier == "~*" else 0)


def select_location(scope, uri):
    """The chain of location blocks nginx picks for uri, outermost first.

    Follows ngx_http_core_find_location: an exact match ends the search; the
    longest prefix match is searched for nested locations first; the regex
    locations of the current level then run in file order unless that prefix
    was declared with "^~". The second value says whether an exact or regex
    location ended the search.
    """
    locations = locations_of(scope)
    for (modifier, pattern), block in locations:
        if modifier == "=" and pattern == uri:
            return [block], True
    best = None
    for (modifier, pattern), block in locations:
        if modifier not in ("", "^~") or not uri.startswith(pattern):
            continue
        if best is None or len(pattern) > len(best[0][1]):
            best = ((modifier, pattern), block)
    chain = []
    noregex = False
    if best is not None:
        nested, final = select_location(best[1], uri)
        chain = [best[1]] + nested
        if final:
            return chain, True
        noregex = best[0][0] == "^~"
    if not noregex:
        for (modifier, pattern), block in locations:
            if modifier in ("~", "~*") and location_regex(modifier, pattern).search(uri):
                nested, _ = select_location(block, uri)
                return [block] + nested, True
    return chain, False


def directive(chain, name):
    """Innermost value of an inherited directive along a location chain."""
    for block in reversed(chain):
        for statement in block.statements:
            if statement == name or statement.startswith(name + " "):
                return statement[len(name):].strip()
    return None


class SiteFile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = NGINX_SITE.read_text(encoding="utf-8")
        cls.http = parse_nginx(cls.text)
        servers = [block for block in cls.http.blocks if block.header == "server"]
        assert len(servers) == 1, "the site file must hold exactly one server block"
        cls.server = servers[0]

    def chain(self, uri):
        return select_location(self.server, uri)[0]

    def gated(self, uri):
        return directive(self.chain(uri), "auth_request") == GATE_URI


# ── K1: /configs/, /hstr/ and /monitor-results/ need a session ──────────────

class SessionGatedDirectoryTests(SiteFile):
    def test_every_file_in_the_three_trees_is_answered_behind_the_gate(self):
        for uri in (
            "/configs/", "/configs/leaf01.txt", "/configs/leaf01.yaml",
            "/configs/sub/dir/leaf01.txt",
            "/hstr/", "/hstr/Problems-2026-08-02--09-33.ini",
            "/monitor-results/", "/monitor-results/bgp-analysis.html",
            "/monitor-results/.lldpq-current.json",
            "/monitor-results/events/bgp.json",
            "/monitor-results/fabric-tables/leaf01.json",
            # The files behind the public export URLs are not themselves
            # public: only the documented /<domain>/export_* paths are.
            "/monitor-results/export/bgp.json",
            "/monitor-results/export/bgp.csv",
            "/monitor-results/transceiver-export.json",
            # Shapes a server-level regex location used to take over.
            "/configs/notes.ini", "/monitor-results/.pipeline-inputs/assets.ini",
            "/monitor-results/REPORT.INI",
        ):
            with self.subTest(uri=uri):
                self.assertTrue(
                    self.gated(uri),
                    f"{uri} is answered by a location without "
                    f"`auth_request {GATE_URI};`",
                )

    def test_the_three_trees_cannot_be_taken_over_by_a_regex_location(self):
        # A regex location wins over a plain prefix location, so a later
        # `location ~ \.json$` at server level would silently serve files out
        # of these trees with no session check. "^~" rules that out.
        declared = {
            pattern: (modifier, block)
            for (modifier, pattern), block in locations_of(self.server)
            if pattern in GATED_PREFIXES
        }
        self.assertEqual(sorted(declared), sorted(GATED_PREFIXES))
        for prefix, (modifier, block) in declared.items():
            with self.subTest(prefix=prefix):
                self.assertEqual(modifier, "^~")
                self.assertIn(f"auth_request {GATE_URI}", block.statements)
                for nested in block.walk():
                    self.assertNotIn("auth_request off", nested.statements)

    def test_no_other_server_location_reaches_into_the_three_trees(self):
        # Exact and longer prefix locations still outrank "^~ /configs/".
        for (modifier, pattern), block in locations_of(self.server):
            if modifier in ("~", "~*") or pattern in GATED_PREFIXES:
                continue
            with self.subTest(location=block.header):
                self.assertFalse(
                    pattern.startswith(GATED_PREFIXES),
                    f"`{block.header}` serves from a session-gated tree "
                    "outside the gated location",
                )

    def test_listing_and_file_rules_inside_the_trees_are_unchanged(self):
        for prefix in GATED_PREFIXES:
            with self.subTest(prefix=prefix):
                # dev-conf.html and archive.html parse the autoindex listing.
                self.assertEqual(directive(self.chain(prefix), "autoindex"), "on")
                ini = self.chain(prefix + "report.ini")
                self.assertEqual(directive(ini, "default_type"), "text/plain")
                self.assertIn("no-store", directive(ini, "add_header"))
                for name in ("tool.sh", "tool.py", "tool.pyc"):
                    self.assertEqual(
                        directive(self.chain(prefix + name), "return"), "404")
        self.assertIn(
            "no-store",
            directive(self.chain("/monitor-results/bgp-analysis.html"), "add_header"),
        )

    def test_an_unauthenticated_request_gets_the_login_page_with_401(self):
        for prefix in GATED_PREFIXES:
            with self.subTest(prefix=prefix):
                self.assertEqual(
                    directive(self.chain(prefix + "x.txt"), "error_page"),
                    "401 /login.html",
                )
        self.assertTrue(LOGIN_PAGE.is_file())
        # The login page itself must not sit behind the gate.
        self.assertFalse(self.gated("/login.html"))

    def test_gate_location_is_internal_and_runs_the_shared_guard(self):
        gate = self.chain(GATE_URI)
        self.assertEqual(len(gate), 1)
        self.assertEqual(gate[0].header, f"location = {GATE_URI}")
        statements = gate[0].statements
        self.assertIn("internal", statements)
        self.assertIn("fastcgi_pass unix:/var/run/fcgiwrap.socket", statements)
        self.assertIn(
            "fastcgi_param SCRIPT_FILENAME /var/www/html/auth-guard.sh", statements)
        self.assertIn("fastcgi_param HTTP_COOKIE $http_cookie", statements)

    def test_documented_public_exports_stay_public(self):
        # README section 02j is the deliberately unauthenticated machine API.
        # Its monitor-domain endpoints are files inside monitor-results/, so
        # exactly those documented paths have to stay outside the gate.
        section = README.read_text(encoding="utf-8").split("## [02j]", 1)[1]
        section = section.split("\n## [", 1)[0]
        documented = set(re.findall(
            r"`(/(?:[a-z_-]+/)?export_(?:json|csv))(?:\?[^`]*)?`", section))
        self.assertLessEqual(
            {"/export_json", "/lldp_results/export_csv", "/bgp/export_json",
             "/fabric-check/export_csv", "/transceiver/export_json",
             "/ai/export_json"},
            documented,
        )
        self.assertGreaterEqual(len(documented), 28)
        for uri in sorted(documented):
            with self.subTest(uri=uri):
                chain = self.chain(uri)
                self.assertTrue(chain, f"{uri} has no location")
                self.assertFalse(self.gated(uri))
                self.assertIsNone(directive(chain, "limit_req"))
        aliased = directive(self.chain("/bgp/export_json"), "alias")
        self.assertEqual(
            aliased, "/var/www/html/monitor-results/export/$lldpq_export_domain.json")

    def test_pages_and_endpoints_that_work_without_a_session_stay_open(self):
        for uri in ("/", "/login.html", "/index.html", "/auth-api",
                    "/cumulus-ztp.sh", "/lldp_results.ini", "/css/auth.js"):
            with self.subTest(uri=uri):
                self.assertFalse(self.gated(uri))


class SessionGateScriptTests(unittest.TestCase):
    """auth-guard.sh executed directly is the auth_request responder."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name)
        self.sessions = self.tmp / "sessions"
        self.sessions.mkdir()
        source = AUTH_GUARD.read_text(encoding="utf-8")
        self.assertIn(GUARD_SESSIONS_LINE, source)
        self.guard = self.tmp / "auth-guard.sh"
        self.guard.write_text(
            source.replace(
                GUARD_SESSIONS_LINE,
                f'LLDPQ_GUARD_SESSIONS_DIR="{self.sessions}"',
            ),
            encoding="utf-8",
        )

    def run_script(self, script, cookie=None):
        # A clean environment: a developer shell must not leak the
        # LLDPQ_AUTH_ROLE short-circuit into the gate.
        environment = {"PATH": os.environ["PATH"]}
        if cookie is not None:
            environment["HTTP_COOKIE"] = cookie
        result = subprocess.run(
            ["bash", str(script)], env=environment, capture_output=True,
            text=True, timeout=15, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def session(self, expires_in, role="operator"):
        path = self.sessions / TOKEN
        path.write_text(
            f"{int(time.time()) + expires_in}\nsomeone\n{role}\n", encoding="utf-8")
        return path

    def test_valid_session_gets_an_empty_2xx(self):
        for role in ("admin", "operator"):
            with self.subTest(role=role):
                self.session(3600, role)
                output = self.run_script(
                    self.guard, f"theme=dark; lldpq_session={TOKEN}")
                self.assertEqual(output, "Status: 204 No Content\n\n")

    def test_missing_malformed_and_unknown_cookies_get_401(self):
        self.session(3600)
        for cookie in (None, "", "lldpq_session=", "lldpq_session=deadbeef",
                       f"lldpq_session={'cd' * 32}",
                       f"old_lldpq_session={TOKEN}",
                       "lldpq_session=../../etc/passwd"):
            with self.subTest(cookie=cookie):
                output = self.run_script(self.guard, cookie)
                self.assertTrue(output.startswith("Status: 401\n"), output)
                self.assertNotIn("204", output)

    def test_expired_session_gets_401_and_is_removed(self):
        path = self.session(-5)
        output = self.run_script(self.guard, f"lldpq_session={TOKEN}")
        self.assertTrue(output.startswith("Status: 401\n"), output)
        self.assertFalse(path.exists())

    def test_sourcing_the_guard_still_prints_nothing(self):
        # Every *-api.sh sources this file; the direct-run block must stay
        # inert there or each API response would start with a stray status.
        api = self.tmp / "some-api.sh"
        api.write_text(
            '#!/bin/bash\nsource "$(dirname "$0")/auth-guard.sh"\n'
            'declare -F require_auth require_admin >/dev/null && echo sourced\n',
            encoding="utf-8",
        )
        self.assertEqual(self.run_script(api), "sourced\n")


# ── K2: only login attempts are rate limited ────────────────────────────────

class LoginThrottleTests(SiteFile):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.maps = {
            block.header.split()[2]: block
            for block in cls.http.blocks if block.header.startswith("map ")
        }
        cls.auth_api = AUTH_API.read_text(encoding="utf-8")
        action_lines = [
            line for line in cls.auth_api.splitlines()
            if line.startswith("ACTION=$(")
        ]
        assert len(action_lines) == 1, action_lines
        cls.action_line = action_lines[0]

    def limit_key(self, variable, query):
        """Value of a `map $query_string $variable` for a query string."""
        block = self.maps[variable]
        self.assertEqual(block.header.split()[1], "$query_string")
        result = None
        for statement in block.statements:
            source, value = statement.rsplit(" ", 1)
            source = source.strip().strip('"')
            if source == "default":
                if result is None:
                    result = value
            elif source.startswith("~"):
                flags = re.IGNORECASE if source.startswith("~*") else 0
                if re.search(source.lstrip("~*"), query, flags):
                    return value
            elif source.lower() == query.lower():
                return value
        return result

    def script_action(self, query):
        """The action auth-api.sh itself extracts from a query string."""
        result = subprocess.run(
            ["bash", "-c", self.action_line + '\nprintf "%s" "$ACTION"'],
            env={"PATH": os.environ["PATH"], "QUERY_STRING": query},
            capture_output=True, text=True, timeout=15, check=True,
        )
        return result.stdout

    def test_every_query_the_script_treats_as_login_is_counted(self):
        # nginx and the CGI parse the query string separately. If nginx only
        # looked at the first `action` argument, `?action=check&action=login`
        # would log in (the script takes the last one) without being counted.
        queries = [
            "action=login", "action=login&remember=true", "x=1&action=login",
            "action=check&action=login", "action=logout&x=2&action=login",
            "xaction=login", "ACTION=check&action=login", "=&action=login",
            "action=login&action=check", "action=loginx", "action=LOGIN",
            "action=log%69n", "action=check", "", "login",
        ]
        selecting = [q for q in queries if self.script_action(q) == "login"]
        self.assertGreaterEqual(len(selecting), 8, selecting)
        for query in selecting:
            with self.subTest(query=query):
                self.assertEqual(
                    self.limit_key("$lldpq_login_client", query),
                    "$binary_remote_addr")
                self.assertNotEqual(self.limit_key("$lldpq_login_any", query), '""')

    def test_polled_and_session_actions_are_never_counted(self):
        # action=check is polled by every page and by the Docker HEALTHCHECK
        # from 127.0.0.1; an empty key is what makes limit_req skip a request.
        used = set()
        for path in (sorted(HTML_DIR.glob("*.html")) + sorted(HTML_DIR.glob("*.js"))
                     + sorted((HTML_DIR / "css").glob("*.js"))):
            used.update(re.findall(
                r"auth-api\?action=([a-z-]+)",
                path.read_text(encoding="utf-8", errors="replace")))
        self.assertLessEqual({"check", "login", "logout", "change-password"}, used)
        healthcheck = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("/auth-api?action=check", healthcheck)
        for action in sorted(used - {"login"}):
            with self.subTest(action=action):
                for variable in ("$lldpq_login_client", "$lldpq_login_any"):
                    self.assertEqual(
                        self.limit_key(variable, f"action={action}"), '""')

    def test_zones_cover_ipv4_and_ipv6_clients_and_rotating_addresses(self):
        zones = {}
        for statement in self.http.statements:
            if statement.startswith("limit_req_zone "):
                _, key, zone, rate = statement.split()
                zones[zone.split("=")[1].split(":")[0]] = (key, rate)
        # Per client: $binary_remote_addr is the address itself for both
        # families (a text match on $remote_addr would be IPv4-shaped).
        self.assertEqual(
            zones["lldpq_login_client"], ("$lldpq_login_client", "rate=6r/m"))
        # All clients together: one shared key, so changing the source
        # address (trivial inside an IPv6 /64) does not lift the limit.
        self.assertEqual(zones["lldpq_login_all"], ("$lldpq_login_any", "rate=30r/m"))
        self.assertEqual(len(zones), 2)
        constant = [
            statement.rsplit(" ", 1)[1]
            for statement in self.maps["$lldpq_login_any"].statements
            if not statement.startswith("default")
        ]
        self.assertEqual(constant, ["login"])

    def test_limit_applies_to_the_auth_endpoint_only_and_never_delays(self):
        limited = [
            block for block in self.http.walk()
            if any(statement.startswith("limit_req ") for statement in block.statements)
        ]
        self.assertEqual([block.header for block in limited], ["location = /auth-api"])
        statements = limited[0].statements
        self.assertEqual(
            sorted(s for s in statements if s.startswith("limit_req ")),
            ["limit_req zone=lldpq_login_all burst=20 nodelay",
             "limit_req zone=lldpq_login_client burst=5 nodelay"],
        )
        self.assertIn("limit_req_status 429", statements)
        # Rejected in nginx, before fcgiwrap: nothing may sleep in one of the
        # four shared CGI workers instead.
        self.assertNotRegex(self.auth_api, r"(?m)^\s*sleep\b")

    def test_throttled_login_answers_json_the_login_page_displays(self):
        auth = self.chain("/auth-api")
        self.assertEqual(
            directive(auth, "error_page"), "429 = @lldpq_login_throttled")
        throttled = [
            block for block in self.server.blocks
            if block.header == "location @lldpq_login_throttled"
        ]
        self.assertEqual(len(throttled), 1)
        self.assertEqual(directive(throttled, "default_type"), "application/json")
        self.assertEqual(directive(throttled, "add_header"), "Retry-After 10 always")
        code, body = directive(throttled, "return").split(" ", 1)
        self.assertEqual(code, "429")
        payload = json.loads(body.strip("'"))
        self.assertIs(payload["success"], False)
        self.assertIn("Too many login attempts", payload["error"])
        page = LOGIN_PAGE.read_text(encoding="utf-8")
        self.assertIn("const data = await response.json();", page)
        self.assertIn("errorDiv.textContent = data.error ||", page)


# ── nginx itself, when this host has one ────────────────────────────────────

def render_site(directory, port, web_root=None, fastcgi=None, ipv6=False):
    """A copy of the site file nginx can load as an unprivileged user."""
    text = NGINX_SITE.read_text(encoding="utf-8")
    swaps = [
        ("listen 80 default_server;", f"listen 127.0.0.1:{port} default_server;"),
        # Same fallback as install.sh and the entrypoint on IPv4-only hosts.
        ("listen [::]:80 default_server;",
         f"listen [::1]:{port} default_server;" if ipv6 else ""),
    ]
    if fastcgi:
        swaps.append(("unix:/var/run/fcgiwrap.socket", fastcgi))
    if web_root:
        swaps.append(("/var/www/html", str(web_root)))
    for old, new in swaps:
        assert old in text, old
        text = text.replace(old, new)
    (directory / "site.conf").write_text(text, encoding="utf-8")
    temp_paths = "\n".join(
        f'    {name}_temp_path "{directory}/{name}-temp";'
        for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")
    )
    conf = directory / "nginx.conf"
    conf.write_text(
        "daemon off;\nmaster_process off;\n"
        f'pid "{directory}/nginx.pid";\n'
        f'error_log "{directory}/error.log";\n'
        "events { worker_connections 64; }\n"
        "http {\n"
        "    types { text/html html; text/plain txt; application/json json; }\n"
        "    access_log off;\n"
        f"{temp_paths}\n"
        f'    include "{directory}/site.conf";\n'
        "}\n",
        encoding="utf-8",
    )
    return conf


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def ipv6_loopback(port):
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(("::1", port))
        return True
    except OSError:
        return False


@unittest.skipUnless(shutil.which("nginx"), "nginx is not installed on this host")
class NginxSyntaxTests(unittest.TestCase):
    def test_rendered_site_passes_nginx_t(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp).resolve()
            conf = render_site(directory, free_port())
            result = subprocess.run(
                ["nginx", "-t", "-p", str(directory), "-c", str(conf)],
                capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


class FastCgiStandIn:
    """fcgiwrap stand-in: runs SCRIPT_FILENAME as a CGI for each request."""

    def __init__(self):
        self.scripts = []
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(32)
        self.address = f"127.0.0.1:{self.listener.getsockname()[1]}"
        threading.Thread(target=self.accept, daemon=True).start()

    def close(self):
        self.listener.close()

    def accept(self):
        while True:
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(
                target=self.serve, args=(connection,), daemon=True).start()

    @staticmethod
    def read(connection, count):
        data = b""
        while len(data) < count:
            chunk = connection.recv(count - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    @staticmethod
    def params(data):
        values, index = {}, 0
        while index < len(data):
            lengths = []
            for _ in range(2):
                if data[index] >> 7:
                    lengths.append(
                        struct.unpack("!I", data[index:index + 4])[0] & 0x7FFFFFFF)
                    index += 4
                else:
                    lengths.append(data[index])
                    index += 1
            name = data[index:index + lengths[0]].decode()
            index += lengths[0]
            values[name] = data[index:index + lengths[1]].decode("latin-1")
            index += lengths[1]
        return values

    def serve(self, connection):
        try:
            raw_params, body = b"", b""
            while True:
                _, kind, request, length, padding = struct.unpack(
                    "!BBHHBx", self.read(connection, 8))
                content = self.read(connection, length + padding)[:length]
                if kind == 4:
                    raw_params += content
                elif kind == 5:
                    if not content:
                        break
                    body += content
            environment = {"PATH": os.environ["PATH"]}
            environment.update(self.params(raw_params))
            self.scripts.append((
                Path(environment["SCRIPT_FILENAME"]).name,
                environment.get("QUERY_STRING", ""),
            ))
            output = subprocess.run(
                ["bash", environment["SCRIPT_FILENAME"]], input=body,
                env=environment, capture_output=True, timeout=20, check=False,
            ).stdout
            for offset in range(0, len(output), 60000):
                chunk = output[offset:offset + 60000]
                connection.sendall(
                    struct.pack("!BBHHBx", 1, 6, request, len(chunk), 0) + chunk)
            connection.sendall(struct.pack("!BBHHBx", 1, 6, request, 0, 0))
            connection.sendall(
                struct.pack("!BBHHBx", 1, 3, request, 8, 0) + bytes(8))
        except (EOFError, OSError, KeyError, subprocess.TimeoutExpired):
            pass
        finally:
            connection.close()


@unittest.skipUnless(os.environ.get("LLDPQ_RUN_SOCKET_TESTS") == "1",
                     "opt-in local nginx socket integration")
class LiveNginxTests(unittest.TestCase):
    PASSWORD = "live-test-password"

    def setUp(self):
        for tool in ("nginx", "flock", "openssl"):
            if not shutil.which(tool):
                self.skipTest(f"{tool} is required")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name).resolve()
        web = self.tmp / "web"
        state = self.tmp / "state"
        (state / "sessions").mkdir(parents=True)
        for directory in ("configs", "hstr", "monitor-results/export"):
            (web / directory).mkdir(parents=True)
        (web / "configs/leaf01.txt").write_text("hostname leaf01\n")
        (web / "configs/leaf01.yaml").write_text("- set: {}\n")
        (web / "hstr/Problems-1.ini").write_text("[problems]\n")
        (web / "monitor-results/bgp-analysis.html").write_text("<html>bgp</html>\n")
        (web / "monitor-results/tool.sh").write_text("#!/bin/sh\n")
        (web / "monitor-results/export/bgp.json").write_text('{"rows": []}\n')
        (web / "monitor-results/export/bgp.csv").write_text("device,peer\n")
        (web / "monitor-results/transceiver-export.json").write_text("{}\n")
        (web / "index.html").write_text("<html>index</html>\n")
        shutil.copy(LOGIN_PAGE, web / "login.html")

        guard = AUTH_GUARD.read_text(encoding="utf-8")
        self.assertIn(GUARD_SESSIONS_LINE, guard)
        (web / "auth-guard.sh").write_text(guard.replace(
            GUARD_SESSIONS_LINE,
            f'LLDPQ_GUARD_SESSIONS_DIR="{state}/sessions"'))
        api = AUTH_API.read_text(encoding="utf-8")
        for old, new in (
            ('USERS_FILE="/etc/lldpq-users.conf"', f'USERS_FILE="{state}/users.conf"'),
            ('USERS_LOCK_FILE="/etc/lldpq-users.conf.lock"',
             f'USERS_LOCK_FILE="{state}/users.conf.lock"'),
            ('LLDPQ_CONFIG_FILE="/etc/lldpq.conf"',
             f'LLDPQ_CONFIG_FILE="{state}/lldpq.conf"'),
            ('SESSIONS_DIR="/var/lib/lldpq/sessions"',
             f'SESSIONS_DIR="{state}/sessions"'),
        ):
            self.assertIn(old, api)
            api = api.replace(old, new)
        (web / "auth-api.sh").write_text(api)
        digest = subprocess.run(
            ["openssl", "dgst", "-sha256"], input=self.PASSWORD.encode(),
            capture_output=True, check=True,
        ).stdout.decode().split()[-1]
        (state / "users.conf").write_text(f"admin:{digest}:admin\n")
        (state / "users.conf.lock").touch()

        self.fastcgi = FastCgiStandIn()
        self.addCleanup(self.fastcgi.close)
        self.port = free_port()
        self.ipv6 = ipv6_loopback(self.port)
        conf = render_site(
            self.tmp, self.port, web_root=web, fastcgi=self.fastcgi.address,
            ipv6=self.ipv6)
        self.nginx = subprocess.Popen(
            ["nginx", "-p", str(self.tmp), "-c", str(conf)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        self.addCleanup(self.stop_nginx)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.2).close()
                break
            except OSError:
                if self.nginx.poll() is not None:
                    self.fail("nginx exited: " + self.nginx.stderr.read().decode())
                time.sleep(0.05)
        else:
            self.fail("nginx did not start listening")

    def stop_nginx(self):
        if self.nginx.poll() is None:
            self.nginx.terminate()
        try:
            self.nginx.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            self.nginx.kill()
            self.nginx.communicate()

    def request(self, path, cookie=None, body=None, host="127.0.0.1"):
        connection = http.client.HTTPConnection(host, self.port, timeout=20)
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            connection.request("POST" if body is not None else "GET", path,
                               body=body, headers=headers)
            response = connection.getresponse()
            return response.status, response.headers, response.read().decode()
        finally:
            connection.close()

    def login(self, password, query="action=login", host="127.0.0.1"):
        return self.request(
            "/auth-api?" + query, body=f"username=admin&password={password}",
            host=host)

    def test_three_trees_need_a_session_and_exports_stay_public(self):
        gated = ("/configs/", "/configs/leaf01.txt", "/hstr/",
                 "/hstr/Problems-1.ini", "/monitor-results/",
                 "/monitor-results/bgp-analysis.html",
                 "/monitor-results/export/bgp.json",
                 "/monitor-results/transceiver-export.json")
        for path in gated:
            with self.subTest(path=path, session=False):
                status, _, body = self.request(path)
                self.assertEqual(status, 401)
                self.assertIn('id="login-form"', body)
                self.assertNotIn("leaf01", body)
        for cookie in ("lldpq_session=deadbeef", f"lldpq_session={TOKEN}"):
            self.assertEqual(self.request("/configs/leaf01.txt", cookie)[0], 401)
        for path in ("/bgp/export_json", "/bgp/export_csv",
                     "/transceiver/export_json", "/login.html", "/"):
            with self.subTest(path=path, session=False):
                self.assertEqual(self.request(path)[0], 200)
        self.assertEqual(self.request(GATE_URI)[0], 404)
        self.assertEqual(self.request("/auth-guard.sh")[0], 404)
        self.assertEqual(self.request("/monitor-results/tool.sh")[0], 404)

        status, headers, body = self.login(self.PASSWORD)
        self.assertEqual(status, 200, body)
        self.assertTrue(json.loads(body)["success"])
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        for path in gated:
            with self.subTest(path=path, session=True):
                self.assertEqual(self.request(path, cookie)[0], 200)
        # dev-conf.html builds its device list from this listing.
        listing = self.request("/configs/", cookie)[2]
        self.assertEqual(
            re.findall(r'href="([^"]+)"', listing),
            ["../", "leaf01.txt", "leaf01.yaml"])
        status, headers, body = self.request("/hstr/Problems-1.ini", cookie)
        self.assertEqual(headers["Content-Type"], "text/plain")
        self.assertIn("no-store", headers["Cache-Control"])
        self.assertEqual(body, "[problems]\n")
        self.assertEqual(self.request("/monitor-results/tool.sh", cookie)[0], 404)

        self.request("/auth-api?action=logout", cookie)
        self.assertEqual(self.request("/configs/leaf01.txt", cookie)[0], 401)

    def failed_logins_until_limited(self, host="127.0.0.1"):
        """Wrong-password attempts accepted before the first 429."""
        started = time.monotonic()
        accepted = 0
        for _ in range(40):
            status = self.login("wrong", host=host)[0]
            if status == 429:
                break
            self.assertEqual(status, 200)
            accepted += 1
        else:
            self.fail("login attempts were never limited")
        # 6 at once, then one more per 10 s that the CGI runs took.
        refilled = int((time.monotonic() - started) // 10) + 1
        self.assertGreaterEqual(accepted, 6)
        self.assertLessEqual(accepted, 6 + refilled)
        return accepted

    def test_only_login_attempts_are_limited(self):
        for _ in range(40):
            status, _, body = self.request("/auth-api?action=check")
            self.assertEqual(status, 200)
            self.assertIn('"authenticated"', body)
        accepted = self.failed_logins_until_limited()
        # The limit counts attempts, not failures: the right password is
        # refused as well until a slot frees up.
        status, headers, body = self.login(self.PASSWORD)
        self.assertEqual(status, 429)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Retry-After"], "10")
        self.assertIs(json.loads(body)["success"], False)
        # A second or prefixed action parameter is still a login attempt.
        for query in ("action=check&action=login", "xaction=login"):
            self.assertEqual(self.login("wrong", query)[0], 429)
        if self.ipv6:
            # An IPv6 client is a client of its own: same allowance, same cap.
            accepted += self.failed_logins_until_limited(host="::1")
        # Throttled attempts never reached the CGI worker pool...
        logins = [query for script, query in self.fastcgi.scripts
                  if script == "auth-api.sh" and "action=login" in query]
        self.assertEqual(len(logins), accepted)
        # ...and everything that is not a login keeps working meanwhile.
        self.assertEqual(self.request("/auth-api?action=check")[0], 200)
        self.assertEqual(self.request("/bgp/export_json")[0], 200)

if __name__ == "__main__":
    unittest.main()
