#!/usr/bin/env python3
"""Session cookie of a login that arrived over TLS.

With LLDPQ_HTTPS_PORT the one nginx server block answers on a TLS port as well
as on port 80. The session cookie carried no Secure attribute, so a session
opened over HTTPS was sent again, in clear text, with every http:// request
to the same host.

nginx now tells the CGI which kind of listener a request came in on
(`fastcgi_param HTTPS $https if_not_empty;` in "location = /auth-api"; the
site file includes no fastcgi_params) and auth-api.sh adds Secure to the login
cookie when that says "on". ZTP clients, probes and operators keep using port
80, so a login over plain HTTP gets the header it always got, byte for byte.

The line that clears the cookie at logout is as it was: a browser replaces a
cookie by name, domain and path, Secure is not part of that, so over TLS it
removes the Secure cookie as well. Over plain HTTP nothing can remove a Secure
cookie, with or without the attribute on that line.

Checked three ways, like test_auth_hardening_nginx.py:
  - the real CGI, run with and without HTTPS in its environment;
  - the site file as text, and `nginx -t` on a rendered copy with a TLS
    listener, where nginx and openssl are installed;
  - opt-in (LLDPQ_RUN_SOCKET_TESTS=1): a live nginx with a plain and a TLS
    listener in front of a FastCGI stand-in running the real CGI.
"""

import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlencode

from test_auth_hardening_nginx import FastCgiStandIn, free_port, parse_nginx, render_site


ROOT = Path(__file__).resolve().parents[1]
NGINX_SITE = ROOT / "etc" / "nginx" / "sites-available" / "lldpq"
AUTH_API = ROOT / "html" / "auth-api.sh"

PASSWORD = "cookie-test-password"
# What a login answered before there was a TLS listener.
PLAIN_ATTRIBUTES = ["Path=/", "HttpOnly", "SameSite=Strict"]
LOGOUT_COOKIE = "Set-Cookie: lldpq_session=; Path=/; HttpOnly; Max-Age=0"


def scratch_cgi(directory, cgi):
    """auth-api.sh written to cgi, with its users file and sessions in directory."""
    (directory / "sessions").mkdir()
    (directory / "users.conf").write_text(
        f"admin:{hashlib.sha256(PASSWORD.encode()).hexdigest()}:admin\n", encoding="utf-8")
    (directory / "users.conf.lock").touch()
    source = AUTH_API.read_text(encoding="utf-8")
    for old, new in (
        ('USERS_FILE="/etc/lldpq-users.conf"', f'USERS_FILE="{directory}/users.conf"'),
        ('USERS_LOCK_FILE="/etc/lldpq-users.conf.lock"',
         f'USERS_LOCK_FILE="{directory}/users.conf.lock"'),
        ('LLDPQ_CONFIG_FILE="/etc/lldpq.conf"', f'LLDPQ_CONFIG_FILE="{directory}/lldpq.conf"'),
        ('SESSIONS_DIR="/var/lib/lldpq/sessions"', f'SESSIONS_DIR="{directory}/sessions"'),
    ):
        assert old in source, old
        source = source.replace(old, new)
    cgi.write_text(source, encoding="utf-8")


def attributes(set_cookie):
    """`name=value; A; B=c` -> ("name=value", ["A", "B=c"]), empty parts dropped."""
    parts = [part.strip() for part in set_cookie.split(";")]
    return parts[0], [part for part in parts[1:] if part]


@unittest.skipUnless(shutil.which("flock"), "login needs util-linux flock")
class LoginCookieTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name).resolve()
        self.cgi = self.tmp / "auth-api.sh"
        scratch_cgi(self.tmp, self.cgi)
        self.sessions = self.tmp / "sessions"

    def call(self, action, https=None, cookie=None, **form):
        """Header lines and JSON body; https is the HTTPS variable, None for unset."""
        body = urlencode(form)
        environment = {
            "PATH": os.environ["PATH"],
            "QUERY_STRING": f"action={action}",
            "REQUEST_METHOD": "POST" if form else "GET",
            "CONTENT_LENGTH": str(len(body)),
        }
        if https is not None:
            environment["HTTPS"] = https
        if cookie:
            environment["HTTP_COOKIE"] = cookie
        result = subprocess.run(
            [shutil.which("bash"), str(self.cgi)], env=environment, input=body,
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        headers, payload = result.stdout.split("\n\n", 1)
        return headers.split("\n"), json.loads(payload)

    def login(self, https=None, remember=False):
        """The headers of a successful login and the token of the session it opened."""
        before = set(self.sessions.iterdir())
        form = {"username": "admin", "password": PASSWORD}
        if remember:
            form["remember"] = "true"
        headers, response = self.call("login", https, **form)
        self.assertIs(response["success"], True, response)
        (session,) = set(self.sessions.iterdir()) - before
        return headers, session.name

    def test_login_over_plain_http_gets_the_header_it_always_got(self):
        # Unset is what nginx sends for port 80 (if_not_empty); the other
        # values are what another web server might put there.
        for https in (None, "", "off"):
            with self.subTest(https=https, remember=False):
                headers, token = self.login(https)
                self.assertEqual(headers, [
                    "Content-Type: application/json",
                    f"Set-Cookie: lldpq_session={token}; Path=/; HttpOnly; SameSite=Strict; ",
                ])
            with self.subTest(https=https, remember=True):
                headers, token = self.login(https, remember=True)
                self.assertEqual(headers, [
                    "Content-Type: application/json",
                    f"Set-Cookie: lldpq_session={token}; Path=/; HttpOnly; SameSite=Strict; "
                    "Max-Age=604800;",
                ])

    def test_login_over_tls_gets_a_secure_cookie(self):
        headers, token = self.login("on")
        self.assertEqual(headers, [
            "Content-Type: application/json",
            f"Set-Cookie: lldpq_session={token}; Path=/; HttpOnly; SameSite=Strict; Secure; ",
        ])
        headers, token = self.login("on", remember=True)
        self.assertEqual(headers, [
            "Content-Type: application/json",
            f"Set-Cookie: lldpq_session={token}; Path=/; HttpOnly; SameSite=Strict; Secure; "
            "Max-Age=604800;",
        ])
        # Read the way a client reads it: one cookie, everything it had before
        # plus Secure.
        cookie = SimpleCookie(headers[1].split(": ", 1)[1])
        self.assertEqual(list(cookie), ["lldpq_session"])
        morsel = cookie["lldpq_session"]
        self.assertEqual(morsel.value, token)
        self.assertEqual(
            {name: value for name, value in morsel.items() if value},
            {"path": "/", "httponly": True, "samesite": "Strict", "secure": True,
             "max-age": "604800"})

    def test_secure_session_is_an_ordinary_session_on_the_server(self):
        # Same session file, so an older image reads it and either listener
        # accepts it (the browser decides where it is sent, not the server).
        _, plain = self.login()
        _, secure = self.login("on")
        for token in (plain, secure):
            lines = (self.sessions / token).read_text(encoding="utf-8").splitlines()
            self.assertEqual(lines[1:], ["admin", "admin"])
            self.assertTrue(lines[0].isdigit())
        for https in (None, "on"):
            _, response = self.call("check", https, cookie=f"lldpq_session={secure}")
            self.assertIs(response["authenticated"], True)

    def test_failed_login_sets_no_cookie_on_either_listener(self):
        for https in (None, "on"):
            headers, response = self.call(
                "login", https, username="admin", password="wrong-password")
            self.assertIs(response["success"], False)
            self.assertEqual(headers, ["Content-Type: application/json"])
        self.assertEqual(list(self.sessions.iterdir()), [])

    def test_logout_clears_the_cookie_with_the_line_it_always_sent(self):
        for https in (None, "on"):
            with self.subTest(https=https):
                login_headers, token = self.login(https)
                headers, response = self.call(
                    "logout", https, cookie=f"lldpq_session={token}")
                self.assertEqual(headers, ["Content-Type: application/json", LOGOUT_COOKIE])
                self.assertIs(response["success"], True)
                self.assertFalse((self.sessions / token).exists())
                # What makes a browser replace the login cookie with this
                # expired one: same name and path, host-only on both sides.
                # Secure is not part of that.
                issued = SimpleCookie(login_headers[1].split(": ", 1)[1])["lldpq_session"]
                cleared = SimpleCookie(LOGOUT_COOKIE.split(": ", 1)[1])["lldpq_session"]
                self.assertEqual((cleared.key, cleared["path"], cleared["domain"]),
                                 (issued.key, issued["path"], issued["domain"]))
                self.assertEqual((cleared.value, cleared["max-age"], cleared["domain"]),
                                 ("", "0", ""))


class SiteFileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site = NGINX_SITE.read_text(encoding="utf-8")
        cls.auth_api = AUTH_API.read_text(encoding="utf-8")
        cls.locations = [block for block in parse_nginx(cls.site).walk()
                         if block.header == "location = /auth-api"]

    def test_auth_endpoint_is_told_about_tls_and_only_then(self):
        self.assertEqual(len(self.locations), 1)
        statements = self.locations[0].statements
        # if_not_empty: nothing at all is passed for port 80, so the CGI's
        # environment there is what it was.
        self.assertEqual([s for s in statements if s.startswith("fastcgi_param HTTPS")],
                         ["fastcgi_param HTTPS $https if_not_empty"])
        self.assertEqual(
            [s.split()[1] for s in statements if s.startswith("fastcgi_param ")],
            ["SCRIPT_FILENAME", "QUERY_STRING", "REQUEST_METHOD", "CONTENT_TYPE",
             "CONTENT_LENGTH", "HTTP_COOKIE", "HTTPS"])
        self.assertIn("fastcgi_pass unix:/var/run/fcgiwrap.socket", statements)
        self.assertIn("fastcgi_param SCRIPT_FILENAME /var/www/html/auth-api.sh", statements)
        # Declared here because nothing else declares it: no fastcgi_params
        # file is included.
        self.assertEqual([s for s in statements if s.startswith("include")], [])

    def test_scheme_is_taken_from_the_connection_not_from_a_request_header(self):
        # A header such as X-Forwarded-Proto is whatever the client says.
        for text in (self.auth_api, "\n".join(self.locations[0].statements)):
            self.assertIsNone(re.search(r"(?i)forwarded", text))
        self.assertEqual(self.auth_api.count('if [ "$HTTPS" = "on" ]; then\n'), 1)

    def test_cgi_writes_the_session_cookie_in_two_places(self):
        cookie_lines = [line.strip() for line in self.auth_api.splitlines()
                        if "Set-Cookie" in line]
        self.assertEqual(cookie_lines, [
            'echo "Set-Cookie: lldpq_session=$TOKEN; Path=/; HttpOnly; SameSite=Strict; '
            '${COOKIE_SECURE}$COOKIE_EXPIRY"',
            f'echo "{LOGOUT_COOKIE}"',
        ])


def self_signed_pair(directory):
    certificate, key = directory / "tls.crt", directory / "tls.key"
    made = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(certificate)],
        capture_output=True, text=True, timeout=60, check=False)
    assert made.returncode == 0, made.stderr
    return certificate, key


def render_site_with_tls(directory, port, tls_port, **options):
    """render_site() plus a TLS listener, as the entrypoint adds one."""
    conf = render_site(directory, port, **options)
    certificate, key = self_signed_pair(directory)
    site = directory / "site.conf"
    text = site.read_text(encoding="utf-8")
    plain = f"listen 127.0.0.1:{port} default_server;"
    assert text.count(plain) == 1, plain
    site.write_text(text.replace(
        plain,
        f"{plain}\n        listen 127.0.0.1:{tls_port} ssl default_server;\n"
        f'        ssl_certificate "{certificate}";\n'
        f'        ssl_certificate_key "{key}";'), encoding="utf-8")
    return conf, certificate


@unittest.skipUnless(shutil.which("nginx"), "nginx is not installed on this host")
class NginxSyntaxTests(unittest.TestCase):
    def nginx_t(self, directory, conf):
        result = subprocess.run(
            ["nginx", "-t", "-p", str(directory), "-c", str(conf)],
            capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_site_without_a_tls_listener_passes_nginx_t(self):
        # The native install and a container without LLDPQ_HTTPS_PORT: $https
        # is a core variable and needs neither a TLS listener nor a module.
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp).resolve()
            self.nginx_t(directory, render_site(directory, free_port()))

    @unittest.skipUnless(shutil.which("openssl"), "openssl is not installed on this host")
    def test_site_with_a_tls_listener_passes_nginx_t(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp).resolve()
            conf, _ = render_site_with_tls(directory, free_port(), free_port())
            self.nginx_t(directory, conf)


@unittest.skipUnless(os.environ.get("LLDPQ_RUN_SOCKET_TESTS") == "1",
                     "opt-in local nginx socket integration")
class LiveNginxTests(unittest.TestCase):
    def setUp(self):
        for tool in ("nginx", "flock", "openssl"):
            if not shutil.which(tool):
                self.skipTest(f"{tool} is required")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.tmp = Path(temporary.name).resolve()
        web, state = self.tmp / "web", self.tmp / "state"
        web.mkdir()
        state.mkdir()
        scratch_cgi(state, web / "auth-api.sh")
        self.sessions = state / "sessions"

        self.fastcgi = FastCgiStandIn()
        self.addCleanup(self.fastcgi.close)
        self.port, self.tls_port = free_port(), free_port()
        conf, certificate = render_site_with_tls(
            self.tmp, self.port, self.tls_port, web_root=web, fastcgi=self.fastcgi.address)
        self.context = ssl.create_default_context(cafile=str(certificate))
        self.context.check_hostname = False
        self.nginx = subprocess.Popen(
            ["nginx", "-p", str(self.tmp), "-c", str(conf)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(self.stop_nginx)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.tls_port), 0.2).close()
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

    def request(self, path, tls, cookie=None, body=None):
        if tls:
            connection = http.client.HTTPSConnection(
                "127.0.0.1", self.tls_port, timeout=20, context=self.context)
        else:
            connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            connection.request("POST" if body is not None else "GET", path,
                               body=body, headers=headers)
            response = connection.getresponse()
            return (response.status, response.headers.get_all("Set-Cookie") or [],
                    json.loads(response.read().decode()))
        finally:
            connection.close()

    def login(self, tls):
        status, cookies, response = self.request(
            "/auth-api?action=login", tls, body=f"username=admin&password={PASSWORD}")
        self.assertEqual(status, 200, response)
        self.assertIs(response["success"], True)
        (cookie,) = cookies
        return attributes(cookie)

    def test_cookie_is_secure_on_the_tls_listener_only(self):
        plain, plain_attributes = self.login(tls=False)
        self.assertEqual(plain_attributes, PLAIN_ATTRIBUTES)
        secure, secure_attributes = self.login(tls=True)
        self.assertEqual(secure_attributes, PLAIN_ATTRIBUTES + ["Secure"])
        self.assertNotEqual(plain, secure)
        for cookie in (plain, secure):
            self.assertRegex(cookie, r"^lldpq_session=[0-9a-f]{64}$")
            self.assertTrue((self.sessions / cookie.split("=", 1)[1]).is_file())

        # The polled check keeps answering on port 80, and sets no cookie.
        status, cookies, response = self.request("/auth-api?action=check", tls=False)
        self.assertEqual((status, cookies, response["authenticated"]), (200, [], False))
        status, cookies, response = self.request("/auth-api?action=check", tls=True, cookie=secure)
        self.assertEqual((status, cookies, response["authenticated"]), (200, [], True))

        for tls, cookie in ((True, secure), (False, plain)):
            status, cookies, response = self.request(
                "/auth-api?action=logout", tls, cookie=cookie)
            self.assertEqual((status, response), (200, {"success": True}))
            self.assertEqual([attributes(value) for value in cookies],
                             [("lldpq_session=", ["Path=/", "HttpOnly", "Max-Age=0"])])
            self.assertFalse((self.sessions / cookie.split("=", 1)[1]).exists())


if __name__ == "__main__":
    unittest.main()
