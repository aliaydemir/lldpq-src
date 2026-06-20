#!/usr/bin/env python3
"""
LLDPq Console — WebSocket ⇄ PTY bridge (stdlib only).

Serves the admin-only web terminal (html/console.html via nginx /console-ws).
Each WebSocket connection attaches to ONE interactive PTY session to a target:
  - a fabric device  -> ssh -tt <user>@<ip>   (resolved server-side from devices.yaml)
  - the LLDPq host    -> bash -l               (target token __lldpq_host__)

Session persistence: each session has a client-supplied id (sid). The PTY survives
WebSocket disconnects (e.g. the user navigates away in the UI) — the master fd keeps
draining into a capped output buffer. Reconnecting with the same sid REATTACHES and
replays the buffer, so open terminals come back where you left them (until idle/max).

Security model (mirrors the CGI split):
  - Runs as **www-data** so it can read the server-side session files at
    /var/lib/lldpq/sessions/<token> (mode 700) and enforce the SAME admin gate as
    auth-guard.sh. No valid *admin* session -> HTTP 403, no PTY spawned. A session can
    only be reattached by the same user that created it.
  - The PTY is spawned as the LLDPq user via `sudo -u <LLDPQ_USER>` (same as
    run-device-command), so SSH keys / host shell run under that account, not www-data.

No third-party packages: asyncio + a minimal RFC6455 implementation + pty/termios.
Binds 127.0.0.1 only; nginx terminates the browser side and proxies here.
"""

import asyncio
import base64
import fcntl
import hashlib
import json
import os
import pwd
import re
import struct
import subprocess
import sys
import termios
import time

# ----------------------------------------------------------------------------- config
LISTEN_HOST = os.environ.get("CONSOLE_PTY_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("CONSOLE_PTY_PORT", "8765"))
SESSIONS_DIR = os.environ.get("LLDPQ_SESSIONS_DIR", "/var/lib/lldpq/sessions")
LLDPQ_CONF = os.environ.get("LLDPQ_CONF", "/etc/lldpq.conf")
IDLE_TIMEOUT = int(os.environ.get("CONSOLE_IDLE_TIMEOUT", "600"))   # seconds without input -> close
MAX_SESSION = int(os.environ.get("CONSOLE_MAX_SESSION", "28800"))   # hard cap, seconds
MAX_BUF = int(os.environ.get("CONSOLE_MAX_BUF", "262144"))          # replay buffer per session
HOST_TARGET = "__lldpq_host__"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_TOKEN_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
_SID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

SESSIONS = {}   # sid -> session dict


def _audit_path():
    for p in ("/var/log/lldpq/console-audit.log",
              os.path.join(_conf().get("LLDPQ_DIR", "/home/lldpq/lldpq"), "console-audit.log"),
              "/tmp/lldpq-console-audit.log"):
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "a"):
                pass
            return p
        except Exception:
            continue
    return None


def audit(msg):
    line = "%s %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%S"), msg)
    sys.stderr.write("[console] " + line)
    sys.stderr.flush()
    p = _audit_path()
    if p:
        try:
            with open(p, "a") as f:
                f.write(line)
        except Exception:
            pass


# ----------------------------------------------------------------------------- helpers
_CONF_CACHE = None


def _conf():
    global _CONF_CACHE
    if _CONF_CACHE is None:
        c = {}
        try:
            with open(LLDPQ_CONF) as f:
                for ln in f:
                    ln = ln.strip()
                    if ln and not ln.startswith("#") and "=" in ln:
                        k, v = ln.split("=", 1)
                        c[k.strip()] = v.strip().strip('"').strip("'")
        except Exception:
            pass
        _CONF_CACHE = c
    return _CONF_CACHE


def _current_user():
    try:
        return pwd.getpwuid(os.geteuid()).pw_name
    except Exception:
        return "www-data"


def validate_admin(cookie_header):
    """Return (ok, username, role) by replicating auth-guard.sh against the session store."""
    token = None
    for part in (cookie_header or "").split(";"):
        part = part.strip()
        if part.startswith("lldpq_session="):
            token = part.split("=", 1)[1].strip()
            break
    if not token or not _TOKEN_RE.match(token):
        return (False, "", "")
    path = os.path.join(SESSIONS_DIR, token)
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except Exception:
        return (False, "", "")
    if len(lines) < 3:
        return (False, "", "")
    try:
        expiry = int(lines[0])
    except ValueError:
        return (False, "", "")
    if time.time() > expiry:
        try:
            os.remove(path)
        except Exception:
            pass
        return (False, "", "")
    return (lines[2] == "admin", lines[1], lines[2])


def _load_devices():
    """hostname(lower) -> (ip, username) from $LLDPQ_DIR/devices.yaml (same source as run-device-command)."""
    out = {}
    path = os.path.join(_conf().get("LLDPQ_DIR", "/home/lldpq/lldpq"), "devices.yaml")
    try:
        import yaml
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return out
    default_user = ((data.get("defaults") or {}).get("username")) or "cumulus"
    for ip, val in (data.get("devices") or {}).items():
        hostname, user = None, default_user
        if isinstance(val, str):
            hostname = val.split()[0] if val.split() else None
        elif isinstance(val, dict):
            hostname = val.get("hostname")
            user = val.get("username", default_user)
        if hostname:
            out[hostname.lower()] = (str(ip), user)
    return out


def resolve_target(target):
    """(label, argv) for a target, or (None, None) if unknown. argv runs as LLDPQ_USER."""
    lldpq_user = _conf().get("LLDPQ_USER") or "lldpq"
    sudo = [] if _current_user() == lldpq_user else ["sudo", "-u", lldpq_user]
    if target == HOST_TARGET:
        return ("LLDPq host (%s)" % lldpq_user, sudo + ["/bin/bash", "-l"])
    dev = _load_devices().get((target or "").lower())
    if not dev:
        return (None, None)
    ip, duser = dev
    ssh = ["ssh", "-tt",
           "-o", "StrictHostKeyChecking=no",
           "-o", "ConnectTimeout=10",
           "-o", "BatchMode=yes",
           "-o", "LogLevel=ERROR",
           "%s@%s" % (duser, ip)]
    return ("%s (%s@%s)" % (target, duser, ip), sudo + ssh)


# ----------------------------------------------------------------------------- websocket framing
def ws_frame(opcode, data: bytes) -> bytes:
    b1 = 0x80 | (opcode & 0x0F)
    n = len(data)
    if n < 126:
        hdr = struct.pack(">BB", b1, n)
    elif n < 65536:
        hdr = struct.pack(">BBH", b1, 126, n)
    else:
        hdr = struct.pack(">BBQ", b1, 127, n)
    return hdr + data


async def ws_read(reader):
    """Read one (de-fragmented) message: returns (opcode, payload). Raises on EOF."""
    frags = []
    first_opcode = None
    while True:
        hdr = await reader.readexactly(2)
        b1, b2 = hdr[0], hdr[1]
        fin = b1 & 0x80
        opcode = b1 & 0x0F
        masked = b2 & 0x80
        ln = b2 & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", await reader.readexactly(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", await reader.readexactly(8))[0]
        mask = await reader.readexactly(4) if masked else b""
        payload = await reader.readexactly(ln) if ln else b""
        if masked and ln:
            payload = bytes(payload[i] ^ mask[i % 4] for i in range(ln))
        if opcode in (0x8, 0x9, 0xA):
            return (opcode, payload)
        if opcode != 0x0:
            first_opcode = opcode
        frags.append(payload)
        if fin:
            return (first_opcode if first_opcode is not None else 0x1, b"".join(frags))


def _set_winsize(fd, rows, cols):
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except Exception:
        pass


# ----------------------------------------------------------------------------- session registry
def _close_session(sess, notify=True):
    if sess.get("closing"):
        return
    sess["closing"] = True
    loop = asyncio.get_event_loop()
    try:
        loop.remove_reader(sess["master"])
    except Exception:
        pass
    try:
        if sess["proc"].poll() is None:
            sess["proc"].terminate()
    except Exception:
        pass
    try:
        os.close(sess["master"])
    except Exception:
        pass
    SESSIONS.pop(sess["sid"], None)
    if notify and sess.get("writer"):
        try:
            sess["writer"].write(ws_frame(0x8, b""))
        except Exception:
            pass
    audit("STOP user=%s target=%s dur=%ss sid=%s" %
          (sess["user"], sess["label"], int(time.time() - sess["started"]), sess["sid"][:8]))


def _make_feed(sess):
    """PTY output pump — runs for the whole PTY lifetime, independent of WS attach state."""
    def on_readable():
        try:
            data = os.read(sess["master"], 65536)
        except (OSError, BlockingIOError):
            return
        if not data:
            _close_session(sess)
            return
        buf = sess["buffer"]
        buf.extend(data)
        if len(buf) > MAX_BUF:
            del buf[:len(buf) - MAX_BUF]
        if sess.get("attached") and sess.get("writer"):
            try:
                sess["writer"].write(ws_frame(0x2, data))
            except Exception:
                pass
    return on_readable


async def _watchdog(sess):
    while not sess.get("closing"):
        await asyncio.sleep(15)
        idle = time.time() - sess["last_input"]
        if idle > IDLE_TIMEOUT or (time.time() - sess["started"]) > MAX_SESSION:
            reason = "idle" if idle > IDLE_TIMEOUT else "max-session"
            if sess.get("writer"):
                try:
                    sess["writer"].write(ws_frame(0x1, ("\r\n\x1b[33m• session closed (%s)\x1b[0m\r\n" % reason).encode()))
                except Exception:
                    pass
            _close_session(sess)
            return


# ----------------------------------------------------------------------------- connection handler
async def handle(reader, writer):
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else "?"
    loop = asyncio.get_event_loop()

    def http_reject(code, text):
        writer.write(("HTTP/1.1 %s\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                      "Content-Length: %d\r\n\r\n%s" % (code, len(text), text)).encode())

    sess = None
    try:
        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = await reader.read(2048)
            if not chunk:
                return
            raw += chunk
            if len(raw) > 16384:
                http_reject("400 Bad Request", "header too large")
                return
        head = raw.split(b"\r\n\r\n", 1)[0].decode("latin1")
        lines = head.split("\r\n")
        request_line = lines[0] if lines else ""
        headers = {}
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        from urllib.parse import unquote
        def _qs(name):
            m = re.search(r"[?&]%s=([^&\s]+)" % name, request_line)
            return unquote(m.group(1)) if m else ""
        target = _qs("target")
        sid = _qs("sid")
        if not _SID_RE.match(sid or ""):
            sid = "eph-%d-%d" % (int(time.time() * 1000), os.getpid())

        ok, user, role = validate_admin(headers.get("cookie", ""))
        if not ok:
            audit("DENY ip=%s target=%s (not admin)" % (peer_ip, target))
            http_reject("403 Forbidden", "Admin session required")
            return

        key = headers.get("sec-websocket-key", "")
        if not key:
            http_reject("400 Bad Request", "missing Sec-WebSocket-Key")
            return
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        writer.write(("HTTP/1.1 101 Switching Protocols\r\n"
                      "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                      "Sec-WebSocket-Accept: %s\r\n\r\n" % accept).encode())
        await writer.drain()

        existing = SESSIONS.get(sid)
        if existing and not existing.get("closing"):
            if existing["user"] != user:
                writer.write(ws_frame(0x1, b"\x1b[31m\xe2\x80\xa2 session belongs to another user\x1b[0m\r\n"))
                writer.write(ws_frame(0x8, b""))
                return
            # ---- REATTACH ----
            sess = existing
            sess["writer"] = writer
            sess["attached"] = True
            if sess["buffer"]:
                writer.write(ws_frame(0x2, bytes(sess["buffer"])))
            writer.write(ws_frame(0x1, b"\r\n\x1b[90m\xe2\x80\xa2 reattached\x1b[0m\r\n"))
            audit("REATTACH ip=%s user=%s target=%s sid=%s" % (peer_ip, user, sess["label"], sid[:8]))
        else:
            # ---- NEW SESSION ----
            label, argv = resolve_target(target)
            if not argv:
                audit("DENY ip=%s user=%s target=%s (unknown target)" % (peer_ip, user, target))
                http_reject("404 Not Found", "Unknown target")  # (post-upgrade; client sees close)
                writer.write(ws_frame(0x1, b"\x1b[31m\xe2\x80\xa2 unknown target\x1b[0m\r\n"))
                writer.write(ws_frame(0x8, b""))
                return
            master, slave = os.openpty()
            _set_winsize(master, 24, 80)
            fcntl.fcntl(master, fcntl.F_SETFL, os.O_NONBLOCK)

            def _preexec():
                try:
                    os.setsid()
                except Exception:
                    pass
                try:
                    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
                except Exception:
                    pass

            env = dict(os.environ)
            env["TERM"] = "xterm-256color"
            proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                                    preexec_fn=_preexec, close_fds=True, env=env)
            os.close(slave)
            sess = {"sid": sid, "user": user, "label": label, "proc": proc, "master": master,
                    "buffer": bytearray(), "writer": writer, "attached": True,
                    "last_input": time.time(), "started": time.time(), "closing": False}
            SESSIONS[sid] = sess
            loop.add_reader(master, _make_feed(sess))
            asyncio.ensure_future(_watchdog(sess))
            audit("START ip=%s user=%s target=%s pid=%s sid=%s" % (peer_ip, user, label, proc.pid, sid[:8]))
            writer.write(ws_frame(0x1, ("\x1b[90m• connecting to %s …\x1b[0m\r\n" % label).encode()))

        # ---- per-connection input loop ----
        explicit_end = False
        try:
            while not sess.get("closing"):
                opcode, payload = await ws_read(reader)
                if opcode is None or opcode == 0x8:
                    break
                if opcode == 0x9:
                    writer.write(ws_frame(0xA, payload))
                    continue
                if opcode == 0xA:
                    continue
                try:
                    msg = json.loads(payload.decode("utf-8", "replace"))
                except Exception:
                    continue
                t = msg.get("t")
                if t == "i":
                    sess["last_input"] = time.time()
                    os.write(sess["master"], msg.get("d", "").encode("utf-8"))
                elif t == "r":
                    _set_winsize(sess["master"], int(msg.get("r", 24)), int(msg.get("c", 80)))
                elif t == "end":
                    explicit_end = True
                    break
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass

        # ---- detach (keep PTY alive) or explicit kill ----
        if sess.get("writer") is writer:
            sess["attached"] = False
            sess["writer"] = None
        if explicit_end:
            _close_session(sess, notify=False)

    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        if sess and sess.get("writer") is writer:
            sess["attached"] = False
            sess["writer"] = None
    except Exception as e:
        audit("ERROR ip=%s: %r" % (peer_ip, e))
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT)
    audit("LISTEN %s:%d as %s (idle=%ss, persist via reattach)" %
          (LISTEN_HOST, LISTEN_PORT, _current_user(), IDLE_TIMEOUT))
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
