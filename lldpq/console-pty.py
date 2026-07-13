#!/usr/bin/env python3
"""
LLDPq Console — WebSocket ⇄ PTY bridge (stdlib only).

Serves the admin-only web terminal (html/console.html via nginx /console-ws).
Each WebSocket connection attaches to ONE interactive PTY session to a target:
  - a fabric device  -> ssh -tt <user>@<ip>   (resolved from Ansible/devices.yaml)
  - the LLDPq host    -> bash -l               (target token __lldpq_host__)

Session persistence: each session has a client-supplied id (sid). The PTY survives
WebSocket disconnects (e.g. the user navigates away in the UI) — the master fd keeps
draining into a capped output buffer. Reconnecting with the same sid REATTACHES and
replays the buffer, so open terminals come back where you left them (until idle/max).

Security model (mirrors the CGI split):
  - Runs as **www-data** so it can read the server-side session files at
    /var/lib/lldpq/sessions/<token> (mode 700) and enforce the SAME admin gate as
    auth-guard.sh. No valid *admin* session -> HTTP 403, no PTY spawned. A session can
    only be reattached with the exact admin token that created it.
  - The PTY is spawned as the LLDPq user via `sudo -u <LLDPQ_USER>` (same as
    run-device-command), so SSH keys / host shell run under that account, not www-data.

The bridge itself is stdlib-only; optional PyYAML is used for the devices.yaml
inventory fallback. It binds 127.0.0.1 only; nginx terminates/proxies browser traffic.
"""

import asyncio
import base64
import errno
import fcntl
import hashlib
import json
import os
import pwd
import re
import shlex
import signal
import struct
import subprocess
import sys
import termios
import time
from urllib.parse import parse_qs, urlsplit

# ----------------------------------------------------------------------------- config
LISTEN_HOST = os.environ.get("CONSOLE_PTY_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("CONSOLE_PTY_PORT", "8765"))
SESSIONS_DIR = os.environ.get("LLDPQ_SESSIONS_DIR", "/var/lib/lldpq/sessions")
LLDPQ_CONF = os.environ.get("LLDPQ_CONF", "/etc/lldpq.conf")
IDLE_TIMEOUT = int(os.environ.get("CONSOLE_IDLE_TIMEOUT", "600"))   # seconds without attached activity
MAX_SESSION = int(os.environ.get("CONSOLE_MAX_SESSION", "28800"))   # hard cap, seconds
MAX_BUF = int(os.environ.get("CONSOLE_MAX_BUF", "262144"))          # replay buffer per session
MAX_WS_FRAME = int(os.environ.get("CONSOLE_MAX_WS_FRAME", "2097152"))
MAX_WS_MESSAGE = int(os.environ.get("CONSOLE_MAX_WS_MESSAGE", "2097152"))
MAX_PTY_INPUT = int(os.environ.get("CONSOLE_MAX_PTY_INPUT", "1048576"))
MAX_WS_WRITE_BUFFER = int(os.environ.get("CONSOLE_MAX_WS_WRITE_BUFFER", "1048576"))
MAX_SESSIONS = int(os.environ.get("CONSOLE_MAX_SESSIONS", "256"))
MAX_SESSIONS_PER_TOKEN = int(os.environ.get("CONSOLE_MAX_SESSIONS_PER_TOKEN", "128"))
MAX_WS_FRAGMENTS = int(os.environ.get("CONSOLE_MAX_WS_FRAGMENTS", "1024"))
PTY_WRITE_TIMEOUT = float(os.environ.get("CONSOLE_PTY_WRITE_TIMEOUT", "5"))
PROCESS_TERM_TIMEOUT = float(os.environ.get("CONSOLE_PROCESS_TERM_TIMEOUT", "2"))
SHUTDOWN_TIMEOUT = float(os.environ.get("CONSOLE_SHUTDOWN_TIMEOUT", "8"))
HOST_TARGET = "__lldpq_host__"
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_TOKEN_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
_SID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

SESSIONS = {}          # sid -> session dict
CLEANUP_TASKS = set()  # process cleanup tasks, including sessions already removed
CLEANUP_PROCS = {}     # cleanup task -> Popen, for bounded shutdown escalation
CONNECTION_TASKS = set()
SHUTTING_DOWN = False


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


def _sanitize_log(value, limit=256):
    """Strip CR/LF/control chars and cap length so audit/journald lines can't be forged."""
    text = _CONTROL_RE.sub("", str(value or ""))
    return text[:limit]


def _client_ip(headers, fallback):
    """Trust the loopback nginx proxy's forwarded client IP over the TCP peername."""
    for name in ("x-real-ip", "x-forwarded-for"):
        candidate = _sanitize_log((headers.get(name, "") or "").split(",")[0], 64).strip()
        if candidate:
            return candidate
    return fallback


def _extract_session_token(cookie_header):
    """Extract a syntactically valid LLDPq session token from a Cookie header."""
    for part in (cookie_header or "").split(";"):
        part = part.strip()
        if part.startswith("lldpq_session="):
            token = part.split("=", 1)[1].strip()
            return token if _TOKEN_RE.fullmatch(token) else None
    return None


def _validate_admin_token(token):
    """Return (ok, username, role) for one exact token in the session store."""
    if not token or not _TOKEN_RE.fullmatch(token):
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


def _authenticate_admin(cookie_header):
    """Return (ok, username, role, token), retaining the authenticated identity."""
    token = _extract_session_token(cookie_header)
    ok, username, role = _validate_admin_token(token)
    return (ok, username, role, token or "")


def validate_admin(cookie_header):
    """Compatibility wrapper returning the historical three-item auth tuple."""
    ok, username, role, _token = _authenticate_admin(cookie_header)
    return (ok, username, role)


def _session_is_authorized(sess):
    """Revalidate the exact token and principal that created a PTY session."""
    ok, username, role = _validate_admin_token(sess.get("token"))
    return ok and role == "admin" and username == sess.get("user")


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


def _ansible_inventory_path():
    ansible_dir = (_conf().get("ANSIBLE_DIR") or "").strip()
    if not ansible_dir or ansible_dir.lower() == "none":
        return None
    for name in ("inventory.ini", "hosts"):
        path = os.path.join(ansible_dir, "inventory", name)
        if os.path.isfile(path):
            return path
    return None


def _load_ansible_devices():
    """hostname(lower) -> (address, username) from the configured INI inventory."""
    path = _ansible_inventory_path()
    if not path:
        return {}

    records = []
    group_vars = {}
    all_vars = {}
    section = None
    section_kind = None
    skip_groups = {"local", "all", "ungrouped"}
    try:
        with open(path) as inventory:
            for raw_line in inventory:
                line = raw_line.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                if line.startswith("[") and line.endswith("]"):
                    name = line[1:-1].strip()
                    if name.endswith(":vars"):
                        section = name[:-5]
                        section_kind = "vars"
                    elif ":" in name:
                        section = None
                        section_kind = None
                    else:
                        section = name
                        section_kind = "hosts"
                    continue
                if section_kind == "vars" and "=" in line:
                    key, value = line.split("=", 1)
                    destination = all_vars if section == "all" else group_vars.setdefault(section, {})
                    destination[key.strip()] = value.strip().strip('"').strip("'")
                    continue
                if section_kind != "hosts" or not section or section in skip_groups:
                    continue
                try:
                    parts = shlex.split(line, comments=True, posix=True)
                except ValueError:
                    continue
                # Keep the Console inventory aligned with fabric-api.sh: host rows
                # shown by that API carry at least one inline Ansible variable.
                if not parts or not any("=" in part for part in parts[1:]):
                    continue
                hostname = parts[0]
                variables = {}
                for part in parts[1:]:
                    if "=" in part:
                        key, value = part.split("=", 1)
                        variables[key] = value
                records.append((section, hostname, variables))
    except (OSError, UnicodeError):
        return {}

    out = {}
    for group, hostname, inline_vars in records:
        variables = dict(all_vars)
        variables.update(group_vars.get(group, {}))
        variables.update(inline_vars)
        address = variables.get("ansible_host") or hostname
        username = variables.get("ansible_user") or "cumulus"
        if hostname and address and username:
            out[hostname.lower()] = (str(address), str(username))
    return out


def resolve_target(target):
    """(label, argv) for a target, or (None, None) if unknown. argv runs as LLDPQ_USER."""
    lldpq_user = _conf().get("LLDPQ_USER") or "lldpq"
    sudo = [] if _current_user() == lldpq_user else ["sudo", "-u", lldpq_user]
    if target == HOST_TARGET:
        return ("LLDPq host (%s)" % lldpq_user, sudo + ["/bin/bash", "-l"])
    # Match the Fabric device list: a non-empty Ansible inventory is authoritative;
    # devices.yaml is used only when no usable Ansible hosts were found.
    devices = _load_ansible_devices()
    if not devices:
        devices = _load_devices()
    dev = devices.get((target or "").lower())
    if not dev:
        return (None, None)
    ip, duser = dev
    ssh = ["ssh", "-tt",
           "-o", "StrictHostKeyChecking=accept-new",
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


class WSProtocolError(Exception):
    """RFC 6455 protocol/policy failure carrying a legal WebSocket close code."""

    def __init__(self, code, reason):
        super().__init__(reason)
        self.code = code
        self.reason = reason


def _valid_close_code(code):
    return code in {1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014} \
        or 3000 <= code <= 4999


def _close_payload(code, reason=""):
    if not _valid_close_code(code):
        code = 1002
        reason = "invalid close code"
    raw = str(reason).encode("utf-8", "replace")[:123]
    while raw:
        try:
            raw.decode("utf-8")
            break
        except UnicodeDecodeError:
            raw = raw[:-1]
    return struct.pack(">H", code) + raw


async def ws_read(reader, state=None):
    """Read one validated client message while retaining fragmentation state."""
    if state is None:
        state = {}
    frags = state.setdefault("frags", bytearray())
    first_opcode = state.get("opcode")
    message_size = state.get("size", 0)
    fragment_count = state.get("fragment_count", 0)
    while True:
        hdr = await reader.readexactly(2)
        b1, b2 = hdr[0], hdr[1]
        if b1 & 0x70:
            raise WSProtocolError(1002, "RSV bits are not supported")
        fin = bool(b1 & 0x80)
        opcode = b1 & 0x0F
        masked = bool(b2 & 0x80)
        if not masked:
            raise WSProtocolError(1002, "client frames must be masked")
        length_marker = b2 & 0x7F
        ln = length_marker
        if length_marker == 126:
            ln = struct.unpack(">H", await reader.readexactly(2))[0]
            if ln < 126:
                raise WSProtocolError(1002, "non-minimal frame length")
        elif length_marker == 127:
            encoded_length = await reader.readexactly(8)
            if encoded_length[0] & 0x80:
                raise WSProtocolError(1002, "invalid 64-bit frame length")
            ln = struct.unpack(">Q", encoded_length)[0]
            if ln < 65536:
                raise WSProtocolError(1002, "non-minimal frame length")
        if ln > MAX_WS_FRAME:
            raise WSProtocolError(1009, "frame too large")

        is_control = opcode >= 0x8
        if is_control and (not fin or ln > 125):
            raise WSProtocolError(1002, "invalid control frame")
        if opcode not in (0x0, 0x1, 0x2, 0x8, 0x9, 0xA):
            raise WSProtocolError(1002, "unsupported opcode")

        if not is_control:
            if opcode == 0x0:
                if first_opcode is None:
                    raise WSProtocolError(1002, "unexpected continuation frame")
            else:
                if first_opcode is not None:
                    raise WSProtocolError(1002, "new message before fragmented message completed")
                first_opcode = opcode
                frags.clear()
                message_size = 0
                fragment_count = 0
            if message_size + ln > MAX_WS_MESSAGE:
                raise WSProtocolError(1009, "message too large")
            if fragment_count + 1 > MAX_WS_FRAGMENTS:
                raise WSProtocolError(1009, "too many message fragments")

        mask = await reader.readexactly(4)
        payload = await reader.readexactly(ln) if ln else b""
        if ln:
            payload = bytes(payload[i] ^ mask[i % 4] for i in range(ln))

        if is_control:
            if opcode == 0x8:
                if len(payload) == 1:
                    raise WSProtocolError(1002, "invalid close payload")
                if len(payload) >= 2:
                    code = struct.unpack(">H", payload[:2])[0]
                    if not _valid_close_code(code):
                        raise WSProtocolError(1002, "invalid close code")
                    try:
                        payload[2:].decode("utf-8")
                    except UnicodeDecodeError as exc:
                        raise WSProtocolError(1007, "invalid close reason") from exc
            return (opcode, payload)

        frags.extend(payload)
        message_size += len(payload)
        fragment_count += 1
        state["opcode"] = first_opcode
        state["size"] = message_size
        state["fragment_count"] = fragment_count
        if fin:
            complete_opcode = first_opcode
            complete = bytes(frags)
            frags.clear()
            state.pop("opcode", None)
            state["size"] = 0
            state["fragment_count"] = 0
            return (complete_opcode, complete)


def _set_winsize(fd, rows, cols):
    try:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    except Exception:
        pass


# ----------------------------------------------------------------------------- session registry
def _writer_buffer_size(writer):
    transport = getattr(writer, "transport", None)
    if transport is None:
        transport = getattr(writer, "_transport", None)
    try:
        return int(transport.get_write_buffer_size())
    except Exception:
        return 0


def _write_ws_frame(writer, opcode, data):
    """Queue one server frame without allowing an unbounded transport buffer."""
    frame = ws_frame(opcode, data)
    try:
        if writer.is_closing():
            return False
    except Exception:
        pass
    if _writer_buffer_size(writer) + len(frame) > MAX_WS_WRITE_BUFFER:
        try:
            writer.close()
        except Exception:
            pass
        return False
    try:
        writer.write(frame)
    except Exception:
        try:
            writer.close()
        except Exception:
            pass
        return False
    if _writer_buffer_size(writer) > MAX_WS_WRITE_BUFFER:
        try:
            writer.close()
        except Exception:
            pass
        return False
    return True


def _close_writer(writer, code=1000, reason=""):
    if writer is None:
        return
    _write_ws_frame(writer, 0x8, _close_payload(code, reason))
    try:
        writer.close()
    except Exception:
        pass


def _attachment_current(sess, writer, attachment_id):
    return (
        not sess.get("closing")
        and sess.get("attached")
        and sess.get("writer") is writer
        and sess.get("attachment_id") == attachment_id
    )


def _detach_attachment(sess, writer, attachment_id, close_writer=False):
    if _attachment_current(sess, writer, attachment_id):
        sess["attached"] = False
        sess["writer"] = None
        # Navigating away starts a fresh documented idle window for reattach.
        sess["last_activity"] = time.time()
    if close_writer:
        try:
            writer.close()
        except Exception:
            pass


def _send_session_frame(sess, opcode, data, attachment_id=None):
    writer = sess.get("writer")
    if attachment_id is None:
        attachment_id = sess.get("attachment_id")
    if not _attachment_current(sess, writer, attachment_id):
        return False
    if _write_ws_frame(writer, opcode, data):
        return True
    _detach_attachment(sess, writer, attachment_id, close_writer=True)
    return False


def _cancel_pty_write_waiter(sess):
    waiter = sess.pop("write_waiter", None)
    if waiter is not None and not waiter.done():
        waiter.set_result(False)
    try:
        asyncio.get_running_loop().remove_writer(sess["master"])
    except (KeyError, RuntimeError, OSError, ValueError):
        pass


def _signal_process_group(proc, sig):
    try:
        # Every Console child calls setsid(), so its PID is also its process-group ID.
        os.killpg(proc.pid, sig)
        return
    except ProcessLookupError:
        pass
    except (AttributeError, OSError):
        pass
    try:
        proc.send_signal(sig)
    except AttributeError:
        try:
            (proc.terminate if sig == signal.SIGTERM else proc.kill)()
        except Exception:
            pass
    except Exception:
        pass


def _process_group_exists(proc):
    try:
        os.killpg(proc.pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (AttributeError, OSError):
        return proc.poll() is None


async def _wait_process(proc, timeout):
    """Poll/reap a Popen child without creating threads or blocking asyncio."""
    loop = asyncio.get_running_loop()
    deadline = None if timeout is None else loop.time() + timeout
    while True:
        status = proc.poll()  # Popen.poll() uses waitpid(..., WNOHANG) and reaps.
        if status is not None:
            return status
        if deadline is not None and loop.time() >= deadline:
            raise subprocess.TimeoutExpired(getattr(proc, "args", "console"), timeout)
        await asyncio.sleep(0.05)


async def _terminate_process(proc):
    """TERM, then KILL and reap a complete PTY process group off the event loop."""
    try:
        _signal_process_group(proc, signal.SIGTERM)
        term_timed_out = False
        try:
            await _wait_process(proc, PROCESS_TERM_TIMEOUT)
        except subprocess.TimeoutExpired:
            term_timed_out = True
        # The process-group leader can exit while a child ignores TERM. Check the
        # group itself before deciding cleanup is complete.
        if term_timed_out or _process_group_exists(proc):
            _signal_process_group(proc, signal.SIGKILL)
        # Async WNOHANG polling keeps the event loop responsive and reaps the leader
        # once SIGKILL takes effect.
        if proc.poll() is None:
            await _wait_process(proc, None)
    except (ChildProcessError, ProcessLookupError):
        pass
    except Exception as exc:
        audit("WARN process cleanup pid=%s: %r" % (getattr(proc, "pid", "?"), exc))


def _track_cleanup_task(task, proc):
    CLEANUP_TASKS.add(task)
    CLEANUP_PROCS[task] = proc

    def finished(done):
        CLEANUP_TASKS.discard(done)
        CLEANUP_PROCS.pop(done, None)

    task.add_done_callback(finished)


def _close_session(sess, notify=True, code=1000, reason="session ended"):
    if sess.get("closing"):
        return
    sess["closing"] = True
    writer = sess.get("writer")
    sess["attached"] = False
    sess["writer"] = None
    sess["attachment_id"] = sess.get("attachment_id", 0) + 1

    _cancel_pty_write_waiter(sess)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is not None:
        try:
            loop.remove_reader(sess["master"])
        except Exception:
            pass
        try:
            loop.remove_writer(sess["master"])
        except Exception:
            pass
    try:
        os.close(sess["master"])
    except (KeyError, OSError):
        pass
    if SESSIONS.get(sess.get("sid")) is sess:
        SESSIONS.pop(sess["sid"], None)
    if notify and writer is not None:
        _close_writer(writer, code, reason)
    proc = sess.get("proc")
    if proc is not None:
        if loop is not None:
            cleanup_task = loop.create_task(_terminate_process(proc))
            sess["cleanup_task"] = cleanup_task
            _track_cleanup_task(cleanup_task, proc)
        else:
            _signal_process_group(proc, signal.SIGTERM)
    watchdog = sess.get("watchdog_task")
    if watchdog is not None and not watchdog.done():
        try:
            current = asyncio.current_task()
        except RuntimeError:
            current = None
        if watchdog is not current:
            watchdog.cancel()
    audit("STOP user=%s target=%s dur=%ss sid=%s reason=%s" %
          (sess.get("user", "?"), sess.get("label", "?"),
           int(time.time() - sess.get("started", time.time())),
           sess.get("sid", "?")[:8], reason))


def _make_feed(sess):
    """PTY output pump — runs for the whole PTY lifetime, independent of WS attach state."""
    def on_readable():
        try:
            data = os.read(sess["master"], 65536)
        except BlockingIOError:
            return
        except OSError as exc:
            if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return
            # Linux PTY masters report EIO when the slave side has exited. Any
            # other permanent read error must also unregister the reader.
            _close_session(sess, reason="PTY closed")
            return
        if not data:
            _close_session(sess, reason="PTY closed")
            return
        buf = sess["buffer"]
        buf.extend(data)
        if len(buf) > MAX_BUF:
            del buf[:len(buf) - MAX_BUF]
        if sess.get("attached") and sess.get("writer"):
            sess["last_activity"] = time.time()
            _send_session_frame(sess, 0x2, data, sess.get("attachment_id"))
    return on_readable


async def _wait_pty_writable(sess, attachment_id):
    loop = asyncio.get_running_loop()
    waiter = loop.create_future()
    sess["write_waiter"] = waiter

    def ready():
        if not waiter.done():
            waiter.set_result(True)

    try:
        loop.add_writer(sess["master"], ready)
        return await asyncio.wait_for(waiter, PTY_WRITE_TIMEOUT)
    except (asyncio.TimeoutError, OSError, ValueError):
        return False
    finally:
        if sess.get("write_waiter") is waiter:
            try:
                loop.remove_writer(sess["master"])
            except Exception:
                pass
            sess.pop("write_waiter", None)


async def _write_pty(sess, data, attachment_id):
    """Write all validated input to a nonblocking PTY, handling partial/EAGAIN."""
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        writer = sess.get("writer")
        if not _attachment_current(sess, writer, attachment_id):
            return False
        try:
            written = os.write(sess["master"], view[offset:])
        except BlockingIOError:
            if not await _wait_pty_writable(sess, attachment_id):
                return False
            continue
        except OSError:
            _close_session(sess, reason="PTY write failed")
            return False
        if written <= 0:
            _close_session(sess, reason="PTY write failed")
            return False
        offset += written
    return True


async def _watchdog(sess):
    while not sess.get("closing"):
        await asyncio.sleep(15)
        if sess.get("closing"):
            return
        if not _session_is_authorized(sess):
            _send_session_frame(
                sess, 0x1,
                b"\r\n\x1b[31m\xe2\x80\xa2 authorization expired\x1b[0m\r\n",
                sess.get("attachment_id"),
            )
            _close_session(sess, code=1008, reason="authorization expired")
            return
        # Keepalive — keeps the WS alive through Cloudflare (~100s) / nginx idle timeouts.
        if sess.get("attached") and sess.get("writer"):
            _send_session_frame(sess, 0x2, b"\x00", sess.get("attachment_id"))
        idle = time.time() - sess["last_activity"]
        warn_at = IDLE_TIMEOUT - 60
        if warn_at > 0:
            if idle >= warn_at and idle <= IDLE_TIMEOUT and not sess.get("idle_warned"):
                if sess.get("attached") and sess.get("writer"):
                    sess["idle_warned"] = True
                    _send_session_frame(
                        sess, 0x1,
                        b"\r\n\x1b[33m\xe2\x80\xa2 session closes in 60s \xe2\x80\x94 "
                        b"press any key to stay\x1b[0m\r\n",
                        sess.get("attachment_id"),
                    )
            elif idle < warn_at:
                sess.pop("idle_warned", None)
        if idle > IDLE_TIMEOUT or (time.time() - sess["started"]) > MAX_SESSION:
            reason = "idle" if idle > IDLE_TIMEOUT else "max-session"
            _send_session_frame(
                sess, 0x1,
                ("\r\n\x1b[33m• session closed (%s)\x1b[0m\r\n" % reason).encode(),
                sess.get("attachment_id"),
            )
            _close_session(sess, reason=reason)
            return


# ----------------------------------------------------------------------------- connection handler
def _session_limit_status(token):
    active = [sess for sess in SESSIONS.values() if not sess.get("closing")]
    if MAX_SESSIONS > 0 and len(active) >= MAX_SESSIONS:
        return ("503 Service Unavailable", "Console session capacity reached")
    owned = sum(1 for sess in active if sess.get("token") == token)
    if MAX_SESSIONS_PER_TOKEN > 0 and owned >= MAX_SESSIONS_PER_TOKEN:
        return ("429 Too Many Requests", "Console session limit reached")
    return None


def _valid_websocket_key(key):
    try:
        return len(base64.b64decode(key.encode("ascii"), validate=True)) == 16
    except (ValueError, UnicodeError):
        return False


def _close_details(payload):
    if len(payload) >= 2:
        code = struct.unpack(">H", payload[:2])[0]
        # 1010 is client-only; acknowledge it with a normal server close.
        if code == 1010:
            return 1000, ""
        return code, payload[2:].decode("utf-8")
    return 1000, ""


async def handle(reader, writer):
    connection_task = asyncio.current_task()
    if connection_task is not None:
        CONNECTION_TASKS.add(connection_task)
        connection_task.add_done_callback(CONNECTION_TASKS.discard)
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else "?"
    loop = asyncio.get_running_loop()

    async def http_reject(code, text, extra_headers=""):
        body = text.encode("utf-8")
        writer.write(("HTTP/1.1 %s\r\nContent-Type: text/plain; charset=utf-8\r\n"
                      "Connection: close\r\n%sContent-Length: %d\r\n\r\n" %
                      (code, extra_headers, len(body))).encode("ascii") + body)
        try:
            await writer.drain()
        except (ConnectionError, RuntimeError, OSError):
            pass

    sess = None
    attachment_id = None
    upgraded = False
    explicit_end = False
    try:
        if SHUTTING_DOWN:
            await http_reject("503 Service Unavailable", "Console service is stopping")
            return
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
        except asyncio.IncompleteReadError as exc:
            if exc.partial:
                await http_reject("400 Bad Request", "incomplete HTTP request")
            return
        except asyncio.LimitOverrunError:
            await http_reject("400 Bad Request", "header too large")
            return
        if len(raw) > 16384:
            await http_reject("400 Bad Request", "header too large")
            return
        try:
            head = raw[:-4].decode("latin1")
        except UnicodeError:
            await http_reject("400 Bad Request", "invalid HTTP headers")
            return
        lines = head.split("\r\n")
        request_parts = lines[0].split() if lines else []
        if len(request_parts) != 3 or request_parts[0] != "GET" or request_parts[2] != "HTTP/1.1":
            await http_reject("400 Bad Request", "invalid WebSocket request")
            return
        headers = {}
        for line in lines[1:]:
            if ":" not in line:
                await http_reject("400 Bad Request", "invalid HTTP header")
                return
            key, value = line.split(":", 1)
            name = key.strip().lower()
            if not name:
                await http_reject("400 Bad Request", "invalid HTTP header")
                return
            headers[name] = value.strip()

        peer_ip = _client_ip(headers, peer_ip)

        request_url = urlsplit(request_parts[1])
        query = parse_qs(request_url.query, keep_blank_values=True)
        target = (query.get("target") or [""])[0]
        log_target = _sanitize_log(target, 128)
        sid = (query.get("sid") or [""])[0]
        kill_only = (query.get("kill") or [""])[0] == "1"
        if not _SID_RE.fullmatch(sid):
            await http_reject("400 Bad Request", "invalid session id")
            return

        ok, user, role, token = _authenticate_admin(headers.get("cookie", ""))
        if not ok:
            audit("DENY ip=%s target=%s (not admin)" % (peer_ip, log_target))
            await http_reject("403 Forbidden", "Admin session required")
            return

        if headers.get("upgrade", "").lower() != "websocket" or \
                "upgrade" not in {part.strip().lower() for part in headers.get("connection", "").split(",")}:
            await http_reject("400 Bad Request", "WebSocket upgrade required")
            return
        if headers.get("sec-websocket-version") != "13":
            await http_reject("426 Upgrade Required", "WebSocket version 13 required",
                              "Sec-WebSocket-Version: 13\r\n")
            return
        key = headers.get("sec-websocket-key", "")
        if not _valid_websocket_key(key):
            await http_reject("400 Bad Request", "invalid Sec-WebSocket-Key")
            return

        existing = SESSIONS.get(sid)
        if existing and existing.get("closing"):
            existing = None
        if existing is not None:
            # A username is not a session credential. Shared/admin accounts that
            # authenticate with a new token must never inherit the old PTY.
            if existing.get("token") != token or existing.get("user") != user:
                audit("DENY ip=%s user=%s sid=%s (session owner mismatch)" %
                      (peer_ip, user, sid[:8]))
                await http_reject("403 Forbidden", "Console session belongs to another login")
                return
            if str(existing.get("target", "")).casefold() != target.casefold():
                audit("DENY ip=%s user=%s sid=%s (session target mismatch)" %
                      (peer_ip, user, sid[:8]))
                await http_reject("409 Conflict", "Console session target does not match")
                return
        else:
            if kill_only:
                # Teardown-only attach for a session that no longer exists.
                # There is nothing to kill, so never spawn a new SSH login
                # just to deliver the queued {t:'end'}.
                audit("KILL-NOOP ip=%s user=%s target=%s sid=%s (no such session)" %
                      (peer_ip, user, log_target, sid[:8]))
                await http_reject("410 Gone", "no such session")
                return
            label, argv = resolve_target(target)
            if not argv:
                audit("DENY ip=%s user=%s target=%s (unknown target)" % (peer_ip, user, log_target))
                await http_reject("404 Not Found", "Unknown target")
                return
            limit_status = _session_limit_status(token)
            if limit_status:
                audit("DENY ip=%s user=%s target=%s (session limit)" % (peer_ip, user, log_target))
                await http_reject(*limit_status)
                return

        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        writer.write(("HTTP/1.1 101 Switching Protocols\r\n"
                      "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                      "Sec-WebSocket-Accept: %s\r\n\r\n" % accept).encode())
        upgraded = True

        if existing is not None:
            # ---- REATTACH ----
            sess = existing
            old_writer = sess.get("writer")
            _cancel_pty_write_waiter(sess)
            attachment_id = sess.get("attachment_id", 0) + 1
            sess["attachment_id"] = attachment_id
            sess["writer"] = writer
            sess["attached"] = True
            sess["last_activity"] = time.time()
            if old_writer is not None and old_writer is not writer:
                _close_writer(old_writer, 1000, "replaced by newer attachment")
            if sess["buffer"]:
                _send_session_frame(sess, 0x2, bytes(sess["buffer"]), attachment_id)
            _send_session_frame(
                sess, 0x1, b"\r\n\x1b[90m\xe2\x80\xa2 reattached\x1b[0m\r\n", attachment_id
            )
            audit("REATTACH ip=%s user=%s target=%s sid=%s" % (peer_ip, user, sess["label"], sid[:8]))
        else:
            # ---- NEW SESSION ----
            master, slave = os.openpty()
            try:
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
            except Exception:
                try:
                    os.close(master)
                except OSError:
                    pass
                raise
            finally:
                try:
                    os.close(slave)
                except OSError:
                    pass
            now = time.time()
            attachment_id = 1
            sess = {"sid": sid, "user": user, "token": token, "target": target,
                    "label": label, "proc": proc, "master": master,
                    "buffer": bytearray(), "writer": writer, "attached": True,
                    "attachment_id": attachment_id, "last_activity": now,
                    "started": now, "closing": False}
            SESSIONS[sid] = sess
            try:
                loop.add_reader(master, _make_feed(sess))
                sess["watchdog_task"] = loop.create_task(_watchdog(sess))
            except Exception:
                _close_session(
                    sess, notify=True, code=1011, reason="session setup failed"
                )
                raise
            audit("START ip=%s user=%s target=%s pid=%s sid=%s" % (peer_ip, user, label, proc.pid, sid[:8]))
            _send_session_frame(
                sess, 0x1, ("\x1b[90m• connecting to %s …\x1b[0m\r\n" % label).encode(),
                attachment_id,
            )

        await writer.drain()

        # ---- per-connection input loop ----
        ws_state = {}
        try:
            while _attachment_current(sess, writer, attachment_id):
                opcode, payload = await ws_read(reader, ws_state)
                # A newer connection may have replaced this attachment while its
                # old input loop was awaiting a frame.
                if not _attachment_current(sess, writer, attachment_id):
                    break
                if opcode == 0x8:
                    code, reason = _close_details(payload)
                    _send_session_frame(sess, 0x8, _close_payload(code, reason), attachment_id)
                    break
                if opcode == 0x9:
                    if not _send_session_frame(sess, 0xA, payload, attachment_id):
                        break
                    continue
                if opcode == 0xA:
                    continue
                if opcode != 0x1:
                    raise WSProtocolError(1003, "only text JSON messages are supported")
                try:
                    msg = json.loads(payload.decode("utf-8"))
                except UnicodeDecodeError as exc:
                    raise WSProtocolError(1007, "invalid UTF-8 message") from exc
                except json.JSONDecodeError as exc:
                    raise WSProtocolError(1007, "invalid JSON message") from exc
                if not isinstance(msg, dict):
                    raise WSProtocolError(1007, "JSON message must be an object")
                t = msg.get("t")
                if t == "i":
                    value = msg.get("d")
                    if not isinstance(value, str):
                        raise WSProtocolError(1007, "input must be a string")
                    encoded = value.encode("utf-8")
                    if len(encoded) > MAX_PTY_INPUT:
                        raise WSProtocolError(1009, "terminal input too large")
                    if not await _write_pty(sess, encoded, attachment_id):
                        break
                    sess["last_activity"] = time.time()
                elif t == "r":
                    rows, cols = msg.get("r"), msg.get("c")
                    if (not isinstance(rows, int) or isinstance(rows, bool) or
                            not isinstance(cols, int) or isinstance(cols, bool) or
                            not 1 <= rows <= 4096 or not 1 <= cols <= 4096):
                        raise WSProtocolError(1008, "invalid terminal dimensions")
                    _set_winsize(sess["master"], rows, cols)
                    sess["last_activity"] = time.time()
                elif t == "end":
                    explicit_end = True
                    break
                else:
                    raise WSProtocolError(1008, "unsupported Console message")
        except WSProtocolError as exc:
            _send_session_frame(sess, 0x8, _close_payload(exc.code, exc.reason), attachment_id)

        # ---- detach (keep PTY alive) or explicit kill ----
        if explicit_end:
            _close_session(sess, notify=False, reason="client ended session")

    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as exc:
        audit("ERROR ip=%s: %r" % (peer_ip, exc))
        if upgraded:
            if sess is not None and attachment_id is not None:
                if not _send_session_frame(
                        sess, 0x8, _close_payload(1011, "internal Console error"), attachment_id):
                    _close_writer(writer, 1011, "internal Console error")
            else:
                _close_writer(writer, 1011, "internal Console error")
        else:
            try:
                await http_reject("500 Internal Server Error", "Console connection failed")
            except Exception:
                pass
    finally:
        if sess is not None and attachment_id is not None:
            _detach_attachment(sess, writer, attachment_id)
        try:
            writer.close()
        except Exception:
            pass
        try:
            await asyncio.wait_for(writer.wait_closed(), 1)
        except (AttributeError, asyncio.TimeoutError, ConnectionError, RuntimeError, OSError):
            pass


async def _shutdown_sessions():
    """Stop handlers, close every PTY, and boundedly drain process cleanup."""
    global SHUTTING_DOWN
    SHUTTING_DOWN = True
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, SHUTDOWN_TIMEOUT)
    current = asyncio.current_task()

    # A closed listening socket does not cancel already accepted client handlers.
    # Cancel them first so none can register a PTY after the session snapshot.
    connections = {
        task for task in CONNECTION_TASKS
        if task is not current and not task.done()
    }
    for task in connections:
        task.cancel()
    if connections:
        connection_timeout = min(2.0, max(0.0, deadline - loop.time()))
        _done, pending_connections = await asyncio.wait(
            connections, timeout=connection_timeout
        )
        for task in pending_connections:
            task.cancel()
        if pending_connections:
            audit("WARN shutdown has %d pending Console connection(s)" %
                  len(pending_connections))

    sessions = list(SESSIONS.values())
    for sess in sessions:
        _close_session(sess, code=1001, reason="Console service stopping")

    # Cancelled watchdog sleeps should be consumed promptly; never spend the process
    # cleanup budget waiting for their normal 15-second interval.
    watchdogs = {
        sess.get("watchdog_task") for sess in sessions
        if sess.get("watchdog_task") is not None
        and sess.get("watchdog_task") is not current
        and not sess.get("watchdog_task").done()
    }
    if watchdogs:
        await asyncio.wait(watchdogs, timeout=min(0.25, max(0.0, deadline - loop.time())))

    cleanup = {task for task in CLEANUP_TASKS if not task.done()}
    pending_cleanup = set()
    if cleanup:
        _done, pending_cleanup = await asyncio.wait(
            cleanup, timeout=max(0.0, deadline - loop.time())
        )
    if pending_cleanup:
        audit("WARN forcing %d Console process cleanup task(s) at shutdown" %
              len(pending_cleanup))
        for task in pending_cleanup:
            proc = CLEANUP_PROCS.get(task)
            if proc is not None:
                _signal_process_group(proc, signal.SIGKILL)
                try:
                    proc.poll()
                except Exception:
                    pass
            task.cancel()
        # Give cancellation one bounded event-loop turn; process groups have already
        # received SIGKILL even if a pathological task does not finish.
        await asyncio.wait(pending_cleanup, timeout=0.1)


async def main():
    loop = asyncio.get_running_loop()
    main_task = asyncio.current_task()
    stopping = False
    term_handler_installed = False

    def request_stop():
        nonlocal stopping
        if not stopping:
            stopping = True
            main_task.cancel()

    try:
        try:
            loop.add_signal_handler(signal.SIGTERM, request_stop)
            term_handler_installed = True
        except (NotImplementedError, RuntimeError, ValueError):
            pass
        server = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT)
        audit("LISTEN %s:%d as %s (idle=%ss, persist via reattach)" %
              (LISTEN_HOST, LISTEN_PORT, _current_user(), IDLE_TIMEOUT))
        try:
            async with server:
                await server.serve_forever()
        except asyncio.CancelledError:
            if not stopping:
                raise
    finally:
        await _shutdown_sessions()
        if term_handler_installed:
            try:
                loop.remove_signal_handler(signal.SIGTERM)
            except (NotImplementedError, RuntimeError, ValueError):
                pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
