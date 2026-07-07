#!/usr/bin/env python3
"""Strict command policy for Ask-AI live device diagnostics.

The regular Device Details command runner supports interactive workflows and has
its own broader policy. Ask-AI is exposed to model-generated text, so it gets a
separate fail-closed policy: one diagnostic command, no shell composition, no
redirection, no arbitrary file reads, and no write-capable subcommands.
"""

from __future__ import annotations

import re
import shlex
from typing import List, Tuple


_MAX_COMMAND_CHARS = 512
_SHELL_CONTROL_RE = re.compile(r"[;&|<>`$(){}\[\]\\\r\n\x00]")
_SAFE_ARG_RE = re.compile(r"^[A-Za-z0-9_.:/,@%+= -]{1,220}$")
_SAFE_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")


def _result(ok: bool, reason: str = "") -> Tuple[bool, str]:
    return ok, reason


def _safe_args(tokens: List[str]) -> bool:
    return bool(tokens) and all(_SAFE_ARG_RE.fullmatch(token or "") for token in tokens)


def _strip_sudo(tokens: List[str]) -> Tuple[bool, List[str]]:
    if tokens and tokens[0] == "sudo":
        return True, tokens[1:]
    return False, tokens


def _allow_nv(tokens: List[str]) -> bool:
    if len(tokens) < 2 or tokens[0] != "nv" or not _safe_args(tokens):
        return False
    if tokens[1] == "show":
        return True
    return len(tokens) >= 3 and tokens[1] == "config" and tokens[2] in {
        "show", "diff", "find",
    }


def _allow_vtysh(tokens: List[str]) -> bool:
    _sudo, tokens = _strip_sudo(tokens)
    if len(tokens) != 3 or tokens[:2] != ["vtysh", "-c"]:
        return False
    command = tokens[2].strip()
    if not command.lower().startswith("show "):
        return False
    return _SAFE_ARG_RE.fullmatch(command) is not None


def _allow_ethtool(tokens: List[str]) -> bool:
    _sudo, tokens = _strip_sudo(tokens)
    if not tokens:
        return False
    if tokens[0] in {"/sbin/ethtool", "ethtool"}:
        tokens = tokens[1:]
    else:
        return False
    if len(tokens) == 1:
        return _SAFE_INTERFACE_RE.fullmatch(tokens[0]) is not None
    return (
        len(tokens) == 2
        and tokens[0] in {"-m", "-S", "-i"}
        and _SAFE_INTERFACE_RE.fullmatch(tokens[1]) is not None
    )


def _allow_ip(tokens: List[str]) -> bool:
    if len(tokens) < 2 or tokens[0] != "ip" or not _safe_args(tokens):
        return False
    family = tokens[1]
    if family not in {"link", "addr", "route", "neigh"}:
        return False
    if len(tokens) == 2:
        return True
    action = tokens[2]
    if family == "route":
        return action in {"show", "list", "get"}
    return action in {"show", "list"}


def _allow_bridge(tokens: List[str]) -> bool:
    if not tokens or tokens[0] not in {"bridge", "/sbin/bridge"}:
        return False
    if len(tokens) < 2 or tokens[1] not in {"fdb", "vlan"}:
        return False
    return _safe_args(tokens) and (len(tokens) == 2 or tokens[2] in {"show", "list"})


def _allow_lldpctl(tokens: List[str]) -> bool:
    _sudo, tokens = _strip_sudo(tokens)
    if not tokens or tokens[0] != "lldpctl":
        return False
    rest = tokens[1:]
    if not rest:
        return True
    if rest[:2] in (["-f", "json"], ["-f", "keyvalue"]):
        rest = rest[2:]
    return len(rest) <= 1 and (not rest or _SAFE_INTERFACE_RE.fullmatch(rest[0]) is not None)


def _allow_journalctl(tokens: List[str]) -> bool:
    _sudo, tokens = _strip_sudo(tokens)
    if not tokens or tokens[0] != "journalctl":
        return False
    flags = {
        "-k", "--dmesg", "--no-pager", "--utc", "--reverse", "--quiet",
        "--merge", "-b", "--boot", "-x", "--catalog", "--all",
    }
    value_options = {
        "-n", "--lines", "-u", "--unit", "-p", "--priority", "-o",
        "--output", "-S", "--since", "-U", "--until", "-g", "--grep",
        "-t", "--identifier",
    }
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in flags:
            index += 1
            continue
        if token in value_options:
            if index + 1 >= len(tokens) or not _SAFE_ARG_RE.fullmatch(tokens[index + 1]):
                return False
            index += 2
            continue
        if any(token.startswith(option + "=") for option in value_options if option.startswith("--")):
            if not _SAFE_ARG_RE.fullmatch(token):
                return False
            index += 1
            continue
        # journal fields such as SYSLOG_IDENTIFIER=frr are read-only filters.
        if re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}=[A-Za-z0-9_.:@%+/-]{1,128}", token):
            index += 1
            continue
        return False
    return True


def _allow_dmesg(tokens: List[str]) -> bool:
    _sudo, tokens = _strip_sudo(tokens)
    if not tokens or tokens[0] != "dmesg":
        return False
    safe_flags = {
        "-T", "--ctime", "--reltime", "--notime", "-x", "--decode",
        "--nopager", "-H", "--human", "-w", "--follow",
    }
    for token in tokens[1:]:
        if token in {"-c", "-C", "--clear", "--read-clear"}:
            return False
        if token in safe_flags:
            continue
        if token.startswith(("--level=", "--facility=", "--color=")) and _SAFE_ARG_RE.fullmatch(token):
            continue
        return False
    return True


def _allow_system_read(tokens: List[str]) -> bool:
    _sudo, stripped = _strip_sudo(tokens)
    if not stripped:
        return False
    if stripped == ["uptime"]:
        return True
    if stripped[0] == "free":
        return all(token in {"-b", "-k", "-m", "-g", "-h", "--si", "-t", "-w", "--wide"}
                   for token in stripped[1:])
    if stripped[0] == "df":
        return all(token in {"-h", "-H", "-i", "-T", "--total", "/"}
                   for token in stripped[1:])
    if stripped[0] in {"sensors", "smonctl", "decode-syseeprom", "cl-resource-query"}:
        return len(stripped) == 1
    return False


def validate_ai_readonly_command(command: str) -> Tuple[bool, str]:
    """Return whether one model-generated command is an allowed diagnostic."""
    if not isinstance(command, str):
        return _result(False, "command must be text")
    command = command.strip()
    if not command:
        return _result(False, "empty command")
    if len(command) > _MAX_COMMAND_CHARS:
        return _result(False, "command is too long")
    if _SHELL_CONTROL_RE.search(command):
        return _result(False, "shell composition and redirection are not allowed")
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return _result(False, "invalid quoting")
    if not tokens:
        return _result(False, "empty command")

    _sudo, bare = _strip_sudo(tokens)
    if not bare:
        return _result(False, "missing program")

    allowed = False
    if bare[0] == "nv" and not _sudo:
        allowed = _allow_nv(bare)
    elif bare[0] == "vtysh":
        allowed = _allow_vtysh(tokens)
    elif bare[0] in {"ethtool", "/sbin/ethtool"}:
        allowed = _allow_ethtool(tokens)
    elif bare[0] == "ip" and not _sudo:
        allowed = _allow_ip(bare)
    elif bare[0] in {"bridge", "/sbin/bridge"} and not _sudo:
        allowed = _allow_bridge(bare)
    elif bare[0] == "lldpctl":
        allowed = _allow_lldpctl(tokens)
    elif bare[0] == "cat" and not _sudo:
        allowed = (
            len(bare) == 2
            and re.fullmatch(r"/proc/net/bonding/[A-Za-z0-9_.:-]{1,64}", bare[1]) is not None
        )
    elif bare[0] == "clagctl":
        allowed = len(bare) == 1 or bare == ["clagctl", "status"]
    elif bare[0] in {"nvt", "/usr/local/bin/nvt"} and not _sudo:
        allowed = len(bare) == 1
    elif bare[0] == "journalctl":
        allowed = _allow_journalctl(tokens)
    elif bare[0] == "dmesg":
        allowed = _allow_dmesg(tokens)
    else:
        allowed = _allow_system_read(tokens)

    if not allowed:
        return _result(False, "command is not in the Ask-AI read-only policy")
    return _result(True)


__all__ = ["validate_ai_readonly_command"]
