"""Shared NVUE power-state evidence for the hardware report and alerts.

PSU efficiency describes the supplies that still deliver power. It cannot
establish whether other supplies failed or the redundancy policy is satisfied.
"""
import re
from pathlib import Path

START = "__LLDPQ_PLATFORM_ENVIRONMENT_START__"
END = "__LLDPQ_PLATFORM_ENVIRONMENT_END__"
SOURCE = "__LLDPQ_HARDWARE_SOURCE_STATUS__:PLATFORM_ENVIRONMENT:"
BAD_STATES = {"bad", "failed", "failure", "fault", "critical", "error"}
ABSENT_STATES = {"absent", "not-present", "not_present"}
ROW = re.compile(r"^\s*(\S+)\s+(psu|ps_r_policy|led|fan|temperature|voltage)\s+(.+?)\s*$", re.I)


def parse_platform_environment(content):
    """Parse only the bounded current sample; unknown data never means OK.

Explicit failures still count when a command returns partial output. A healthy
verdict needs a complete section, successful command and recognized PSU states.
Empty optional slots are allowed only with an affirmative redundancy verdict.
"""
    result = {"psus": [], "redundancy": [], "leds": [], "issues": [],
              "grade": None, "complete": False, "collection_status": "unavailable",
              "summary": "PSU status unavailable"}
    if START not in content:
        return result
    block = content.split(START, 1)[1]
    closed = END in block
    block = block.split(END, 1)[0]
    source_states = re.findall(r"^" + re.escape(SOURCE) + r"(\S+)\s*$", block, re.M)
    source_ok = source_states == ["OK"]
    policy = None
    malformed = False
    for line in block.splitlines():
        match = ROW.match(line)
        if not match:
            if re.match(r"^\s*\S+\s+(psu|ps_r_policy)\s*$", line, re.I):
                malformed = True
            # NVUE may wrap the long redundancy explanation after "PSU".
            if policy is not None and line.strip() and not line.startswith("__"):
                policy["detail"] += " " + line.strip()
            continue
        name, kind, detail = match.groups()
        kind = kind.lower()
        policy = None
        state = detail.split()[0].lower().rstrip(":") if detail.strip() else "unknown"
        row = {"name": name, "state": state,
               "detail": detail}
        if kind == "psu":
            result["psus"].append(row)
        elif kind == "ps_r_policy":
            result["redundancy"].append(row)
            policy = row
        elif kind == "led" and name.upper() in {"POWER", "SYSTEM"}:
            result["leds"].append(row)

    issues = result["issues"]
    def issue(kind, row, severity, message):
        issues.append({"kind": kind, "name": row["name"],
                       "severity": severity, "message": message})

    policies_ok = bool(result["redundancy"])
    known = not malformed
    for row in result["redundancy"]:
        good = re.search(r"Good PSUs\s*-\s*(\d+)", row["detail"], re.I)
        required = re.search(r"Required PSUs\s*-\s*(\d+)", row["detail"], re.I)
        row["good_psus"] = int(good[1]) if good else None
        row["required_psus"] = int(required[1]) if required else None
        counts_present = good is not None and required is not None
        shortage = counts_present and row["good_psus"] < row["required_psus"]
        suffix = (f" ({row['good_psus']} good / {row['required_psus']} required)"
                  if counts_present else "")
        if row["state"] in BAD_STATES or shortage:
            issue("redundancy", row, "CRITICAL", f"{row['name']}: {row['state']}" + suffix)
        elif row["state"] in {"warning", "warn"}:
            issue("redundancy", row, "WARNING", f"{row['name']}: {row['detail']}")
        elif row["state"] != "ok":
            known = False
        if re.search(r"(?:Good|Required) PSUs", row["detail"], re.I) and not counts_present:
            known = False  # A truncated explanation cannot confirm recovery.
            policies_ok = False
        policies_ok = policies_ok and row["state"] == "ok" and not shortage

    for row in result["psus"]:
        state = row["state"]
        if state in BAD_STATES:
            issue("psu", row, "CRITICAL", f"{row['name']}: {state}")
        elif state in {"warning", "warn"}:
            issue("psu", row, "WARNING", f"{row['name']}: {row['detail']}")
        elif state != "ok" and not (state in ABSENT_STATES and policies_ok):
            known = False

    for row in result["leds"]:
        state = row["state"]
        if state == "red" or state in BAD_STATES:
            issue("led", row, "CRITICAL", f"{row['name']} LED: {state}")
        elif state in {"amber", "yellow", "warning", "warn"}:
            issue("led", row, "WARNING", f"{row['name']} LED: {state}")
        elif state not in {"green", "ok"}:
            known = False

    for rows in (result["psus"], result["redundancy"], result["leds"]):
        if len({row["name"] for row in rows}) != len(rows):
            known = False
    result["complete"] = closed and source_ok and bool(result["psus"]) and known
    if issues:
        result["grade"] = "CRITICAL" if any(i["severity"] == "CRITICAL" for i in issues) else "WARNING"
        result["summary"] = "; ".join(i["message"] for i in issues)
    elif result["complete"]:
        result["grade"] = "EXCELLENT"
        result["summary"] = "PSU status OK" + ("; redundancy OK" if policies_ok else "")
    if result["complete"]:
        result["collection_status"] = "current"
    elif result["psus"] or result["redundancy"] or result["leds"]:
        result["collection_status"] = "partial"
        if not issues:
            result["summary"] = "PSU status incomplete or unrecognized"
    return result


def read_platform_environment(path):
    try:
        return parse_platform_environment(Path(path).read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return parse_platform_environment("")
