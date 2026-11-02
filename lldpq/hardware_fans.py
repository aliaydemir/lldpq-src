"""Current fan presence, state and speed evidence shared by reports and alerts."""
import re
import statistics
from pathlib import Path

try:
    from .hardware_environment import START, END, SOURCE, ROW, BAD_STATES, ABSENT_STATES, parse_platform_environment
except ImportError:
    from hardware_environment import START, END, SOURCE, ROW, BAD_STATES, ABSENT_STATES, parse_platform_environment

GRADE_PRIORITY = {"CRITICAL": 4, "WARNING": 3, "GOOD": 2, "EXCELLENT": 1}
FAN_START = "__LLDPQ_PLATFORM_FANS_START__"
FAN_END = "__LLDPQ_PLATFORM_FANS_END__"
FAN_SOURCE = "__LLDPQ_HARDWARE_SOURCE_STATUS__:PLATFORM_FANS:"

# Absolute fan RPM thresholds cannot be trusted across platforms: chassis fans
# idle far below PSU fans and both swing with inlet temperature, so a single
# fleet-wide band both false-flags a cool chassis fan as CRITICAL and always
# grades a fast PSU fan EXCELLENT even as it slows. Grade each fan against the
# median of its own cohort (same fan type, same device); a fan that lags its
# peers - or has stopped while peers spin - is the reliable fault signal. Values
# are CRITICAL/WARNING/GOOD ratio boundaries relative to that cohort baseline.
FAN_COHORT_RATIO_THRESHOLDS = (0.5, 0.7, 0.85)


def _classify_fan(name):
    """Return a coarse cohort key ('psu' or 'system') for a fan by its label."""
    return "psu" if "psu" in str(name).lower() else "system"


def grade_fans_relative(fans):
    """Grade fans by deviation from their own cohort baseline.

    Returns ``(overall_grade, per_fan_details)`` where ``per_fan_details`` is a
    list of dicts (name/rpm/type/grade/baseline/ratio) that feeds the expandable
    detail panel. ``overall_grade`` is the worst per-fan grade, or ``None`` when
    no fan can be graded (the caller treats that as missing telemetry).
    """
    numeric_fans = []
    for name, rpm in (fans or {}).items():
        if isinstance(rpm, bool) or not isinstance(rpm, (int, float)):
            continue
        if rpm != rpm or abs(rpm) == float("inf"):
            continue
        numeric_fans.append((str(name), float(rpm)))

    cohorts = {}
    for name, rpm in numeric_fans:
        if rpm > 0:
            cohorts.setdefault(_classify_fan(name), []).append(rpm)
    baselines = {
        cohort: statistics.median(values)
        for cohort, values in cohorts.items() if values
    }
    critical_ratio, warning_ratio, good_ratio = FAN_COHORT_RATIO_THRESHOLDS
    details = []
    grades = []
    for name, rpm in numeric_fans:
        cohort = _classify_fan(name)
        baseline = baselines.get(cohort)
        ratio = None
        if rpm <= 0:
            # An empty slot is not reported as a fan at all, so a fan that is
            # reported and reads zero has stopped. Treating an all-zero set as
            # missing telemetry filed a switch whose entire fan tray had
            # failed under "Unknown", alongside boxes that merely lack
            # lm-sensors, and kept it out of the Critical count.
            grade = "CRITICAL"
        elif baseline and baseline > 0:
            ratio = rpm / baseline
            if ratio < critical_ratio:
                grade = "CRITICAL"
            elif ratio < warning_ratio:
                grade = "WARNING"
            elif ratio < good_ratio:
                grade = "GOOD"
            else:
                grade = "EXCELLENT"
        else:
            grade = None
        details.append({
            "name": name,
            "rpm": int(rpm) if float(rpm).is_integer() else round(rpm, 1),
            "type": cohort,
            "grade": grade,
            "baseline": (
                int(baseline) if baseline and float(baseline).is_integer()
                else (round(baseline, 1) if baseline else None)
            ),
            "ratio": round(ratio, 2) if ratio is not None else None,
        })
        if grade:
            grades.append(grade)

    overall = (
        max(grades, key=lambda g: GRADE_PRIORITY.get(g, 0)) if grades else None
    )
    return overall, details


def _section(content, start, end, source):
    if start not in content:
        return "", False, False
    block = content.split(start, 1)[1]
    closed = end in block
    block = block.split(end, 1)[0]
    statuses = re.findall(r"^" + re.escape(source) + r"(\S+)\s*$", block, re.M)
    return block, closed and statuses == ["OK"], True


def _sensor_identity(name):
    """Map only unambiguous sensor labels; never infer a fan from RPM/order."""
    match = re.fullmatch(r"Chassis Fan Drawer-(\d+)(?: Tach (\d+))?", name, re.I)
    if match:
        return f"FAN{match[1]}/{match[2] or '1'}"
    match = re.fullmatch(r"PSU-?(\d+)(?:\([LR]\)|[LR])?\s*Fan\s*1", name, re.I)
    return f"PSU{match[1]}/FAN" if match else name


def _number(value):
    return int(value) if re.fullmatch(r"\d+", value) else None


def evaluate_fan_health(content, thresholds=None):
    """Use current NVUE presence/state before RPM; never use historical fans.

The detailed table supplies speed and platform limits. The parent environment
table is a state fallback. Any explicit failure wins over a conflicting OK or
cached lm-sensors RPM. Legacy files can still use current sensor readings.
"""
    general, general_ok, general_present = _section(content, START, END, SOURCE)
    detailed, detailed_ok, detailed_present = _section(content, FAN_START, FAN_END, FAN_SOURCE)
    rows = {}
    malformed = False
    for line in general.splitlines():
        match = ROW.match(line)
        if match and match[2].lower() == 'fan':
            name, _, detail = match.groups()
            if name in rows:
                malformed = True
            rows.setdefault(name, {'name': name, 'states': [], 'source': 'NVUE'})['states'].append(detail.split()[0].lower())
        elif re.match(r'^\s*\S+\s+fan\s*$', line, re.I):
            malformed = True
    general_names = set(rows)
    detailed_names = set()
    for line in detailed.splitlines():
        parts = line.split()
        if not parts or parts[0] == 'Name' or parts[0].startswith(('---', '__')):
            continue
        if len(parts) != 6:
            malformed = True
            if len(parts) < 2:
                continue
            # Preserve an explicit absent/bad state even when the command
            # stopped before it printed the speed columns.
            parts = (parts + ['N/A'] * 6)[:6]
        name, state, rpm, maximum, minimum, direction = parts
        if name in detailed_names:
            malformed = True
        detailed_names.add(name)
        row = rows.setdefault(name, {'name': name, 'states': [], 'source': 'NVUE'})
        row['states'].append(state.lower())
        row.update(rpm=_number(rpm), min_rpm=_number(minimum), max_rpm=_number(maximum), direction=direction)

    # Explicitly optional, absent PSU slots do not have fans to monitor.
    power = parse_platform_environment(content)
    optional_psus = {p['name'].upper() for p in power['psus'] if power['complete'] and p['state'] in ABSENT_STATES}
    sensor_rpms = {}
    counts = {}
    for name, rpm in re.findall(r'^([^\n:]*fan[^\n:]*):[ \t]*(\d+)[ \t]*RPM\b', content, re.I | re.M):
        name = name.strip()
        counts[name] = counts.get(name, 0) + 1
        if counts[name] > 1:
            name += f"#{counts[name]}"
        sensor_rpms[name] = int(rpm)
    # NVUE inventory replaces the differently named sensor inventory. Known
    # aliases only provide RPM when the detailed NVUE table is absent.
    if rows:
        aliases = {_sensor_identity(name): rpm for name, rpm in sensor_rpms.items()}
        for name, row in rows.items():
            if not detailed_present:
                row['rpm'] = aliases.get(name)
    else:
        rows = {name: {'name': name, 'states': [], 'rpm': rpm, 'source': 'lm-sensors'}
                for name, rpm in sensor_rpms.items()}

    has_states = bool(general_names or detailed_names)
    virt = re.search(r'^PLATFORM_VIRT:\s*(\S+)', content, re.M)
    virtual = bool(virt and virt[1].lower() not in ('none', 'unknown'))
    if detailed_present:
        complete = detailed_ok and bool(detailed_names) and general_names.issubset(detailed_names)
    elif has_states:
        complete = general_ok
    else:
        complete = bool(rows) and (virtual or not (general_present or detailed_present))
    if virtual and not has_states:
        complete = bool(rows)
    if has_states and general_names and not general_ok:
        complete = False
    if not has_states and re.search(r'^__LLDPQ_HARDWARE_SOURCE_STATUS__:SENSORS:(?:ERROR|UNAVAILABLE)', content, re.M):
        complete = False
    complete = complete and not malformed
    for row in rows.values():
        states = row.pop('states')
        known_states = {'ok', 'warn', 'warning'} | BAD_STATES | ABSENT_STATES
        if any(state not in known_states for state in states) or len(set(states)) > 1:
            complete = False
        row['state'] = next((s for s in states if s in BAD_STATES | ABSENT_STATES),
                            next((s for s in states if s != 'ok'), 'ok' if states else 'not reported'))
        row['optional'] = row['state'] in ABSENT_STATES and row['name'].split('/')[0].upper() in optional_psus
        if row['state'] in BAD_STATES | ABSENT_STATES:
            row['rpm'] = None  # Do not show a phantom positive RPM for an absent fan.
        if row['name'] in detailed_names and row['state'] == 'ok' and row.get('rpm') is None:
            complete = False

    _, speeds = grade_fans_relative({name: row.get('rpm') for name, row in rows.items()})
    speeds = {row['name']: row for row in speeds}
    issues = []
    grades = []
    for name, row in rows.items():
        detail = speeds.get(name, {'type': _classify_fan(name), 'rpm': None, 'grade': None, 'baseline': None, 'ratio': None})
        row.update(detail)
        grade = row['grade']
        reason = f"{name}: {row['state']}"
        state = row['state']
        if row['optional']:
            grade = None
        elif state in BAD_STATES | ABSENT_STATES:
            grade = 'CRITICAL'
        elif state in ('warn', 'warning') and grade != 'CRITICAL':
            grade = 'WARNING'
        elif state not in ('ok', 'not reported') and grade not in ('WARNING', 'CRITICAL'):
            grade = None
        elif state == 'ok' and grade is None and (name not in detailed_names):
            grade = 'EXCELLENT'
        rpm = row.get('rpm')
        if rpm is not None and not row['optional']:
            minimum, maximum = row.get('min_rpm'), row.get('max_rpm')
            if (minimum is not None and rpm < minimum) or (maximum is not None and rpm > maximum):
                grade = 'CRITICAL'
            if thresholds is not None and minimum is None:
                # Configured RPM bands are the fallback for sensors without
                # platform limits; NVUE's model-specific minimum takes priority.
                if rpm < thresholds.get('fan_rpm_critical', 3000):
                    grade = 'CRITICAL'
                elif rpm < thresholds.get('fan_rpm_warning', 4000) and grade != 'CRITICAL':
                    grade = 'WARNING'
            reason = f"{name}: {rpm} RPM (state: {state})"
        row['grade'] = grade
        if grade:
            grades.append(grade)
        if grade in ('WARNING', 'CRITICAL'):
            issues.append({'kind': 'fan', 'name': name, 'severity': grade, 'message': reason})
    grade = max(grades, key=GRADE_PRIORITY.get) if grades else None
    if not complete and grade not in ('WARNING', 'CRITICAL'):
        grade = None
    summary = '; '.join(i['message'] for i in issues) if issues else ('Fans OK' if grade else 'Fan status incomplete or unavailable')
    return {'fans': list(rows.values()), 'issues': issues, 'grade': grade, 'complete': complete,
            'summary': summary, 'collection_status': 'current' if complete else 'partial' if rows else 'unavailable'}


def read_fan_health(path):
    try:
        return evaluate_fan_health(Path(path).read_text(encoding='utf-8', errors='replace'))
    except OSError:
        return evaluate_fan_health('')

