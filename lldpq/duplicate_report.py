#!/usr/bin/env python3
"""Semantic HTML/CSV renderer for :mod:`duplicate_analyzer`.

The analyzer deliberately keeps collection and classification separate from
presentation.  This renderer never turns mobility, historical evidence, or
replicated IPv4 link-local observations into a confirmed duplicate count.
"""

import html
import ipaddress
import json
import os
import tempfile
from datetime import datetime, timezone


ACTIVITY_ORDER = {"active": 0, "settled": 1, "historical": 2}


def _esc(value):
    return html.escape(str(value), quote=True)


def _sorted_numbers(values):
    return sorted((str(value) for value in values), key=lambda value: (
        0, int(value)
    ) if value.isdigit() else (1, value))


def _plain_join(values, separator=", "):
    return separator.join(str(value) for value in values if str(value))


def _html_join(values, separator="<br>"):
    rendered = [_esc(value) for value in values if str(value)]
    return separator.join(rendered) or "&mdash;"


def _ip_sort_key(value):
    try:
        address = ipaddress.ip_address(value)
        return "%d:%0*d" % (address.version, 39, int(address))
    except ValueError:
        return "9:" + str(value).lower()


def _scope_sort_key(scope):
    kind, _, value = str(scope).partition(":")
    rank = {"vni": 0, "vlan": 1, "interface": 2}.get(kind, 9)
    numeric = int(value) if value.isdigit() else 10**12
    return "%d:%012d:%s" % (rank, numeric, value.lower())


def _format_utc(value):
    if not value:
        return ""
    if isinstance(value, (int, float)):
        value = datetime.fromtimestamp(value, timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _ago(seconds):
    if seconds is None:
        return "Unknown"
    seconds = max(0, int(seconds))
    if seconds < 90:
        return "%ds ago" % seconds
    if seconds < 5400:
        return "%dm ago" % (seconds // 60)
    if seconds < 172800:
        return "%dh ago" % (seconds // 3600)
    return "%dd ago" % (seconds // 86400)


def _activity_badge(activity):
    css = {
        "active": "badge-red",
        "settled": "badge-orange",
        "historical": "badge-gray",
        "observed": "badge-blue",
    }.get(activity, "badge-gray")
    return '<span class="badge %s">%s</span>' % (css, _esc(activity or "unknown"))


def _confidence(record):
    incident = record.get("incident_type", "unknown")
    if record.get("confirmed_conflict"):
        return "Confirmed"
    if incident.startswith("dad_flagged"):
        return "FRR flagged"
    if incident.startswith("dad_event"):
        return "Observed in DAD log"
    if incident in {"ip_mobility", "mac_mobility"}:
        return "Mobility anomaly"
    if incident == "possible_loop":
        return "Suspected"
    if record.get("suspected_conflict"):
        return "Suspected"
    return "Observed"


def _scope_html(record):
    scope = record.get("scope", "unknown")
    vni = record.get("vni", "unknown")
    vlans = _sorted_numbers(record.get("vlans", set()))
    vrfs = sorted(record.get("vrfs", set()))
    parts = ['<span class="mono">%s</span>' % _esc(scope)]
    if vni != "unknown" and not scope.startswith("vni:"):
        parts.append('<span class="dim">VNI %s</span>' % _esc(vni))
    if vlans:
        parts.append('<span class="dim">VLAN %s</span>' % _esc(_plain_join(vlans)))
    if vrfs:
        parts.append('<span class="dim">VRF %s</span>' % _esc(_plain_join(vrfs)))
    return "<br>".join(parts)


def _alias_span(value, css=""):
    value = str(value)
    return (
        '<span%s data-p2p-key="%s" data-p2p-orig="%s" '
        'data-csv-value="%s">%s</span>'
        % (
            (' class="%s"' % _esc(css)) if css else "",
            _esc(value), _esc(value), _esc(value), _esc(value),
        )
    )


def _port_html(analyzer, host, port, historical=False):
    canonical = "%s:%s" % (host, port)
    css = "location historical" if historical else "location"
    value = (
        '<span class="%s" data-csv-value="%s">%s:<span class="port">%s</span></span>'
        % (
            css,
            _esc(canonical),
            _alias_span(host, "device"),
            _alias_span(port, "interface"),
        )
    )
    description = analyzer.if_desc.get((host, port))
    if description:
        value += '<span class="pdesc">%s</span>' % _esc(description)
    if historical:
        value += '<span class="dim">historical evidence</span>'
    return value


def _ip_locations(analyzer, record):
    current = []
    for encoded in sorted(record.get("ports", set())):
        if ":" in encoded:
            host, port = encoded.split(":", 1)
            current.append(_port_html(analyzer, host, port))
        else:
            current.append(_alias_span(encoded, "device"))
    if not current:
        current = [_alias_span(host, "device") for host in sorted(
            record.get("local_hosts", set())
        )]
    historical = []
    for encoded in sorted(record.get("historical_ports", set())):
        if ":" in encoded:
            host, port = encoded.split(":", 1)
            historical.append(_port_html(analyzer, host, port, historical=True))
        else:
            historical.append('<span class="historical">%s</span>' % _esc(encoded))
    return current, historical


def _mac_locations(analyzer, record):
    current = []
    for host, ports in sorted(record.get("local_ports", {}).items()):
        for port in sorted(ports):
            current.append(_port_html(analyzer, host, port))
    return current, []


def _vtep_html(analyzer, record):
    values = []
    for vtep in sorted(record.get("vteps", set())):
        host = analyzer.vtep2host.get(vtep)
        if host:
            values.append('%s <span class="dim">(%s)</span>' % (
                _alias_span(host, "device"), _esc(vtep)
            ))
        else:
            values.append('<span class="mono">%s</span>' % _esc(vtep))
    return "<br>".join(values) or "&mdash;"


def _record_devices(analyzer, record):
    devices = set(record.get("local_hosts", set()))
    devices.update(record.get("local_ports", {}).keys())
    devices.update(record.get("flagged_hosts", set()))
    for encoded in record.get("ports", set()) | record.get("historical_ports", set()):
        if ":" in encoded:
            devices.add(encoded.split(":", 1)[0])
    devices.update(
        analyzer.vtep2host[vtep] for vtep in record.get("vteps", set())
        if vtep in analyzer.vtep2host
    )
    return devices


def _sequence_html(record):
    sequence = record.get("seq") or 0
    if not sequence:
        return "&mdash;"
    output = ['<span class="mono">%s</span>' % _esc("{:,}".format(sequence))]
    delta = record.get("delta")
    if delta is not None:
        css = "delta-up" if record.get("sequence_active") else "delta-neutral"
        output.append('<span class="%s">%s</span>' % (
            css, _esc("Δ +{:,}".format(delta))
        ))
    interval = record.get("seq_interval_sec")
    rate = record.get("seq_rate_per_min")
    if interval:
        detail = "over %ss" % int(interval)
        if rate is not None:
            detail += " · %.2f moves/min" % rate
        output.append('<span class="dim">%s</span>' % _esc(detail))
    threshold = record.get("seq_activity_threshold")
    if threshold:
        output.append('<span class="dim">policy threshold: %s moves/window</span>' % _esc(threshold))
    return "<br>".join(output)


def _incident_note(record):
    incident = record.get("incident_type", "unknown")
    labels = {
        "confirmed_ip_conflict": "Multiple current MAC claims for one IP",
        "dad_flagged_ip": "FRR currently flags this IP",
        "dad_event_ip": "Recent FRR duplicate-address event",
        "ip_mobility": "One endpoint moving between locations; not an IP conflict",
        "confirmed_mac_conflict": "Same MAC currently present at multiple non-MH attachment points",
        "dad_flagged_mac": "FRR currently flags this MAC",
        "dad_event_mac": "Recent FRR MAC duplicate-address event",
        "mac_mobility": "MAC mobility anomaly; not a confirmed simultaneous conflict",
        "possible_loop": "Several MACs moved across the same endpoint pair in the same scope",
    }
    note = labels.get(incident, "Correlated observation")
    if record.get("mh_possible"):
        note += "; multi-attachment may be EVPN multihoming"
    if record.get("frozen"):
        note += "; DAD freeze policy may be affecting forwarding"
    if record.get("participates_in_ip_conflict"):
        note += "; participates in a confirmed duplicate-IP incident"
    return note


def _evidence_html(record):
    sources = sorted(record.get("evidence_sources", set()))
    return " ".join('<span class="evidence">%s</span>' % _esc(source) for source in sources) or "&mdash;"


def _row_attributes(row_id, category, activity, devices, aged=False):
    return (
        'data-record-id="%s" data-category="%s" data-activity="%s" '
        'data-devices="%s" data-aged="%s"'
        % (
            _esc(row_id), _esc(category), _esc(activity),
            _esc(" ".join(sorted(devices))), "true" if aged else "false",
        )
    )


def _atomic_write(path, content):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=directory,
            prefix=".duplicate-report.", delete=False,
        ) as handle:
            temporary = handle.name
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        if temporary:
            try:
                os.unlink(temporary)
            except OSError:
                pass
        raise


def _export_record(row_id, record_type, activity, scope, vlans, address, macs,
                   current_locations, historical_locations, remote_vteps,
                   sequence, delta, interval, rate, last_event, age,
                   sampled_logs, evidence, confidence, note, **extra):
    row = {
        "record_id": row_id,
        "record_type": record_type,
        "activity": activity,
        "confidence": confidence,
        "scope": scope,
        "vlans": _plain_join(_sorted_numbers(vlans)),
        "address": address,
        "macs": _plain_join(sorted(macs)),
        "current_locations": _plain_join(current_locations, "; "),
        "historical_locations": _plain_join(historical_locations, "; "),
        "remote_vteps": _plain_join(remote_vteps, "; "),
        "evpn_sequence": sequence or "",
        "sequence_delta": "" if delta is None else delta,
        "sample_interval_seconds": "" if interval is None else int(interval),
        "moves_per_minute": "" if rate is None else round(rate, 4),
        "last_event_utc": last_event,
        "last_event_age": age,
        "sampled_dad_events": sampled_logs or 0,
        "evidence": _plain_join(sorted(evidence)),
        "note": note,
    }
    row.update(extra)
    return row


def _td(content, sort_value="", css="", extra=""):
    attributes = []
    if sort_value != "":
        attributes.append('data-sort="%s"' % _esc(sort_value))
    if css:
        attributes.append('class="%s"' % _esc(css))
    if extra:
        attributes.append(extra)
    return "<td%s>%s</td>" % ((" " + " ".join(attributes)) if attributes else "", content)


def _plain_ip_locations(record):
    current = sorted(record.get("ports", set()))
    if not current:
        current = sorted(record.get("local_hosts", set()))
    return current, sorted(record.get("historical_ports", set()))


def _plain_mac_locations(record):
    return sorted(
        "%s:%s" % (host, port)
        for host, ports in record.get("local_ports", {}).items()
        for port in ports
    ), []


def _plain_vteps(analyzer, record):
    values = []
    for vtep in sorted(record.get("vteps", set())):
        host = analyzer.vtep2host.get(vtep)
        values.append("%s (%s)" % (host, vtep) if host else vtep)
    return values


def _category(record, address_kind):
    incident = record.get("incident_type", "unknown")
    if incident == "possible_loop":
        return "loop"
    if incident in {"ip_mobility", "mac_mobility"}:
        return "mobility"
    if record.get("confirmed_conflict"):
        return "confirmed_%s" % address_kind
    if incident.startswith("dad_"):
        return "dad_%s" % address_kind
    return "suspected_%s" % address_kind


def _render_ip_row(analyzer, record, row_id, exports):
    activity = record.get("activity", "settled")
    category = _category(record, "ip")
    devices = _record_devices(analyzer, record)
    current_html, historical_html = _ip_locations(analyzer, record)
    current_plain, historical_plain = _plain_ip_locations(record)
    remote_plain = _plain_vteps(analyzer, record)
    latest_utc = _format_utc(record.get("latest"))
    age = _ago(record.get("recency")) if record.get("latest") else ""
    note = _incident_note(record)
    exports.append(_export_record(
        row_id, record.get("incident_type", "ip"), activity,
        record.get("scope", "unknown"), record.get("vlans", set()),
        record.get("ip", ""), record.get("macs", set()),
        current_plain, historical_plain, remote_plain,
        record.get("seq"), record.get("delta"), record.get("seq_interval_sec"),
        record.get("seq_rate_per_min"), latest_utc, age,
        record.get("events"), record.get("evidence_sources", set()),
        _confidence(record), note,
        historical_macs=_plain_join(sorted(record.get("historical_macs", set()))),
    ))
    macs_html = _html_join(sorted(record.get("macs", set())))
    historical_macs = sorted(record.get("historical_macs", set()))
    if historical_macs:
        macs_html += '<br><span class="dim">historical: %s</span>' % _esc(
            _plain_join(historical_macs)
        )
    last_html = "&mdash;"
    if latest_utc:
        last_html = '<time datetime="%s" title="%s">%s</time>' % (
            _esc(latest_utc), _esc(latest_utc), _esc(age)
        )
    attributes = _row_attributes(
        row_id, category, activity, devices, activity == "historical"
    )
    cells = [
        _td(_activity_badge(activity), ACTIVITY_ORDER.get(activity, 9)),
        _td('<span class="confidence">%s</span>' % _esc(_confidence(record))),
        _td(_scope_html(record), _scope_sort_key(record.get("scope", "unknown"))),
        _td(_esc(record.get("ip", "")), _ip_sort_key(record.get("ip", "")), "mono"),
        _td(macs_html, _plain_join(sorted(record.get("macs", set()))), "mono"),
        _td("<br>".join(current_html) or "&mdash;", _plain_join(current_plain), "mono", 'data-display-locations="current"'),
        _td("<br>".join(historical_html) or "&mdash;", _plain_join(historical_plain), "mono"),
        _td(_vtep_html(analyzer, record), _plain_join(remote_plain), "mono"),
        _td(_sequence_html(record), record.get("seq") or 0, "mono"),
        _td(last_html, record.get("latest").timestamp() if record.get("latest") else -1),
        _td(_esc(record.get("events") or 0), record.get("events") or 0, "mono"),
        _td(_evidence_html(record)),
        _td(_esc(note)),
    ]
    return "<tr %s>%s</tr>" % (attributes, "".join(cells))


def _render_mac_row(analyzer, record, row_id, exports):
    activity = record.get("activity", "settled")
    category = _category(record, "mac")
    devices = _record_devices(analyzer, record)
    current_html, historical_html = _mac_locations(analyzer, record)
    current_plain, historical_plain = _plain_mac_locations(record)
    remote_plain = _plain_vteps(analyzer, record)
    latest_utc = _format_utc(record.get("latest"))
    age = _ago(record.get("recency")) if record.get("latest") else ""
    note = _incident_note(record)
    exports.append(_export_record(
        row_id, record.get("incident_type", "mac"), activity,
        record.get("scope", "unknown"), record.get("vlans", set()),
        record.get("mac", ""), {record.get("mac", "")},
        current_plain, historical_plain, remote_plain,
        record.get("seq"), record.get("delta"), record.get("seq_interval_sec"),
        record.get("seq_rate_per_min"), latest_utc, age,
        record.get("events"), record.get("evidence_sources", set()),
        _confidence(record), note,
        attachment_count=record.get("attachment_count", 0),
        possible_loop_size=record.get("loop_count", 0),
    ))
    last_html = "&mdash;"
    if latest_utc:
        last_html = '<time datetime="%s" title="%s">%s</time>' % (
            _esc(latest_utc), _esc(latest_utc), _esc(age)
        )
    attributes = _row_attributes(
        row_id, category, activity, devices, activity == "historical"
    )
    cells = [
        _td(_activity_badge(activity), ACTIVITY_ORDER.get(activity, 9)),
        _td('<span class="confidence">%s</span>' % _esc(_confidence(record))),
        _td(_scope_html(record), _scope_sort_key(record.get("scope", "unknown"))),
        _td(_esc(record.get("mac", "")), record.get("mac", ""), "mono"),
        _td("<br>".join(current_html) or "&mdash;", _plain_join(current_plain), "mono", 'data-display-locations="current"'),
        _td(_vtep_html(analyzer, record), _plain_join(remote_plain), "mono"),
        _td(_sequence_html(record), record.get("seq") or 0, "mono"),
        _td(last_html, record.get("latest").timestamp() if record.get("latest") else -1),
        _td(_esc(record.get("events") or 0), record.get("events") or 0, "mono"),
        _td(_evidence_html(record)),
        _td(_esc(note)),
    ]
    return "<tr %s>%s</tr>" % (attributes, "".join(cells))


def _render_mobility_row(analyzer, record, row_id, exports, address_kind):
    if address_kind == "ip":
        return _render_ip_row(analyzer, record, row_id, exports)
    return _render_mac_row(analyzer, record, row_id, exports)


def _render_apipa_row(analyzer, claim, row_id, exports):
    observers = sorted(claim.get("observers", set()))
    # A remote EVPN copy can appear on dozens of switches. Listing every replica
    # in every row made the report huge and implied they were endpoint owners.
    # Keep only non-extern/local observations as actionable locations; expose the
    # complete replication scale through the counters instead.
    local_interfaces = sorted({
        (host, dev) for host, dev, _state, extern in claim.get("observations", set())
        if not extern
    })
    devices = {host for host, _dev in local_interfaces}
    if not devices and len(observers) == 1:
        devices.add(observers[0])
    interface_plain = ["%s:%s" % pair for pair in local_interfaces]
    observer_html = '<span class="mono">%d</span> device%s' % (
        len(observers), "s" if len(observers) != 1 else ""
    )
    location_html = "<br>".join(
        _port_html(analyzer, host, dev) for host, dev in local_interfaces
    ) or '<span class="dim">No local owner in this snapshot</span>'
    scope_record = {
        "scope": claim.get("scope", "unknown"),
        "vni": claim.get("vni", "unknown"),
        "vlans": claim.get("vlans", set()),
        "vrfs": claim.get("vrfs", set()),
    }
    resolved = (
        claim.get("mac") != "unknown"
        and bool(set(claim.get("states", set())) - {"FAILED", "INCOMPLETE"})
    )
    note = (
        "IPv4 link-local claim; DHCP failure is possible but not proven"
        if resolved else
        "Unresolved IPv4 link-local neighbor attempt; not counted as a unique endpoint claim"
    )
    exports.append(_export_record(
        row_id, "ipv4_link_local_claim" if resolved else "ipv4_link_local_unresolved",
        "observed",
        claim.get("scope", "unknown"), claim.get("vlans", set()),
        claim.get("ip", ""), {claim.get("mac", "unknown")},
        interface_plain, [], [], "", None, None, None, "", "",
        0, {"kernel_neighbor"}, "Observed" if resolved else "Unresolved", note,
        observer_count=len(observers),
        observation_count=claim.get("observation_count", 0),
        local_observations=claim.get("local_observations", 0),
        extern_observations=claim.get("extern_observations", 0),
        non_vlan_observations=claim.get("non_vlan_observations", 0),
        neighbor_states=_plain_join(sorted(claim.get("states", set()))),
    ))
    attributes = _row_attributes(row_id, "ipv4ll", "observed", devices)
    counts = (
        '<span class="mono">%d total</span><br>'
        '<span class="dim">%d local · %d EVPN replicated · %d non-VLAN</span>'
        % (
            claim.get("observation_count", 0),
            claim.get("local_observations", 0),
            claim.get("extern_observations", 0),
            claim.get("non_vlan_observations", 0),
        )
    )
    cells = [
        _td(_scope_html(scope_record), _scope_sort_key(claim.get("scope", "unknown"))),
        _td(_esc(claim.get("ip", "")), _ip_sort_key(claim.get("ip", "")), "mono"),
        _td(_esc(claim.get("mac", "unknown")), claim.get("mac", ""), "mono"),
        _td(_html_join(sorted(claim.get("states", set()))), _plain_join(sorted(claim.get("states", set())))),
        _td(observer_html, len(observers)),
        _td(location_html, _plain_join(interface_plain), "mono", 'data-display-locations="current"'),
        _td(counts, claim.get("observation_count", 0)),
        _td(_esc(note)),
    ]
    return "<tr %s>%s</tr>" % (attributes, "".join(cells))


def _coverage_html(analyzer, summary):
    current = summary["coverage_current_hosts"]
    expected = summary["coverage_expected_hosts"]
    partial = summary["coverage_partial"]
    css = "coverage-banner coverage-partial" if partial else "coverage-banner coverage-complete"
    status = "PARTIAL" if partial else "COMPLETE"
    pieces = [
        '<div id="coverageDetails" class="%s" tabindex="-1">' % css,
        '<strong>Coverage %s:</strong> %d / %d expected devices contributed current data.'
        % (_esc(status), current, expected),
    ]
    unavailable = summary.get("coverage_unavailable_hosts", [])
    if unavailable:
        pieces.append('<div><strong>Unavailable:</strong> %s</div>' % " ".join(
            _alias_span(host, "device") for host in unavailable
        ))
    if summary.get("sequence_baseline_warmup"):
        pieces.append(
            '<div><strong>Mobility baseline warming up:</strong> this run created the new per-observer sequence baseline. Active movement rates become authoritative after the next current collection.</div>'
        )
    if analyzer.coverage_failures:
        pieces.append("<details><summary>Source/schema warnings (%d)</summary><ul>" % summary["coverage_failures"])
        for host, labels in sorted(analyzer.coverage_failures.items()):
            pieces.append("<li>%s: %s</li>" % (
                _alias_span(host, "device"), _esc(_plain_join(sorted(set(labels))))
            ))
        pieces.append("</ul></details>")
    sample_totals = {}
    collection_times = []
    for host, metadata in analyzer.collection_meta.items():
        if isinstance(metadata.get("collection_time"), (int, float)):
            collection_times.append(metadata["collection_time"])
        for label, sample in (metadata.get("samples") or {}).items():
            aggregate = sample_totals.setdefault(
                label, {"matches": 0, "emitted": 0, "hosts": 0, "truncated": 0, "unknown": 0}
            )
            aggregate["hosts"] += 1
            if str(sample.get("matches", "")).isdigit():
                aggregate["matches"] += int(sample["matches"])
            else:
                aggregate["unknown"] += 1
            if str(sample.get("emitted", "")).isdigit():
                aggregate["emitted"] += int(sample["emitted"])
            if sample.get("truncated") == "YES":
                aggregate["truncated"] += 1
    if collection_times:
        pieces.append(
            '<div><strong>Collection UTC range:</strong> %s — %s</div>'
            % (_esc(_format_utc(min(collection_times))), _esc(_format_utc(max(collection_times))))
        )
    if sample_totals:
        pieces.append(
            '<details><summary>Collection sample metadata</summary><div class="table-wrap">'
            '<table class="dup-table"><thead><tr><th>Source</th><th>Hosts</th>'
            '<th>Matches</th><th>Emitted</th><th>Truncated hosts</th><th>Unknown totals</th>'
            '</tr></thead><tbody>'
        )
        for label, values in sorted(sample_totals.items()):
            pieces.append(
                '<tr><td>%s</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td></tr>'
                % (
                    _esc(label), values["hosts"], values["matches"], values["emitted"],
                    values["truncated"], values["unknown"],
                )
            )
        pieces.append("</tbody></table></div></details>")
    pieces.append("</div>")
    return "".join(pieces)


def _dad_config_html(analyzer):
    hosts = sorted(set(analyzer.current_hosts) | set(analyzer.dup_config))
    if not hosts:
        return '<p class="dim">No DAD configuration lines were parsed.</p>'
    rows = []
    for host in hosts:
        config = analyzer.dup_config.get(host, {})
        enabled = config.get("enabled")
        if enabled is True:
            state, css = "Enabled", "badge-green"
        elif enabled is False:
            state, css = "Off — reason unverified", "badge-orange"
        else:
            state, css = "Unknown", "badge-gray"
        policy = "n/a"
        if config.get("max_moves") is not None and config.get("time") is not None:
            policy = "%s moves / %ss" % (config["max_moves"], config["time"])
        rows.append(
            "<tr><td>%s</td><td><span class=\"badge %s\">%s</span></td>"
            "<td class=\"mono\">%s</td><td class=\"mono\">%s</td><td>%s</td></tr>"
            % (
                _alias_span(host, "device"), css, _esc(state),
                _esc(policy), _esc(config.get("freeze") or "n/a"),
                _esc(
                    "Enabled" if config.get("warning_only") is True else
                    "Disabled" if config.get("warning_only") is False else "Unknown"
                ),
            )
        )
    return (
        '<div class="table-wrap"><table class="dup-table"><thead><tr>'
        '<th>Switch</th><th>DAD state</th><th>Move policy</th><th>Freeze</th><th>Warning-only</th>'
        '</tr></thead><tbody>%s</tbody></table></div>' % "".join(rows)
    )


def _empty_rows(column_count, message):
    return (
        '<tr class="empty-row"><td colspan="%d">%s</td></tr>'
        '<tr class="no-match-row" hidden><td colspan="%d">No records match the current filters.</td></tr>'
        % (column_count, _esc(message), column_count)
    )


def _hidden_semantic_metrics(summary):
    values = []
    for key, value in sorted(summary.items()):
        if isinstance(value, bool):
            display = "true" if value else "false"
        elif isinstance(value, (int, float)):
            display = str(value)
        else:
            continue
        values.append(
            '<span data-metric-key="%s" data-metric-value="%s"></span>'
            % (_esc(key), _esc(display))
        )
    return '<div class="semantic-metrics" aria-hidden="true">%s</div>' % "".join(values)


def _card(css, value, label, filter_value="", metric_key="", title=""):
    attributes = ['type="button"', 'class="summary-card %s"' % _esc(css)]
    if filter_value:
        attributes.append('data-card-filter="%s"' % _esc(filter_value))
    if title:
        attributes.append('title="%s"' % _esc(title))
    if not filter_value:
        attributes.append('data-no-filter="true"')
    metric_attribute = (
        ' data-metric-key="%s" data-metric-value="%s"' % (
            _esc(metric_key), _esc(value)
        ) if metric_key else ""
    )
    return (
        '<button %s%s><span class="metric">%s</span>'
        '<span class="metric-label">%s</span></button>'
        % (" ".join(attributes), metric_attribute, _esc(value), _esc(label))
    )


def export_duplicate_report(analyzer, output_file):
    """Write a complete semantic duplicate report atomically."""
    summary = analyzer.summary()
    export_rows = []
    all_devices = set(analyzer.current_hosts) | set(analyzer.unavailable_hosts)

    ip_findings = []
    ip_mobility = []
    for record in sorted(
        analyzer.ip_dups.values(),
        key=lambda row: (
            ACTIVITY_ORDER.get(row.get("activity"), 9),
            _scope_sort_key(row.get("scope", "unknown")),
            _ip_sort_key(row.get("ip", "")),
        ),
    ):
        all_devices.update(_record_devices(analyzer, record))
        target = ip_mobility if record.get("incident_type") == "ip_mobility" else ip_findings
        prefix = "ipmob" if target is ip_mobility else "ip"
        row_id = "%s-%05d" % (prefix, len(target) + 1)
        target.append(_render_ip_row(analyzer, record, row_id, export_rows))

    mac_findings = []
    mac_mobility = []
    excluded_mh = 0
    for record in sorted(
        analyzer.mac_dups.values(),
        key=lambda row: (
            ACTIVITY_ORDER.get(row.get("activity"), 9),
            _scope_sort_key(row.get("scope", "unknown")),
            row.get("mac", ""),
        ),
    ):
        all_devices.update(_record_devices(analyzer, record))
        if (record.get("incident_type") == "unknown"
                and record.get("mh_possible")
                and not record.get("dad_flagged")
                and not record.get("dad_event")
                and not record.get("mobility")):
            excluded_mh += 1
            continue
        target = mac_mobility if record.get("incident_type") == "mac_mobility" else mac_findings
        prefix = "macmob" if target is mac_mobility else "mac"
        row_id = "%s-%05d" % (prefix, len(target) + 1)
        target.append(_render_mac_row(analyzer, record, row_id, export_rows))

    ipv4ll_rows = []
    for claim in sorted(
        analyzer.apipa_claims.values(),
        key=lambda row: (
            _scope_sort_key(row.get("scope", "unknown")),
            _ip_sort_key(row.get("ip", "")),
            row.get("mac", ""),
        ),
    ):
        all_devices.update(claim.get("observers", set()))
        row_id = "ipv4ll-%05d" % (len(ipv4ll_rows) + 1)
        ipv4ll_rows.append(_render_apipa_row(analyzer, claim, row_id, export_rows))

    ip_finding_count = len(ip_findings)
    ip_mobility_count = len(ip_mobility)
    mac_finding_count = len(mac_findings)
    mac_mobility_count = len(mac_mobility)
    ipv4ll_count = len(ipv4ll_rows)
    if not ip_findings:
        ip_findings.append(_empty_rows(13, "No current IP conflict or DAD finding in the available data."))
    else:
        ip_findings.append('<tr class="no-match-row" hidden><td colspan="13">No records match the current filters.</td></tr>')
    if not ip_mobility:
        ip_mobility.append(_empty_rows(13, "No IP mobility anomaly in the available data."))
    else:
        ip_mobility.append('<tr class="no-match-row" hidden><td colspan="13">No records match the current filters.</td></tr>')
    if not mac_findings:
        mac_findings.append(_empty_rows(11, "No current MAC conflict, DAD finding, or loop signal in the available data."))
    else:
        mac_findings.append('<tr class="no-match-row" hidden><td colspan="11">No records match the current filters.</td></tr>')
    if not mac_mobility:
        mac_mobility.append(_empty_rows(11, "No MAC mobility anomaly in the available data."))
    else:
        mac_mobility.append('<tr class="no-match-row" hidden><td colspan="11">No records match the current filters.</td></tr>')
    if not ipv4ll_rows:
        ipv4ll_rows.append(_empty_rows(8, "No IPv4 link-local claim in the available data."))
    else:
        ipv4ll_rows.append('<tr class="no-match-row" hidden><td colspan="8">No records match the current filters.</td></tr>')

    active_mobility = summary["ip_mobility_active"] + summary["mac_mobility_active"]
    cards = [
        _card("card-critical", summary["confirmed_ip_active"], "Confirmed Active IP", "confirmed_ip|active", "confirmed_ip_active"),
        _card("card-warning", active_mobility, "Active Mobility", "mobility|active", "active_mobility",
              "IP and MAC mobility anomalies; these are not counted as confirmed duplicates"),
        _card("card-critical", summary["confirmed_mac_active"], "Active MAC Conflicts", "confirmed_mac|active", "confirmed_mac_active"),
        _card("card-warning", summary["possible_loops"], "Possible Loops", "loop|active", "possible_loops"),
        _card("card-info", summary["apipa_unique"], "IPv4LL Unique Claims", "ipv4ll|", "apipa_unique",
              "Unique scope + IPv4LL address + MAC claims"),
        _card("card-info", summary["apipa_observations"], "IPv4LL Observations", "ipv4ll|", "apipa_observations",
              "Raw per-switch observations, including EVPN replicas"),
        _card("card-info", "%d/%d" % (
            summary["coverage_current_hosts"], summary["coverage_expected_hosts"]
        ), "Coverage Current / Expected", "coverage|", "", "Open coverage details"),
        _card("card-info", summary["affected_vnis"], "VNIs with Signals", "", "affected_vnis"),
    ]
    summary_with_derived = dict(summary)
    summary_with_derived["active_mobility"] = active_mobility
    summary_with_derived["mh_possible_excluded"] = excluded_mh
    summary_json = json.dumps(
        summary_with_derived, sort_keys=True, separators=(",", ":")
    ).replace("</", "<\\/")
    export_json = json.dumps(
        export_rows, sort_keys=True, separators=(",", ":")
    ).replace("</", "<\\/")
    device_json = json.dumps(sorted(all_devices), separators=(",", ":")).replace("</", "<\\/")

    stale_count = sum(
        1 for record in list(analyzer.ip_dups.values()) + list(analyzer.mac_dups.values())
        if record.get("activity") == "historical"
    )
    report_utc = _format_utc(analyzer.analysis_now)
    generated_epoch = int(analyzer.analysis_epoch)
    replacements = {
        "__REPORT_UTC__": _esc(report_utc),
        "__GENERATED_EPOCH__": str(generated_epoch),
        "__CARDS__": "".join(cards),
        "__SEMANTIC_METRICS__": _hidden_semantic_metrics(summary_with_derived),
        "__SUMMARY_JSON__": summary_json,
        "__COVERAGE__": _coverage_html(analyzer, summary),
        "__IP_ROWS__": "".join(ip_findings),
        "__IP_MOBILITY_ROWS__": "".join(ip_mobility),
        "__MAC_ROWS__": "".join(mac_findings),
        "__MAC_MOBILITY_ROWS__": "".join(mac_mobility),
        "__IPV4LL_ROWS__": "".join(ipv4ll_rows),
        "__IP_COUNT__": str(ip_finding_count),
        "__IP_MOBILITY_COUNT__": str(ip_mobility_count),
        "__MAC_COUNT__": str(mac_finding_count),
        "__MAC_MOBILITY_COUNT__": str(mac_mobility_count),
        "__IPV4LL_COUNT__": str(ipv4ll_count),
        "__MH_EXCLUDED__": str(excluded_mh),
        "__AGED_COUNT__": str(stale_count),
        "__DAD_CONFIG__": _dad_config_html(analyzer),
        "__EXPORT_JSON__": export_json,
        "__DEVICE_JSON__": device_json,
    }
    document = PAGE_TEMPLATE
    for placeholder, value in replacements.items():
        document = document.replace(placeholder, value)
    _atomic_write(output_file, document)


PAGE_TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Duplicate and Mobility Analysis</title>
<link rel="shortcut icon" href="/png/favicon.ico">
<style>
*{box-sizing:border-box}html,body{margin:0;padding:0;background:#1e1e1e;color:#d4d4d4;font-family:Arial,sans-serif}
body{padding:20px;font-size:14px}.page-header{display:flex;justify-content:space-between;align-items:flex-start;gap:20px;margin-bottom:18px;padding-bottom:14px;border-bottom:1px solid #404040}
.page-title{font-size:24px;font-weight:650;color:#76b900}.subtitle,.last-updated,.dim{color:#929292;font-size:12px}.last-updated{margin-top:5px}.action-buttons{display:flex;align-items:center;justify-content:flex-end;gap:9px;flex-wrap:wrap}
.btn,select{min-height:34px;border:1px solid #555;border-radius:5px;background:#333;color:#ddd;padding:7px 11px;font:inherit}.btn{cursor:pointer}.btn:hover,.btn:focus-visible,select:focus-visible{border-color:#76b900;outline:2px solid rgba(118,185,0,.25);outline-offset:1px}.btn-primary{background:#5d9200;border-color:#76b900;color:#fff}.btn-info{background:#176c94;border-color:#4fc3f7;color:#fff}.btn[disabled]{opacity:.55;cursor:wait}
.summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:10px;margin-bottom:16px}.summary-card{display:block;width:100%;text-align:left;background:#282828;color:#ddd;border:0;border-left:4px solid #76b900;border-radius:6px;padding:13px 14px;cursor:pointer}.summary-card:hover,.summary-card:focus-visible{background:#323232;outline:2px solid rgba(118,185,0,.35)}.summary-card.active{box-shadow:0 0 0 2px #76b900 inset}.card-critical{border-left-color:#f44336}.card-warning{border-left-color:#ff9800}.card-info{border-left-color:#4fc3f7}.metric{display:block;font-size:22px;font-weight:700}.metric-label{display:block;margin-top:3px;color:#aaa;font-size:11px;text-transform:uppercase;letter-spacing:.02em}.semantic-metrics{display:none}
.coverage-banner{border:1px solid;border-radius:6px;padding:11px 14px;margin:0 0 16px;line-height:1.5}.coverage-complete{border-color:#5f9307;background:rgba(118,185,0,.08)}.coverage-partial{border-color:#ff9800;background:rgba(255,152,0,.10);color:#ffd08a}.coverage-banner details{margin-top:6px}.coverage-banner ul{margin:6px 0 0;padding-left:20px}
.filter-bar{display:flex;align-items:center;gap:9px;flex-wrap:wrap;margin-bottom:16px;padding:10px 12px;background:#282828;border-radius:6px}.filter-status{flex:1;color:#b9d58c}.filter-status:empty::before{content:'Showing all current records';color:#888}
.report-section{background:#292929;border-radius:7px;margin-bottom:18px;overflow:hidden}.section-header{display:flex;justify-content:space-between;align-items:center;padding:11px 14px;background:#333;color:#76b900;font-weight:650}.section-count{color:#bbb;font-size:12px;font-weight:400}.section-help{padding:9px 14px 0;color:#999;font-size:12px}.table-wrap{overflow-x:auto;padding:12px 14px 15px}.dup-table{width:100%;min-width:1060px;border-collapse:collapse;font-size:12px}.dup-table th,.dup-table td{border:1px solid #444;padding:8px 9px;text-align:left;vertical-align:top}.dup-table th{background:#373737;color:#a5d653;white-space:nowrap;cursor:pointer;user-select:none}.dup-table th:focus-visible{outline:2px solid #76b900;outline-offset:-2px}.dup-table tbody tr{background:#252525}.dup-table tbody tr:hover{background:#303030}.empty-row td,.no-match-row td{text-align:center;color:#9ac65a;padding:18px}.mono{font-family:Consolas,'Courier New',monospace}.badge{display:inline-block;padding:3px 7px;border-radius:4px;font-size:10px;text-transform:uppercase;font-weight:700;white-space:nowrap}.badge-red{background:rgba(244,67,54,.2);color:#ff7272}.badge-orange{background:rgba(255,152,0,.2);color:#ffb74d}.badge-green{background:rgba(118,185,0,.2);color:#a8dd43}.badge-gray{background:rgba(158,158,158,.2);color:#aaa}.badge-blue{background:rgba(79,195,247,.18);color:#81d4fa}.confidence{white-space:nowrap}.location{display:inline-block}.historical{opacity:.65}.pdesc{display:block;color:#ca994a;font-size:10px;font-style:italic;margin:1px 0 5px}.delta-up{color:#ff7373;font-weight:700}.delta-neutral{color:#aaa}.evidence{display:inline-block;background:#393939;border-radius:3px;padding:2px 5px;margin:1px;font-size:10px;color:#bcbcbc}details summary{cursor:pointer;color:#b9d58c}
.modal{display:none;position:fixed;z-index:2500;inset:0;background:rgba(0,0,0,.72);padding:25px}.modal.show{display:flex;align-items:center;justify-content:center}.modal-box{width:min(900px,96vw);max-height:88vh;overflow:auto;background:#292929;border-radius:8px;box-shadow:0 8px 35px rgba(0,0,0,.6)}.modal-head{position:sticky;top:0;display:flex;justify-content:space-between;align-items:center;background:#353535;padding:12px 16px;border-bottom:1px solid #484848;z-index:1}.modal-head h2{font-size:17px;color:#76b900;margin:0}.modal-close{border:0;background:transparent;color:#aaa;font-size:25px;cursor:pointer}.modal-body{padding:15px 18px;line-height:1.55}.modal-body h3{color:#8ac929;font-size:14px;margin:18px 0 5px}.modal-body code{background:#1d1d1d;color:#e2c65e;border-radius:3px;padding:1px 4px}
@media(max-width:900px){body{padding:12px}.page-header{flex-direction:column}.action-buttons{justify-content:flex-start}.dup-table{min-width:980px}}
</style>
</head>
<body data-generated-epoch="__GENERATED_EPOCH__">
<header class="page-header">
  <div>
    <div class="page-title">Duplicate, Mobility and IPv4LL Analysis</div>
    <div class="subtitle">Confirmed conflicts are kept separate from mobility anomalies and replicated neighbor observations.</div>
    <div class="last-updated">Generated: <time datetime="__REPORT_UTC__">__REPORT_UTC__</time></div>
  </div>
  <div class="action-buttons">
    <label><span class="dim">Device </span><select id="deviceFilter"><option value="">All devices</option></select></label>
    <button type="button" class="btn" id="thresholdButton">Thresholds &amp; sources</button>
    <button type="button" class="btn btn-info" id="run-analysis">Run analysis</button>
    <button type="button" class="btn" id="agedButton" aria-pressed="false">Show historical (__AGED_COUNT__)</button>
    <button type="button" class="btn" id="exportViewButton">Export current view</button>
    <button type="button" class="btn btn-primary" id="exportAllButton">Export all CSV</button>
  </div>
</header>

<script type="application/json" id="duplicateSummaryData" data-duplicate-summary>__SUMMARY_JSON__</script>
__SEMANTIC_METRICS__
<section class="summary-grid" aria-label="Duplicate analysis summary">__CARDS__</section>
__COVERAGE__

<div class="filter-bar">
  <span class="filter-status" id="filterStatus" aria-live="polite"></span>
  <button type="button" class="btn" id="clearFiltersButton">Show all</button>
</div>

<section class="report-section" data-report-section id="ipFindingsSection">
  <div class="section-header"><span>IP conflicts and DAD findings</span><span class="section-count"><span data-visible-count>__IP_COUNT__</span> visible</span></div>
  <div class="section-help">Only simultaneous/corroborated conflicts and FRR DAD evidence appear here. Mobility-only records are listed separately.</div>
  <div class="table-wrap"><table class="dup-table" id="ipTable">
    <thead><tr>
      <th data-sort-type="number" tabindex="0">Activity</th><th tabindex="0">Confidence</th><th tabindex="0">Scope</th><th tabindex="0">IP</th><th tabindex="0">Current MAC claim(s)</th><th tabindex="0">Current location(s)</th><th tabindex="0">Historical evidence</th><th tabindex="0">Observed remote/VTEP</th><th data-sort-type="number" tabindex="0">EVPN sequence / rate</th><th data-sort-type="number" tabindex="0">Last DAD event</th><th data-sort-type="number" tabindex="0">Sampled DAD events</th><th tabindex="0">Evidence</th><th tabindex="0">Finding</th>
    </tr></thead><tbody>__IP_ROWS__</tbody>
  </table></div>
</section>

<section class="report-section" data-report-section id="ipMobilitySection">
  <div class="section-header"><span>IP endpoint mobility anomalies</span><span class="section-count"><span data-visible-count>__IP_MOBILITY_COUNT__</span> visible</span></div>
  <div class="section-help">These records describe one endpoint moving or re-registering. They are not counted as confirmed duplicate IPs.</div>
  <div class="table-wrap"><table class="dup-table" id="ipMobilityTable">
    <thead><tr>
      <th data-sort-type="number" tabindex="0">Activity</th><th tabindex="0">Confidence</th><th tabindex="0">Scope</th><th tabindex="0">IP</th><th tabindex="0">MAC claim(s)</th><th tabindex="0">Current location(s)</th><th tabindex="0">Historical evidence</th><th tabindex="0">Observed remote/VTEP</th><th data-sort-type="number" tabindex="0">EVPN sequence / rate</th><th data-sort-type="number" tabindex="0">Last DAD event</th><th data-sort-type="number" tabindex="0">Sampled DAD events</th><th tabindex="0">Evidence</th><th tabindex="0">Finding</th>
    </tr></thead><tbody>__IP_MOBILITY_ROWS__</tbody>
  </table></div>
</section>

<section class="report-section" data-report-section id="macFindingsSection">
  <div class="section-header"><span>MAC conflicts, DAD findings and loop signals</span><span class="section-count"><span data-visible-count>__MAC_COUNT__</span> visible</span></div>
  <div class="section-help">Bond/LAG-only multi-attachment is not automatically called a duplicate. __MH_EXCLUDED__ ambiguous/expected multihoming attachment records were excluded from this findings table.</div>
  <div class="table-wrap"><table class="dup-table" id="macTable">
    <thead><tr>
      <th data-sort-type="number" tabindex="0">Activity</th><th tabindex="0">Confidence</th><th tabindex="0">Scope</th><th tabindex="0">MAC</th><th tabindex="0">Current location(s)</th><th tabindex="0">Observed remote/VTEP</th><th data-sort-type="number" tabindex="0">EVPN sequence / rate</th><th data-sort-type="number" tabindex="0">Last DAD event</th><th data-sort-type="number" tabindex="0">Sampled DAD events</th><th tabindex="0">Evidence</th><th tabindex="0">Finding</th>
    </tr></thead><tbody>__MAC_ROWS__</tbody>
  </table></div>
</section>

<section class="report-section" data-report-section id="macMobilitySection">
  <div class="section-header"><span>MAC mobility anomalies</span><span class="section-count"><span data-visible-count>__MAC_MOBILITY_COUNT__</span> visible</span></div>
  <div class="section-help">High or policy-significant movement is shown separately from a simultaneous MAC conflict.</div>
  <div class="table-wrap"><table class="dup-table" id="macMobilityTable">
    <thead><tr>
      <th data-sort-type="number" tabindex="0">Activity</th><th tabindex="0">Confidence</th><th tabindex="0">Scope</th><th tabindex="0">MAC</th><th tabindex="0">Current location(s)</th><th tabindex="0">Observed remote/VTEP</th><th data-sort-type="number" tabindex="0">EVPN sequence / rate</th><th data-sort-type="number" tabindex="0">Last DAD event</th><th data-sort-type="number" tabindex="0">Sampled DAD events</th><th tabindex="0">Evidence</th><th tabindex="0">Finding</th>
    </tr></thead><tbody>__MAC_MOBILITY_ROWS__</tbody>
  </table></div>
</section>

<section class="report-section" data-report-section id="ipv4llSection">
  <div class="section-header"><span>IPv4 link-local claims (169.254.0.0/16)</span><span class="section-count"><span data-visible-count>__IPV4LL_COUNT__</span> visible</span></div>
  <div class="section-help">A resolved claim is unique by scope + IP + MAC. Unresolved/FAILED attempts remain visible but are not included in the headline claim count. Raw switch observations and EVPN replicas are separate. IPv4LL may indicate a DHCP problem, but does not prove one.</div>
  <div class="table-wrap"><table class="dup-table" id="ipv4llTable">
    <thead><tr><th tabindex="0">Scope</th><th tabindex="0">IPv4LL address</th><th tabindex="0">MAC</th><th tabindex="0">Neighbor state(s)</th><th data-sort-type="number" tabindex="0">Observers</th><th tabindex="0">Observed interface(s)</th><th data-sort-type="number" tabindex="0">Observation breakdown</th><th tabindex="0">Interpretation</th></tr></thead>
    <tbody>__IPV4LL_ROWS__</tbody>
  </table></div>
</section>

<div class="modal" id="thresholdModal" role="dialog" aria-modal="true" aria-labelledby="thresholdTitle">
  <div class="modal-box" tabindex="-1">
    <div class="modal-head"><h2 id="thresholdTitle">Detection policy, sources and DAD state</h2><button type="button" class="modal-close" aria-label="Close dialog">&times;</button></div>
    <div class="modal-body">
      <h3>Incident model</h3>
      <p><strong>Confirmed conflict</strong> requires current corroborating evidence. A mobility sequence alone is never labelled a duplicate. <strong>Activity</strong> is a separate dimension: movement is active only when its rate reaches the configured DAD moves/window policy (safe fallback: 5 moves / 180 seconds).</p>
      <h3>Evidence sources</h3>
      <p><code>show evpn ... duplicate</code> supplies current FRR DAD flags; full MAC/ARP tables supply per-observer mobility sequence; bridge FDB supplies current local attachment points; IPv4 neighbor data supplies IP/MAC claims and IPv4LL health; FRR log rows supply sampled event evidence.</p>
      <p><strong>Sampled DAD events</strong> are deduplicated by timestamp/VNI/MAC/IP/VTEP signature and are not a lifetime counter. The collector reports total matching log rows, emitted rows and truncation separately. Any truncation makes coverage partial.</p>
      <h3>State and history</h3>
      <p>Sequence samples are tracked per observer. Historical MAC/port evidence has its own last-seen timestamp, expires, and never becomes current merely because an incident remains present.</p>
      <h3>Duplicate-address detection by switch</h3>
      <p>DAD being off is not automatically attributed to EVPN multihoming. The reason remains unverified unless independent ES/MH evidence is available.</p>
      <p><strong>Excluded from findings:</strong> __MH_EXCLUDED__ FDB records were present only on bond/LAG-like attachment points without DAD, movement, or non-MH conflict evidence.</p>
      __DAD_CONFIG__
    </div>
  </div>
</div>

<script type="application/json" id="duplicateExportData">__EXPORT_JSON__</script>
<script>
(function(){
'use strict';
var GENERATED_EPOCH=Number('__GENERATED_EPOCH__');
var EXPORT_ROWS=JSON.parse(document.getElementById('duplicateExportData').textContent||'[]');
var DEVICES=__DEVICE_JSON__;
var filterState={category:'',activity:'',device:'',showHistorical:false};
var lastDialogTrigger=null;

function rows(){return Array.prototype.slice.call(document.querySelectorAll('tr[data-record-id]'));}
function categoryMatches(rowCategory,wanted){
  if(!wanted)return true;
  if(wanted==='mobility')return rowCategory==='mobility';
  return rowCategory===wanted;
}
function applyFilters(){
  var visibleTotal=0;
  rows().forEach(function(row){
    var deviceList=(row.getAttribute('data-devices')||'').toLowerCase().split(/\s+/).filter(Boolean);
    var visible=categoryMatches(row.getAttribute('data-category')||'',filterState.category) &&
      (!filterState.activity||row.getAttribute('data-activity')===filterState.activity) &&
      (!filterState.device||deviceList.indexOf(filterState.device.toLowerCase())>=0) &&
      (filterState.showHistorical||row.getAttribute('data-aged')!=='true');
    row.hidden=!visible;if(visible)visibleTotal++;
  });
  document.querySelectorAll('[data-report-section]').forEach(function(section){
    var dataRows=Array.prototype.slice.call(section.querySelectorAll('tr[data-record-id]'));
    var count=dataRows.filter(function(row){return !row.hidden;}).length;
    var counter=section.querySelector('[data-visible-count]');if(counter)counter.textContent=String(count);
    var noMatch=section.querySelector('.no-match-row');
    if(noMatch)noMatch.hidden=!(dataRows.length>0&&count===0);
  });
  var parts=[];
  if(filterState.category)parts.push('type: '+filterState.category.replace(/_/g,' '));
  if(filterState.activity)parts.push('activity: '+filterState.activity);
  if(filterState.device)parts.push('device: '+filterState.device);
  if(filterState.showHistorical)parts.push('historical included');
  document.getElementById('filterStatus').textContent=parts.length?('Filtered — '+parts.join(' · ')):'';
  return visibleTotal;
}
function clearFilters(){
  filterState.category='';filterState.activity='';filterState.device='';filterState.showHistorical=false;
  document.getElementById('deviceFilter').value='';
  var aged=document.getElementById('agedButton');aged.setAttribute('aria-pressed','false');aged.textContent='Show historical (__AGED_COUNT__)';
  document.querySelectorAll('.summary-card').forEach(function(card){card.classList.remove('active');});
  applyFilters();
}
function activateCard(card){
  document.querySelectorAll('.summary-card').forEach(function(item){item.classList.remove('active');});
  var spec=card.getAttribute('data-card-filter')||'';
  if(spec.indexOf('coverage|')===0){document.getElementById('coverageDetails').focus();return;}
  var parts=spec.split('|');filterState.category=parts[0]||'';filterState.activity=parts[1]||'';
  card.classList.add('active');applyFilters();
  var first=rows().find(function(row){return !row.hidden;});if(first)first.scrollIntoView({behavior:'smooth',block:'center'});
}

function compareValues(a,b,type){
  if(type==='number'){var x=Number(a),y=Number(b);x=Number.isFinite(x)?x:-Infinity;y=Number.isFinite(y)?y:-Infinity;return x-y;}
  return String(a).localeCompare(String(b),undefined,{numeric:true,sensitivity:'base'});
}
function sortTable(th){
  var table=th.closest('table'),body=table.tBodies[0],index=th.cellIndex,type=th.getAttribute('data-sort-type')||'text';
  var ascending=th.getAttribute('aria-sort')!=='ascending';
  Array.prototype.slice.call(table.querySelectorAll('th')).forEach(function(item){item.removeAttribute('aria-sort');});
  th.setAttribute('aria-sort',ascending?'ascending':'descending');
  var sortable=Array.prototype.slice.call(body.querySelectorAll('tr[data-record-id]'));
  sortable.sort(function(left,right){var a=left.cells[index],b=right.cells[index];var av=a.getAttribute('data-sort')||a.textContent.trim(),bv=b.getAttribute('data-sort')||b.textContent.trim();var result=compareValues(av,bv,type);return ascending?result:-result;});
  sortable.forEach(function(row){body.appendChild(row);});
  var noMatch=body.querySelector('.no-match-row');if(noMatch)body.appendChild(noMatch);
}

function csvEscape(value){value=value===null||value===undefined?'':String(value);return '"'+value.replace(/"/g,'""')+'"';}
var CSV_COLUMNS=[
  ['Record Type','record_type'],['Activity','activity'],['Confidence','confidence'],['Scope','scope'],['VLAN(s)','vlans'],['Address','address'],['MAC(s)','macs'],
  ['Current Locations (canonical)','current_locations'],['Current Locations (display)','display_locations'],['Historical Locations','historical_locations'],['Remote VTEP(s)','remote_vteps'],
  ['EVPN Sequence','evpn_sequence'],['Sequence Delta','sequence_delta'],['Sample Interval Seconds','sample_interval_seconds'],['Moves Per Minute','moves_per_minute'],
  ['Last Event UTC','last_event_utc'],['Last Event Age','last_event_age'],['Sampled DAD Events','sampled_dad_events'],['Evidence','evidence'],['Neighbor States','neighbor_states'],
  ['Observer Count','observer_count'],['Observation Count','observation_count'],['Local Observations','local_observations'],['EVPN Replicated Observations','extern_observations'],
  ['Non-VLAN Observations','non_vlan_observations'],['Attachment Count','attachment_count'],['Possible Loop Size','possible_loop_size'],['Note','note']
];
function displayedLocation(recordId){
  var row=document.querySelector('tr[data-record-id="'+String(recordId).replace(/"/g,'\\"')+'"]');if(!row)return '';
  var cell=row.querySelector('[data-display-locations]');return cell?(cell.innerText||cell.textContent||'').replace(/\s+/g,' ').trim():'';
}
function exportCSV(currentOnly){
  var visible={};if(currentOnly)rows().forEach(function(row){if(!row.hidden)visible[row.getAttribute('data-record-id')]=true;});
  var selected=EXPORT_ROWS.filter(function(record){return !currentOnly||visible[record.record_id];});
  var output=[CSV_COLUMNS.map(function(column){return column[0];})];
  selected.forEach(function(record){var copy=Object.assign({},record,{display_locations:displayedLocation(record.record_id)});output.push(CSV_COLUMNS.map(function(column){return copy[column[1]]===undefined?'':copy[column[1]];}));});
  var csv='\uFEFF'+output.map(function(row){return row.map(csvEscape).join(',');}).join('\r\n');
  var blob=new Blob([csv],{type:'text/csv;charset=utf-8'}),url=URL.createObjectURL(blob),anchor=document.createElement('a');
  anchor.href=url;anchor.download='Duplicate_Analysis_'+(currentOnly?'Current_View_':'All_')+new Date().toISOString().replace(/[:.]/g,'-')+'.csv';document.body.appendChild(anchor);anchor.click();anchor.remove();setTimeout(function(){URL.revokeObjectURL(url);},1000);
}

function openDialog(){lastDialogTrigger=document.activeElement;var modal=document.getElementById('thresholdModal');modal.classList.add('show');modal.querySelector('.modal-box').focus();}
function closeDialog(){var modal=document.getElementById('thresholdModal');modal.classList.remove('show');if(lastDialogTrigger)lastDialogTrigger.focus();}
function setRunState(button,text,disabled){button.disabled=disabled;button.textContent=text;}
function fetchNoCache(url){return fetch(url+(url.indexOf('?')>=0?'&':'?')+'_='+Date.now(),{cache:'no-store',credentials:'same-origin'});}
function pollAnalysis(button,sawCollecting,deadline){
  if(Date.now()>deadline){setRunState(button,'Run analysis',false);alert('Analysis did not finish within 20 minutes. The previous report remains available.');return;}
  Promise.all([
    fetchNoCache('/monitor-results/.lldpq-stale').then(function(response){return response.ok?response.text():'';}).catch(function(){return '';}),
    fetchNoCache('/monitor-results/duplicate-analysis.html').then(function(response){return response.ok?response.text():'';}).catch(function(){return '';})
  ]).then(function(values){
    var marker=values[0],report=values[1],collecting=/^status=collecting$/m.test(marker),stale=/^status=stale$/m.test(marker);sawCollecting=sawCollecting||collecting;
    if(stale&&sawCollecting){setRunState(button,'Run analysis',false);var reason=(marker.match(/^reason=(.*)$/m)||[])[1]||'monitoring failed';alert('Analysis failed: '+reason+'. Last-known-good report was preserved.');return;}
    if(report){var doc=new DOMParser().parseFromString(report,'text/html'),epoch=Number(doc.body&&doc.body.getAttribute('data-generated-epoch'));if(epoch>GENERATED_EPOCH&&!collecting){location.reload();return;}}
    setRunState(button,collecting?'Collecting…':'Queued…',true);setTimeout(function(){pollAnalysis(button,sawCollecting,deadline);},3000);
  }).catch(function(){setTimeout(function(){pollAnalysis(button,sawCollecting,deadline);},4000);});
}
function runAnalysis(){
  var button=document.getElementById('run-analysis');setRunState(button,'Requesting…',true);
  fetch('/trigger-monitor',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin'}).then(function(response){if(!response.ok)throw new Error('HTTP '+response.status);return response.json();}).then(function(data){if(!data||data.status!=='success')throw new Error((data&&data.message)||'request rejected');pollAnalysis(button,false,Date.now()+20*60*1000);}).catch(function(error){setRunState(button,'Run analysis',false);alert('Could not trigger analysis: '+error.message);});
}

var deviceAliases={};
function refreshDeviceOptions(){
  var aliasesOn=true;try{aliasesOn=localStorage.getItem('lldpq_port_alias_on')!=='false';}catch(error){}
  var select=document.getElementById('deviceFilter'),selected=select.value;select.innerHTML='<option value="">All devices</option>';
  DEVICES.forEach(function(device){var option=document.createElement('option'),alias=deviceAliases[String(device).toLowerCase()];option.value=device;option.textContent=(aliasesOn&&alias)?(alias+' ('+device+')'):device;select.appendChild(option);});select.value=selected;
}
function loadDeviceAliases(){fetch('/display-aliases.json',{cache:'no-store'}).then(function(response){return response.ok?response.json():{};}).then(function(data){var map=(data&&data.devices)||{};Object.keys(map).forEach(function(key){deviceAliases[String(key).toLowerCase()]=map[key];});refreshDeviceOptions();}).catch(refreshDeviceOptions);}

document.addEventListener('DOMContentLoaded',function(){
  loadDeviceAliases();applyFilters();
  document.querySelectorAll('.summary-card[data-card-filter]').forEach(function(card){card.addEventListener('click',function(){activateCard(card);});});
  document.querySelectorAll('.dup-table th').forEach(function(th){th.setAttribute('role','button');if(!th.hasAttribute('tabindex'))th.setAttribute('tabindex','0');th.addEventListener('click',function(){sortTable(th);});th.addEventListener('keydown',function(event){if(event.key==='Enter'||event.key===' '){event.preventDefault();sortTable(th);}});});
  document.getElementById('deviceFilter').addEventListener('change',function(){filterState.device=this.value;applyFilters();});
  document.getElementById('clearFiltersButton').addEventListener('click',clearFilters);
  document.getElementById('agedButton').addEventListener('click',function(){filterState.showHistorical=!filterState.showHistorical;this.setAttribute('aria-pressed',filterState.showHistorical?'true':'false');this.textContent=(filterState.showHistorical?'Hide':'Show')+' historical (__AGED_COUNT__)';applyFilters();});
  document.getElementById('exportViewButton').addEventListener('click',function(){exportCSV(true);});document.getElementById('exportAllButton').addEventListener('click',function(){exportCSV(false);});
  document.getElementById('thresholdButton').addEventListener('click',openDialog);document.querySelector('#thresholdModal .modal-close').addEventListener('click',closeDialog);document.getElementById('thresholdModal').addEventListener('click',function(event){if(event.target===this)closeDialog();});
  document.getElementById('run-analysis').addEventListener('click',runAnalysis);
  document.addEventListener('click',function(event){if(event.target&&event.target.id==='p2pAliasToggle')setTimeout(refreshDeviceOptions,30);});
});
window.addEventListener('storage',function(event){if(event.key==='lldpq_port_alias_on')refreshDeviceOptions();});
document.addEventListener('keydown',function(event){if(event.key==='Escape'&&document.getElementById('thresholdModal').classList.contains('show'))closeDialog();});
})();
</script>
<script src="/p2p-alias.js"></script>
<script src="/css/analysis-guard.js"></script>
</body>
</html>'''
