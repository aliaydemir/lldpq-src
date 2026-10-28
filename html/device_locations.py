"""Rack / unit imports and the common P2P + simple-mapping location join.

The join uses device hostnames, never display aliases or a guessed short name.
Conflicting complete locations are reported and omitted from the result.
"""

import csv
import io
import json
import os
import re
import time
import xml.etree.ElementTree as ET
import zipfile

import ai_p2p

FORMAT = 'lldpq-locations-v1'
MAX_ROWS = 100000
MAX_WORKBOOK_BYTES = 128 * 1024 * 1024
_DATE_CELL = object()
_EMPTY = {'', '-', 'n/a', 'na', 'none', 'null', 'tbd', 'unknown'}
_HEADERS = {
    'hostname': 'hostname', 'googlehostname': 'hostname',
    'devicename': 'hostname', 'device': 'hostname',
    'rack': 'rack', 'rackname': 'rack',
    'upos': 'unit', 'uposition': 'unit', 'ru': 'unit', 'unit': 'unit',
    'rackunit': 'unit', 'u': 'unit',
}


def _text(value):
    return '' if value is None else str(value).strip()


def normalize_unit(value):
    """A positive unit or inclusive ascending unit range, without guessing dates."""
    if value is _DATE_CELL:
        raise ValueError('U-Pos is an Excel date; format the cell as Text and re-enter the unit or range')
    raw = _text(value)
    # Excel stores an integer numeric cell as 6 or 6.0.
    if re.fullmatch(r'[0-9]+\.0+', raw):
        raw = raw.split('.')[0]
    raw = raw.replace('\u2013', '-').replace('\u2014', '-')
    match = re.fullmatch(r'([0-9]+)(?:\s*-\s*([0-9]+))?', raw)
    if not match:
        raise ValueError('U-Pos must be a positive unit or ascending range, such as 6 or 6-7 (not a date)')
    first, last = int(match[1]), int(match[2] or match[1])
    if first < 1 or last < first:
        raise ValueError('U-Pos must be positive and a range must be ascending')
    return str(first) if first == last else '%d-%d' % (first, last)


def _record(hostname, rack, unit):
    if hostname is _DATE_CELL or rack is _DATE_CELL:
        raise ValueError('Hostname and Rack must be text, not Excel dates')
    hostname, rack = _text(hostname), _text(rack)
    if hostname.lower() in _EMPTY or rack.lower() in _EMPTY:
        raise ValueError('Hostname, Rack and U-Pos are required')
    if any(c.isspace() for c in hostname) or any(ord(c) < 32 for c in rack):
        raise ValueError('Hostname cannot contain whitespace and Rack cannot contain control characters')
    return {'hostname': hostname, 'rack': rack, 'unit': normalize_unit(unit)}


def _collect(records, warnings=None, filename=''):
    by_host = {}
    warnings = list(warnings or [])
    for row, context in records:
        if len(by_host) >= MAX_ROWS:
            raise ValueError('mapping exceeds %d devices' % MAX_ROWS)
        try:
            record = _record(row.get('hostname'), row.get('rack'), row.get('unit'))
        except ValueError as exc:
            raise ValueError('%s: %s' % (context, exc)) from exc
        key = record['hostname'].lower()
        prior = by_host.get(key)
        if prior:
            if (prior['rack'].lower(), prior['unit']) != (record['rack'].lower(), record['unit']):
                raise ValueError('%s: conflicting locations for %s (%s / U%s and %s / U%s)' % (
                    context, record['hostname'], prior['rack'], prior['unit'], record['rack'], record['unit']))
            warnings.append('%s: duplicate location for %s was merged' % (context, record['hostname']))
            continue
        by_host[key] = record
    if not by_host:
        raise ValueError('No device locations found; include Hostname, Rack and U-Pos columns')
    return {'format': FORMAT, 'source_file': os.path.basename(filename),
            'generated_at': int(time.time()), 'locations': list(by_host.values()),
            'warnings': warnings}


def validate_design(data, filename=''):
    """Validate canonical uploads too, so JSON cannot bypass CSV validation."""
    if not isinstance(data, dict) or data.get('format') != FORMAT or not isinstance(data.get('locations'), list):
        raise ValueError('Location JSON must use format %s and a locations list' % FORMAT)
    records = []
    for i, row in enumerate(data['locations'], 1):
        if not isinstance(row, dict):
            raise ValueError('location %d must be an object' % i)
        records.append((row, 'location %d' % i))
    warnings = [str(w) for w in data.get('warnings', [])] if isinstance(data.get('warnings'), list) else []
    return _collect(records, warnings, filename or data.get('source_file', ''))


def _table_records(rows, name, warnings):
    columns = None
    records = []
    for rownum, values in rows:
        if rownum > MAX_ROWS:
            raise ValueError('%s exceeds %d rows' % (name, MAX_ROWS))
        if not any(_text(v) for v in values):
            continue
        if columns is None:
            found = {}
            for i, value in enumerate(values):
                key = _HEADERS.get(re.sub(r'[^a-z0-9]', '', _text(value).lower()))
                if key:
                    if key in found:
                        raise ValueError('%s row %d: duplicate %s column' % (name, rownum, key))
                    found[key] = i
            if all(key in found for key in ('hostname', 'rack', 'unit')):
                columns = found
            elif rownum >= 50:
                break
            continue
        row = {key: values[i] if i < len(values) else '' for key, i in columns.items()}
        # Formatting, notes or data outside the three selected columns are irrelevant.
        if not any(_text(v) for v in row.values()):
            continue
        records.append((row, '%s row %d' % (name, rownum)))
    if columns is None:
        warnings.append('%s: no Hostname / Rack / U-Pos header found; sheet skipped' % name)
    return records


def _date_styles(zf):
    """Find Excel date styles before numeric serials can be mistaken for RU."""
    try:
        root = ET.fromstring(zf.read('xl/styles.xml'))
    except KeyError:
        return set()
    ns = ai_p2p._M
    date_ids = set(range(14, 23)) | set(range(27, 37)) | set(range(45, 48)) | set(range(50, 59))
    for fmt in root.findall(ns + 'numFmts/' + ns + 'numFmt'):
        code = fmt.get('formatCode', '')
        code = re.sub(r'"[^"]*"|\\.|\[[^]]*\]', '', code).lower()
        if re.search(r'[ymdhs]', code):
            date_ids.add(int(fmt.get('numFmtId', '0')))
    return {i for i, xf in enumerate(root.findall(ns + 'cellXfs/' + ns + 'xf'))
            if int(xf.get('numFmtId', '0')) in date_ids}


def _xlsx_records(content, warnings):
    records = []
    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        if sum(info.file_size for info in zf.infolist()) > MAX_WORKBOOK_BYTES:
            raise ValueError('Expanded workbook exceeds 128 MiB')
        shared = ai_p2p._load_shared_strings(zf)
        dates = _date_styles(zf)
        ns = ai_p2p._M

        def sheet_rows(target):
            with zf.open(target) as stream:
                for _, elem in ET.iterparse(stream, events=('end',)):
                    if elem.tag != ns + 'row':
                        continue
                    rownum = int(elem.get('r', '0'))
                    cells = {}
                    for cell in elem.findall(ns + 'c'):
                        col = ai_p2p._col_ref_to_index(cell.get('r', 'A1'))
                        if col > 16383:
                            raise ValueError('Invalid Excel column reference')
                        value = ai_p2p._cell_value(cell, shared)
                        if value and (cell.get('t') == 'd' or
                                      (cell.get('t', 'n') == 'n' and int(cell.get('s', '0')) in dates)):
                            value = _DATE_CELL
                        cells[col] = value
                    yield rownum, [cells.get(i, '') for i in range(max(cells, default=-1) + 1)]
                    elem.clear()

        for name, target in ai_p2p._sheet_targets(zf):
            records.extend(_table_records(sheet_rows(target), name, warnings))
    return records


def parse_upload(content, filename):
    suffix = os.path.splitext(filename)[1].lower()
    if suffix == '.json':
        return validate_design(json.loads(content.decode('utf-8-sig')), filename)
    warnings = []
    if suffix == '.csv':
        text = content.decode('utf-8-sig')
        try:
            dialect = csv.Sniffer().sniff(text[:65536], delimiters=',;')
        except csv.Error:
            dialect = csv.excel
        records = _table_records(enumerate(csv.reader(io.StringIO(text), dialect), 1), 'CSV', warnings)
    elif suffix in ('.xlsx', '.xlsm'):
        records = _xlsx_records(content, warnings)
    else:
        raise ValueError('Rack / Unit Mapping accepts .csv, .xlsx or .xlsm files')
    return _collect(records, warnings, filename)


def resolve_locations(p2p_design, location_design):
    """Return only unambiguous complete device locations, plus all conflicts.

    P2P is the source when both sources agree. Missing/incomplete P2P entries
    do not prevent fallback to a simple mapping. Inputs are never modified.
    """
    candidates = {}

    def add(hostname, rack, unit, source):
        try:
            record = _record(hostname, rack, unit)
        except (ValueError, TypeError):
            return
        key = record['hostname'].lower()
        record['source'] = source
        entries = candidates.setdefault(key, [])
        identity = (record['rack'].lower(), record['unit'])
        if not any((r['rack'].lower(), r['unit']) == identity for r in entries):
            entries.append(record)

    connections = p2p_design.get('connections', []) if isinstance(p2p_design, dict) else []
    for conn in connections if isinstance(connections, list) else []:
        if not isinstance(conn, dict):
            continue
        for side in ('source', 'dest'):
            add(conn.get(side + '_name'), conn.get(side + '_rack'), conn.get(side + '_ru'), 'p2p')
    rows = location_design.get('locations', []) if isinstance(location_design, dict) else []
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, dict):
            add(row.get('hostname'), row.get('rack'), row.get('unit'), 'locations')
    locations, conflicts = {}, []
    for key, entries in candidates.items():
        if len(entries) == 1:
            locations[key] = entries[0]
        else:
            hostname = entries[0]['hostname']
            conflicts.append({'hostname': hostname, 'message': 'Conflicting Rack / Unit locations for %s: %s' % (
                hostname, '; '.join('%s / U%s (%s)' % (r['rack'], r['unit'], r['source']) for r in entries)),
                'locations': entries})
    return {'locations': locations, 'conflicts': conflicts}
