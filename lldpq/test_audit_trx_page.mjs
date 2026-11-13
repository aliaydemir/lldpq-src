// Transceiver page: one physical module is one module, however many breakout
// ports it serves.
//
// The inventory has one row per port, and every breakout sibling of a cage
// reports the same module. Counted per row, a module split 4x outvoted three
// unsplit ones: the page took the split module's firmware for the majority and
// put the "mixed" badge on the modules that were on the real majority version.
// "Total Modules", the coverage badges and the Analysis Scope totals were
// port counts as well.
//
// The real processor builds the inventory, the real page script renders it in
// node:vm, and the real lifecycle-scope.js scopes the rows the page rendered.
// All vendor, part and serial values are invented.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const read = path => fs.readFileSync(new URL('../' + path, import.meta.url), 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));

// leaf1: one module split 4x on firmware 4.0.0 and three unsplit modules on
// 4.0.1. leaf2: one twin-port module split 2x on a host that was not reached.
const built = spawnSync('python3', ['-c', `
import contextlib, io, sys, tempfile
from pathlib import Path
from unittest import mock
sys.path.insert(0, ${JSON.stringify(new URL('.', import.meta.url).pathname)})
import process_transceiver_data as transceiver

def block(interface, serial):
    return (f"--- Interface: {interface}\\nInterface state: up\\n"
            "\\tIdentifier : 0x19 (OSFP 8X Pluggable Transceiver)\\n"
            "\\tVendor name : ACME\\n\\tVendor PN : PN-EXAMPLE-DR4\\n"
            f"\\tVendor rev : A3\\n\\tVendor SN : {serial}\\n"
            "\\tConnector : 0x28 (MPO 2x12)\\n")

with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    (root / 'optical-data').mkdir()
    (root / 'transceiver-data').mkdir()
    (root / 'optical-data' / 'leaf1_optical.txt').write_text(
        ''.join(block(f'swp3s{i}', 'SN-EX-0001') for i in range(4))
        + block('swp5', 'SN-EX-0002') + block('swp6', 'SN-EX-0003')
        + block('swp7', 'SN-EX-0004'))
    (root / 'transceiver-data' / 'leaf1_transceiver.txt').write_text(
        'swp3|FW Version : 4.0.0\\nswp5|FW Version : 4.0.1\\n'
        'swp6|FW Version : 4.0.1\\nswp7|FW Version : 4.0.1\\n')
    (root / 'optical-data' / 'leaf2_optical.txt').write_text(
        block('swp1s0', 'SN-EX-0010') + block('swp1s1', 'SN-EX-0010'))
    with mock.patch.object(transceiver, '_inventory_hostnames', return_value=None), \\
         contextlib.redirect_stdout(io.StringIO()):
        transceiver.process_transceiver_data(
            str(root / 'optical-data'), str(root / 'transceiver-data'), str(root))
    print((root / 'transceiver_inventory.json').read_text())
`], { encoding: 'utf8', env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
assert.equal(built.status, 0, built.stderr);
const inventory = JSON.parse(built.stdout);

// The same collection as an inventory file written before the fix: no module
// on the rows, no port count, and every total counted once per row.
function writtenBeforeTheFix() {
    const rows = inventory.modules.map(({ module, ...row }) => row);
    const fwVersions = {}, statusCounts = {};
    for (const row of rows) {
        if (row.fw_version) {
            const versions = fwVersions[row.part_number] || (fwVersions[row.part_number] = {});
            versions[row.fw_version] = (versions[row.fw_version] || 0) + 1;
        }
        statusCounts[row.fw_status] = (statusCounts[row.fw_status] || 0) + 1;
    }
    const { total_ports, ...summary } = inventory.summary;
    return { ...inventory, modules: rows, summary: {
        ...summary, total_modules: rows.length, fw_versions: fwVersions, status_counts: statusCounts } };
}

const pageScript = read('html/transceiver.html').match(/<script>([\s\S]*?)<\/script>/)[1];

// Loads the page script on `data` and returns what the operator would see.
async function page(data) {
    const elements = new Map();
    const element = id => {
        if (!elements.has(id)) {
            elements.set(id, {
                value: '', textContent: '', innerHTML: '', className: '',
                options: [{ outerHTML: '<option value="">All</option>' }],
                insertAdjacentHTML(_where, html) { this.innerHTML += html; },
            });
        }
        return elements.get(id);
    };
    const downloads = [];
    const context = vm.createContext({
        console, setTimeout, clearTimeout,
        requestAnimationFrame: () => 0, cancelAnimationFrame() {},
        fetch: async () => ({ json: async () => structuredClone(data) }),
        Blob: class { constructor(parts) { this.text = parts.join(''); } },
        URL: { createObjectURL: blob => { downloads.push(blob.text); return 'blob:test'; }, revokeObjectURL() {} },
        document: {
            getElementById: element, addEventListener() {}, querySelectorAll: () => [],
            createElement: () => ({ click() {} }),
        },
    });
    vm.runInContext(pageScript, context);
    await context.loadData();
    await settle();
    return {
        text: id => String(element(id).textContent),
        banner: () => element('coverage-banner').innerHTML,
        rows: () => tableRows(element('module-table').innerHTML),
        search(text) { element('filter-search').value = text; context.renderTable(); return this.rows(); },
        csv: () => { context.downloadCSV(); return downloads.at(-1); },
    };
}

const decode = text => text.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'").replace(/&amp;/g, '&');

// The rendered <tr> elements as plain objects: attributes and cell texts.
function tableRows(html) {
    return html.split('<tr ').slice(1).map(chunk => {
        const attributes = {};
        for (const [, name, value] of chunk.slice(0, chunk.indexOf('>')).matchAll(/([\w-]+)="([^"]*)"/g)) {
            attributes[name] = decode(value);
        }
        const cells = Array.from(chunk.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g),
            match => decode(match[1].replace(/<[^>]+>/g, '')).trim());
        return { attributes, cells, device: cells[0], port: cells[1], firmware: cells[7] };
    });
}

const mixedPorts = rows => rows.filter(row => /mixed/.test(row.firmware)).map(row => row.port);
const splitPorts = ['swp3s0', 'swp3s1', 'swp3s2', 'swp3s3'];

test('the firmware majority is taken per module: one split module does not outvote three', async () => {
    assert.deepEqual(inventory.summary.fw_versions, { 'PN-EXAMPLE-DR4': { '4.0.0': 1, '4.0.1': 3 } });
    const view = await page(inventory);
    const rows = view.rows();

    assert.equal(rows.length, 9);
    // The odd one out is the split module, on each of its four ports.
    assert.deepEqual(mixedPorts(rows), splitPorts);
    for (const row of rows.filter(row => ['swp5', 'swp6', 'swp7'].includes(row.port))) {
        assert.equal(row.firmware, '4.0.1');
    }
});

test('an inventory file written before the fix is read per module as well', async () => {
    const stale = writtenBeforeTheFix();
    assert.equal(stale.summary.total_modules, 9);
    assert.deepEqual(stale.summary.fw_versions, { 'PN-EXAMPLE-DR4': { '4.0.0': 4, '4.0.1': 3 } });
    const view = await page(stale);
    const rows = view.rows();

    assert.deepEqual(mixedPorts(rows), splitPorts);
    assert.equal(view.text('total-modules'), '5');
    assert.equal(view.text('total-ports'), '9');
    assert.match(view.banner(), />4 ok</);
    assert.match(view.banner(), /Partial coverage<\/strong> — 1 unreachable /);
    // The rows name the same modules the processor names today.
    assert.deepEqual(rows.map(row => row.attributes['data-module']).sort(),
        inventory.modules.map(row => row.module).sort());
});

test('the card and the CSV header show modules and ports', async () => {
    const view = await page(inventory);

    assert.equal(view.text('total-modules'), '5');
    assert.equal(view.text('total-ports'), '9');
    assert.match(read('html/transceiver.html'),
        /<div class="card-value" id="total-modules">-<\/div>\s*<div class="card-label">Total Modules \(<span id="total-ports">-<\/span> ports\)<\/div>/);
    const header = view.csv().split('\n').filter(line => line.startsWith('#'));
    assert.ok(header.includes('# Total Modules: 5'), header.join('\n'));
    assert.ok(header.includes('# Total Ports: 9'), header.join('\n'));
    assert.ok(header.includes('# Status ok: 4'), header.join('\n'));
    assert.ok(header.includes('# Status unreachable: 1'), header.join('\n'));
    // One CSV line per port, as before.
    assert.equal(view.csv().split('\n').filter(line => line.startsWith('"leaf')).length, 9);
});

test('the coverage banner counts modules, not ports', async () => {
    const banner = (await page(inventory)).banner();

    assert.match(banner, /Partial coverage<\/strong> — 1 unreachable \(these modules have no firmware data\)/);
    assert.match(banner, /<span class="cov-badge">4 ok<\/span>/);
    assert.match(banner, /<span class="cov-badge">1 failed\/unreachable<\/span>/);
});

test('every port row names its module and the sub-ports stay searchable', async () => {
    const view = await page(inventory);
    const rows = view.rows();

    assert.deepEqual(rows.map(row => [row.device, row.port, row.attributes['data-module']]), [
        ...splitPorts.map(port => ['leaf1', port, 'leaf1/swp3/SN-EX-0001']),
        ['leaf1', 'swp5', 'leaf1/swp5/SN-EX-0002'],
        ['leaf1', 'swp6', 'leaf1/swp6/SN-EX-0003'],
        ['leaf1', 'swp7', 'leaf1/swp7/SN-EX-0004'],
        ['leaf2', 'swp1s0', 'leaf2/swp1/SN-EX-0010'],
        ['leaf2', 'swp1s1', 'leaf2/swp1/SN-EX-0010'],
    ]);
    assert.deepEqual(view.search('swp3s2').map(row => row.port), ['swp3s2']);
    assert.deepEqual(view.search('sn-ex-0010').map(row => row.port), ['swp1s0', 'swp1s1']);
});

// Runs the real lifecycle-scope.js on the Transceiver page with `rows` (as
// rendered by the page) in the module table and `selected` as the hosts of the
// chosen Analysis Scope. Returns the summary card texts it wrote.
async function scopedCards(rows, selected) {
    const classList = () => {
        const names = new Set();
        return { add: name => names.add(name), remove: name => names.delete(name),
            contains: name => names.has(name),
            toggle(name, on) { if (on) names.add(name); else names.delete(name); } };
    };
    const node = (textContent, attributes = {}) => ({
        textContent, classList: classList(),
        matches: () => false, querySelector: () => null, closest: () => null,
        getAttribute: name => (name in attributes ? attributes[name] : null),
        hasAttribute: name => name in attributes,
        setAttribute(name, value) { attributes[name] = String(value); },
        removeAttribute(name) { delete attributes[name]; },
    });
    const table = {
        tHead: { rows: [{ cells: ['Device', 'Port', 'Identifier', 'Vendor', 'Part Number',
            'Serial Number', 'Rev', 'FW Version', 'Cable-Byte130'].map(label => node(label + ' ▲')) }] },
        querySelector: () => null,
        querySelectorAll: () => tableRowNodes,
    };
    const tableRowNodes = rows.map(row => ({
        ...node('', { ...row.attributes }),
        dataset: 'data-module' in row.attributes ? { module: row.attributes['data-module'] } : {},
        cells: row.cells.map(text => node(text)),
        closest: () => table,
    }));
    const cards = Object.fromEntries(['total-modules', 'total-ports', 'unique-models', 'devices-count', 'mixed-fw']
        .map(id => [id, node('-')]));
    const document = {
        head: { appendChild() {} },
        body: { classList: classList(), insertBefore() {} },
        createElement: () => ({}),
        addEventListener() {},
        getElementById: () => null,
        querySelector: selector => cards[selector.slice(1)] || null,
        querySelectorAll(selector) {
            if (selector === 'table') return [table];
            if (selector === '#module-table > tr') return tableRowNodes;
            return [];
        },
    };
    const window = {};
    vm.runInNewContext(read('html/lifecycle-scope.js'), {
        window, document, console, setTimeout, clearTimeout,
        location: { pathname: '/transceiver.html' },
        sessionStorage: { getItem: () => 'commissioning' },
        MutationObserver: class { observe() {} disconnect() {} },
        fetch: async () => ({ ok: true, json: async () => ({ success: true,
            devices: ['leaf1', 'leaf2'].map(hostname => ({
                hostname, state: selected.includes(hostname) ? 'commissioning' : 'handed_over' })) }) }),
    });
    await settle();
    await settle();
    assert.ok(window.LLDPqLifecycleScope, 'lifecycle-scope.js did not load');
    return Object.fromEntries(Object.entries(cards).map(([id, card]) => [id, card.textContent]));
}

test('the Analysis Scope totals count a split module once and give the ports beside it', async () => {
    const rows = (await page(inventory)).rows();

    assert.deepEqual(await scopedCards(rows, ['leaf1']), {
        'total-modules': '4', 'total-ports': '7', 'unique-models': '1', 'devices-count': '1', 'mixed-fw': '1' });
    assert.deepEqual(await scopedCards(rows, ['leaf2']), {
        'total-modules': '1', 'total-ports': '2', 'unique-models': '1', 'devices-count': '1', 'mixed-fw': '0' });
    // Scoped to every host, the cards agree with the unscoped page.
    const all = await scopedCards(rows, ['leaf1', 'leaf2']);
    assert.equal(all['total-modules'], String(inventory.summary.total_modules));
    assert.equal(all['total-ports'], String(inventory.summary.total_ports));
});

test('a row without a module stamp still counts by itself under the Analysis Scope', async () => {
    const rows = (await page(inventory)).rows().map(row => {
        const { 'data-module': _module, ...attributes } = row.attributes;
        return { ...row, attributes };
    });

    const cards = await scopedCards(rows, ['leaf1']);
    assert.equal(cards['total-modules'], '7');
    assert.equal(cards['total-ports'], '7');
});

// A hand-built inventory in the format written before the fix: no module on
// the rows, no port count in the summary.
const oldRow = (port, serial, fields = {}) => ({
    device: 'leaf9', port, identifier: 'OSFP', vendor: 'ACME', part_number: 'PN-EXAMPLE-DR4',
    serial, vendor_rev: 'A3', connector: '', fw_version: '', cable_byte130: '',
    fw_status: 'ok', fw_status_detail: '', ...fields,
});
const oldInventory = rows => ({ last_update: '2026-01-01T00:00:00+00:00', modules: rows,
    summary: { total_modules: rows.length, unique_models: 1, devices_with_modules: 1,
        mixed_fw_models: [], fw_versions: {}, status_counts: {} } });

test('a serial with markup stays text inside the data-module attribute', async () => {
    // The key holds what the module itself reports as its serial number.
    const serial = '"><b onload=x>&';
    const html = await page(oldInventory([oldRow('swp1s0', serial), oldRow('swp1s1', serial)]));
    const rows = html.rows();
    assert.equal(rows.length, 2);
    assert.deepEqual(rows.map(row => row.attributes['data-module']),
        ['leaf9/swp1/' + serial, 'leaf9/swp1/' + serial]);
    // Nothing of the serial closed the attribute or opened a tag of its own.
    assert.deepEqual(rows.map(row => Object.keys(row.attributes).sort()),
        [['class', 'data-idx', 'data-module', 'onclick'], ['class', 'data-idx', 'data-module', 'onclick']]);
    assert.deepEqual(rows.map(row => row.cells.length), [9, 9]);
    assert.equal(html.text('total-modules'), '1');
});

test('of a module\'s rows the first one with a firmware version speaks for it', async () => {
    // One module on four ports: the first row has no version, the second and
    // the fourth disagree. Then a module without any version, one whose row
    // has no part number (a module, but of no model), and two more modules
    // of the model, one on each version.
    const data = oldInventory([
        oldRow('swp3s0', 'SN-EX-0001'),
        oldRow('swp3s1', 'SN-EX-0001', { fw_version: '4.0.1' }),
        oldRow('swp3s2', 'SN-EX-0001'),
        oldRow('swp3s3', 'SN-EX-0001', { fw_version: '4.0.2' }),
        oldRow('swp4', 'SN-EX-0002', { fw_status: 'no_data' }),
        oldRow('swp5', 'SN-EX-0003', { part_number: '', fw_version: '9.9.9' }),
        oldRow('swp6', 'SN-EX-0004', { fw_version: '4.0.2' }),
        oldRow('swp7', 'SN-EX-0005', { fw_version: '4.0.1', fw_status: undefined }),
    ]);
    data.summary.mixed_fw_models = ['PN-EXAMPLE-DR4'];
    const view = await page(data);

    assert.equal(view.text('total-modules'), '5');
    assert.equal(view.text('total-ports'), '8');
    const header = view.csv().split('\n').filter(line => line.startsWith('#'));
    // A row without a status counts as ok.
    assert.ok(header.includes('# Status ok: 4'), header.join('\n'));
    assert.ok(header.includes('# Status no-data: 1'), header.join('\n'));
    // swp3 counts once, with 4.0.1, which makes 4.0.1 the majority of the
    // model, two modules to one: the rows on 4.0.2 are the odd ones.
    assert.deepEqual(mixedPorts(view.rows()), ['swp3s3', 'swp6']);
});
