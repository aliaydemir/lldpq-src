// BER page under an Analysis Scope: the "Not Graded" card.
//
// The card shows one count and, under it, how many of those ports are still
// awaiting a traffic sample and how many are idle (unused or down). The page
// writes the fabric-wide numbers into #awaiting-ports / #idle-ports and stamps
// every idle row with data-idle="1". lifecycle-scope.js recounts the cards
// from the rows of the selected hosts, so it has to recount these two as
// well: a scoped "0 Not Graded" above "1 awaiting sample - 2 idle" would be
// the fabric's numbers under a scoped count.
//
// The real analyzer builds the page from collector files and the real
// lifecycle-scope.js rescopes its rows.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const read = path => fs.readFileSync(new URL('../' + path, import.meta.url), 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));

// leaf1: swp1 in service, swp2 still collecting a sample, swp3 never used,
// swp4 stopped after 400 packets. leaf2: swp1 in service, swp2 still
// collecting a sample. leaf3: one port in service.
const built = spawnSync('python3', ['-c', `
import contextlib, io, os, sys, tempfile
from pathlib import Path
sys.path.insert(0, ${JSON.stringify(new URL('.', import.meta.url).pathname)})
for name in ('LLDPQ_ASSETS_FILE', 'LLDPQ_DEVICES_FILE', 'LLDPQ_COLLECTION_STATUS_FILE',
             'LLDPQ_PIPELINE_ID', 'MONITOR_DATA_MAX_AGE_MINUTES'):
    os.environ.pop(name, None)
import process_ber_data

HEADER = ("Inter-|   Receive                                                |  Transmit\\n"
          " face |bytes    packets errs drop fifo frame compressed multicast|"
          "bytes    packets errs drop fifo colls carrier compressed\\n")

def capture(ports):
    rows = ["    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0"]
    for name, packets in ports.items():
        rows.append(f"{name:>6}: {packets * 1000} {packets} 0 0 0 0 0 0 "
                    f"{packets * 1000} {packets} 0 0 0 0 0 0")
    return HEADER + "\\n".join(rows) + "\\n"

with tempfile.TemporaryDirectory() as tmp:
    data = Path(tmp) / 'monitor-results' / 'ber-data'
    data.mkdir(parents=True)
    for cycle, stopped in enumerate((700, 900, 900), start=1):
        (data / 'leaf1_interface_errors.txt').write_text(capture({
            'swp1': cycle * 1000000, 'swp2': cycle * 100, 'swp3': 0, 'swp4': stopped}))
        (data / 'leaf2_interface_errors.txt').write_text(capture({
            'swp1': cycle * 1000000, 'swp2': cycle * 100}))
        (data / 'leaf3_interface_errors.txt').write_text(capture({'swp1': cycle * 1000000}))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            ok = process_ber_data.process_ber_data_files(str(data))
        assert ok, output.getvalue()
    print((data.parent / 'ber-analysis.html').read_text())
`], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' } });
assert.equal(built.status, 0, built.stderr);
const pageHtml = built.stdout;

// The port rows the analyzer rendered: attributes of each <tr class="ber-row">.
const portRows = Array.from(pageHtml.matchAll(/<tr class="ber-row"([^>]*)>/g), match => {
    const attributes = {};
    for (const [, name, value] of match[1].matchAll(/([\w-]+)="([^"]*)"/g)) attributes[name] = value;
    return attributes;
});
// The number the page itself printed into the element with this id.
const printed = id => {
    const match = pageHtml.match(new RegExp(`id="${id}"[^>]*>([^<]*)<`));
    assert.ok(match, `the BER page has no #${id}`);
    return match[1].trim();
};

test('the page prints the breakdown and stamps the idle rows', () => {
    assert.deepEqual(
        portRows.map(row => [row['data-port'], row['data-status'], row['data-idle'] || '']).sort(),
        [
            ['leaf1:swp1', 'excellent', ''],
            ['leaf1:swp2', 'unknown', ''],
            ['leaf1:swp3', 'unknown', '1'],
            ['leaf1:swp4', 'unknown', '1'],
            ['leaf2:swp1', 'excellent', ''],
            ['leaf2:swp2', 'unknown', ''],
            ['leaf3:swp1', 'excellent', ''],
        ]);
    assert.deepEqual(['unknown-ports', 'awaiting-ports', 'idle-ports'].map(printed), ['4', '2', '2']);
});

// Runs the real lifecycle-scope.js on the BER page rows with `selected` as the
// hosts of the chosen Analysis Scope. Returns the card texts it left behind;
// every card starts with the number the page printed.
async function scopedCards(selected, { withBreakdown = true } = {}) {
    const classList = () => {
        const names = new Set();
        return { add: name => names.add(name), remove: name => names.delete(name),
            contains: name => names.has(name),
            toggle(name, on) { if (on) names.add(name); else names.delete(name); } };
    };
    const node = (textContent, attributes = {}) => ({
        textContent, classList: classList(), attributes,
        matches: () => false, querySelector: () => null, closest: () => null,
        getAttribute: name => (name in attributes ? attributes[name] : null),
        hasAttribute: name => name in attributes,
        setAttribute(name, value) { attributes[name] = String(value); },
        removeAttribute(name) { delete attributes[name]; },
    });
    const table = {
        tHead: { rows: [{ cells: ['Device', 'Port', 'Status'].map(label => node(label)) }] },
        querySelector: () => null,
        querySelectorAll: () => rowNodes,
    };
    const rowNodes = portRows.map(row => ({
        ...node('', { ...row }),
        // What the browser derives from data-device-key / data-status / data-idle.
        dataset: { deviceKey: row['data-device-key'], status: row['data-status'],
            ...('data-idle' in row ? { idle: row['data-idle'] } : {}) },
        cells: [node(row['data-port'].split(':')[0]), node(row['data-port'].split(':')[1]),
            node(row['data-status'])],
        closest: () => table,
    }));
    const ids = ['total-ports', 'excellent-ports', 'good-ports', 'warning-ports', 'critical-ports',
        'unknown-ports'].concat(withBreakdown ? ['awaiting-ports', 'idle-ports'] : []);
    const cards = Object.fromEntries(ids.map(id => [id, node(printed(id))]));
    const document = {
        head: { appendChild() {} },
        body: { classList: classList(), insertBefore() {} },
        createElement: () => ({}),
        addEventListener() {},
        getElementById: () => null,
        querySelector: selector => cards[selector.slice(1)] || null,
        querySelectorAll(selector) {
            if (selector === 'table') return [table];
            if (selector === '#ber-table tbody > tr') return rowNodes;
            return [];
        },
    };
    const window = {};
    vm.runInNewContext(read('html/lifecycle-scope.js'), {
        window, document, console, setTimeout, clearTimeout,
        location: { pathname: '/ber-analysis.html' },
        sessionStorage: { getItem: () => 'commissioning' },
        MutationObserver: class { observe() {} disconnect() {} },
        fetch: async () => ({ ok: true, json: async () => ({ success: true,
            devices: ['leaf1', 'leaf2', 'leaf3'].map(hostname => ({
                hostname, state: selected.includes(hostname) ? 'commissioning' : 'handed_over' })) }) }),
    });
    await settle();
    await settle();
    assert.ok(window.LLDPqLifecycleScope, 'lifecycle-scope.js did not load');
    return Object.fromEntries(Object.entries(cards).map(([id, card]) => [id, card.textContent]));
}

const notGraded = cards => [cards['unknown-ports'], cards['awaiting-ports'], cards['idle-ports']];

test('the breakdown under Not Graded is recounted for the hosts of the scope', async () => {
    assert.deepEqual(notGraded(await scopedCards(['leaf1'])), ['3', '1', '2']);
    assert.deepEqual(notGraded(await scopedCards(['leaf2'])), ['1', '1', '0']);
    assert.deepEqual(notGraded(await scopedCards(['leaf3'])), ['0', '0', '0']);
    assert.deepEqual(notGraded(await scopedCards(['leaf2', 'leaf3'])), ['1', '1', '0']);
});

test('the two parts always add up to the scoped Not Graded count', async () => {
    for (const selected of [['leaf1'], ['leaf2'], ['leaf3'], ['leaf1', 'leaf3'], ['leaf1', 'leaf2', 'leaf3']]) {
        const [total, awaiting, idle] = notGraded(await scopedCards(selected)).map(Number);
        assert.equal(awaiting + idle, total, selected.join('+'));
    }
});

test('scoped to every host the card repeats what the page printed', async () => {
    const all = await scopedCards(['leaf1', 'leaf2', 'leaf3']);
    assert.deepEqual(notGraded(all), ['unknown-ports', 'awaiting-ports', 'idle-ports'].map(printed));
});

test('a BER page without the breakdown elements is still rescoped', async () => {
    // A page generated before the breakdown existed has no #awaiting-ports.
    const cards = await scopedCards(['leaf1'], { withBreakdown: false });
    assert.deepEqual([cards['total-ports'], cards['excellent-ports'], cards['unknown-ports']], ['4', '1', '3']);
});
