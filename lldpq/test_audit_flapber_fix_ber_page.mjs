// BER page: the "Not Graded" card counts two kinds of ports, and the page
// script and the Analysis Scope have to keep them apart.
//
// * The card filter must say how many of the listed ports are awaiting a
//   traffic sample and how many are idle (unused or down).
// * Under an Analysis Scope, lifecycle-scope.js recounts the card from the
//   visible rows but knows nothing of the breakdown under it, so the page
//   hides that line for as long as the card is rescoped.
//
// The real analyzer builds the page from collector files, its own inline
// script runs in node:vm, and the real lifecycle-scope.js rescopes the cards.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const read = path => fs.readFileSync(new URL('../' + path, import.meta.url), 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));

// leaf1: swp1 in service, swp2 still collecting a sample, swp3 never used,
// swp4 stopped after 400 packets. leaf2: one port in service.
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
        (data / 'leaf2_interface_errors.txt').write_text(capture({'swp1': cycle * 1000000}))
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
const port = row => row['data-port'];

test('the page lists the two kinds of ungraded ports apart', () => {
    assert.deepEqual(
        portRows.map(row => [port(row), row['data-status'], row['data-idle'] || '']).sort(),
        [
            ['leaf1:swp1', 'excellent', ''],
            ['leaf1:swp2', 'unknown', ''],
            ['leaf1:swp3', 'unknown', '1'],
            ['leaf1:swp4', 'unknown', '1'],
            ['leaf2:swp1', 'excellent', ''],
        ]);
});

// Runs the page's own inline scripts and returns its filterPorts() together
// with what it wrote: the filter line and the rows left visible.
function pageFilter() {
    const scripts = Array.from(
        pageHtml.matchAll(/<script(?![^>]*\bsrc=)(?![^>]*text\/html)[^>]*>([\s\S]*?)<\/script>/g),
        match => match[1]);
    assert.ok(scripts.some(script => script.includes('function filterPorts')));
    const elements = new Map();
    const element = id => {
        if (!elements.has(id)) {
            elements.set(id, {
                id, style: {}, textContent: '', value: '',
                classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
                addEventListener() {}, appendChild() {}, querySelectorAll: () => [],
            });
        }
        return elements.get(id);
    };
    // jQuery and select2 are not under test: every call returns the stub.
    const chain = new Proxy(function () {}, {
        get: (_target, key) => (key === Symbol.toPrimitive ? () => '' : chain),
        apply: () => chain,
    });
    const window = { addEventListener() {} };
    const context = vm.createContext({
        window, console, $: chain, jQuery: chain,
        setTimeout() {}, clearTimeout() {}, requestAnimationFrame() {},
        fetch: () => new Promise(() => {}),
        localStorage: { getItem: () => null, setItem() {} },
        sessionStorage: { getItem: () => null, setItem() {} },
        location: { pathname: '/ber-analysis.html', search: '', hash: '' },
        navigator: {},
        document: {
            getElementById: element, querySelector: () => null, querySelectorAll: () => [],
            addEventListener() {}, createElement: () => element('created'),
            body: element('body'),
        },
    });
    for (const script of scripts) vm.runInContext(script, context);
    context.stubRows = portRows.map(row => ({
        port: port(row), style: {},
        dataset: { status: row['data-status'], ...(row['data-idle'] ? { idle: row['data-idle'] } : {}) },
    }));
    vm.runInContext('allRows = stubRows;', context);
    return filterType => {
        vm.runInContext(`filterPorts(${JSON.stringify(filterType)});`, context);
        return {
            text: element('filter-text').textContent,
            shown: context.stubRows.filter(row => row.style.display !== 'none').map(row => row.port).sort(),
        };
    };
}

test('the Not Graded filter says how many ports are awaiting and how many are idle', () => {
    const filter = pageFilter();

    assert.deepEqual(filter('UNKNOWN'), {
        text: 'Showing 3 Ports Not Graded (1 awaiting sample, 2 idle)',
        shown: ['leaf1:swp2', 'leaf1:swp3', 'leaf1:swp4'],
    });
    // The other filters keep their wording.
    assert.deepEqual(filter('EXCELLENT'), {
        text: 'Showing 2 Excellent Ports', shown: ['leaf1:swp1', 'leaf2:swp1'],
    });
});

// Runs the real lifecycle-scope.js on the BER page rows with `selected` as the
// hosts of the chosen Analysis Scope. Returns the summary card nodes.
async function scopedCards(selected) {
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
        dataset: { deviceKey: row['data-device-key'], status: row['data-status'] },
        cells: [node(port(row).split(':')[0]), node(port(row).split(':')[1]), node(row['data-status'])],
        closest: () => table,
    }));
    const cards = Object.fromEntries(
        ['total', 'excellent', 'good', 'warning', 'critical', 'unknown']
            .map(grade => [grade + '-ports', node('-')]));
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
            devices: ['leaf1', 'leaf2'].map(hostname => ({
                hostname, state: selected.includes(hostname) ? 'commissioning' : 'handed_over' })) }) }),
    });
    await settle();
    await settle();
    assert.ok(window.LLDPqLifecycleScope, 'lifecycle-scope.js did not load');
    return cards;
}

test('the breakdown under Not Graded is hidden while an Analysis Scope recounts the card', async () => {
    // The card as generated: the count, its label, then the breakdown line.
    // All three are children of the card, so the line is a later sibling of
    // the count.
    assert.match(pageHtml,
        /<div class="summary-card card-info" id="unknown-card"[^>]*>\s*<div class="metric" id="unknown-ports">3<\/div>\s*<div class="metric-label">Not Graded<\/div>\s*<div class="metric-note"><span id="awaiting-ports">1<\/span> awaiting sample &middot; <span id="idle-ports">2<\/span> idle<\/div>\s*<\/div>/);

    // The scope recounts #unknown-ports and marks it as rescoped ...
    const cards = await scopedCards(['leaf2']);
    assert.equal(cards['total-ports'].textContent, '1');
    assert.equal(cards['unknown-ports'].textContent, '0');
    assert.equal(cards['unknown-ports'].attributes['data-lifecycle-original'], '-');
    const both = await scopedCards(['leaf1', 'leaf2']);
    assert.equal(both['unknown-ports'].textContent, '3');
    assert.ok('data-lifecycle-original' in both['unknown-ports'].attributes);

    // ... and that mark is what hides the line that was not recounted: the
    // rule keys on it and reaches the later sibling inside the same card.
    const style = pageHtml.match(/<style>([\s\S]*?)<\/style>/)[1];
    assert.match(style,
        /#unknown-ports\[data-lifecycle-original\]\s*~\s*\.metric-note\s*\{\s*display:\s*none;\s*\}/);
    // No other rule shows the line again.
    assert.equal(Array.from(style.matchAll(/\.metric-note\s*\{[^}]*\}/g))
        .filter(rule => /display/.test(rule[0])).length, 1);
});
