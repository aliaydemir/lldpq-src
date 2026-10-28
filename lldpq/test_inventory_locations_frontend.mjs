import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const html = readFileSync(new URL('../html/inventory.html', import.meta.url), 'utf8');
const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(match => match[1]).join('\n');

function page(handler) {
    const elements = new Map();
    function element(id) {
        if (!elements.has(id)) {
            const classes = new Set();
            elements.set(id, { innerHTML: '', textContent: '', className: '', disabled: false,
                classList: { add: value => classes.add(value), remove: value => classes.delete(value), contains: value => classes.has(value) } });
        }
        return elements.get(id);
    }
    const calls = [];
    const context = vm.createContext({
        document: { getElementById: element, querySelectorAll: () => [], addEventListener: () => {} },
        window: { confirm: () => true }, URLSearchParams, Blob, FormData, setTimeout,
        fetch: async (url, options = {}) => {
            const query = new URL(url, 'http://lldpq.test').searchParams;
            const call = { action: query.get('action'), query, body: options.body, options };
            calls.push(call);
            return { ok: true, status: 200, json: async () => handler(call) };
        },
    });
    vm.runInContext(script, context);
    return { context, element, calls };
}

function preview(overrides = {}) {
    return { success: true, version: 'v1', filename: 'rack.csv',
        rows: [{ hostname: 'switch-01', rack: 'C1', unit: '6-7', match: 'matched', conflict: false }],
        counts: { total: 1, matched: 1, unmatched: 0, conflicts: 0 }, conflicts: [], warnings: [],
        token: 'reviewed-v1', can_activate: true, ...overrides };
}

test('locations upload opens a preview without activating the mapping', async () => {
    const p = page(call => {
        if (call.action === 'upload') return { success: true, version: 'v1', filename: 'rack.csv' };
        if (call.action === 'list') return { success: true, versions: { locations: [{ version: 'v1', filename: 'rack.csv', summary: { total_locations: 1 } }] } };
        if (call.action === 'preview-locations') return preview();
        throw new Error('Unexpected action: ' + call.action);
    });
    const file = new Blob(['Hostname,Rack,U-Pos\nswitch-01,C1,6-7'], { type: 'text/csv' });
    file.name = 'rack.csv';
    await p.context.uploadDesign('locations', { files: [file], value: 'rack.csv' });
    assert.deepEqual(p.calls.map(c => c.action), ['upload', 'list', 'preview-locations']);
    assert.equal(p.element('pw-locations').classList.contains('show'), true);
    assert.equal(p.element('btn-apply-locations').disabled, false);
    assert.match(p.element('list-locations').innerHTML, /Preview/);
    assert.doesNotMatch(p.element('list-locations').innerHTML, /Use as Design/);
});

test('Use Mapping requires a preview token and sends the reviewed version only once', async () => {
    const p = page(call => {
        if (call.action === 'preview-locations') return preview();
        if (call.action === 'activate') return { success: true };
        if (call.action === 'list') return { success: true, versions: {} };
        throw new Error('Unexpected action: ' + call.action);
    });
    await p.context.applyLocationMapping();
    assert.equal(p.calls.length, 0);
    await p.context.activate('locations', 'v1');
    assert.equal(p.calls[0].action, 'preview-locations');
    await Promise.all([p.context.applyLocationMapping(), p.context.applyLocationMapping()]);
    const activations = p.calls.filter(c => c.action === 'activate');
    assert.equal(activations.length, 1);
    assert.deepEqual(JSON.parse(activations[0].body), { kind: 'locations', version: 'v1', confirm: 'reviewed-v1' });
    assert.equal(p.element('pw-locations').classList.contains('show'), false);
});

test('conflicts are shown and cannot be applied, even if can_activate is inconsistent', async () => {
    const p = page(() => preview({
        rows: [{ hostname: 'switch-01', rack: 'C2', unit: '6-7', match: 'matched', conflict: true }],
        counts: { total: 1, matched: 1, unmatched: 0, conflicts: 1 },
        conflicts: [{ hostname: 'switch-01', message: 'P2P has C1 / U6-7, mapping has C2 / U6-7' }],
    }));
    await p.context.previewLocations('v1');
    assert.match(p.element('location-preview-conflicts').innerHTML, /P2P has C1/);
    assert.match(p.element('location-preview-rows').innerHTML, /Conflicting locations/);
    assert.equal(p.element('btn-apply-locations').disabled, true);
    await p.context.applyLocationMapping();
    assert.equal(p.calls.length, 1);
});

test('unmatched hostnames stay visible and can be explicitly activated', async () => {
    const p = page(() => preview({
        rows: [{ hostname: '<unknown>', rack: 'C&1', unit: '6-7', match: 'unmatched', conflict: false }],
        counts: { total: 1, matched: 0, unmatched: 1, conflicts: 0 }, warnings: ['Hostname <unknown> is not in devices.yaml'],
    }));
    await p.context.previewLocations('v1');
    assert.match(p.element('location-preview-rows').innerHTML, /Unmatched hostname/);
    assert.match(p.element('location-preview-rows').innerHTML, /&lt;unknown&gt;/);
    assert.match(p.element('location-preview-warnings').innerHTML, /&lt;unknown&gt;/);
    assert.equal(p.element('btn-apply-locations').disabled, false);
});

test('late previews cannot replace a newer version or reopen a closed preview', async () => {
    const pending = new Map();
    const p = page(call => new Promise(resolve => pending.set(call.query.get('version'), resolve)));
    const old = p.context.previewLocations('v1');
    await new Promise(resolve => setImmediate(resolve));
    const recent = p.context.previewLocations('v2');
    await new Promise(resolve => setImmediate(resolve));
    pending.get('v2')(preview({ version: 'v2', filename: 'new.csv', token: 'v2-token' }));
    await recent;
    pending.get('v1')(preview());
    await old;
    assert.equal(p.element('location-preview-name').textContent, 'new.csv');
    const closed = p.context.previewLocations('v3');
    await new Promise(resolve => setImmediate(resolve));
    p.context.clearLocationPreview();
    pending.get('v3')(preview({ version: 'v3' }));
    await closed;
    assert.equal(p.element('pw-locations').classList.contains('show'), false);
    assert.equal(p.element('btn-apply-locations').disabled, true);
});

test('a stale or failed activation requires a new preview before another attempt', async () => {
    const p = page(call => call.action === 'preview-locations' ? preview()
        : { success: false, error: 'confirm token missing or stale' });
    await p.context.previewLocations('v1');
    await p.context.applyLocationMapping();
    await p.context.applyLocationMapping();
    assert.equal(p.calls.filter(c => c.action === 'activate').length, 1);
    assert.equal(p.element('btn-apply-locations').disabled, true);
    assert.match(p.element('st-location-preview').textContent, /Preview the mapping again/);
});

test('existing design cards retain activation, while active locations remain previewable', () => {
    const p = page(() => ({ success: true }));
    const version = { version: 'v1', filename: "rack's mapping.csv", summary: {} };
    p.context.renderVersions('p2p', [version]);
    p.context.renderVersions('ipam', [version]);
    p.context.renderVersions('locations', [{ ...version, active: true }]);
    assert.match(p.element('list-p2p').innerHTML, /Use as Design/);
    assert.match(p.element('list-ipam').innerHTML, /Use as Design/);
    assert.match(p.element('list-locations').innerHTML, /Preview/);
    assert.match(p.element('list-locations').innerHTML, /Active/);
    assert.doesNotMatch(p.element('list-locations').innerHTML, />Del</);
    assert.match(p.element('list-p2p').innerHTML, /rack&#39;s mapping.csv/);
});

test('P2P location warnings are visible without changing its activation workflow', async () => {
    const p = page(call => call.action === 'activate'
        ? { success: true, warnings: ['Ambiguous locations were omitted.'], conflicts: [{ hostname: 'switch-01', message: 'switch-01: C1 conflicts with C2' }] }
        : { success: true, versions: {} });
    await p.context.activate('p2p', 'p2p-v1');
    assert.deepEqual(JSON.parse(p.calls[0].body), { kind: 'p2p', version: 'p2p-v1' });
    assert.match(p.element('st-p2p').textContent, /Active design set/);
    assert.match(p.element('st-p2p').textContent, /Ambiguous locations were omitted/);
    assert.match(p.element('st-p2p').textContent, /C1 conflicts with C2/);
});
