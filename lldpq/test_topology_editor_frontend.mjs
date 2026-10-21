import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const setupPage = fs.readFileSync(new URL('../html/setup.html', import.meta.url), 'utf8');
const resultsPage = fs.readFileSync(new URL('../html/lldp.html', import.meta.url), 'utf8');
const draft = 'graph topology {\n  "leaf-01":"swp1" -- "server-01":"eth0";\n}';
const revision = 'original-revision';

function response(data, status = 200) {
    return { ok: status >= 200 && status < 300, status, json: async () => data };
}

function htmlResponse(status) {
    return { ok: status >= 200 && status < 300, status, json: async () => { throw new SyntaxError('Unexpected token <'); } };
}

function deferred() {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return { promise, resolve };
}

function setupHarness(reply) {
    const elements = {
        'ta-topology': { value: draft, placeholder: '' },
        'save-topology': { disabled: false },
    };
    const cfg = {
        url: '/edit-topology', file: 'topology.dot', ta: 'ta-topology', st: 'st-topology',
        loaded: true, dirty: true, editVersion: 1, loadSeq: 0, opSeq: 0, revision,
    };
    const statuses = [];
    const done = [];
    const requests = [];
    const context = {
        FILES: { topology: cfg },
        document: { getElementById: id => elements[id] },
        window: { confirm: () => true },
        setStatus: (id, message, kind) => statuses.push({ id, message, kind }),
        markDone: (...args) => done.push(args),
        fetch: async (url, options) => { requests.push({ url, options }); return reply; },
    };
    const start = setupPage.indexOf('async function readEditorResponse(');
    const end = setupPage.indexOf('function downloadFile(', start);
    assert.ok(start >= 0 && end > start, 'execute the actual Setup editor functions');
    vm.runInNewContext(setupPage.slice(start, end), context);
    return {
        cfg, requests, done,
        save: () => context.saveFile('topology'),
        load: () => context.loadFile('topology', true),
        edit(value) { elements['ta-topology'].value = value; cfg.editVersion++; },
        get value() { return elements['ta-topology'].value; },
        get message() { return statuses.at(-1)?.message; },
        get disabled() { return elements['save-topology'].disabled; },
    };
}

function resultsHarness(reply) {
    let value = draft;
    let runs = 0;
    const requests = [];
    const timers = [];
    const elements = {
        topologyEditorStatus: { textContent: '' },
        topologyEditorModal: { style: { display: 'flex' } },
    };
    const context = {
        editor: { getValue: () => value, setValue: text => { value = text; } },
        document: { getElementById: id => elements[id] },
        runLLDPCheck: () => { runs++; },
        setTimeout: callback => { timers.push(callback); },
        fetch: async (url, options) => { requests.push({ url, options }); return reply; },
    };
    const start = resultsPage.indexOf('// ===== Topology Editor Functions =====');
    const end = resultsPage.indexOf('</script>', start);
    assert.ok(start >= 0 && end > start, 'execute the actual Results editor functions');
    vm.runInNewContext(resultsPage.slice(start, end) + `
        topologyEditorCM = editor;
        topologyRevision = ${JSON.stringify(revision)};
        resetReplacePanel = () => {};
        globalThis.getRevision = () => topologyRevision;
    `, context);
    return {
        requests, timers,
        save: () => context.saveTopologyOnly(),
        saveAndRun: () => context.saveTopologyAndRun(),
        load: () => context.openTopologyEditor(),
        get value() { return value; },
        get message() { return elements.topologyEditorStatus.textContent; },
        get revision() { return context.getRevision(); },
        get runs() { return runs; },
        get visible() { return elements.topologyEditorModal.style.display === 'flex'; },
    };
}

const failures = [
    ['Nginx HTML 413', () => htmlResponse(413), /HTTP 413.*server upload limit/i],
    ['proxy HTML 502', () => htmlResponse(502), /HTTP 502/],
    ['false success on HTTP 500', () => response({ success: true, content: 'wrong', revision: 'wrong' }, 500), /HTTP 500/],
    ['application size error', () => response({ success: false, error: 'topology.dot exceeds the 10 MiB limit' }, 413), /topology\.dot exceeds the 10 MiB limit/],
    ['invalid DOT', () => response({ success: false, error: 'Invalid topology syntax' }, 400), /Invalid topology syntax/],
    ['revision conflict', () => response({ success: false, conflict: true, error: 'topology.dot changed on disk.' }, 409), /changed.*(disk|loaded)/],
    ['application error on HTTP 200', () => response({ success: false, error: 'Cannot write topology.dot' }), /Cannot write topology\.dot/],
    ['HTML instead of JSON on HTTP 200', () => htmlResponse(200), /HTTP 200/],
    ['null JSON response', () => response(null), /HTTP 200/],
];

for (const [label, reply, message] of failures) {
    test(`Setup save: ${label} preserves draft, revision and dirty state`, async () => {
        const h = setupHarness(reply());
        await h.save();
        assert.match(h.message, message);
        assert.equal(h.value, draft);
        assert.equal(h.cfg.revision, revision);
        assert.equal(h.cfg.dirty, true);
        assert.equal(h.disabled, false);
        assert.equal(h.done.length, 0);
    });
    for (const action of ['save', 'saveAndRun']) {
        test(`Results ${action}: ${label} preserves editor and cannot start a scan`, async () => {
            const h = resultsHarness(reply());
            await h[action]();
            assert.match(h.message, message);
            assert.equal(h.value, draft);
            assert.equal(h.revision, revision);
            assert.equal(h.runs, 0);
            assert.equal(h.visible, true);
            assert.equal(h.timers.length, 0);
        });
    }
}

for (const [label, reply, message] of failures.filter(([label]) => label !== 'revision conflict')) {
    test(`editor load: ${label} cannot replace existing content`, async () => {
        const setup = setupHarness(reply());
        await setup.load();
        assert.match(setup.message, message);
        assert.equal(setup.value, draft);
        assert.equal(setup.cfg.dirty, true);
        assert.equal(setup.cfg.revision, revision);
        const results = resultsHarness(reply());
        await results.load();
        assert.match(results.message, message);
        assert.equal(results.value, draft);
        assert.equal(results.revision, null);
        await results.saveAndRun();
        assert.equal(results.runs, 0);
        assert.equal(results.requests.length, 1, 'failed initial load cannot supply a revision for Save');
    });
}

test('Setup initial load failure cannot enable Save without a revision', async () => {
    const h = setupHarness(htmlResponse(502));
    h.cfg.loaded = false;
    h.cfg.revision = null;
    await h.load();
    await h.save();
    assert.equal(h.requests.length, 1);
    assert.equal(h.cfg.loaded, false);
    assert.match(h.message, /before saving/);
});

test('successful saves send the complete draft and update the optimistic revision', async () => {
    const saved = { success: true, revision: 'saved-revision' };
    const setup = setupHarness(response(saved));
    await setup.save();
    assert.equal(setup.cfg.dirty, false);
    assert.equal(setup.cfg.revision, saved.revision);
    assert.match(setup.message, /Saved topology\.dot/);
    assert.deepEqual(JSON.parse(setup.requests[0].options.body), { content: draft, expected_revision: revision });
    for (const action of ['save', 'saveAndRun']) {
        const results = resultsHarness(response(saved));
        await results[action]();
        assert.equal(results.revision, saved.revision);
        assert.equal(results.runs, action === 'saveAndRun' ? 1 : 0);
        assert.equal(results.visible, action !== 'saveAndRun');
        assert.deepEqual(JSON.parse(results.requests[0].options.body), { content: draft, expected_revision: revision });
    }
});

test('successful loads still populate both editors and their revisions', async () => {
    const loaded = { success: true, revision: 'loaded-revision', content: 'graph topology {}' };
    const setup = setupHarness(response(loaded));
    await setup.load();
    assert.equal(setup.value, loaded.content);
    assert.equal(setup.cfg.dirty, false);
    assert.equal(setup.cfg.revision, loaded.revision);
    const results = resultsHarness(response(loaded));
    await results.load();
    assert.equal(results.value, loaded.content);
    assert.equal(results.revision, loaded.revision);
});

test('Setup preserves edits made while successful save/load responses are pending', async () => {
    for (const action of ['save', 'load']) {
        const pending = deferred();
        const h = setupHarness(pending.promise);
        const operation = h[action]();
        h.edit('graph topology { "new" -- "draft"; }');
        pending.resolve(response({ success: true, revision: 'new-revision', content: 'older content' }));
        await operation;
        assert.equal(h.value, 'graph topology { "new" -- "draft"; }');
        assert.equal(h.cfg.dirty, true);
        assert.equal(h.cfg.revision, 'new-revision');
    }
});
