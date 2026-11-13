// Setup page status lines for two replies that are a success with a caveat.
//
// Setup → Run LLDPq on an inventory without devices: bin/lldpq prints one line
// and exits 0 before it collects anything. The page reported "Done ✓ — Fabric /
// LLDP / Analysis pages are now up to date." above a log saying that nothing
// was collected. Setup → Backup & Restore: the export leaves a devices.yaml
// without devices out of the bundle and says so under "warnings", which the
// page did not show. The real page code is run in node:vm.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const read = path => fs.readFileSync(new URL('../' + path, import.meta.url), 'utf8');
const setup = read('html/setup.html');
const flush = async () => { for (let i = 0; i < 10; i++) await new Promise(resolve => setImmediate(resolve)); };

function fragment(start, end) {
    const from = setup.indexOf(start);
    assert.notEqual(from, -1, 'not found: ' + start);
    const to = setup.indexOf(end, from);
    assert.notEqual(to, -1, 'not found: ' + end);
    return setup.slice(from, to);
}

// The page with the given reply per API action; records every status line.
function setupPage(replies) {
    const status = [], done = [], elements = {};
    const element = id => elements[id] ||= { textContent: '', disabled: false, checked: false,
        scrollHeight: 0, scrollTop: 0, clientHeight: 0, click() {}, remove() {} };
    const context = vm.createContext({
        setTimeout: () => 0, clearTimeout() {}, atob, Uint8Array, Blob,
        URL: { createObjectURL: () => 'blob:bundle', revokeObjectURL() {} },
        fetch: async (url, options) => {
            const reply = replies[JSON.parse(options.body).action];
            assert.ok(reply, 'unexpected request: ' + options.body);
            return { json: async () => reply };
        },
        document: { getElementById: element, createElement: () => element('download-link'),
            body: { appendChild() {} } },
        setStatus: (id, message, cls) => status.push({ id, message, cls }),
        markDone: (step, isDone) => done.push([step, isDone]),
    });
    vm.runInContext('let runActive = false, runPollTimer = null, runJobId = null, runPollEpoch = 0;', context);
    vm.runInContext(fragment('/* ---- Step 8: Run LLDPq', '/* ---- Step 11: Update LLDPq'), context);
    vm.runInContext(fragment('async function backupExport(){', 'async function backupImport(){'), context);
    return { context, status, done, element };
}

// What bin/lldpq prints for an inventory without devices, in the image's tree.
const nothingCollected = (() => {
    const line = read('bin/lldpq').match(/^    echo "(No devices in \$LLDPQ_DIR\/devices\.yaml yet, [^"]*)"$/m);
    assert.ok(line, 'the no-devices line of bin/lldpq was not found');
    return line[1].replace('$LLDPQ_DIR', '/home/lldpq/lldpq');
})();
const job = 'a'.repeat(32);
const finished = (log, exitCode) => ({ success: true, done: true, ok: exitCode === 0, running: false,
    pid_recorded: false, job_id: job, stale_reservation: false, exit_code: exitCode, log });

// Run LLDPq clicked, then the page reopened on the same finished run.
async function runThenReopen(reply) {
    const page = setupPage({ run: { success: true, job_id: job }, 'run-log': reply });
    await page.context.runLLDPq();
    await flush();
    const clicked = { ...page.status.at(-1), done: page.done.at(-1), log: page.element('run-output').textContent };
    await page.context.showRunLog();
    await flush();
    return { clicked, reopened: { ...page.status.at(-1), done: page.done.at(-1) } };
}

test('Run LLDPq on an inventory without devices does not report refreshed pages', async () => {
    const { clicked, reopened } = await runThenReopen(finished(nothingCollected, 0));
    assert.equal(clicked.log, nothingCollected);
    for (const shown of [clicked, reopened]) {
        assert.equal(shown.id, 'run-status');
        assert.notEqual(shown.cls, 'ok');
        assert.notEqual(shown.cls, 'err');
        assert.match(shown.message, /no devices/);
        assert.doesNotMatch(shown.message, /up to date|successfully|✓/);
        assert.deepEqual(shown.done, ['run', false]);
    }
});

test('Run LLDPq that collected, or failed, reports what it did before', async () => {
    const collected = await runThenReopen(finished('Asset discovery...\nNo devices in maintenance.\nDone', 0));
    assert.deepEqual(collected.clicked, { id: 'run-status', cls: 'ok', done: ['run', true],
        message: 'Done ✓ — Fabric / LLDP / Analysis pages are now up to date.',
        log: 'Asset discovery...\nNo devices in maintenance.\nDone' });
    assert.deepEqual(collected.reopened, { id: 'run-status', cls: 'info', done: ['run', true],
        message: 'Last run finished successfully.' });

    const failed = await runThenReopen(finished('Asset discovery failed; monitoring was not published.', 1));
    assert.deepEqual([failed.clicked.message, failed.clicked.cls, failed.clicked.done],
        ['LLDPq run failed (exit 1) — review the log above.', 'err', ['run', false]]);
    assert.deepEqual([failed.reopened.message, failed.reopened.cls, failed.reopened.done],
        ['Last run failed (exit 1).', 'err', ['run', false]]);
});

const leftOut = 'devices.yaml was left out of the bundle: it has no devices.';

test('Backup export shows what the export left out of the bundle', async () => {
    // The sentence the export handler puts under "warnings"
    assert.ok(read('html/setup-api.sh').includes(`'devices.yaml was left out of the bundle: it has no devices.'`));
    const page = setupPage({ 'backup-export': { success: true, filename: 'lldpq-config.tar.gz', data: '',
        has_key: false, files: ['tracking.yaml'], warnings: [leftOut] } });
    await page.context.backupExport();
    const shown = page.status.at(-1);
    assert.deepEqual([shown.id, shown.cls], ['bk-export-msg', 'ok']);
    assert.ok(shown.message.startsWith('Downloaded bundle — store it securely ✓'), shown.message);
    assert.ok(shown.message.includes(leftOut), shown.message);
});

test('Backup export without warnings shows the line it always did', async () => {
    // "warnings" is empty for a complete bundle and absent in a 4.2.x reply
    for (const [extra, message] of [
        [{ has_key: false, warnings: [] }, 'Downloaded bundle — store it securely ✓'],
        [{ has_key: false }, 'Downloaded bundle — store it securely ✓'],
        [{ has_key: true, warnings: [] },
            'Downloaded bundle — store it securely; it includes the collector private key ✓'],
    ]) {
        const page = setupPage({ 'backup-export': { success: true, filename: 'lldpq-config.tar.gz', data: '',
            files: ['devices.yaml'], ...extra } });
        await page.context.backupExport();
        assert.deepEqual(page.status.at(-1), { id: 'bk-export-msg', message, cls: 'ok' });
    }
});
