// Page follow-ups of the login check on /configs/, /hstr/ and /monitor-results/.
//
// Those trees are now answered only after a CGI session gate, so every such
// request needs a free fcgiwrap worker for a moment. A page that keeps as many
// device commands in flight as there are workers starves that gate for every
// logged-in user, so the pages' own fan-outs have to stay below the default
// worker count. The remaining tests cover page texts and error handling that
// went stale with the same change set. The real page code is run in node:vm.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const read = path => fs.readFileSync(new URL('../' + path, import.meta.url), 'utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));

function fragment(source, start, end) {
    const from = source.indexOf(start);
    assert.notEqual(from, -1, 'not found: ' + start);
    const to = source.indexOf(end, from);
    assert.notEqual(to, -1, 'not found: ' + end);
    return source.slice(from, to);
}

// Worker count of an installation that sets nothing: the container
// entrypoint default and the native systemd drop-in.
function defaultWorkers() {
    const container = read('docker/docker-entrypoint.sh')
        .match(/^LLDPQ_FCGI_WORKERS="\$\{LLDPQ_FCGI_WORKERS:-(\d+)\}"$/m);
    const native = read('etc/systemd/system/fcgiwrap.service.d/lldpq-workers.conf')
        .match(/^ExecStart=\/usr\/sbin\/fcgiwrap -f -c (\d+)$/m);
    assert.ok(container, 'container default worker count not found');
    assert.ok(native, 'native default worker count not found');
    return Math.min(Number(container[1]), Number(native[1]));
}

// fetch stub: every request stays open across an event-loop turn, and the
// highest number of requests open at once is kept per API action.
function trackedFetch(reply) {
    const calls = [], open = {}, peak = {};
    const fetch = async (url, options = {}) => {
        const query = new URL(url, 'http://lldpq.test').searchParams;
        const call = { action: query.get('action'), hostname: query.get('hostname'),
            body: options.body ? JSON.parse(options.body) : null };
        calls.push(call);
        open[call.action] = (open[call.action] || 0) + 1;
        peak[call.action] = Math.max(peak[call.action] || 0, open[call.action]);
        try {
            await settle();
            const data = reply(call);
            return { ok: true, status: 200, json: async () => data };
        } finally {
            open[call.action]--;
        }
    };
    return { fetch, calls, peak: action => peak[action] || 0 };
}

function stubElements() {
    const elements = new Map();
    return id => {
        if (!elements.has(id)) {
            const classes = new Set();
            elements.set(id, {
                value: '', textContent: '', innerHTML: '', className: '', style: {}, disabled: true,
                classList: { add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c) },
                querySelector: () => ({ className: '', textContent: '', innerHTML: '' }),
            });
        }
        return elements.get(id);
    };
}

const devices = Array.from({ length: 10 }, (_, i) => `leaf-${i + 1}`);

test('Commands page keeps fewer device commands in flight than the default worker pool', async () => {
    const script = read('html/commands.html').match(/<script>([\s\S]*?)<\/script>/)[1];
    const net = trackedFetch(call => ({ success: true, output: 'up ' + call.body.device }));
    const element = stubElements();
    const context = vm.createContext({
        console, setTimeout, clearTimeout, AbortController, fetch: net.fetch,
        document: { getElementById: element, addEventListener() {} },
    });
    vm.runInContext(script, context);
    const pool = vm.runInContext('POOL', context);
    vm.runInContext(`${JSON.stringify(devices)}.forEach(name => selected.add(name))`, context);
    await context.runOnTarget('uptime');

    assert.ok(Number.isInteger(pool) && pool >= 1);
    assert.ok(pool < defaultWorkers(), `POOL ${pool} leaves no fcgiwrap worker free`);
    assert.equal(net.peak('run-device-command'), pool);
    assert.deepEqual(net.calls.map(c => c.body.device).sort(), [...devices].sort());
    assert.match(element('resSummary').innerHTML, /OK: 10\b/);
});

const migration = read('html/fabric-migration.html');

// Runs fragments of the Fabric Migration page and records the limit of every
// fetchPool() call the page makes.
function migrationPage(reply, globals, fragments) {
    const net = trackedFetch(reply);
    const limits = [];
    const context = vm.createContext({
        console, fetch: net.fetch, $: stubElements(), escapeHtml: value => String(value),
        showAlert() {}, showLoading() {}, ...globals,
    });
    vm.runInContext(fragment(migration, '    async function fetchPool(', '    // ---------- Description tokenizer'), context);
    for (const [start, end] of fragments) vm.runInContext(fragment(migration, start, end), context);
    const fetchPool = context.fetchPool;
    context.fetchPool = (items, limit, fn) => { limits.push(limit); return fetchPool(items, limit, fn); };
    return { context, net, limits };
}

test('Fabric Migration verify runs its device commands through fetchPool below the default worker pool', async () => {
    const vlans = { NEW: 20, OLD: 10 };
    const applied = Object.fromEntries(devices.map(dev => [dev, { applied: [{ name: 'swp1', new: 'NEW', old: 'OLD' }] }]));
    const { context, net, limits } = migrationPage(call => {
        if (call.action !== 'run-device-command') throw new Error('Unexpected action: ' + call.action);
        if (call.body.device === 'leaf-2') return { success: false, error: 'ssh failed' };
        if (call.body.device === 'leaf-3') throw new Error('network down');
        return { success: true, output: 'port              vlan-id\nswp1              20 PVID Egress Untagged\n' };
    }, {
        appliedPlan: { changes: applied }, planDevices: () => devices,
        profileInfo: name => ({ vlan: vlans[name] ?? null }), checkArpInTargetVrfs: async () => {},
    }, [['    function parseBridgeVlan(', '    async function checkArpInTargetVrfs(']]);
    await context.runVerification();

    assert.equal(limits.length, 1);
    assert.ok(limits[0] >= 1 && limits[0] < defaultWorkers(), `limit ${limits[0]} leaves no fcgiwrap worker free`);
    assert.equal(net.peak('run-device-command'), limits[0]);
    assert.deepEqual(net.calls.map(c => c.body),
        devices.map(device => ({ device, command: 'sudo bridge vlan show' })));

    // Same result as the unbounded fan-out: one row per device in plan order,
    // a failed or unreachable device is reported and does not stop the others
    const rows = [...context.$('verify-table-body').innerHTML.matchAll(
        /<td>([^<]*)<\/td>[\s\S]*?<span class="status-pill [^"]*">([^<]*)<\/span>/g)].map(m => [m[1], m[2]]);
    assert.deepEqual(rows, devices.map(dev => [dev,
        dev === 'leaf-2' ? 'NO DATA - ssh failed' : dev === 'leaf-3' ? 'NO DATA - network down' : 'PASS']));
    assert.equal(context.$('c5-pass').textContent, '8/10');
    assert.equal(context.$('c5-warn').textContent, 2);
});

test('Fabric Migration bounds the device lookups of a loaded plan the same way', async () => {
    const changes = Object.fromEntries(devices.map(dev => [dev, { applied: [{ name: 'swp1' }] }]));
    const steps = [];
    const { context, net, limits } = migrationPage(call => {
        if (call.action === 'get-migration-plan') {
            return { success: true, plan: { id: 'plan-1', name: 'p', created: '', total_applied: 10, changes } };
        }
        if (call.action !== 'get-device') throw new Error('Unexpected action: ' + call.action);
        if (call.hostname === 'leaf-4') return { success: false, error: 'Device file not found' };
        if (call.hostname === 'leaf-5') throw new Error('network down');
        return { success: true, hostname: call.hostname, port_profiles: { P: { owner: call.hostname } } };
    }, {
        appliedPlan: null, deviceData: { 'leaf-1': { cached: true } }, portProfiles: {}, vlanProfilesData: {},
        closePlansModal() {}, goStep: step => steps.push(step),
    }, [['    function planDevices() {', '    function buildDeployScope() {'],
        ['    async function loadPlan(id) {', '    // ---------- Rack patterns']]);
    await context.loadPlan('plan-1');

    assert.equal(limits.length, 1);
    assert.ok(limits[0] >= 1 && limits[0] < defaultWorkers(), `limit ${limits[0]} leaves no fcgiwrap worker free`);
    const lookups = net.calls.filter(c => c.action === 'get-device').map(c => c.hostname);
    assert.equal(net.peak('get-device'), limits[0]);
    // Cached devices are not asked again; failed lookups leave no entry
    assert.deepEqual(lookups, devices.slice(1));
    assert.deepEqual(Object.keys(context.deviceData).sort(),
        devices.filter(dev => dev !== 'leaf-4' && dev !== 'leaf-5').sort());
    assert.equal(context.deviceData['leaf-1'].cached, true);
    assert.match(context.portProfiles.P.owner, /^leaf-\d+$/);
    assert.equal(context.$('rollback-btn').disabled, false);
    assert.deepEqual(steps, [5]);
});

test('ZTP flow page shows the password step the saved script runs', () => {
    const flow = read('html/lldpq-ztp-new-device-flow.html');
    assert.ok(flow.includes(
        `<span class="step-code">echo 'cumulus:$6$&lt;salt&gt;$&lt;hash&gt;' | chpasswd -e</span>`));
    // No clear-text "chpasswd" form is left on the page
    assert.deepEqual([...flow.matchAll(/chpasswd[^<]*/g)].map(m => m[0]), ['chpasswd -e']);
    assert.match(flow, /SHA-512 crypt hash/);
    // What Save writes (hash_ztp_password_lines)
    assert.ok(read('html/provision-api.sh').includes(`return "%secho 'cumulus:%s' | chpasswd -e" % (`));
});

const telemetry = read('html/telemetry.html');
const fabricApi = read('html/fabric-api.sh');

// fetch stub: a streamed NDJSON response carrying the given lines
function ndjsonFetch(lines) {
    const ndjson = lines.map(line => JSON.stringify(line)).join('\n') + '\n';
    return async () => {
        let sent = false;
        const read = async () => {
            if (sent) return { done: true };
            sent = true;
            return { done: false, value: new TextEncoder().encode(ndjson) };
        };
        return { ok: true, status: 200, body: { getReader: () => ({ read }) } };
    };
}

// Enable/Disable Telemetry progress log for the given per-device results
async function telemetryLog(results) {
    const log = [];
    const context = vm.createContext({
        TextDecoder,
        addLogEntry: (message, type, device) => log.push({ message, type, device }),
        fetch: ndjsonFetch(results),
    });
    vm.runInContext(fragment(telemetry, '        async function readNdjsonStream(',
        '        // Stream check-telemetry-capability'), context);
    vm.runInContext(fragment(telemetry, '        async function streamTelemetryCommands(',
        '        async function enableTelemetry()'), context);
    const counts = await context.streamTelemetryCommands(results.map(result => result.device),
        ['nv set system telemetry enable on', 'nv config apply -y'], 'Telemetry enabled');
    return { log, counts: { ...counts } };  // copied out of the vm realm for deepEqual
}

// The sentences run-telemetry-commands prints when it refuses a device, by
// exit code (pending_guard is a run of adjacent Python string literals).
function refusalMessages() {
    const guard = [...fragment(fabricApi, 'pending_guard = (', '\n)\n').matchAll(/^\s*"(.*)"$/gm)]
        .map(m => m[1]).join('').replaceAll('\\"', '"');
    return Object.fromEntries([...guard.matchAll(/echo "([^"]+)" >&2; exit (\d+)/g)].map(m => [m[2], m[1]]));
}

test('Telemetry: a stale revision on LLDPq\'s own apply no longer asks for a manual detach', async () => {
    // The hint relies on the backend detaching its own staged change
    assert.ok(fabricApi.includes(`'{ rc=$?; nv config detach >/dev/null 2>&1; exit $rc; }'`));

    const nvue = 'Error: Stale revision 12, the applied configuration has changed';
    const { log, counts } = await telemetryLog([
        { device: 'leaf-1', success: false, error: nvue },
        { device: 'leaf-2', success: true, output: '' },
    ]);
    assert.deepEqual(counts, { success: 1, failed: 1 });
    assert.deepEqual(log[1], { message: 'Telemetry enabled', type: 'success', device: 'leaf-2' });
    const { message, type, device } = log[0];
    assert.deepEqual([type, device], ['error', 'leaf-1']);
    assert.ok(message.startsWith('Failed: ' + nvue), message);
    assert.match(message, /LLDPq detached its own staged change, retry$/);
    assert.doesNotMatch(message, /Pending config exists|run "nv config detach"/);
});

test('Telemetry: a device refused for pending changes shows the backend sentence unchanged', async () => {
    const refusals = refusalMessages();
    assert.deepEqual(Object.keys(refusals).sort(), ['3', '4']);
    for (const sentence of Object.values(refusals)) {
        // Changes that were pending before are the operator's: nothing was
        // detached, so the detach/retry hint must not be attached to these
        assert.match(sentence, /nothing was changed/);
        assert.doesNotMatch(sentence, /Stale revision/);
        for (const error of [sentence, 'Error: NVUE did not answer\n' + sentence,
            'Error: Stale revision\n' + sentence]) {
            const { log, counts } = await telemetryLog([{ device: 'leaf-1', success: false, error }]);
            assert.deepEqual(counts, { success: 0, failed: 1 });
            assert.deepEqual(log, [{ message: 'Failed: ' + error, type: 'error', device: 'leaf-1' }]);
        }
    }
});

test('Telemetry: what a device printed reaches the progress log as text, never as markup', async () => {
    // Stand-in DOM that keeps apart what a browser would parse as HTML and
    // what it would show as text
    const parsed = [];
    const createElement = tag => ({
        tag, className: '', nodes: [],
        set innerHTML(html) { parsed.push(html); },
        set textContent(text) { this.nodes = [String(text)]; },
        get textContent() {
            return this.nodes.map(node => typeof node === 'string' ? node : node.textContent).join('');
        },
        append(...nodes) { this.nodes.push(...nodes); },
        appendChild(node) { this.nodes.push(node); },
    });
    const progress = createElement('div');
    const context = vm.createContext({
        TextDecoder,
        document: { createElement, getElementById: id => { assert.equal(id, 'progressLog'); return progress; } },
    });
    vm.runInContext(fragment(telemetry, '        function addLogEntry(',
        '        async function enableTelemetry()'), context);

    // ssh stderr of a device, passed on by run_on_device and by the capability check
    const markup = '<img src=x onerror=alert(1)>';
    const stderr = `bash: ${markup}: command not found`;
    const stale = `Error: Stale revision 12 ${markup}`;
    context.fetch = ndjsonFetch([
        { device: 'leaf-1', status: 'error', detail: stderr },
        { device: 'leaf-2', status: 'supported', detail: '' },
        { done: true },
    ]);
    await context.streamCapabilityCheck(['leaf-1', 'leaf-2']);
    context.fetch = ndjsonFetch([
        { device: 'leaf-1', success: false, error: stderr },
        { device: 'leaf-2', success: false, error: stale },
        { device: 'leaf-3', success: true, output: '' },
    ]);
    await context.streamTelemetryCommands(['leaf-1', 'leaf-2', 'leaf-3'], ['nv config apply -y'], 'Telemetry enabled');
    context.addLogEntry('Enabled: 1, Failed: 2', 'info');

    assert.deepEqual(parsed, []);
    assert.deepEqual(progress.nodes.map(entry => [entry.className, entry.textContent]), [
        ['log-entry error', `[leaf-1] Check failed: ${stderr}`],
        ['log-entry success', '[leaf-2] Telemetry export supported'],
        ['log-entry error', `[leaf-1] Failed: ${stderr}`],
        ['log-entry error', `[leaf-2] Failed: ${stale} - LLDPq detached its own staged change, retry`],
        ['log-entry success', '[leaf-3] Telemetry enabled'],
        ['log-entry info', 'Enabled: 1, Failed: 2'],
    ]);
    // The device label is still its own element, the one the style sheet colours
    const label = progress.nodes[0].nodes[0];
    assert.deepEqual([label.tag, label.className, label.textContent], ['span', 'device', '[leaf-1]']);
    assert.match(telemetry, /^        \.log-entry \.device \{$/m);
});

// Configs page: listFiles() with the given /configs/ response
async function configsListing(response) {
    const state = { extracted: 0, errors: [] };
    const count = { textContent: '2/2 devices' };
    const context = vm.createContext({
        files: ['leaf-1.txt', 'leaf-1.yaml'],
        console: { error: (...args) => state.errors.push(args) },
        document: { getElementById: id => { assert.equal(id, 'deviceCount'); return count; } },
        DOMParser: class {
            parseFromString(html) {
                const links = [...html.matchAll(/<a href="([^"]*)"/g)].map(m => ({ getAttribute: () => m[1] }));
                return { querySelectorAll: () => links };
            }
        },
        fetch: async url => { assert.equal(url, '/configs/'); return response; },
        extractDevices: () => { state.extracted++; },
    });
    vm.runInContext(fragment(read('html/dev-conf.html'), '        function listFiles() {',
        '        function extractDevices() {'), context);
    context.listFiles();
    await settle();
    return { files: Array.from(context.files), count: count.textContent, ...state };
}

test('Configs page reads the device list from a successful /configs/ listing', async () => {
    const body = '<html><body><pre><a href="../">../</a>\n<a href="leaf-2.txt">leaf-2.txt</a>\n' +
        '<a href="leaf-2.yaml">leaf-2.yaml</a></pre></body></html>';
    const page = await configsListing({ ok: true, status: 200, text: async () => body });
    assert.deepEqual(page.files, ['leaf-2.txt', 'leaf-2.yaml']);
    assert.equal(page.extracted, 1);
    assert.equal(page.errors.length, 0);
    assert.equal(page.count, '2/2 devices');
});

test('Configs page reports a refused or failed /configs/ request instead of an empty device list', async () => {
    for (const [status, body] of [
        [401, '<html><body><form id="loginForm"></form></body></html>'],
        [401, '<html><body><a href="/login.html">Sign in</a></body></html>'],
        [500, '<html><body><h1>500 Internal Server Error</h1></body></html>'],
    ]) {
        const page = await configsListing({ ok: false, status, text: async () => body });
        assert.equal(page.count, 'Error loading devices');
        assert.equal(page.errors.length, 1);
        // The device tree already on screen is neither emptied nor rebuilt
        assert.equal(page.extracted, 0);
        assert.deepEqual(page.files, ['leaf-1.txt', 'leaf-1.yaml']);
    }
});
