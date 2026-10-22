import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const page = fs.readFileSync(new URL('../html/setup.html', import.meta.url), 'utf8');
const inventory = [
    { ip: '192.0.2.11', hostname: 'leaf-01', username: 'cumulus' },
    { ip: '2001:db8::12', hostname: 'leaf-02', username: 'cumulus' },
    { ip: 'fe80::13%eth0', hostname: 'oob-03', username: 'admin' },
];
const reply = (data, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => data });
const verifyReply = ips => reply({ success: true, total: ips.length, trusted: ips.length, sudo_ok: ips.length,
    results: ips.map(ip => ({ ip, trusted: true, sudo_ok: true })) });
const distributionReply = (ips, failed = []) => reply({ success: true, total: ips.length,
    send_key_ok: ips.length - failed.length, sudo_fix_ok: ips.length - failed.length,
    results: ips.map(ip => ({ ip, send_key: failed.includes(ip) ? 'fail' : 'already', sudo_fix: failed.includes(ip) ? 'fail' : 'ok' })) });

class Element {
    constructor(tag = 'div') {
        this.tagName = tag; this.children = []; this.style = {}; this.value = ''; this.disabled = false;
        this.checked = false; this.attributes = {}; this.listeners = {};
    }
    set textContent(text) { this.children = []; this.text = String(text); }
    get textContent() { return (this.text || '') + this.children.map(child => child.textContent).join(''); }
    appendChild(child) { this.children.push(child); return child; }
    append(...children) { children.forEach(child => this.appendChild(typeof child === 'string' ? Object.assign(new Element(), { textContent: child }) : child)); }
    replaceChildren(...children) { this.text = ''; this.children = children; }
    setAttribute(name, value) { this.attributes[name] = value; }
    addEventListener(name, listener) { this.listeners[name] = listener; }
}

function harness() {
    const elements = new Map();
    const element = id => {
        if (!elements.has(id)) elements.set(id, new Element());
        return elements.get(id);
    };
    const requests = [], done = [], statuses = new Map(), responses = [];
    const context = {
        document: { getElementById: element, createElement: tag => new Element(tag),
            createTextNode: text => Object.assign(new Element(), { textContent: text }) },
        setStatus: (id, message, kind) => statuses.set(id, { message, kind }),
        markDone: (...args) => done.push(args),
        keyExists: false,
        fetch: async (url, options) => {
            const payload = JSON.parse(options.body);
            requests.push({ url, payload });
            if (responses.length) return responses.shift();
            if (payload.action === 'list-key-devices') return reply({ success: true, devices: inventory });
            throw new Error('Unexpected operation: ' + JSON.stringify(payload));
        },
    };
    const states = page.slice(page.indexOf('let keyRetryIps ='), page.indexOf('let runActive ='));
    const start = page.indexOf('/* ---- Step 2: SSH key info');
    const end = page.indexOf('/* ---- Step 8: Run LLDPq', start);
    assert.ok(start > 0 && end > start);
    vm.createContext(context);
    vm.runInContext(states + page.slice(start, end) + '\nglobalThis.getRetryIps = () => keyRetryIps.slice();', context);
    return {
        context, requests, done, statuses, element,
        queue: response => responses.push(response),
        load: () => context.loadKeyDevices(),
        select: ip => context.toggleKeyDevice(ip, true),
        all: () => context.selectKeyDevices(true),
        clear: () => context.selectKeyDevices(false),
        selected: () => Array.from(context.selectedKeyDevices()),
        search(query) { element('key-device-search').value = query; context.renderKeyDevices(); },
        visible: () => Array.from(context.filteredKeyDevices(), device => device.ip),
        verify: () => context.verifyKeys(),
        distribute: (...args) => context.distributeKeys(...args),
        retry: () => context.distributeKeys(Array.from(context.getRetryIps())),
        password: value => { element('key-pw').value = value; },
        get message() { return statuses.get('key-progress')?.message; },
    };
}

test('saved inventory loads without implicit selection or device probes', async () => {
    const h = harness(); await h.load();
    assert.deepEqual(h.requests, [{ url: '/setup-api.sh', payload: { action: 'list-key-devices' } }]);
    assert.deepEqual(h.selected(), []);
    assert.equal(h.element('verify-btn').disabled, true);
    assert.equal(h.element('key-btn').disabled, true);
    assert.equal(h.element('key-device-count').textContent, '0 of 3 selected');
    assert.match(page, />Verify selected<\/button>/);
    assert.match(page, />Distribute selected<\/button>/);
    assert.doesNotMatch(page, /Distribute to all/);
});

test('empty Verify, Distribute and empty retry never fall back to every device', async () => {
    const h = harness(); await h.load(); h.password('temporary');
    await h.verify(); await h.distribute();
    h.select(inventory[0].ip); await h.distribute([]);
    assert.equal(h.requests.length, 1);
    assert.match(h.message, /Select at least one/);
});

test('IPv4 verify sends only the selected IP and never marks the whole inventory done', async () => {
    const h = harness(); await h.load(); h.select(inventory[0].ip);
    h.queue(verifyReply([inventory[0].ip])); await h.verify();
    assert.deepEqual(h.requests.at(-1).payload, { action: 'verify', selected_devices: [inventory[0].ip] });
    assert.deepEqual(h.done.at(-1), ['keys', false]);
    assert.match(h.message, /^Selected devices trust/);
    assert.doesNotMatch(h.message, /^All devices/);
});

test('explicit Select all can verify the complete IPv4 and IPv6 inventory', async () => {
    const h = harness(); await h.load(); h.all();
    h.queue(verifyReply(inventory.map(device => device.ip))); await h.verify();
    assert.deepEqual(h.requests.at(-1).payload.selected_devices, inventory.map(device => device.ip));
    assert.deepEqual(h.done.at(-1), ['keys', true]);
});

for (const ip of ['2001:db8::12', 'fe80::13%eth0']) {
    test(`distribution preserves IPv6 address ${ip} and clears transient password on success`, async () => {
        const h = harness(); await h.load(); h.select(ip); h.password('temporary-password');
        h.queue(distributionReply([ip])); await h.distribute();
        assert.deepEqual(h.requests.at(-1).payload, { password: 'temporary-password', selected_devices: [ip] });
        assert.equal(h.element('key-pw').value, '');
        assert.deepEqual(h.done.at(-1), ['keys', false]);
        assert.match(h.element('key-summary').textContent, /selected devices have the key/);
    });
}

test('hostname/IP search and filtered selection preserve hidden selections until Clear', async () => {
    const h = harness(); await h.load(); h.select(inventory[0].ip);
    h.search('OOB-'); assert.deepEqual(h.visible(), [inventory[2].ip]);
    assert.equal(h.element('key-select-all').textContent, 'Select filtered');
    h.all(); assert.deepEqual(h.selected(), [inventory[0].ip, inventory[2].ip]);
    h.search('db8::'); assert.deepEqual(h.visible(), [inventory[1].ip]);
    assert.equal(h.element('key-device-count').textContent, '2 of 3 selected');
    h.clear(); assert.deepEqual(h.selected(), []);
    h.search('missing'); assert.match(h.element('key-device-body').textContent, /No devices match/);
});

test('checkbox selection uses the actual inventory address and handles literal text safely', async () => {
    const h = harness();
    h.queue(reply({ success: true, devices: [{ ip: '2001:db8::1', hostname: '<script>switch</script>', username: 'admin' }] }));
    await h.load();
    const row = h.element('key-device-body').children[0];
    const checkbox = row.children[0].children[0];
    checkbox.checked = true; checkbox.listeners.change();
    assert.deepEqual(h.selected(), ['2001:db8::1']);
    assert.equal(row.children[1].textContent, '<script>switch</script>');
    assert.equal(row.children[1].children.length, 0);
});

test('inventory refresh clears selection, retry results, filter and transient password', async () => {
    const h = harness(); await h.load(); h.all(); h.password('temporary');
    h.queue(distributionReply(inventory.map(device => device.ip), [inventory[1].ip])); await h.distribute();
    assert.equal(h.element('key-retry-btn').style.display, 'inline-flex');
    h.search('leaf');
    h.queue(reply({ success: true, devices: [inventory[2]] })); await h.load();
    assert.deepEqual(h.selected(), []);
    assert.equal(h.element('key-pw').value, '');
    assert.equal(h.element('key-device-search').value, '');
    assert.equal(h.element('key-results').style.display, 'none');
    assert.equal(h.element('key-retry-btn').style.display, 'none');
    assert.equal(h.message, '');
    await h.retry(); assert.equal(h.requests.length, 3);
});

for (const badReply of [reply({ success: false, error: 'Invalid devices.yaml' }, 400), reply({ success: true, devices: [null] }), reply({ success: true, devices: [] }, 500)]) {
    test('failed or malformed inventory refresh cannot leave old actionable selections', async () => {
        const h = harness(); await h.load(); h.all(); h.queue(badReply); await h.load();
        assert.deepEqual(h.selected(), []);
        assert.equal(h.element('key-btn').disabled, true);
        assert.equal(h.element('key-device-picker').disabled, false, 'refresh remains available');
        assert.equal(h.statuses.get('key-device-status').kind, 'err');
        h.password('temporary'); await h.distribute(); assert.equal(h.requests.length, 2);
    });
}

test('verify/distribute and selection are locked together while a request is pending', async () => {
    const h = harness(); await h.load(); h.select(inventory[1].ip); h.password('temporary');
    let resolve;
    h.queue(new Promise(done => { resolve = done; }));
    const pending = h.distribute();
    assert.equal(h.element('key-device-picker').disabled, true);
    assert.equal(h.element('verify-btn').disabled, true);
    assert.equal(h.element('key-btn').disabled, true);
    assert.equal(h.element('key-pw').disabled, true);
    h.all(); h.clear(); h.select(inventory[0].ip);
    await h.verify(); await h.distribute();
    assert.deepEqual(h.selected(), [inventory[1].ip]);
    assert.equal(h.requests.length, 2);
    resolve(distributionReply([inventory[1].ip])); await pending;
    assert.equal(h.element('key-device-picker').disabled, false);
    assert.equal(h.element('verify-btn').disabled, false);
});

test('inventory changes during verification refresh only after it finishes', async () => {
    const h = harness(); await h.load(); h.select(inventory[1].ip);
    let resolve;
    h.queue(new Promise(done => { resolve = done; }));
    const pending = h.verify(); await h.load();
    assert.equal(h.requests.length, 2);
    resolve(verifyReply([inventory[1].ip])); await pending;
    await new Promise(done => setImmediate(done));
    assert.equal(h.requests.length, 3);
    assert.deepEqual(h.requests.at(-1).payload, { action: 'list-key-devices' });
    assert.deepEqual(h.selected(), []);
});

test('retry targets only actual failed devices from the previous request, independent of new selection', async () => {
    const h = harness(); await h.load(); h.select(inventory[0].ip); h.select(inventory[1].ip); h.password('temporary');
    h.queue(distributionReply([inventory[0].ip, inventory[1].ip], [inventory[1].ip])); await h.distribute();
    h.clear(); h.select(inventory[2].ip);
    h.queue(distributionReply([inventory[1].ip])); await h.retry();
    assert.deepEqual(h.requests.at(-1).payload, { password: 'temporary', retry_devices: [inventory[1].ip] });
    assert.equal(h.element('key-retry-btn').style.display, 'none');
    assert.equal(h.element('key-pw').value, '');
    assert.deepEqual(h.done.at(-1), ['keys', false]);
});

test('a new verify clears a stale retry set even when verification fails', async () => {
    const h = harness(); await h.load(); h.select(inventory[0].ip); h.password('temporary');
    h.queue(distributionReply([inventory[0].ip], [inventory[0].ip])); await h.distribute();
    h.queue(reply({ success: false, error: 'Inventory changed' }, 400)); await h.verify();
    assert.equal(h.element('key-retry-btn').style.display, 'none');
    await h.retry(); assert.equal(h.requests.length, 3);
    assert.equal(h.element('verify-btn').disabled, false);
});

test('HTTP failure never reports success and unlocks selected-device controls', async () => {
    const h = harness(); await h.load(); h.select(inventory[0].ip); h.password('temporary');
    h.queue(reply({ success: true }, 500)); await h.distribute();
    assert.match(h.message, /Distribution failed/);
    assert.equal(h.element('key-device-picker').disabled, false);
    assert.equal(h.element('key-btn').disabled, false);
    assert.equal(h.done.some(([key, done]) => key === 'keys' && done), false);
});

test('saving inventory refreshes the picker using the saved backend inventory', async () => {
    const h = harness(); await h.load(); h.all();
    h.context.FILES = { devices: { loaded: true, revision: 'before', file: 'devices.yaml', ta: 'ta-devices', st: 'st-devices', editVersion: 0, opSeq: 0, url: '/edit-devices' } };
    h.element('ta-devices').value = 'devices: {}';
    const start = page.indexOf('async function readEditorResponse(');
    const end = page.indexOf('function downloadFile(', start);
    vm.runInContext(page.slice(start, end), h.context);
    h.queue(reply({ success: true, revision: 'after' }));
    h.queue(reply({ success: true, devices: [] }));
    await h.context.saveFile('devices'); await new Promise(done => setImmediate(done));
    assert.deepEqual(h.requests.at(-1).payload, { action: 'list-key-devices' });
    assert.deepEqual(h.selected(), []);
    assert.equal(h.element('key-device-count').textContent, '0 of 0 selected');
});

test('retry HTTP failure keeps the last failed scope available without using a new selection', async () => {
    const h = harness(); await h.load(); h.select(inventory[0].ip); h.password('temporary');
    h.queue(distributionReply([inventory[0].ip], [inventory[0].ip])); await h.distribute();
    h.clear(); h.select(inventory[2].ip);
    h.queue(reply({ success: false, error: 'Temporary failure' }, 503)); await h.retry();
    assert.equal(h.element('key-retry-btn').style.display, 'inline-flex');
    assert.equal(h.element('key-retry-btn').disabled, false);
    assert.equal(h.element('key-pw').value, 'temporary');
    h.queue(distributionReply([inventory[0].ip])); await h.retry();
    assert.deepEqual(h.requests.at(-1).payload, { password: 'temporary', retry_devices: [inventory[0].ip] });
});

test('duplicated or incomplete verify results cannot claim all selected devices succeeded', async () => {
    const h = harness(); await h.load(); h.select(inventory[0].ip); h.select(inventory[1].ip);
    h.queue(verifyReply([inventory[0].ip, inventory[0].ip])); await h.verify();
    assert.match(h.message, /Some selected devices still need/);
    assert.deepEqual(h.done.at(-1), ['keys', false]);
});
