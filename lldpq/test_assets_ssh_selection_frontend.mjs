import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const page = fs.readFileSync(new URL('../html/assets.html', import.meta.url), 'utf8');
const start = page.indexOf('// ─── SSH Setup Modal ───');
const script = page.slice(start, page.indexOf('</script>', start));
const inventory = [
    { ip: '192.0.2.11', hostname: 'leaf-01', username: 'cumulus' },
    { ip: '2001:db8::12', hostname: 'leaf-02', username: 'cumulus' },
    { ip: 'fe80::13%eth0', hostname: 'oob-03', username: 'admin' },
];
const reply = (data, status = 200) => ({ ok: status >= 200 && status < 300, status, json: async () => data });
const listReply = devices => reply({ success: true, devices });
const resultReply = (ips, failed = []) => reply({ success: true, results: ips.map(ip => ({
    ip, hostname: inventory.find(device => device.ip === ip)?.hostname || ip,
    send_key: failed.includes(ip) ? 'fail' : 'already', sudo_fix: failed.includes(ip) ? 'skipped' : 'ok',
})) });
const deferred = () => {
    let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve };
};

class Element {
    constructor(tag = 'div') {
        this.tagName = tag; this.children = []; this.style = {}; this.dataset = {}; this.value = '';
        this.disabled = false; this.checked = false; this.listeners = {}; this.type = '';
    }
    set textContent(value) { this.text = String(value); this.children = []; }
    get textContent() { return (this.text || '') + this.children.map(child => child.textContent).join(''); }
    get rows() { return this.children; }
    appendChild(child) {
        if (child.parent) child.remove();
        child.parent = this; this.children.push(child); return child;
    }
    append(...children) { children.forEach(child => this.appendChild(child)); }
    replaceChildren(...children) { this.text = ''; this.children.forEach(child => { child.parent = null; }); this.children = []; this.append(...children); }
    remove() { if (this.parent) { this.parent.children = this.parent.children.filter(child => child !== this); this.parent = null; } }
    addEventListener(name, listener) { this.listeners[name] = listener; }
}

function harness() {
    const elements = new Map(), requests = [], alerts = [];
    const queues = { key: [], list: [], setup: [] };
    const element = id => {
        if (!elements.has(id)) elements.set(id, new Element());
        return elements.get(id);
    };
    element('sshSetupModal').style.display = 'none';
    const context = {
        AbortController, console,
        document: { getElementById: element, createElement: tag => new Element(tag),
            createTextNode: text => Object.assign(new Element(), { textContent: text }) },
        assetText: (value, fallback = '') => value == null ? fallback : String(value),
        alert: message => alerts.push(message),
        fetch: async (url, options = {}) => {
            const payload = options.body ? JSON.parse(options.body) : null;
            const kind = payload?.action === 'list-key-devices' ? 'list' : payload ? 'setup' : 'key';
            requests.push({ url, payload, signal: options.signal, kind });
            if (queues[kind].length) return queues[kind].shift();
            if (kind === 'key') return reply({ success: true, public_key: 'ssh-ed25519 test', key_type: 'ed25519', key_file: '/test/key' });
            if (kind === 'list') return listReply(inventory);
            throw new Error('Unexpected setup request');
        },
    };
    vm.createContext(context); vm.runInContext(script, context);
    return {
        context, element, requests, alerts,
        queue: (kind, response) => queues[kind].push(response),
        open: () => context.openSSHSetupModal(), close: () => context.closeSSHSetupModal(),
        refresh: () => context.loadSSHKeyDevices(),
        select: ip => context.toggleSSHKeyDevice(ip, true),
        selected: () => Array.from(context.selectedSSHKeyDevices()),
        all: () => context.selectSSHKeyDevices(true), clear: () => context.selectSSHKeyDevices(false),
        search(query) { element('sshDeviceSearch').value = query; context.renderSSHKeyDevices(); },
        password(value) { element('sshPassword').value = value; context.checkPasswordInput(); },
        run: (...args) => context.runSSHSetup(...args),
        retry: () => context.retrySSHSetup(),
    };
}

test('opening Assets SSH modal reads inventory and key status without selecting or contacting devices', async () => {
    const h = harness(); await h.open();
    assert.deepEqual(h.requests.map(request => request.kind).sort(), ['key', 'list']);
    assert.deepEqual(h.requests.find(request => request.kind === 'list').payload, { action: 'list-key-devices' });
    assert.deepEqual(h.selected(), []);
    assert.equal(h.element('sshDeviceCount').textContent, '0 of 3 selected');
    h.password('secret'); assert.equal(h.element('sshRunBtn').disabled, true);
    assert.match(page, /max-width: 700px; max-height: 90vh; overflow-y: auto/);
});

for (const ip of inventory.map(device => device.ip)) {
    test(`Assets setup targets only selected ${ip} and clears the password afterward`, async () => {
        const h = harness(); await h.open(); h.select(ip); h.password('secret');
        h.queue('setup', resultReply([ip])); assert.equal(await h.run(), true);
        assert.deepEqual(h.requests.at(-1).payload, { password: 'secret', selected_devices: [ip] });
        assert.equal(h.element('sshPassword').value, '');
        assert.equal(h.element('sshPassword').type, 'password');
        assert.equal(h.element('sshRunBtn').disabled, true);
        assert.equal(h.element('sshResultsBody').rows.length, 1);
    });
}

test('empty selection and empty retry never trigger all-device setup', async () => {
    const h = harness(); await h.open(); h.password('secret');
    assert.equal(await h.run(), false);
    h.select(inventory[0].ip); assert.equal(await h.run([]), false);
    assert.equal(h.requests.filter(request => request.kind === 'setup').length, 0);
});

test('hostname and IPv6 search select only filtered rows while Clear removes hidden selections too', async () => {
    const h = harness(); await h.open(); h.select(inventory[0].ip);
    h.search('OOB-'); assert.equal(h.element('sshDeviceList').children.length, 1);
    assert.equal(h.element('sshDeviceSelectAll').textContent, 'Select filtered');
    h.all(); assert.deepEqual(h.selected(), [inventory[0].ip, inventory[2].ip]);
    h.search('db8::'); h.all(); assert.deepEqual(h.selected(), inventory.map(device => device.ip));
    h.clear(); assert.deepEqual(h.selected(), []);
    h.search('missing'); assert.match(h.element('sshDeviceList').textContent, /No devices match/);
});

test('checkboxes preserve exact IPv6 scope and render hostnames as text', async () => {
    const h = harness(); h.queue('list', listReply([{ ...inventory[2], hostname: '<script>name</script>' }]));
    await h.open(); const row = h.element('sshDeviceList').children[0];
    const checkbox = row.children[0]; checkbox.checked = true; checkbox.listeners.change();
    assert.deepEqual(h.selected(), [inventory[2].ip]);
    assert.equal(h.element('sshDeviceList').children[0].children[0], checkbox, 'single selection retains the focused checkbox');
    assert.equal(h.element('sshDeviceCount').textContent, '1 of 1 selected');
    assert.equal(row.children[1].textContent, '<script>name</script>');
    assert.equal(row.children[1].children.length, 0);
});

test('selection, refresh, close and duplicate setup remain locked while distribution is pending', async () => {
    const h = harness(); await h.open(); h.select(inventory[1].ip); h.password('secret');
    const pending = deferred(); h.queue('setup', pending.promise); const running = h.run();
    assert.equal(h.element('sshDevicePicker').disabled, true);
    h.all(); h.clear(); h.select(inventory[0].ip);
    assert.equal(await h.refresh(), false); assert.equal(h.close(), false); assert.equal(await h.run(), false);
    assert.deepEqual(h.selected(), [inventory[1].ip]);
    assert.equal(h.requests.filter(request => request.kind === 'setup').length, 1);
    pending.resolve(resultReply([inventory[1].ip])); await running;
    assert.equal(h.element('sshDevicePicker').disabled, false);
    assert.equal(h.close(), true);
});

test('closing and reopening ignores old inventory and old key-status responses', async () => {
    const h = harness(); const oldList = deferred(), oldKey = deferred();
    h.queue('list', oldList.promise); h.queue('key', oldKey.promise); const firstOpen = h.open();
    const firstRequests = h.requests.slice(); assert.equal(h.close(), true);
    assert.ok(firstRequests.every(request => request.signal.aborted));
    h.queue('list', listReply([inventory[2]])); await h.open();
    h.select(inventory[2].ip); h.password('fresh');
    oldList.resolve(listReply([inventory[0]])); oldKey.resolve(reply({ success: false })); await firstOpen;
    await new Promise(done => setImmediate(done));
    assert.deepEqual(h.selected(), [inventory[2].ip]);
    assert.equal(h.element('sshDeviceCount').textContent, '1 of 1 selected');
    assert.equal(h.element('sshKeyStatus').dataset.hasKey, 'true');
    assert.equal(h.element('sshPassword').value, 'fresh');
    assert.equal(h.element('sshRunBtn').disabled, false);
});

test('late refresh response cannot replace the newer inventory', async () => {
    const h = harness(); await h.open(); const old = deferred(); h.queue('list', old.promise);
    const first = h.refresh(); h.queue('list', listReply([inventory[2]])); await h.refresh();
    h.select(inventory[2].ip); old.resolve(listReply([inventory[0]])); await first;
    assert.deepEqual(h.selected(), [inventory[2].ip]);
    assert.equal(h.element('sshDeviceCount').textContent, '1 of 1 selected');
});

for (const bad of [reply({ success: false, error: 'Invalid inventory' }, 400), listReply([null]), listReply([inventory[0], inventory[0]])]) {
    test('failed or malformed refresh clears previously actionable selection', async () => {
        const h = harness(); await h.open(); h.all(); h.password('secret'); h.queue('list', bad); await h.refresh();
        assert.deepEqual(h.selected(), []); assert.equal(h.element('sshPassword').value, '');
        assert.equal(h.element('sshRunBtn').disabled, true);
        assert.equal(h.element('sshDevicePicker').disabled, false);
        assert.ok(h.element('sshDeviceStatus').textContent);
        h.password('secret'); assert.equal(await h.run(), false);
        assert.equal(h.requests.filter(request => request.kind === 'setup').length, 0);
    });
}

test('retry sends only failed targets from the previous operation regardless of current selection', async () => {
    const h = harness(); await h.open(); h.select(inventory[0].ip); h.select(inventory[1].ip); h.password('secret');
    h.queue('setup', resultReply([inventory[0].ip, inventory[1].ip], [inventory[1].ip])); await h.run();
    h.clear(); h.select(inventory[2].ip); h.password('retry-secret');
    h.queue('setup', resultReply([inventory[1].ip])); await h.run([inventory[1].ip, inventory[2].ip]);
    assert.deepEqual(h.requests.at(-1).payload, { password: 'retry-secret', retry_devices: [inventory[1].ip] });
    assert.equal(h.element('sshResultsBody').rows.length, 2);
    assert.equal(h.element('sshRetryBtn').style.display, 'none');
    assert.match(h.element('sshSummary').textContent, /2\/2/);
});

test('refresh clears old result and retry state together with the selection', async () => {
    const h = harness(); await h.open(); h.select(inventory[0].ip); h.password('secret');
    h.queue('setup', resultReply([inventory[0].ip], [inventory[0].ip])); await h.run();
    h.search('leaf'); h.password('again'); await h.refresh();
    assert.deepEqual(h.selected(), []); assert.equal(h.element('sshDeviceSearch').value, '');
    assert.equal(h.element('sshPassword').value, '');
    assert.equal(h.element('sshResultsArea').style.display, 'none');
    assert.equal(h.element('sshRetryBtn').style.display, 'none');
    h.retry(); assert.equal(h.requests.filter(request => request.kind === 'setup').length, 1);
});

test('failed retry request retains the retry control and its original bounded target set', async () => {
    const h = harness(); await h.open(); h.select(inventory[0].ip); h.password('secret');
    h.queue('setup', resultReply([inventory[0].ip], [inventory[0].ip])); await h.run();
    h.clear(); h.select(inventory[2].ip); h.password('retry-secret');
    h.queue('setup', reply({ success: false, error: 'Temporary error' }, 503));
    assert.equal(await h.run([inventory[0].ip]), false);
    assert.equal(h.element('sshRetryBtn').style.display, 'inline-block');
    assert.equal(h.element('sshPassword').value, '');
    h.password('retry-again'); h.queue('setup', resultReply([inventory[0].ip]));
    assert.equal(await h.run([inventory[0].ip]), true);
    assert.deepEqual(h.requests.at(-1).payload, { password: 'retry-again', retry_devices: [inventory[0].ip] });
});

test('request failure clears transient password and restores selector controls', async () => {
    const h = harness(); await h.open(); h.select(inventory[0].ip); h.password('secret');
    h.context.togglePasswordVisibility('sshPassword', h.element('sshPasswordToggle'));
    h.queue('setup', reply({ success: false, error: 'Device removed from inventory' }, 400));
    assert.equal(await h.run(), false);
    assert.match(h.alerts.at(-1), /Device removed/);
    assert.equal(h.element('sshPassword').value, '');
    assert.equal(h.element('sshPassword').type, 'password');
    assert.equal(h.element('sshDevicePicker').disabled, false);
    assert.equal(h.element('sshRunBtn').disabled, true);
});

test('closing the idle modal clears password visibility and selection', async () => {
    const h = harness(); await h.open(); h.all(); h.password('secret');
    h.context.togglePasswordVisibility('sshPassword', h.element('sshPasswordToggle'));
    assert.equal(h.close(), true); assert.deepEqual(h.selected(), []);
    assert.equal(h.element('sshPassword').value, ''); assert.equal(h.element('sshPassword').type, 'password');
    assert.equal(await h.run(), false);
});
