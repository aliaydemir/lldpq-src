import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const page = fs.readFileSync(new URL('../html/provision.html', import.meta.url), 'utf8');
const addresses = fs.readFileSync(new URL('../html/css/ip-address.js', import.meta.url), 'utf8');
const start = page.indexOf('// ===================== GLOBAL STATE');
const script = page.slice(start, page.indexOf('</script>', start));
const utils = {};
vm.runInNewContext(addresses, utils);
const IP = utils.LLDPqIP;

function harness(bindings = []) {
    const elements = new Map();
    const events = [], requests = [], confirmations = [], blobs = [];
    function element(id) {
        if (!elements.has(id)) elements.set(id, {
            value: '', checked: false, disabled: false, style: {}, textContent: '', innerHTML: '', dataset: {},
            classList: { add() {}, remove() {} }, focus() {}, click() {}, appendChild() {},
        });
        return elements.get(id);
    }
    const context = vm.createContext({
        document: { getElementById: element, addEventListener() {}, querySelectorAll() { return []; }, querySelector: element, createElement: element },
        window: { addEventListener() {} }, console, setTimeout() {}, clearTimeout() {}, setInterval() {}, clearInterval() {},
        Blob, URL: { createObjectURL(blob) { blobs.push(blob); return 'blob:test'; }, revokeObjectURL() {} },
    });
    vm.runInContext(addresses, context);
    vm.runInContext(script, context);
    context.showToast = (message, kind) => events.push({ message, kind });
    context.showConfirmModal = (title, message, callback) => confirmations.push({ title, message, callback });
    context.apiCall = async (action, payload) => { requests.push({ action, payload }); return { success: true, dhcp_changed: false }; };
    context.loadKnownRoles = () => {};
    vm.runInContext(`allBindings = ${JSON.stringify(bindings)}; inventoryLoaded = true;`, context);
    return {
        context, element, events, requests, confirmations, blobs,
        run: code => vm.runInContext(code, context),
        state: () => JSON.parse(vm.runInContext('JSON.stringify(allBindings)', context)),
        setDiscovered: devices => vm.runInContext(`allDiscovered = ${JSON.stringify(devices)};`, context),
        edit(values) { for (const [key, value] of Object.entries(values)) element('modal' + key).value = value; context.saveBinding(); },
        import(text) { element('bulkImportText').value = text; context.applyBulkImport(); },
    };
}

test('canonical IPv6 supports compression, dotted embedded IPv4 and first longest zero run', () => {
    assert.equal(IP.parse('2001:0DB8:0000:0000:0000:0000:0000:0010').canonical, '2001:db8::10');
    assert.equal(IP.parse('0:0:0:0:0:ffff:c000:201').canonical, '::ffff:192.0.2.1');
    assert.equal(IP.parse('::ffff:192.0.2.1').canonical, '::ffff:192.0.2.1');
    assert.equal(IP.parse('2001:0:0:1:0:0:1:1').canonical, '2001::1:0:0:1:1');
    assert.equal(IP.parse('2001:db8:1:2:3:4:5:0').canonical, '2001:db8:1:2:3:4:5:0');
    assert.equal(IP.parse('192.0.2.200').canonical, '192.0.2.200');
});

test('invalid literals are rejected instead of mistaken for hostnames', () => {
    for (const value of ['2001:::1', '2001::db8::1', '12345::1', '1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8::', '::ffff:192.0.2.999', '[2001:db8::1]', '192.0.2.999', '192.0.02.1', 'leaf-1', '::1%']) {
        assert.equal(IP.parse(value), null, value);
    }
});

test('link-local requires a scope and scope spelling participates in device identity', () => {
    assert.equal(IP.parse('fe80::1'), null);
    assert.equal(IP.parse('febf::1'), null);
    assert.equal(IP.parse('fe80:0:0:0:0:0:0:1%en-1').canonical, 'fe80::1%en-1');
    assert.equal(IP.parse('fe80::1%2').canonical, 'fe80::1%2');
    assert.notEqual(IP.key('fe80::1%eth0'), IP.key('fe80::1%eth1'));
    assert.notEqual(IP.key('fe80::1%Eth0'), IP.key('fe80::1%eth0'));
    for (const value of ['fe80::1%-x', 'fe80::1%eth0%eth1', 'fe80::1%eth 0', '192.0.2.1%eth0']) assert.equal(IP.parse(value), null);
});

test('numeric address ordering works across IPv4, IPv6 and equivalent spellings', () => {
    const values = ['2001:db8::10', '192.0.2.200', '2001:db8::2', '192.0.2.9', '::1'];
    assert.deepEqual(values.sort(IP.compare), ['192.0.2.9', '192.0.2.200', '::1', '2001:db8::2', '2001:db8::10']);
    assert.equal(IP.compare('2001:0db8:0:0:0:0:0:1', '2001:db8::1'), 0);
});

test('discovery accepts bounded mixed families and scopes while rejecting huge networks before expansion', () => {
    for (const value of ['192.0.2.10-192.0.2.20,2001:db8::1-2001:db8::10', '2001:db8::/120', 'fe80::%en-1/126', 'fe80::1%en-1-fe80::a%en-1', '192.0.2.0/31,2001:db8::/127', 'fe80::1%en-1']) {
        assert.equal(IP.discoveryError(value), '', value);
    }
    for (const value of ['2001:db8::/64', '192.0.0.0/16', '2001:db8::1-2001:db8::ffff']) assert.match(IP.discoveryError(value), /1,500/);
    for (const value of ['fe80::1', 'fe80::1%eth0-fe80::2%eth1', '192.0.2.1-2001:db8::1', '2001:db8::5-2001:db8::1', '2001:db8::/129', '192.0.2.1-20']) assert.ok(IP.discoveryError(value), value);
    assert.equal(IP.discoveryError('2001:db8::/126', 3), '');
    assert.ok(IP.discoveryError('2001:db8::/126', 2));
    for (const value of ['::', '0.0.0.0', 'ff02::1%eth0', '224.0.0.1', 'ff02::%eth0/120', '223.255.255.255-224.0.0.1']) assert.match(IP.discoveryError(value), /unicast/);
});

test('private-range warning applies only to IPv4, including when IPv6 embeds dotted octets', () => {
    const h = harness();
    assert.equal(h.context.checkPrivateRange('::ffff:192.0.2.1'), '');
    assert.equal(h.context.checkPrivateRange('2001:db8::/120'), '');
    assert.equal(h.context.checkPrivateRange('192.168.0.0/24'), '');
    assert.match(h.context.checkPrivateRange('92.168.0.1-92.168.0.3'), /not a private IP/);
});

test('bulk CSV and compact IPv6 lines normalize addresses without enabling DHCP', () => {
    const h = harness();
    const parsed = h.context.parseBulkText('Hostname,MAC,IP,Serial,Role\nv6,aa:bb:cc:dd:ee:01,2001:0DB8:0:0:0:0:0:1,,leaf\nv4,aa:bb:cc:dd:ee:02,192.0.2.2,,leaf\nlink fe80::1%eth0');
    assert.equal(parsed.errors.length, 0);
    assert.equal(parsed.entries[0].ip, '2001:db8::1');
    assert.equal(parsed.entries[0].dhcp, false);
    assert.equal(parsed.entries[1].dhcp, true);
    assert.equal(parsed.entries[2].ip, 'fe80::1%eth0');
    assert.equal(parsed.entries[2].dhcp, false);
});

test('import preserves unrelated fields and disables DHCP on IPv4-to-IPv6 change', () => {
    const h = harness([{ hostname: 'leaf', ip: '192.0.2.1', mac: 'aa:bb:cc:dd:ee:01', dhcp: true, username: 'custom', password: 'example', role: 'leaf', notes: 'keep' }]);
    h.import('leaf 2001:0db8::1');
    assert.deepEqual(h.state()[0], { hostname: 'leaf', ip: '2001:db8::1', mac: 'aa:bb:cc:dd:ee:01', dhcp: false, username: 'custom', password: 'example', role: 'leaf', notes: 'keep', serial: '', commented: false });
});

test('importing a MAC alone cannot enable DHCP on an existing IPv6 device', () => {
    const h = harness([{ hostname: 'leaf', ip: '2001:db8::1', mac: '-', dhcp: false }]);
    h.import('leaf aa:bb:cc:dd:ee:01');
    assert.equal(h.state()[0].dhcp, false);
});

test('duplicate equivalent IPv6 imports leave the entire inventory unchanged', () => {
    const before = [{ hostname: 'old', ip: '2001:db8::1', mac: '-' }];
    const h = harness(before);
    h.import('new 2001:0db8:0:0:0:0:0:1');
    assert.deepEqual(h.state(), before);
    assert.match(h.element('bulkImportPreview').textContent, /Duplicate IP/);
});

test('IPv6 modal edits preserve metadata and reject an equivalent address assigned elsewhere', () => {
    const h = harness([{ hostname: 'leaf', ip: '192.0.2.1', mac: '-', role: 'leaf', dhcp: true, username: 'admin', notes: 'keep' }]);
    h.edit({ Hostname: 'leaf', OrigHostname: 'leaf', IP: '2001:0db8::1', MAC: '-', Role: 'leaf' });
    assert.equal(h.state()[0].ip, '2001:db8::1');
    assert.equal(h.state()[0].dhcp, false);
    assert.equal(h.state()[0].username, 'admin');
    assert.equal(h.state()[0].notes, 'keep');
    h.edit({ Hostname: 'other', OrigHostname: '', IP: '2001:0db8:0:0:0:0:0:1', MAC: '-' });
    assert.equal(h.state().length, 1);
    assert.match(h.events.at(-1).message, /Duplicate/);
});

test('bare link-local modal save leaves inventory untouched; scoped save succeeds', () => {
    const h = harness();
    h.edit({ Hostname: 'link', IP: 'fe80::1' });
    assert.equal(h.state().length, 0);
    assert.match(h.events.at(-1).message, /%interface/);
    h.edit({ Hostname: 'link', IP: 'fe80::1%eth0' });
    assert.equal(h.state()[0].ip, 'fe80::1%eth0');
    assert.equal(h.state()[0].dhcp, false);
});

test('IPv4 modal save and DHCP controls retain IPv4 behavior but never enable IPv6 DHCP', () => {
    const h = harness([{ hostname: 'v6', ip: '2001:db8::1', mac: 'aa:bb:cc:dd:ee:01', dhcp: false }]);
    h.edit({ Hostname: 'v4', IP: '192.0.2.1', MAC: 'aa:bb:cc:dd:ee:02' });
    h.context.toggleAllDhcp(true);
    assert.equal(h.state().find(b => b.hostname === 'v4').dhcp, true);
    assert.equal(h.state().find(b => b.hostname === 'v6').dhcp, false);
    h.context.toggleDhcp('v6', true);
    assert.equal(h.state()[0].dhcp, false);
});

test('save sends IPv6 management data without prompting for an unchanged DHCP service', async () => {
    const h = harness();
    h.edit({ Hostname: 'leaf', IP: '2001:db8::1', MAC: 'aa:bb:cc:dd:ee:01' });
    await h.context.saveBindings();
    assert.equal(h.requests[0].action, 'save-bindings');
    assert.equal(h.requests[0].payload.bindings[0].dhcp, false);
    assert.equal(h.requests[0].payload.bindings[0].ip, '2001:db8::1');
    assert.equal(h.requests[0].payload.restart_dhcp, false);
    assert.equal(h.confirmations.length, 0);
});

test('discovery export retains the saved management address for a dual-stack identity and adds IPv6 with DHCP off', async () => {
    const h = harness([{ hostname: 'dual', ip: '192.0.2.1', mac: 'aa:bb:cc:dd:ee:01', dhcp: true, username: 'custom' }]);
    h.setDiscovered([
        { hostname: 'dual', ip: '2001:db8::1', discovered_mac: 'aa:bb:cc:dd:ee:01', device_type: 'provisioned' },
        { hostname: 'new', ip: '2001:0db8::2', discovered_mac: 'aa:bb:cc:dd:ee:02', device_type: 'provisioned' },
    ]);
    await h.context.exportDiscoveredToDevicesYaml();
    await h.confirmations[0].callback();
    assert.equal(h.state().length, 2);
    assert.equal(h.state()[0].ip, '192.0.2.1');
    assert.equal(h.state()[0].username, 'custom');
    assert.equal(h.state()[1].ip, '2001:db8::2');
    assert.equal(h.state()[1].dhcp, false);
    assert.equal(h.requests[0].payload.restart_dhcp, false);
});

test('discovery export reports conflicting factory hostnames instead of discarding a physical device', async () => {
    const before = [{ hostname: 'cumulus', ip: '192.0.2.1', mac: 'aa:bb:cc:dd:ee:01', serial: 'serial-1', dhcp: true }];
    for (const identity of [
        { discovered_mac: 'aa:bb:cc:dd:ee:02', serial: 'serial-2' },
        { discovered_mac: 'aa:bb:cc:dd:ee:01', serial: 'serial-2' },
        { discovered_mac: 'aa:bb:cc:dd:ee:02', serial: 'serial-1' },
    ]) {
        const h = harness(before);
        h.setDiscovered([{ hostname: 'cumulus', ip: '2001:db8::2', device_type: 'provisioned', ...identity }]);
        await h.context.exportDiscoveredToDevicesYaml();
        assert.equal(h.requests.length, 0);
        assert.equal(h.confirmations.length, 0);
        assert.deepEqual(h.state(), before);
        assert.match(h.events.at(-1).message, /conflicting MAC or serial identities/);
    }
});

test('two newly discovered IPv6 devices sharing a factory hostname cannot silently collapse', async () => {
    const h = harness();
    h.setDiscovered([
        { hostname: 'cumulus', ip: '2001:db8::1', discovered_mac: 'aa:bb:cc:dd:ee:01', device_type: 'provisioned' },
        { hostname: 'cumulus', ip: '2001:db8::2', discovered_mac: 'aa:bb:cc:dd:ee:02', device_type: 'provisioned' },
    ]);
    await h.context.exportDiscoveredToDevicesYaml();
    assert.equal(h.requests.length, 0);
    assert.equal(h.confirmations.length, 0);
    assert.deepEqual(h.state(), []);
    assert.match(h.events.at(-1).message, /Assign distinct hostnames/);
});

test('matching serial or MAC still deduplicates dual-stack identity without replacing the saved hostname', async () => {
    for (const identity of [
        { mac: '-', serial: 'serial-1', discovered_mac: '' },
        { mac: 'aa:bb:cc:dd:ee:01', serial: '', discovered_mac: 'AA:BB:CC:DD:EE:01' },
    ]) {
        const before = [{ hostname: 'saved', ip: '192.0.2.1', mac: identity.mac, serial: identity.serial, username: 'custom' }];
        const h = harness(before);
        h.setDiscovered([{ hostname: 'actual', ip: '2001:db8::1', device_type: 'provisioned', ...identity }]);
        await h.context.exportDiscoveredToDevicesYaml();
        await h.confirmations[0].callback();
        assert.deepEqual(h.state(), before);
    }
});

test('hostname matching remains compatible for IPv4 discovery with unknown MAC and serial', async () => {
    const before = [{ hostname: 'saved', ip: '192.0.2.1', mac: '-', serial: '', username: 'custom' }];
    const h = harness(before);
    h.setDiscovered([{ hostname: 'saved', ip: '192.0.2.2', device_type: 'provisioned' }]);
    await h.context.exportDiscoveredToDevicesYaml();
    await h.confirmations[0].callback();
    assert.deepEqual(h.state(), before);
});

test('IPv6 CSV export includes static entries with no MAC and sorts addresses numerically', async () => {
    const h = harness([
        { hostname: 'ten', ip: '2001:db8::10', mac: '' },
        { hostname: 'two', ip: '2001:db8::2', mac: '-' },
        { hostname: 'v4', ip: '192.0.2.20', mac: 'aa:bb:cc:dd:ee:01' },
    ]);
    h.context.downloadBindingsCSV();
    const csv = await h.blobs[0].text();
    assert.ok(csv.indexOf('v4,') < csv.indexOf('two,'));
    assert.ok(csv.indexOf('two,') < csv.indexOf('ten,'));
    assert.match(csv, /ten,-,2001:db8::10/);
    assert.equal(h.context.parseBulkText(csv).errors.length, 0);
});

test('Inventory discovery lookup matches equivalent IPv6 text and renders no DHCP checkbox', () => {
    const h = harness([{ hostname: 'leaf', ip: '2001:0db8:0:0:0:0:0:1', mac: 'aa:bb:cc:dd:ee:01', dhcp: false }]);
    h.setDiscovered([{ ip: '2001:db8::1', device_type: 'provisioned', has_binding: true }]);
    h.context.renderBindings();
    assert.match(h.element('bindingCount').innerHTML, /Active: 1/);
    assert.doesNotMatch(h.element('bindingsBody').innerHTML, /onchange="toggleDhcp/);
    assert.match(h.element('bindingsBody').innerHTML, /IPv6 management only/);
});

test('IPv6 discovery shows monitoring status and cannot trigger any generated config action', async () => {
    const h = harness();
    const device = { hostname: 'leaf', ip: '2001:db8::1', device_type: 'provisioned', identity_verified: true };
    assert.match(h.context.renderPostProvisionBadge(device), /Monitoring/);
    assert.equal(h.context.generatedConfigDeployState(device, new Set(['leaf'])).enabled, false);
    assert.equal(h.context.renderGeneratedConfigAction(device, new Set(['leaf'])), '');
    await h.context.deployGeneratedConfig('leaf', device.ip);
    assert.equal(h.requests.length, 0);
    assert.equal(h.confirmations.length, 0);
    assert.equal(h.context.getUpgradePayload([device]), null);
});

test('IPv6 provisioning selection remains disabled even with reachable discovery data', () => {
    const h = harness();
    h.run(`upgradeDevices = [{hostname:'v6',ip:'2001:db8::1',reachable:true}]; bcDeviceGroups = {leaf: upgradeDevices};`);
    h.context.renderUpgradeTable();
    assert.match(h.element('upgradeBody').innerHTML, /data-ip="2001:db8::1" disabled/);
    assert.match(h.element('upgradeBody').innerHTML, /monitoring only/);
    h.context.renderBCDeviceList();
    assert.match(h.element('bcDeviceList').innerHTML, /disabled title="IPv6 management only"/);
    h.context.upgradeSetSel('2001:db8::1', true);
    h.context.bcSetSel('2001:db8::1', true);
    assert.equal(h.run('upgradeSelected.size + bcSelected.size'), 0);
});

test('an oversized IPv6 discovery range is rejected without sending a request', async () => {
    const h = harness();
    h.element('discoveryRange').value = '2001:db8::/64';
    await h.context.saveDiscoverySettings();
    assert.equal(h.requests.length, 0);
    assert.match(h.events[0].message, /1,500/);
});
