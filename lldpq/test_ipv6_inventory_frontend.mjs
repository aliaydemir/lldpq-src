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
    assert.match(h.element('bindingsBody').innerHTML, /DHCPv6 is not configured/);
});

test('IPv6 discovery leaves deployment manual and explicit generated config still requires identity', async () => {
    const h = harness();
    const device = { hostname: 'leaf', ip: '2001:db8::1', device_type: 'provisioned', identity_verified: true };
    assert.match(h.context.renderPostProvisionBadge(device), /Manual/);
    assert.equal(h.context.generatedConfigDeployState(device, new Set(['leaf'])).enabled, true);
    assert.match(h.context.renderGeneratedConfigAction(device, new Set(['leaf'])), /Re-deploy/);
    assert.equal(h.context.generatedConfigDeployState({ ...device, identity_verified: false }, new Set(['leaf'])).enabled, false);
    assert.equal(h.context.generatedConfigDeployState({ ...device, mac_status: 'mismatch' }, new Set(['leaf'])).enabled, false);
    await h.context.deployGeneratedConfig('leaf', device.ip);
    assert.equal(h.requests.length, 0);
    assert.equal(h.confirmations.length, 1);
    await h.confirmations[0].callback();
    assert.equal(h.requests[0].action, 'deploy-generated-config');
    assert.equal(h.requests[0].payload.ip, device.ip);
});

test('reachable IPv6 devices can be selected for explicit Upgrade and Base Config', () => {
    const h = harness();
    h.run(`upgradeDevices = [{hostname:'v6',ip:'2001:db8::1',reachable:true}]; bcDeviceGroups = {leaf: upgradeDevices};`);
    h.context.renderUpgradeTable();
    assert.doesNotMatch(h.element('upgradeBody').innerHTML, /data-ip="2001:db8::1" disabled/);
    assert.match(h.element('upgradeBody').innerHTML, /candidate/);
    h.context.renderBCDeviceList();
    assert.doesNotMatch(h.element('bcDeviceList').innerHTML, /disabled title="IPv6 management only"/);
    h.context.upgradeSetSel('2001:db8::1', true);
    h.context.bcSetSel('2001:db8::1', true);
    assert.equal(h.run('upgradeSelected.size + bcSelected.size'), 2);
    h.context.document.querySelectorAll = selector => selector === '.upgrade-dev-cb:checked'
        ? [{ dataset: { index: '0' } }] : [];
    assert.equal(h.context.selectedUpgradeDevices()[0].ip, '2001:db8::1');
});

test('unreachable IPv6 and already-current devices retain existing upgrade selection gates', () => {
    const h = harness();
    h.element('upgradeTargetVersion').value = '5.16.1';
    h.run(`upgradeDevices = [
        {hostname:'offline',ip:'2001:db8::1',reachable:false},
        {hostname:'current',ip:'2001:db8::2',reachable:true,current_version:'5.16.1'}
    ];`);
    h.context.renderUpgradeTable();
    assert.match(h.element('upgradeBody').innerHTML, /data-ip="2001:db8::1" disabled/);
    assert.match(h.element('upgradeBody').innerHTML, /data-ip="2001:db8::2" disabled/);
});

test('explicit Base Config sends mixed addresses and updates scoped IPv6 progress', async () => {
    const h = harness();
    const devices = [
        { ip: '192.0.2.1', hostname: 'v4', username: 'cumulus' },
        { ip: 'fe80::1%en-1', hostname: 'v6', username: 'admin' },
    ];
    h.context.document.querySelectorAll = selector => selector === '.bc-dev-cb:checked'
        ? devices.map(dataset => ({ dataset })) : [];
    h.context.apiCall = async (action, payload) => {
        h.requests.push({ action, payload });
        return { success: true, results: devices.map(device => ({ ...device, success: true, message: 'Applied' })) };
    };
    await h.context.deployBaseConfig();
    assert.equal(h.requests.length, 1);
    assert.equal(h.requests[0].action, 'deploy-base-config');
    assert.equal(h.requests[0].payload.devices[1].ip, 'fe80::1%en-1');
    assert.equal(h.requests[0].payload.disable_ztp, false);
    assert.match(h.element('deployProgress').innerHTML, /id="deploy-address-fe80%3A%3A1%25en-1"/);
    assert.match(h.element('deploy-address-fe80%3A%3A1%25en-1').innerHTML, /Applied/);
    assert.equal(h.element('deployStatusText').textContent, 'Done: 2 OK, 0 failed');
    assert.equal(h.element('btnDeploy').disabled, false);
});

test('scoped IPv6 interfaces with punctuation retain independent deployment progress rows', async () => {
    const h = harness();
    const devices = [
        { ip: 'fe80::1%eth0.100', hostname: 'vlan', username: 'cumulus' },
        { ip: 'fe80::1%eth0-100', hostname: 'dash', username: 'cumulus' },
    ];
    const rowIds = devices.map(device => 'deploy-' + h.context.rowIdFromIp(device.ip));
    assert.notEqual(rowIds[0], rowIds[1]);
    assert.equal(h.context.rowIdFromIp('192.0.2.1'), '192-0-2-1');
    assert.equal(h.context.rowIdFromIp('fe80:0:0:0:0:0:0:1%eth0.100'), h.context.rowIdFromIp(devices[0].ip));
    h.context.document.querySelectorAll = selector => selector === '.bc-dev-cb:checked'
        ? devices.map(dataset => ({ dataset })) : [];
    h.context.apiCall = async () => ({
        success: true,
        results: [
            { ...devices[0], success: true, message: 'VLAN applied' },
            { ...devices[1], success: false, error: 'Dash failed' },
        ],
    });
    await h.context.deployBaseConfig();
    for (const rowId of rowIds) assert.ok(h.element('deployProgress').innerHTML.includes(`id="${rowId}"`));
    assert.match(h.element(rowIds[0]).innerHTML, /VLAN applied/);
    assert.doesNotMatch(h.element(rowIds[0]).innerHTML, /Dash failed/);
    assert.match(h.element(rowIds[1]).innerHTML, /Dash failed/);
    assert.equal(h.element('deployStatusText').textContent, 'Done: 1 OK, 1 failed');
});

test('Upgrade image server accepts IPv6 authorities while ZTP retains its existing validator', () => {
    const h = harness();
    for (const [input, expected] of [
        ['192.0.2.10', '192.0.2.10'],
        ['images.example:8080', 'images.example:8080'],
        ['IMAGES.EXAMPLE:8080', 'images.example:8080'],
        ['2001:0DB8:0:0:0:0:0:10', '[2001:db8::10]'],
        ['[2001:db8::10]:8080', '[2001:db8::10]:8080'],
        ['[fd00::10]:65535', '[fd00::10]:65535'],
    ]) assert.equal(h.context.upgradeImageServerRef(input), expected, input);
    for (const value of [
        '', '__IMAGE_SERVER_IP__', '2001:::1', '[2001:db8::1', '2001:db8::g',
        'http://[2001:db8::1]', '[2001:db8::1]/images', 'host/path', 'host;echo',
        'fe80::1', 'fe80::1%eth0', '[fe80::1%eth0]:8080', '[2001:db8::1%eth0]',
        '::', 'ff02::1', '0.0.0.0', '224.0.0.1', '192.0.2.999',
        '::ffff:0.0.0.0', '::ffff:224.0.0.1', '-invalid.example', 'invalid-.example', 'bad..example',
        '[2001:db8::1]:0', '[2001:db8::1]:65536', 'host:99999',
    ]) assert.equal(h.context.upgradeImageServerRef(value), '', value);
    assert.equal(h.context.isUsableImageServer('192.0.2.10'), true);
    assert.equal(h.context.isUsableImageServer('[2001:db8::10]'), false);
});

test('Upgrade server override survives refresh without modifying the saved ZTP input', () => {
    const h = harness();
    h.element('ztpImageServer').value = '192.0.2.10';
    h.context.syncUpgradeServerIPFromZTP();
    assert.equal(h.element('upgradeServerIP').value, '192.0.2.10');
    h.element('upgradeServerIP').value = '2001:db8::10';
    h.context.onUpgradeServerInput();
    h.run(`upgradeDetectedServerIP = '192.0.2.20'`);
    h.context.syncUpgradeServerIPFromZTP();
    assert.equal(h.element('upgradeServerIP').value, '2001:db8::10');
    assert.equal(h.element('ztpImageServer').value, '192.0.2.10');
    assert.match(h.element('upgradeServerInfo').innerHTML, /Upgrade only/);
    assert.equal(h.requests.length, 0);
});

test('recovered upgrade job keeps its IPv6 server through later default refreshes', () => {
    const h = harness();
    h.element('ztpImageServer').value = '192.0.2.10';
    h.context.attachUpgradeJob({ id: 'existing-job', server_ip: '[2001:db8::10]:8080', complete: true, devices: [] });
    h.context.syncUpgradeServerIPFromZTP();
    assert.equal(h.element('upgradeServerIP').value, '[2001:db8::10]:8080');
    assert.equal(h.element('ztpImageServer').value, '192.0.2.10');
});

test('Upgrade payload accepts IPv6 devices and canonically brackets the separate image server', () => {
    const h = harness();
    h.element('upgradeImage').value = 'cumulus-5.16.1.bin';
    h.element('upgradeTargetVersion').value = '5.16.1';
    h.element('upgradeServerIP').value = '2001:db8::10';
    h.element('upgradeBaseAfter').checked = true;
    h.element('upgradeStopOnFailure').checked = true;
    const devices = [{ hostname: 'v6', ip: 'fe80::1%eth0' }, { hostname: 'v4', ip: '192.0.2.1' }];
    const payload = h.context.getUpgradePayload(devices);
    assert.equal(payload.server_ip, '[2001:db8::10]');
    assert.equal(payload.devices[0].ip, 'fe80::1%eth0');
    assert.equal(payload.devices.length, 2);
    assert.equal(payload.base_config_after, true);
    assert.equal(payload.stop_on_failure, true);
    h.element('upgradeServerIP').value = '[fe80::10%eth0]';
    assert.equal(h.context.getUpgradePayload(devices), null);
    assert.match(h.events.at(-1).message, /Link-local image servers are not supported/);
});

test('an oversized IPv6 discovery range is rejected without sending a request', async () => {
    const h = harness();
    h.element('discoveryRange').value = '2001:db8::/64';
    await h.context.saveDiscoverySettings();
    assert.equal(h.requests.length, 0);
    assert.match(h.events[0].message, /1,500/);
});
