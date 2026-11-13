import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

// Fabric Exit: the add and edit dialogs list the device's real ports (from the
// existing get-device endpoint) instead of a fixed swp1-swp16 range / a single
// frozen option, and fall back to exactly the old lists when nothing is known.

const page = fs.readFileSync(new URL('../html/fabric-exit.html', import.meta.url), 'utf8');
const script = page.match(/<script>([\s\S]*?)<\/script>/)[1];

const LEGACY_ADD_LIST = '<option value="">Select interface...</option>' +
    Array.from({ length: 16 }, (_, i) => `<option value="swp${i + 1}">swp${i + 1}</option>`).join('');
const range = (from, to) => Array.from({ length: to - from + 1 }, (_, i) => `swp${from + i}`);
const optionValues = html => [...html.matchAll(/<option value="([^"]*)"/g)].map(m => m[1]);
const groups = html => Object.fromEntries(
    [...html.matchAll(/<optgroup label="([^"]*)">([\s\S]*?)<\/optgroup>/g)].map(m => [m[1], optionValues(m[2])]));
const settle = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => {
    let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve };
};

class Element {
    constructor() {
        this.value = ''; this.textContent = ''; this.style = {}; this.dataset = {}; this.options = [];
        this.checked = false; this.disabled = false; this.html = '';
        const classes = new Set();
        this.classList = { add: c => classes.add(c), remove: c => classes.delete(c), contains: c => classes.has(c) };
    }
    get innerHTML() { return this.html; }
    // Like a browser, a select shows its first option after its markup is replaced
    set innerHTML(html) {
        this.html = String(html);
        const values = optionValues(this.html);
        if (values.length) this.value = values[0];
    }
    addEventListener() {}
}

function harness(handler) {
    const elements = new Map(), calls = [], errors = [];
    const element = id => {
        if (!elements.has(id)) elements.set(id, new Element());
        return elements.get(id);
    };
    const context = vm.createContext({
        console: { error: (...args) => errors.push(args), log: () => {} },
        document: { getElementById: element, addEventListener: () => {} },
        fetch: async (url, options = {}) => {
            const query = new URL(url, 'http://lldpq.test').searchParams;
            const call = { action: query.get('action'), hostname: query.get('hostname'),
                body: options.body ? JSON.parse(options.body) : null };
            calls.push(call);
            const data = await handler(call);
            return { ok: true, status: 200, json: async () => data };
        },
    });
    vm.runInContext(script, context);
    return { context, element, calls, errors, lookups: () => calls.filter(c => c.action === 'get-device') };
}

const emptyLists = call => {
    if (call.action === 'list-external-peers') return { success: true, peers: [], devices: [], bgp_profiles: {} };
    if (call.action === 'list-vtep-devices') return { success: true, devices: [] };
    throw new Error('Unexpected action: ' + call.action);
};

const peer = (overrides = {}) => ({
    device: 'border-01', vrf: 'RED', bgp_profile: 'BORDER', interface: 'swp1.1002',
    local_ip: '192.0.2.1', local_ip_cidr: '192.0.2.1/30', remote_peer: '192.0.2.2',
    weight: null, policy_name: null, policy_direction: null, soft_reconfiguration: false, bfd_enabled: false,
    ...overrides,
});

const borderConfig = {
    vrfs: { RED: { bgp: { bgp_profile: 'BORDER' } } },
    interfaces: {
        swp10: {}, swp1: { description: 'fw', subinterfaces: { 1002: { ip: '192.0.2.1/30', vlan: 1002, vrf: 'RED' } } },
        swp2: { breakout: '4x' }, swp2s1: {}, swp2s0: {},
        swp31: { ip: '10.0.0.1/31' }, swp3: {}, swp4: null,
        swp6: { subinterfaces: { 1002: { ip: '198.51.100.1/31', vlan: 1002, vrf: 'BLUE' } } },
        swp7: { subinterfaces: { 2000: { ip: '198.51.100.3/31', vlan: 2000, vrf: 'RED' } } },
        lo: { ip: '10.255.0.1/32' }, eth0: {}, vlan10: {},
    },
    bonds: { bond1: { bond_members: ['swp3', 'swp4'] } },
};

async function addDialogList(config) {
    const p = harness(call => {
        if (call.action === 'get-device') return { success: true, config };
        throw new Error('Unexpected action: ' + call.action);
    });
    p.element('add-device').value = 'border-01';
    await p.context.onAddDeviceChange();
    assert.deepEqual(p.lookups().map(c => c.hostname), ['border-01']);
    return p.element('add-parent-interface').innerHTML;
}

test('add dialog lists the real ports of the selected device', async () => {
    const html = await addDialogList(borderConfig);
    assert.ok(html.startsWith('<option value="">Select interface...</option>'));
    assert.deepEqual(groups(html), {
        // natural order; breakout parent swp2 and bond members swp3/swp4 cannot carry a subinterface
        'In inventory': ['swp1', 'swp2s0', 'swp2s1', 'swp6', 'swp7', 'swp10', 'swp31'],
        // generic range only for ports the inventory does not know
        'Not in inventory': ['swp5', 'swp8', 'swp9', ...range(11, 16)],
    });
});

test('add dialog is not grouped when the inventory lists every port of the range', async () => {
    const interfaces = Object.fromEntries(range(1, 20).map(name => [name, {}]));
    const html = await addDialogList({ vrfs: {}, interfaces });
    assert.doesNotMatch(html, /optgroup/);
    assert.deepEqual(optionValues(html), ['', ...range(1, 20)]);
});

test('add dialog keeps the fixed swp1-swp16 list when the inventory lists no port', async () => {
    for (const config of [{ vrfs: {} }, { vrfs: {}, interfaces: null }, { vrfs: {}, interfaces: { lo: {}, eth0: {} } }]) {
        assert.equal(await addDialogList(config), LEGACY_ADD_LIST);
    }
});

const EMPTY_ADD_LIST = '<option value="">Select interface...</option>';
const otherDevice = { success: true, config: { vrfs: { Y_VRF: {} }, interfaces: { swp40: {} } } };

test('add dialog drops a late reply for a device that is no longer selected', async () => {
    const slow = deferred();
    const p = harness(call => {
        if (call.action !== 'get-device') throw new Error('Unexpected action: ' + call.action);
        return call.hostname === 'border-01' ? slow.promise : otherDevice;
    });
    p.element('add-device').value = 'border-01';
    const first = p.context.onAddDeviceChange();
    p.element('add-device').value = 'border-02';
    // The previous device's list is gone as soon as the device changes
    const second = p.context.onAddDeviceChange();
    assert.equal(p.element('add-parent-interface').innerHTML, EMPTY_ADD_LIST);
    await second;
    const ports = p.element('add-parent-interface').innerHTML;
    const vrfs = p.element('add-vrf').innerHTML;
    assert.deepEqual(groups(ports)['In inventory'], ['swp40']);
    assert.deepEqual(optionValues(vrfs), ['', 'Y_VRF']);

    slow.resolve({ success: true, config: borderConfig });
    await first;
    assert.deepEqual(p.lookups().map(c => c.hostname), ['border-01', 'border-02']);
    assert.equal(p.element('add-parent-interface').innerHTML, ports);
    assert.equal(p.element('add-vrf').innerHTML, vrfs);
});

test('add dialog does not keep the ports of the previous device when the lookup fails', async () => {
    for (const failure of [
        () => ({ success: false, error: 'Device file not found' }),
        () => ({ success: true }),
        () => { throw new Error('network down'); },
    ]) {
        const p = harness(call => {
            if (call.action !== 'get-device') throw new Error('Unexpected action: ' + call.action);
            return call.hostname === 'border-01' ? { success: true, config: borderConfig } : failure();
        });
        p.element('add-device').value = 'border-01';
        await p.context.onAddDeviceChange();
        assert.ok(optionValues(p.element('add-parent-interface').innerHTML).includes('swp10'));

        p.element('add-device').value = 'border-02';
        await p.context.onAddDeviceChange();
        assert.equal(p.element('add-parent-interface').innerHTML, EMPTY_ADD_LIST);

        // Without a port the dialog cannot be saved for the wrong device
        for (const [id, value] of [['add-vrf', 'RED'], ['add-vlan-id', '1002'],
            ['add-local-ip', '192.0.2.1/30'], ['add-remote-peer', '192.0.2.2']]) p.element(id).value = value;
        await p.context.saveNewPeer();
        assert.equal(p.element('result-modal-title').textContent, 'Missing Fields');
        assert.deepEqual(p.calls.filter(c => c.action !== 'get-device'), []);
    }
});

test('add dialog reports a failed lookup only for the device that is still selected', async () => {
    const slow = deferred();
    const p = harness(call => {
        if (call.action !== 'get-device') throw new Error('Unexpected action: ' + call.action);
        return call.hostname === 'border-01' ? slow.promise : otherDevice;
    });
    p.element('add-device').value = 'border-01';
    const first = p.context.onAddDeviceChange();
    p.element('add-device').value = 'border-02';
    await p.context.onAddDeviceChange();
    const ports = p.element('add-parent-interface').innerHTML;

    slow.resolve(Promise.reject(new Error('network down')));
    await first;
    assert.equal(p.errors.length, 1);
    assert.equal(p.element('result-modal').classList.contains('visible'), false);
    assert.equal(p.element('add-parent-interface').innerHTML, ports);

    // The same failure for the selected device is still shown, as before
    const q = harness(() => { throw new Error('network down'); });
    q.element('add-device').value = 'border-01';
    await q.context.onAddDeviceChange();
    assert.equal(q.element('result-modal').classList.contains('visible'), true);
    assert.equal(q.element('result-modal-message').textContent, 'Failed to load device configuration');
    assert.equal(q.element('result-modal-details').textContent, 'network down');
});

test('add dialog empties the port list when no device is selected', async () => {
    const slow = deferred();
    const p = harness(() => slow.promise);
    p.element('add-device').value = 'border-01';
    const first = p.context.onAddDeviceChange();
    p.element('add-device').value = '';
    await p.context.onAddDeviceChange();
    slow.resolve({ success: true, config: borderConfig });
    await first;
    assert.equal(p.lookups().length, 1);
    assert.equal(p.element('add-parent-interface').innerHTML, EMPTY_ADD_LIST);
});

test('add dialog empties a filled port list when the device is cleared', async () => {
    const p = harness(() => ({ success: true, config: borderConfig }));
    p.element('add-device').value = 'border-01';
    await p.context.onAddDeviceChange();
    assert.ok(optionValues(p.element('add-parent-interface').innerHTML).includes('swp10'));
    p.element('add-device').value = '';
    await p.context.onAddDeviceChange();
    assert.equal(p.lookups().length, 1);
    assert.equal(p.element('add-parent-interface').innerHTML, EMPTY_ADD_LIST);
});

test('a reply that arrives after the add dialog was reopened does not fill it', async () => {
    const slow = deferred();
    const p = harness(() => slow.promise);
    p.element('add-device').value = 'border-01';
    const first = p.context.onAddDeviceChange();
    p.context.openAddPeerModal();
    slow.resolve({ success: true, config: borderConfig });
    await first;
    assert.equal(p.element('add-device').value, '');
    assert.equal(p.element('add-parent-interface').innerHTML, EMPTY_ADD_LIST);
    assert.equal(p.element('add-vrf').innerHTML, '<option value="">Select VRF...</option>');
});

test('edit dialog offers the peer VLAN on the other ports of its device', async () => {
    assert.ok(page.includes('<input type="hidden" id="edit-original-interface">'));
    const p = harness(call => {
        if (call.action === 'get-device') return { success: true, config: borderConfig };
        throw new Error('Unexpected action: ' + call.action);
    });
    p.context.openEditModal(peer());
    // The dialog opens at once with the current interface, as before
    assert.equal(p.element('edit-interface').innerHTML, '<option value="swp1.1002">swp1.1002</option>');
    await settle();

    assert.deepEqual(p.lookups().map(c => c.hostname), ['border-01']);
    const html = p.element('edit-interface').innerHTML;
    assert.ok(html.startsWith('<option value="swp1.1002">swp1.1002</option>'));
    assert.equal(p.element('edit-interface').value, 'swp1.1002');
    assert.deepEqual(groups(html), {
        // swp6.1002 already exists (another VRF) and swp1.1002 is the peer itself: never offered again
        'In inventory': ['swp2s0.1002', 'swp2s1.1002', 'swp7.1002', 'swp10.1002', 'swp31.1002'],
        'Not in inventory': ['swp5', 'swp8', 'swp9', ...range(11, 16)].map(name => name + '.1002'),
    });
    assert.equal(optionValues(html).filter(value => value === 'swp1.1002').length, 1);
});

test('edit dialog keeps its single current interface when the device lookup fails', async () => {
    const single = '<option value="swp1.1002">swp1.1002</option>';
    for (const handler of [
        () => ({ success: false, error: 'Device file not found' }),
        () => ({ success: true }),
        () => { throw new Error('network down'); },
    ]) {
        const p = harness(handler);
        p.context.openEditModal(peer());
        await settle();
        assert.equal(p.lookups().length, 1);
        assert.equal(p.element('edit-interface').innerHTML, single);
        assert.equal(p.element('edit-interface').value, 'swp1.1002');
    }
});

test('edit dialog keeps its single current interface when the reply does not show the peer subinterface', async () => {
    // get-device reads only <host>.yaml: for a device kept in <host>.yml it
    // answers success with a config that has no interfaces, so the dialog
    // cannot tell which subinterfaces exist (another peer of the same VRF may
    // sit on swp2.1002, and saving onto it would overwrite that link)
    const single = '<option value="swp1.1002">swp1.1002</option>';
    for (const config of [
        {},
        { vrfs: { RED: { bgp: { bgp_profile: 'BORDER' } } } },
        { interfaces: null },
        { interfaces: { swp1: { description: 'fw' }, swp2: {} } },
        { interfaces: { swp1: { subinterfaces: { 2000: { ip: '198.51.100.3/31', vlan: 2000, vrf: 'RED' } } } } },
    ]) {
        const p = harness(() => ({ success: true, config }));
        p.context.openEditModal(peer());
        await settle();
        assert.equal(p.lookups().length, 1);
        assert.equal(p.element('edit-interface').innerHTML, single);
        assert.equal(p.element('edit-interface').value, 'swp1.1002');
    }
});

test('edit dialog does not look up ports for peers that have no subinterface', async () => {
    for (const name of ['lo', 'swp5', '']) {
        const p = harness(() => { throw new Error('no request expected'); });
        p.context.openEditModal(peer({ interface: name }));
        await settle();
        assert.equal(p.calls.length, 0);
        assert.equal(p.element('edit-interface').innerHTML, `<option value="${name}">${name}</option>`);
        assert.equal(p.element('edit-original-interface').value, name);
    }
});

test('a late reply for a previously opened peer does not repopulate the dialog', async () => {
    const slow = deferred();
    const p = harness(call => {
        if (call.action !== 'get-device') throw new Error('Unexpected action: ' + call.action);
        return call.hostname === 'border-01' ? slow.promise : { success: true, config: { interfaces: {
            swp40: {}, swp9: { subinterfaces: { 300: { ip: '203.0.113.1/31', vlan: 300, vrf: 'RED' } } },
        } } };
    });
    p.context.openEditModal(peer());
    p.context.openEditModal(peer({ device: 'border-02', interface: 'swp9.300' }));
    await settle();
    const second = p.element('edit-interface').innerHTML;
    assert.deepEqual(groups(second)['In inventory'], ['swp40.300']);

    slow.resolve({ success: true, config: borderConfig });
    await settle();
    assert.equal(p.element('edit-interface').innerHTML, second);
});

test('saving a changed interface also sends the original one', async () => {
    const p = harness(call => {
        if (call.action === 'get-device') return { success: true, config: borderConfig };
        if (call.action === 'update-external-peer') return { success: true };
        return emptyLists(call);
    });
    p.context.openEditModal(peer());
    await settle();
    p.element('edit-interface').value = 'swp10.1002';
    await p.context.savePeerEdit();

    const update = p.calls.find(c => c.action === 'update-external-peer');
    assert.equal(update.body.interface, 'swp10.1002');
    assert.equal(update.body.original_interface, 'swp1.1002');
    assert.equal(update.body.local_ip, '192.0.2.1/30');

    // Contract with the CGI: update-external-peer drops the previous
    // subinterface only when it is told which one that was (the drop itself
    // is exercised in test_fabric_exit_interface_move.py)
    const api = fs.readFileSync(new URL('../html/fabric-api.sh', import.meta.url), 'utf8');
    const start = api.indexOf('\n    update-external-peer)\n');
    assert.notEqual(start, -1);
    assert.ok(api.slice(start, api.indexOf('\nPYTHON\n', start)).includes("data.get('original_interface'"));
});

test('deleting from the edit dialog targets the saved interface, not an unsaved selection', async () => {
    const p = harness(call => {
        if (call.action === 'get-device') return { success: true, config: borderConfig };
        if (call.action === 'delete-external-peer') return { success: true };
        return emptyLists(call);
    });
    p.context.openEditModal(peer());
    await settle();
    p.element('edit-interface').value = 'swp10.1002';
    p.context.deletePeer();
    assert.equal(p.element('delete-peer-interface').textContent, 'swp1.1002');
    await p.context.confirmDeletePeer();

    const del = p.calls.find(c => c.action === 'delete-external-peer');
    assert.equal(del.body.interface, 'swp1.1002');
    assert.equal(del.body.remote_peer, '192.0.2.2');
});
