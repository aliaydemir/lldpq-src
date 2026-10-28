import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const html = fs.readFileSync(new URL('../html/lldp.html', import.meta.url), 'utf8');
const between = (start, end) => html.slice(html.indexOf(start), html.indexOf(end, html.indexOf(start)));
function harness() {
    const elements = {
        'download-csv': { disabled: false, setAttribute() {} },
        'location-notice': { textContent: '', style: {} },
    };
    let renders = 0;
    const requests = [];
    const context = vm.createContext({
        document: { getElementById: id => elements[id] },
        p2pDesignStatus: 'ready', deviceLocationsStatus: 'loading', deviceLocations: {},
        deviceLocationsGeneration: 0, pendingConnectionsRender: null,
        allConnections: [{}], applyCurrentFilters: () => renders++,
        fetch: () => new Promise(resolve => requests.push(resolve)),
    });
    vm.runInContext(between('function updateCsvExportAvailability()', 'function escHtml(v)') +
        between('function connectionLocationValues(connection)', 'function designStatusFor(conn)'), context);
    return { context, elements, requests, renders: () => renders };
}
const response = (locations = {}, conflicts = []) => ({ ok: true, json: async () => ({success:true,locations,conflicts}) });
const mapped = { 'leaf-01': {rack:'C1',unit:'6-7'}, 'actual':{rack:'C3',unit:'18'} };

test('canonical exact hostnames resolve independently; missing neighbors do not inherit expected location', () => {
    const h = harness();
    h.context.deviceLocations = mapped;
    const get = connection => Array.from(h.context.connectionLocationValues(connection));
    assert.deepEqual(get({localDevice:' LEAF-01 ',expectedDevice:'missing',actualDevice:'actual'}), ['C1','6-7','','','C3','18']);
    assert.deepEqual(get({localDevice:'leaf-01.example',expectedDevice:'leaf-01'}), ['','','C1','6-7','','']);
    assert.deepEqual(get({localDevice:'constructor'}), ['','','','','','']);
});

test('CSV stays disabled until locations and pending rows are ready', async () => {
    const h = harness();
    const pending = h.context.loadDeviceLocations();
    assert.equal(h.elements['download-csv'].disabled, true);
    h.context.pendingConnectionsRender = {};
    h.requests[0](response(mapped));
    await pending;
    assert.equal(h.elements['download-csv'].disabled, true);
    h.context.pendingConnectionsRender = null;
    h.context.updateCsvExportAvailability();
    assert.equal(h.elements['download-csv'].disabled, false);
    assert.equal(h.renders(), 1);
});

test('a failed refresh removes stale locations and exposes the reason', async () => {
    const h = harness();
    h.context.deviceLocations = mapped;
    const pending = h.context.loadDeviceLocations();
    h.requests[0]({ok:false,status:503});
    await pending;
    assert.deepEqual(Object.keys(h.context.deviceLocations), []);
    assert.equal(h.elements['download-csv'].disabled, false);
    assert.match(h.elements['location-notice'].textContent, /could not be loaded/);
});

test('a late earlier response cannot replace newer mapping data', async () => {
    const h = harness();
    const old = h.context.loadDeviceLocations();
    const current = h.context.loadDeviceLocations();
    h.requests[1](response(mapped));
    await current;
    h.requests[0](response({'leaf-01':{rack:'OLD',unit:'1'}}));
    await old;
    assert.equal(h.context.deviceLocations['leaf-01'].rack, 'C1');
    assert.equal(h.renders(), 1);
});

test('conflicts are explained without changing LLDP connection status', async () => {
    const h = harness();
    const pending = h.context.loadDeviceLocations();
    h.requests[0](response({}, [{hostname:'leaf-01'}]));
    await pending;
    assert.match(h.elements['location-notice'].textContent, /Conflicting.*leaf-01/);
    assert.deepEqual(Object.keys(h.context.deviceLocations), []);
});
