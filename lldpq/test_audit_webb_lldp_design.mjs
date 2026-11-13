// LLDP page, Design status of three-part 'X/Y/Z' breakout ports.
//
// The real functions of html/lldp.html are evaluated here: the design index
// (buildP2pIndex), the report parser (parseAndDisplayLLDPData) and the status
// (designStatusFor). Covered: a neighbor on the wrong breakout leg is a
// Mismatch once the precise sub-port is resolved, the breakout width of a
// port follows the live ports of the report (a switch may mix 2x/4x/8x), and
// an unsplit port written X/1/1 is swpX when the report shows it unsplit.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const html = fs.readFileSync(new URL('../html/lldp.html', import.meta.url), 'utf8');
function between(start, end) {
    const from = html.indexOf(start);
    const to = html.indexOf(end, from);
    assert.ok(from >= 0 && to > from, `lldp.html no longer contains ${start} .. ${end}`);
    return html.slice(from, to);
}

function page({ deviceAliases = {} } = {}) {
    const element = { innerHTML: '', style: {}, insertRow: () => ({}) };
    const context = vm.createContext({ document: { getElementById: () => element } });
    vm.runInContext(`
        let allConnections = [];
        let totalConnections = 0, successConnections = 0, failedConnections = 0,
            warningConnections = 0, noInfoConnections = 0;
        const LLDP_STATUS_PRIORITY = {};
        let portAliasLc = {}, portAliasRevLc = {};
        let deviceAliasLc = {}, deviceAliasRevLc = {};
        const determineLLDPStatus = () => ({ status: 'SUCCESS' });
        const updateSummaryCards = () => {}, setupSummaryCardEvents = () => {},
            renderConnectionsTable = () => {}, populateDeviceList = () => {},
            initDeviceSearch = () => {}, applyCurrentFilters = () => {},
            updateCsvExportAvailability = () => {};
    ` + between('function normalizedValue(value)', 'function sameHostname(left, right)')
      + between("let p2pDesignStatus = 'loading';", 'function setP2pDesignStatus(status)')
      + between('function deviceKeysJs(name)', 'function loadP2pDesign()')
      + between('function designStatusFor(conn)', 'function kvRow(label, value, cls)')
      + between('function parseLLDPReportData(data)', 'function showFallbackContent(error)')
      + between('function validTimestampParts(', 'function parseLastModifiedHeader(value)')
      + `
        globalThis.page = {
            aliases(map) {
                Object.keys(map).forEach(real => {
                    deviceAliasLc[real.toLowerCase()] = map[real];
                    deviceAliasRevLc[map[real].toLowerCase()] = real.toLowerCase();
                });
            },
            // What loadP2pDesign does with a fetched design.
            design(records) { buildP2pIndex({ connections: records }); p2pDesignStatus = 'ready'; },
            // What loadLLDPData does with a fetched lldp_results.ini.
            report(text) { parseAndDisplayLLDPData(text); },
            rows: () => allConnections,
            status: conn => designStatusFor(conn),
            designFor: conn => activeP2pDesignFor(conn),
        };
    `, context);
    context.page.aliases(deviceAliases);
    return context.page;
}

const cable = (a, aPort, b, bPort) => ({
    source_name: a, source_port: aPort, dest_name: b, dest_port: bPort,
    sheet_name: 'P2P', network_type: 'eth',
});

// lldp_results.ini as lldp-validate.py writes it.
// rows: [device, port, status, expNbr, expPort, actNbr, actPort, portStatus]
function reportText(rows) {
    const devices = [...new Set(rows.map(row => row[0]))];
    const rule = '-'.repeat(60);
    return ['Created on 2026-01-01 00-00-00', ''].concat(devices.flatMap(device => [
        `===== ${device} =====`, '', rule,
        'Port Status Exp-Nbr Exp-Nbr-Port Act-Nbr Act-Nbr-Port Port-Status', rule,
        ...rows.filter(row => row[0] === device).map(row => row.slice(1).join(' ')), '', '',
    ])).join('\n');
}

const find = (p, device, port) => {
    const row = p.rows().find(c => c.localDevice === device && c.localPort === port);
    assert.ok(row, `report row ${device}:${port}`);
    return row;
};

// LEAF-01: swp1 is a twin-port 2x split (one leg per spine), swp33 a 4x
// split written as two groups of two, swp5 is not split.
const MIXED_DESIGN = [
    cable('LEAF-01', '1/1/1', 'SPINE-01', 'swp1s0'),
    cable('LEAF-01', '1/2/1', 'SPINE-02', 'swp1s0'),
    cable('LEAF-01', '33/1/1', 'SPINE-03', 'swp1'),
    cable('LEAF-01', '33/1/2', 'SPINE-03', 'swp2'),
    cable('LEAF-01', '33/2/1', 'SPINE-03', 'swp3'),
    cable('LEAF-01', '33/2/2', 'SPINE-03', 'swp4'),
    cable('LEAF-01', '5/1/1', 'SPINE-04', 'swp5'),
];
const pass = (device, port, nbr, nbrPort) => [device, port, 'Pass', nbr, nbrPort, nbr, nbrPort, 'UP'];
// The wiring report of that switch when every cable is where it belongs.
const MIXED_REPORT = [
    pass('LEAF-01', 'swp1s0', 'SPINE-01', 'swp1s0'), pass('LEAF-01', 'swp1s1', 'SPINE-02', 'swp1s0'),
    pass('LEAF-01', 'swp33s0', 'SPINE-03', 'swp1'), pass('LEAF-01', 'swp33s1', 'SPINE-03', 'swp2'),
    pass('LEAF-01', 'swp33s2', 'SPINE-03', 'swp3'), pass('LEAF-01', 'swp33s3', 'SPINE-03', 'swp4'),
    pass('LEAF-01', 'swp5', 'SPINE-04', 'swp5'),
    pass('SPINE-01', 'swp1s0', 'LEAF-01', 'swp1s0'), pass('SPINE-02', 'swp1s0', 'LEAF-01', 'swp1s1'),
    pass('SPINE-03', 'swp1', 'LEAF-01', 'swp33s0'), pass('SPINE-03', 'swp2', 'LEAF-01', 'swp33s1'),
    pass('SPINE-03', 'swp3', 'LEAF-01', 'swp33s2'), pass('SPINE-03', 'swp4', 'LEAF-01', 'swp33s3'),
    pass('SPINE-04', 'swp5', 'LEAF-01', 'swp5'),
];

test('a neighbor on the wrong breakout leg is a Mismatch once the precise sub-port is resolved', () => {
    const p = page();
    p.design([cable('SPINE-01', 'swp1s0', 'LEAF-01', '1/1/1'), cable('SPINE-02', 'swp1s0', 'LEAF-01', '1/2/1')]);
    const seen = port => p.status({
        localDevice: 'SPINE-02', localPort: 'swp1s0', actualDevice: 'LEAF-01', actualPort: port });
    assert.equal(seen('swp1s1').code, 'match');
    // swp1s0, swp1s2 and swp1s4 are all tolerant aliases of '1/2/1'.
    for (const wrong of ['swp1s0', 'swp1s2', 'swp1s4', 'swp1s3']) {
        const status = seen(wrong);
        assert.equal(status.code, 'mismatch', wrong);
        assert.equal(status.reason, `Design expects LEAF-01:1/2/1 (swp1s1), live shows LEAF-01:${wrong}.`);
    }
    assert.equal(p.status({ localDevice: 'SPINE-01', localPort: 'swp1s0',
        actualDevice: 'LEAF-01', actualPort: 'swp1s1' }).code, 'mismatch');
});

test('a port without a resolved spelling keeps the tolerant notation match', () => {
    const p = page();
    p.design([cable('SPINE-01', 'swp49', 'LEAF-01', '49/1'), cable('SPINE-01', 'swp50', 'LEAF-01', '50')]);
    const seen = (local, port) => p.status({
        localDevice: 'SPINE-01', localPort: local, actualDevice: 'LEAF-01', actualPort: port });
    assert.equal(p.designFor({ localDevice: 'SPINE-01', localPort: 'swp49' }).peer_port_os, '');
    assert.equal(seen('swp49', 'swp49s0').code, 'match');
    assert.equal(seen('swp49', 'swp49').code, 'match');
    assert.equal(seen('swp50', 'swp50').code, 'match');
    assert.equal(seen('swp49', 'swp49s1').code, 'mismatch');
    assert.equal(seen('swp50', 'swp51').code, 'mismatch');
});

test('a switch that mixes breakout widths is fitted per port from the live report', () => {
    for (const order of ['design first', 'report first']) {
        const p = page();
        if (order === 'design first') { p.design(MIXED_DESIGN); p.report(reportText(MIXED_REPORT)); }
        else { p.report(reportText(MIXED_REPORT)); p.design(MIXED_DESIGN); }
        assert.equal(p.rows().length, MIXED_REPORT.length);
        p.rows().forEach(conn => {
            const status = p.status(conn);
            assert.equal(status.code, 'match', `${order}: ${conn.localDevice}:${conn.localPort} ${status.reason}`);
        });
        // The far end of SPINE-02 is the second leg of a 2x port: swp1s1, not swp1s2.
        assert.equal(p.designFor(find(p, 'SPINE-02', 'swp1s0')).peer_port_os, 'swp1s1', order);
        assert.equal(p.designFor(find(p, 'SPINE-03', 'swp3')).peer_port_os, 'swp33s2', order);
        const leg = p.designFor(find(p, 'LEAF-01', 'swp1s1'));
        assert.deepEqual([leg.local_port, leg.local_port_os, leg.peer_device], ['1/2/1', 'swp1s1', 'SPINE-02'], order);
    }
});

test('swapped legs on the mixed-width switch are flagged from every row with the real names', () => {
    const p = page();
    const swapped = MIXED_REPORT.map(row => row.slice());
    const fail = (device, port, exp, expPort, act, actPort) =>
        swapped.splice(swapped.findIndex(row => row[0] === device && row[1] === port), 1,
            [device, port, 'Fail', exp, expPort, act, actPort, 'UP']);
    fail('LEAF-01', 'swp1s0', 'SPINE-01', 'swp1s0', 'SPINE-02', 'swp1s0');
    fail('LEAF-01', 'swp1s1', 'SPINE-02', 'swp1s0', 'SPINE-01', 'swp1s0');
    fail('SPINE-01', 'swp1s0', 'LEAF-01', 'swp1s0', 'LEAF-01', 'swp1s1');
    fail('SPINE-02', 'swp1s0', 'LEAF-01', 'swp1s1', 'LEAF-01', 'swp1s0');
    p.design(MIXED_DESIGN);
    p.report(reportText(swapped));
    const reasons = {
        'LEAF-01:swp1s0': 'Design expects SPINE-01:swp1s0, live shows SPINE-02:swp1s0.',
        'LEAF-01:swp1s1': 'Design expects SPINE-02:swp1s0, live shows SPINE-01:swp1s0.',
        'SPINE-01:swp1s0': 'Design expects LEAF-01:1/1/1 (swp1s0), live shows LEAF-01:swp1s1.',
        'SPINE-02:swp1s0': 'Design expects LEAF-01:1/2/1 (swp1s1), live shows LEAF-01:swp1s0.',
    };
    p.rows().forEach(conn => {
        const status = p.status(conn);
        const expected = reasons[`${conn.localDevice}:${conn.localPort}`];
        assert.equal(status.code, expected ? 'mismatch' : 'match', `${conn.localDevice}:${conn.localPort}`);
        if (expected) assert.equal(status.reason, expected);
    });
});

test('a row for a port the switch does not report is no evidence of a wider split', () => {
    // topology.dot still carries the device-wide name swp1s2: the wiring
    // report has a No-Info row for it (Port-Status N/A) next to the live leg.
    const rows = MIXED_REPORT.filter(row => !(row[0] === 'LEAF-01' && row[1] === 'swp1s1')
        && !(row[0] === 'SPINE-02'));
    rows.push(['LEAF-01', 'swp1s2', 'No-Info', 'SPINE-02', 'swp1s0', 'None', 'None', 'N/A']);
    rows.push(['LEAF-01', 'swp1s1', 'Fail', 'None', 'None', 'SPINE-02', 'swp1s0', 'UP']);
    rows.push(['SPINE-02', 'swp1s0', 'Fail', 'LEAF-01', 'swp1s2', 'LEAF-01', 'swp1s1', 'UP']);
    const p = page();
    p.design(MIXED_DESIGN);
    p.report(reportText(rows));
    const spine = p.status(find(p, 'SPINE-02', 'swp1s0'));
    assert.equal(spine.design.peer_port_os, 'swp1s1');
    assert.equal(spine.code, 'match');
    assert.equal(p.status(find(p, 'LEAF-01', 'swp1s1')).code, 'match');
});

test('the port a neighbor advertises is live evidence when its switch has no rows of its own', () => {
    // LEAF-01 was not collected: only the spines report what they see.
    const p = page();
    p.design(MIXED_DESIGN);
    p.report(reportText(MIXED_REPORT.filter(row => row[0] !== 'LEAF-01')));
    p.rows().forEach(conn => assert.equal(p.status(conn).code, 'match', `${conn.localDevice}:${conn.localPort}`));
    assert.equal(p.designFor(find(p, 'SPINE-02', 'swp1s0')).peer_port_os, 'swp1s1');
    assert.equal(p.designFor(find(p, 'SPINE-04', 'swp5')).peer_port_os, 'swp5');
});

test('without live evidence the device-wide width stays, as for sparsely cabled ports', () => {
    const p = page();
    p.design([cable('A', 'swp49', 'SP-01', '1/1/4'), cable('B', 'swp49', 'SP-01', '3/1/1'),
        cable('C', 'swp49', 'SP-01', '3/2/1')]);
    assert.equal(p.designFor({ localDevice: 'C', localPort: 'swp49' }).peer_port_os, 'swp3s4');
    // The far end named in the report is live evidence of its own.
    p.report(reportText([pass('C', 'swp49', 'SP-01', 'swp3s4'), pass('B', 'swp49', 'SP-01', 'swp3s0')]));
    assert.equal(p.status(find(p, 'C', 'swp49')).code, 'match');
    assert.equal(p.designFor(find(p, 'C', 'swp49')).peer_port_os, 'swp3s4');
});

test('an unsplit port written X/1/1 is swpX when the report shows it unsplit', () => {
    const p = page();
    p.design(MIXED_DESIGN);
    assert.equal(p.designFor({ localDevice: 'SPINE-04', localPort: 'swp5' }).peer_port_os, 'swp5s0');
    // Before any report the fitted name is swp5s0; a live swp5 is the same
    // port (first lane of an unsplit port), not a different spelling to reject.
    assert.equal(p.status({ localDevice: 'SPINE-04', localPort: 'swp5', actualDevice: 'LEAF-01',
        actualPort: 'swp5' }).code, 'match');
    p.report(reportText(MIXED_REPORT));
    const spine = p.status(find(p, 'SPINE-04', 'swp5'));
    assert.equal(spine.design.peer_port_os, 'swp5');
    assert.equal(spine.code, 'match');
    const leaf = p.designFor(find(p, 'LEAF-01', 'swp5'));
    assert.deepEqual([leaf.local_port, leaf.local_port_os], ['5/1/1', 'swp5']);
    assert.equal(p.status({ localDevice: 'SPINE-04', localPort: 'swp5', actualDevice: 'LEAF-01',
        actualPort: 'swp6' }).reason, 'Design expects LEAF-01:5/1/1 (swp5), live shows LEAF-01:swp6.');
});

test('a port is live when the switch lists it, whatever its link state', () => {
    const design = [cable('LEAF-01', '5/1/1', 'SPINE-04', 'swp5')];
    const fitted = portStatus => {
        const p = page();
        p.design(design);
        p.report(reportText([['LEAF-01', 'swp5', 'No-Info', 'SPINE-04', 'swp5', 'None', 'None', portStatus]]));
        return p.designFor({ localDevice: 'SPINE-04', localPort: 'swp5' }).peer_port_os;
    };
    for (const listed of ['UP', 'DOWN', 'UNKNOWN']) assert.equal(fitted(listed), 'swp5', listed);
    // N/A: the switch did not list the port, the row only repeats topology.dot.
    assert.equal(fitted('N/A'), 'swp5s0');
});

test('a design label reaches the live ports of its switch through the display alias', () => {
    const p = page({ deviceAliases: { 'LEAF-01': 'LEAF A1' } });
    p.design(MIXED_DESIGN.map(rec => ({ ...rec, source_name: 'LEAF A1' })));
    p.report(reportText(MIXED_REPORT));
    p.rows().forEach(conn => assert.equal(p.status(conn).code, 'match', `${conn.localDevice}:${conn.localPort}`));
    assert.equal(p.designFor(find(p, 'SPINE-02', 'swp1s0')).peer_port_os, 'swp1s1');
});

// Every row of a report against a design: [device:port, status code].
const codes = p => Array.from(p.rows(), conn => [`${conn.localDevice}:${conn.localPort}`, p.status(conn).code]);
const allMatch = (p, label) => p.rows().forEach(conn => {
    const status = p.status(conn);
    assert.equal(status.code, 'match', `${label}: ${conn.localDevice}:${conn.localPort} ${status.reason}`);
});

test('two switches that share a first label are fitted apart', () => {
    // leaf-01.pod1 splits port 1 2x, leaf-01.pod2 splits it 4x; all cabled as designed.
    const design = [
        cable('H1', 'swp1', 'leaf-01.pod1', '1/1/1'), cable('H2', 'swp1', 'leaf-01.pod1', '1/2/1'),
        cable('H3', 'swp1', 'leaf-01.pod2', '1/1/1'), cable('H4', 'swp1', 'leaf-01.pod2', '1/1/2'),
        cable('H5', 'swp1', 'leaf-01.pod2', '1/2/1'), cable('H6', 'swp1', 'leaf-01.pod2', '1/2/2'),
    ];
    const report = [
        pass('H1', 'swp1', 'leaf-01.pod1', 'swp1s0'), pass('H2', 'swp1', 'leaf-01.pod1', 'swp1s1'),
        pass('H3', 'swp1', 'leaf-01.pod2', 'swp1s0'), pass('H4', 'swp1', 'leaf-01.pod2', 'swp1s1'),
        pass('H5', 'swp1', 'leaf-01.pod2', 'swp1s2'), pass('H6', 'swp1', 'leaf-01.pod2', 'swp1s3'),
        pass('leaf-01.pod1', 'swp1s0', 'H1', 'swp1'), pass('leaf-01.pod1', 'swp1s1', 'H2', 'swp1'),
        pass('leaf-01.pod2', 'swp1s0', 'H3', 'swp1'), pass('leaf-01.pod2', 'swp1s1', 'H4', 'swp1'),
        pass('leaf-01.pod2', 'swp1s2', 'H5', 'swp1'), pass('leaf-01.pod2', 'swp1s3', 'H6', 'swp1'),
    ];
    for (const order of ['design first', 'report first']) {
        const p = page();
        if (order === 'design first') { p.design(design); p.report(reportText(report)); }
        else { p.report(reportText(report)); p.design(design); }
        allMatch(p, order);
        assert.equal(p.designFor(find(p, 'H2', 'swp1')).peer_port_os, 'swp1s1', order);
        assert.equal(p.designFor(find(p, 'H5', 'swp1')).peer_port_os, 'swp1s2', order);
    }
    // The same without any report: each switch is fitted by its own rows.
    const p = page();
    p.design(design);
    assert.equal(p.designFor({ localDevice: 'H2', localPort: 'swp1' }).peer_port_os, 'swp1s1');
    assert.equal(p.designFor({ localDevice: 'H5', localPort: 'swp1' }).peer_port_os, 'swp1s2');
});

test('a design that names its switch by FQDN is fitted with the live ports of the short name', () => {
    const p = page();
    p.design(MIXED_DESIGN.map(rec => ({ ...rec, source_name: 'leaf-01.example.com' })));
    p.report(reportText(MIXED_REPORT));
    allMatch(p, 'fqdn design');
    const spine = p.designFor(find(p, 'SPINE-02', 'swp1s0'));
    assert.deepEqual([spine.peer_port, spine.peer_port_os, spine.peer_port_guess], ['1/2/1', 'swp1s1', false]);
    const leaf = p.designFor(find(p, 'LEAF-01', 'swp1s1'));
    assert.deepEqual([leaf.local_port, leaf.local_port_os, leaf.peer_device], ['1/2/1', 'swp1s1', 'SPINE-02']);
});

test('a cable on another leg of the port is not the design row of that leg', () => {
    // The design uses only the second leg; the cable sits on the first.
    const p = page();
    p.design([cable('H1', 'swp1', 'LEAF-01', '1/2/1')]);
    p.report(reportText([pass('H1', 'swp1', 'LEAF-01', 'swp1s0'), pass('LEAF-01', 'swp1s0', 'H1', 'swp1')]));
    const far = p.status(find(p, 'H1', 'swp1'));
    assert.equal(far.code, 'mismatch');
    assert.equal(far.reason, 'Design expects LEAF-01:1/2/1 (swp1s1), live shows LEAF-01:swp1s0.');
    // Seen from the breakout switch: swp1s0 is not a port of this design.
    const local = p.status(find(p, 'LEAF-01', 'swp1s0'));
    assert.equal(local.code, 'design-unresolved');
    assert.equal(local.reason, 'No design record matches this device:port.');
    assert.equal(p.designFor(find(p, 'LEAF-01', 'swp1s0')), null);
    // The design row is still found on its own port and by its design text.
    assert.equal(p.designFor({ localDevice: 'LEAF-01', localPort: 'swp1s1' }).peer_device, 'H1');
    assert.equal(p.designFor({ localDevice: 'LEAF-01', localPort: '1/2/1' }).peer_device, 'H1');
});

test('a host cabled one leg off is flagged on both ends of a 4x port', () => {
    // 4x port written as two groups of two: H2 belongs on 1/2/1 (swp1s2) but
    // sits on swp1s1.
    const p = page();
    p.design([cable('H1', 'swp1', 'LEAF-01', '1/1/1'), cable('H2', 'swp1', 'LEAF-01', '1/2/1'),
        cable('H3', 'swp1', 'LEAF-01', '1/2/2')]);
    p.report(reportText([
        pass('H1', 'swp1', 'LEAF-01', 'swp1s0'), pass('H2', 'swp1', 'LEAF-01', 'swp1s1'),
        pass('H3', 'swp1', 'LEAF-01', 'swp1s3'),
        pass('LEAF-01', 'swp1s0', 'H1', 'swp1'), pass('LEAF-01', 'swp1s1', 'H2', 'swp1'),
        pass('LEAF-01', 'swp1s3', 'H3', 'swp1'),
    ]));
    assert.deepEqual(codes(p), [
        ['H1:swp1', 'match'], ['H2:swp1', 'mismatch'], ['H3:swp1', 'match'],
        ['LEAF-01:swp1s0', 'match'], ['LEAF-01:swp1s1', 'design-unresolved'], ['LEAF-01:swp1s3', 'match'],
    ]);
    assert.equal(p.status(find(p, 'H2', 'swp1')).reason,
        'Design expects LEAF-01:1/2/1 (swp1s2), live shows LEAF-01:swp1s1.');
});

test('a fitted name that is only a guess does not turn a correctly cabled port red', () => {
    // A 4x port written with one group per leg (1/1/1, 1/2/1), legs 3 and 4
    // in the design by their OS names. The report shows four sub-ports, so
    // 1/2/1 is read as the first port of a second group of two: swp1s2.
    const design = [cable('H1', 'swp1', 'LEAF-01', '1/1/1'), cable('H2', 'swp1', 'LEAF-01', '1/2/1'),
        cable('H3', 'swp1', 'LEAF-01', 'swp1s2'), cable('H4', 'swp1', 'LEAF-01', 'swp1s3')];
    const report = [
        pass('H1', 'swp1', 'LEAF-01', 'swp1s0'), pass('H2', 'swp1', 'LEAF-01', 'swp1s1'),
        pass('H3', 'swp1', 'LEAF-01', 'swp1s2'), pass('H4', 'swp1', 'LEAF-01', 'swp1s3'),
        pass('LEAF-01', 'swp1s0', 'H1', 'swp1'), pass('LEAF-01', 'swp1s1', 'H2', 'swp1'),
        pass('LEAF-01', 'swp1s2', 'H3', 'swp1'), pass('LEAF-01', 'swp1s3', 'H4', 'swp1'),
    ];
    const p = page();
    p.design(design);
    p.report(reportText(report));
    allMatch(p, 'one group per leg');
    const h2 = p.designFor(find(p, 'H2', 'swp1'));
    assert.deepEqual([h2.peer_port_os, h2.peer_port_guess], ['swp1s2', true]);
    // The guess does not take swp1s2 from the row that names it outright ...
    assert.equal(p.designFor(find(p, 'LEAF-01', 'swp1s2')).peer_device, 'H3');
    // ... and the guessed row is still found on the leg it may mean.
    assert.equal(p.designFor(find(p, 'LEAF-01', 'swp1s1')).peer_device, 'H2');
    // Group 1 never depends on the width.
    assert.equal(p.designFor(find(p, 'H1', 'swp1')).peer_port_guess, false);
});

test('a guessed name is tolerant, not blind: a port no notation gives is a Mismatch', () => {
    // SP-01 port 3 is cabled in two groups; the report proves four sub-ports
    // (swp3s3), which fits two groups of two and four groups of one.
    const design = [cable('B', 'swp49', 'SP-01', '3/1/1'), cable('C', 'swp49', 'SP-01', '3/2/1')];
    const seen = port => {
        const p = page();
        p.design(design);
        p.report(reportText([pass('B', 'swp49', 'SP-01', 'swp3s0'), pass('D', 'swp49', 'SP-01', 'swp3s3'),
            ['C', 'swp49', 'Fail', 'SP-01', 'swp3s2', 'SP-01', port, 'UP']]));
        return p.status(find(p, 'C', 'swp49'));
    };
    assert.equal(seen('swp3s2').design.peer_port_guess, true);
    assert.equal(seen('swp3s2').code, 'match');     // two groups of two
    assert.equal(seen('swp3s1').code, 'match');     // one group per leg
    const wrong = seen('swp3s3');
    assert.equal(wrong.code, 'mismatch');
    assert.equal(wrong.reason, 'Design expects SP-01:3/2/1 (swp3s2), live shows SP-01:swp3s3.');
    assert.equal(seen('swp4s2').code, 'mismatch');
});

test('a design leg in group 2 does not match a port the switch reports unsplit', () => {
    // The design splits port 5 for two spines; the switch has swp5, unsplit.
    const p = page();
    p.design([cable('SPINE-01', 'swp1', 'LEAF-01', '5/1/1'), cable('SPINE-02', 'swp1', 'LEAF-01', '5/2/1')]);
    p.report(reportText([pass('SPINE-01', 'swp1', 'LEAF-01', 'swp5'),
        ['SPINE-02', 'swp1', 'Fail', 'LEAF-01', 'swp5s1', 'LEAF-01', 'swp5', 'UP']]));
    assert.equal(p.designFor(find(p, 'SPINE-02', 'swp1')).peer_port_os, 'swp5s1');
    assert.equal(p.status(find(p, 'SPINE-01', 'swp1')).code, 'match');
    const second = p.status(find(p, 'SPINE-02', 'swp1'));
    assert.equal(second.code, 'mismatch');
    assert.equal(second.reason, 'Design expects LEAF-01:5/2/1 (swp5s1), live shows LEAF-01:swp5.');
});

test('a sparsely cabled wide port is fitted from the far ends the report itself names', () => {
    // Design alone: 1/1/1 + 1/2/1 read as a 2x port (swp1s0, swp1s1). The
    // port is 4x with legs 1 and 3 cabled; each row brings its own evidence.
    const design = [cable('SPINE-01', 'swp1s0', 'LEAF-01', '1/1/1'), cable('SPINE-02', 'swp1s0', 'LEAF-01', '1/2/1')];
    const p = page();
    p.design(design);
    assert.equal(p.designFor({ localDevice: 'SPINE-02', localPort: 'swp1s0' }).peer_port_os, 'swp1s1');
    p.report(reportText([pass('SPINE-01', 'swp1s0', 'LEAF-01', 'swp1s0'), pass('SPINE-02', 'swp1s0', 'LEAF-01', 'swp1s2')]));
    allMatch(p, 'sparse 4x');
    const second = p.designFor(find(p, 'SPINE-02', 'swp1s0'));
    assert.deepEqual([second.peer_port_os, second.peer_port_guess], ['swp1s2', true]);
    // On a port the report proves 2x the second leg is swp1s1 and nothing else.
    const twin = page();
    twin.design(design);
    twin.report(reportText([pass('SPINE-01', 'swp1s0', 'LEAF-01', 'swp1s1'),
        ['SPINE-02', 'swp1s0', 'Fail', 'LEAF-01', 'swp1s1', 'LEAF-01', 'swp1s0', 'UP']]));
    assert.deepEqual(codes(twin), [['SPINE-01:swp1s0', 'mismatch'], ['SPINE-02:swp1s0', 'mismatch']]);
    assert.equal(twin.designFor(find(twin, 'SPINE-02', 'swp1s0')).peer_port_guess, false);
});

