import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const bmc = require('../html/css/bmc.js');
const csvHeader = 'Switch,Port,Expected-MAC,Hostname,VLAN,BMC-IP,Enabled\r\n';
const sample = { switch:'oob-01', port:'swp1', expected_mac:'aa:bb:cc:dd:ee:02', hostname:'server-01', vlan:10, bmc_ip:'192.0.2.10', enabled:true };

test('CSV accepts spreadsheet BOM, CRLF and common MAC spellings', () => {
    const rows = bmc.parseCSV('\uFEFF' + csvHeader + 'oob-01,swp1,AABB.CCDD.EE02,server-01,10,192.0.2.10,true\r\n');
    assert.deepEqual(rows, [sample]);
    assert.equal(bmc.normalizeMac('AA-BB-CC-DD-EE-02'), sample.expected_mac);
});

test('CSV round trip preserves quoted commas, double quotes and line breaks', () => {
    const source = [{ ...sample, hostname:'server, "one"\nBMC' }, { ...sample, port:'swp2', vlan:null, enabled:false }];
    assert.deepEqual(bmc.parseCSV(bmc.toCSV(source)), source);
});

test('minimal CSV defaults optional fields without converting missing VLAN to zero', () => {
    assert.deepEqual(bmc.parseCSV('switch,port,expected_mac,hostname\noob-01,swp1,aabbccddeeff,server-01'), [{
        switch:'oob-01', port:'swp1', expected_mac:'aa:bb:cc:dd:ee:ff', hostname:'server-01', vlan:null, bmc_ip:'', enabled:true
    }]);
});

test('new mapping templates and exports contain only the four requested fields', () => {
    const header = '"switch","port","expected_mac","hostname"\r\n';
    assert.equal(bmc.toCSV([]),header);
    const rows = [bmc.mapping({switch:'oob-01',port:'swp1',expected_mac:'02:00:00:00:00:01',hostname:'server-01'})];
    assert.ok(bmc.toCSV(rows).startsWith(header));
    assert.deepEqual(bmc.parseCSV(bmc.toCSV(rows)),rows);
    assert.equal(rows[0].enabled,true);
});

test('legacy mapping exports retain options so a round trip cannot silently change monitoring', () => {
    const rows = [bmc.mapping({...sample,vlan:20,enabled:false})];
    assert.ok(bmc.toCSV(rows).split('\r\n')[0].includes('"enabled"'));
    assert.deepEqual(bmc.parseCSV(bmc.toCSV(rows)),rows);
});

test('CSV accepts false/zero/no and true/one/yes enabled values', () => {
    for (const value of ['false','0','No']) assert.equal(bmc.parseCSV(csvHeader + `oob-01,swp1,aabbccddeeff,server-01,,,${value}`)[0].enabled,false);
    for (const value of ['true','1','YES','']) assert.equal(bmc.parseCSV(csvHeader + `oob-01,swp1,aabbccddeeff,server-01,,,${value}`)[0].enabled,true);
});

test('CSV rejects malformed quoting and column count instead of shifting port identities', () => {
    for (const body of ['"oob-01,swp1,aabbccddeeff,server-01,,,true', 'oob-01,swp1,aabbccddeeff,"server"oops,,,true', 'oob-01,swp1,aabbccddeeff,server-01']) {
        assert.throws(() => bmc.parseCSV(csvHeader + body));
    }
});

test('CSV rejects duplicate, unknown and missing identity headers', () => {
    for (const header of ['switch,port,expected_mac,switch', 'switch,port,expected_mac,hostname,typo', 'port,expected_mac,hostname']) {
        assert.throws(() => bmc.parseCSV(header + '\n'));
    }
});

test('CSV rejects invalid values with row context', () => {
    for (const body of ['oob-01,swp1,bad,server-01,,,true', 'oob-01,swp1,aabbccddeeff,server-01,4095,,true', 'oob-01,swp1,aabbccddeeff,server-01,,,maybe', 'oob-01,,aabbccddeeff,server-01,,,true']) {
        assert.throws(() => bmc.parseCSV(csvHeader + body), /row 2/i);
    }
});

test('empty CSV raises an error but a header-only template has no rows', () => {
    assert.throws(() => bmc.parseCSV('  \n'));
    assert.deepEqual(bmc.parseCSV(bmc.toCSV([])), []);
});

const results = [
    { ...sample, status:'MATCH', active_macs:['aa:bb:cc:dd:ee:02'] },
    { ...sample, port:'swp2', status:'WRONG_PORT', active_macs:[] },
    { ...sample, port:'swp3', status:'PORT_DOWN' },
    { ...sample, port:'swp4', status:'MISMATCH' },
    { ...sample, port:'swp5', status:'NOT_SEEN' },
    { ...sample, port:'swp6', status:'UNKNOWN' },
    { ...sample, port:'swp7', status:'STALE' },
    { ...sample, port:'swp8', status:'DISABLED' }
];

test('summary and summary-card filters select the same status populations', () => {
    const counts = bmc.summarize(results);
    assert.deepEqual(counts,{total:8, match:1, problem:3, notSeen:1, unknown:3});
    for (const [status,key] of [['MATCH','match'],['__connection','problem'],['NOT SEEN','notSeen'],['__unknown','unknown']]) {
        assert.equal(bmc.filterRows(results,{status}).length, counts[key]);
    }
});

test('problem filter includes missing data without calling disabled mappings problems', () => {
    const rows = bmc.filterRows(results,{problems:true});
    assert.equal(rows.length,6);
    assert.ok(rows.every(row => !['MATCH','DISABLED'].includes(row.status)));
});

test('search, switch and status filters combine without altering source observations', () => {
    const before = JSON.stringify(results);
    assert.equal(bmc.filterRows(results,{search:'AA:BB:CC:DD:EE:02',switch:'oob-01',status:'MATCH'}).length,1);
    assert.equal(bmc.filterRows(results,{switch:'another-switch'}).length,0);
    assert.equal(bmc.filterRows(results,{search:'swp2',status:'WRONG PORT'})[0].port,'swp2');
    assert.equal(JSON.stringify(results),before);
});

test('CSV result export keeps all active MACs in one column', () => {
    const csv = bmc.toCSV([{active_macs:['aa:bb:cc:dd:ee:02','aa:bb:cc:dd:ee:04']}],['active_macs']);
    assert.equal(csv,'"active_macs"\r\n"aa:bb:cc:dd:ee:02; aa:bb:cc:dd:ee:04"\r\n');
});

test('request generations discard stale replies and late file imports after close', async () => {
    const gate = bmc.requestGate(); let shown = '';
    let finishOld; const old = new Promise(resolve => { finishOld = resolve; });
    const oldToken = gate.next();
    const pending = old.then(value => { if (gate.current(oldToken)) shown = value; });
    const currentToken = gate.next(); if (gate.current(currentToken)) shown = 'current mappings';
    finishOld('old mappings'); await pending; assert.equal(shown,'current mappings');
    gate.invalidate(); assert.equal(gate.current(currentToken),false);
});

test('editor pagination retains full draft identities across page changes and deletions', () => {
    const draft = Array.from({length:121},(_,index) => ({...sample,port:'swp' + (index + 1)}));
    const middle = bmc.paginate(draft,1);
    assert.equal(middle.items.length,50);
    assert.equal(middle.start,50);
    assert.equal(middle.items[0].port,'swp51');
    // Visible fields edit the original draft, so saving / exporting does not
    // lose modifications made on an earlier page.
    middle.items[3].hostname = 'updated-on-page-two';
    assert.equal(draft[53].hostname,'updated-on-page-two');
    assert.equal(bmc.parseCSV(bmc.toCSV(draft))[53].hostname,'updated-on-page-two');
    assert.equal(bmc.paginate(draft,2).items.length,21);
    draft.splice(50);
    assert.equal(bmc.paginate(draft,2).page,0);
    assert.equal(bmc.paginate([],5).items.length,0);
});

test('editor page selection locates an edited mapping and a newly appended row', () => {
    const draft = Array.from({length:150},(_,index) => ({...sample,port:'swp' + (index + 1)}));
    const selectedIndex = draft.findIndex(row => row.port === 'swp131');
    assert.equal(bmc.paginate(draft,Math.floor(selectedIndex / 50)).items[30].port,'swp131');
    draft.push({...sample,port:'swp151'});
    const appendedPage = bmc.paginate(draft,Math.floor((draft.length - 1) / 50));
    assert.equal(appendedPage.page,3);
    assert.deepEqual(appendedPage.items,[draft[150]]);
});
