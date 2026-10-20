import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const results = require('../html/css/bmc-results.js');
const sample = { switch:'oob-01', port:'swp1', expected_mac:'aa:bb:cc:dd:ee:01', active_macs:['aa:bb:cc:dd:ee:01'], hostname:'server-01', status:'MATCH' };

test('device picker matches local switches and BMC hostnames, with multiple selections', () => {
    const rows = [sample,{...sample,switch:'oob-02',hostname:'server-02'},{...sample,switch:'oob-02',hostname:'server-03'}];
    assert.deepEqual(results.filterDevices(rows,['oob-02']),rows.slice(1));
    assert.deepEqual(results.filterDevices(rows,['server-02']),[rows[1]]);
    assert.deepEqual(results.filterDevices(rows,['oob-01','server-03']),[rows[0],rows[2]]);
    assert.deepEqual(results.filterDevices(rows,[]),rows);
    assert.deepEqual(results.filterDevices(rows,['missing']),[]);
});

test('device options deduplicate switches and hosts and sort numbers naturally', () => {
    const rows = [{...sample,switch:'oob-10',hostname:'server-10'},{...sample,switch:'oob-2',hostname:'server-2'},{...sample,switch:'oob-2',hostname:'oob-10'}];
    assert.deepEqual(results.deviceOptions(rows),{switches:['oob-2','oob-10'],hosts:['server-2','server-10']});
});

test('port sorting covers the whole result set and retains source observations', () => {
    const rows = Array.from({length:1600},(_,index) => ({...sample,port:'swp' + (1600-index)}));
    const sorted = results.sortRows(rows,1);
    assert.equal(sorted[0].port,'swp1'); assert.equal(sorted.at(-1).port,'swp1600');
    assert.equal(rows[0].port,'swp1600');
    assert.equal(results.sortRows(rows,1,true)[0].port,'swp1600');
});

test('status sorting ranks failed connections before missing observations and matches', () => {
    const rows = ['MATCH','UNKNOWN','WRONG_PORT','NOT_SEEN','PORT_DOWN','MISMATCH'].map(status => ({...sample,status}));
    assert.deepEqual(results.sortRows(rows,5).map(row => row.status),['PORT_DOWN','MISMATCH','WRONG_PORT','NOT_SEEN','UNKNOWN','MATCH']);
    assert.equal(results.sortRows(rows,5,true)[0].status,'MATCH');
});

test('filter labels preserve every active MAC and normalize status labels', () => {
    const row = {...sample,active_macs:['aa:bb:cc:dd:ee:01','aa:bb:cc:dd:ee:02'],status:'WRONG_PORT'};
    assert.equal(results.valuesFor(row)[3],'aa:bb:cc:dd:ee:01; aa:bb:cc:dd:ee:02');
    assert.equal(results.valuesFor(row)[5],'WRONG PORT');
    assert.equal(results.valuesFor({...sample,active_macs:[]})[3],'—');
});

test('CSV population excludes funnel-hidden, lifecycle-hidden and non-data rows', () => {
    const row = (item, classes = [], hidden = false, display = '') => ({_bmcRow:item,hidden,style:{display},classList:{contains:name => classes.includes(name)}});
    const table = {tBodies:[{rows:[row(sample),row({...sample,port:'swp2'},['tf-hidden']),row({...sample,port:'swp3'},['lldpq-lifecycle-hidden']),row({...sample,port:'swp4'},[],true),row({...sample,port:'swp5'},[],false,'none'),row(null)]}]};
    assert.deepEqual(results.displayedRows(table),[sample]);
});

test('P2P aliases change only switch, port and hostname display, case-insensitively', () => {
    const aliases = results.aliasMaps({devices:{'OOB-01':'OOB-A','SERVER-01':'HOST-A','MATCH':'bad'},interfaces:{swp1:'BMC1','oob-01':'wrong namespace'}});
    assert.deepEqual(results.valuesFor(sample,aliases,true),['OOB-A','BMC1',sample.expected_mac,sample.expected_mac,'HOST-A','MATCH']);
    assert.deepEqual(results.valuesFor(sample,aliases,false),results.valuesFor(sample));
    assert.equal(sample.switch,'oob-01'); assert.equal(sample.port,'swp1');
    assert.deepEqual(results.valuesFor(sample,results.aliasMaps(null)),results.valuesFor(sample));
});

test('P2P sorting follows visible field labels while retaining mapping identities', () => {
    const second = {...sample,switch:'oob-02',port:'swp2'};
    const aliases = results.aliasMaps({devices:{'oob-01':'Z','oob-02':'A'},interfaces:{swp1:'M10',swp2:'M2'}});
    assert.deepEqual(results.sortRows([sample,second],0,false,aliases,true),[second,sample]);
    assert.deepEqual(results.sortRows([sample,second],1,false,aliases,true),[second,sample]);
    assert.deepEqual(results.sortRows([sample,second],1,false,aliases,false),[sample,second]);
});

test('result CSV follows P2P display without changing source mappings or MACs', () => {
    const aliases = results.aliasMaps({devices:{'oob-01':'OOB-A','server-01':'HOST-A'},interfaces:{swp1:'BMC1'}});
    const exported = results.exportRows([sample],aliases,true)[0];
    assert.equal(exported.switch,'OOB-A'); assert.equal(exported.port,'BMC1'); assert.equal(exported.hostname,'HOST-A');
    assert.deepEqual(exported.active_macs,sample.active_macs); assert.equal(sample.switch,'oob-01');
    assert.deepEqual(results.exportRows([sample],aliases,false),[sample]);
});

test('grouped device search accepts canonical names and aliases with stable selection values', () => {
    const option = {id:'oob-01',text:'oob-01',element:{dataset:{alias:'FIELD-A'}}};
    const group = {text:'Switches',children:[option,{id:'oob-02',text:'oob-02'}]};
    assert.deepEqual(results.matchDevice({term:'field-a'},group).children,[option]);
    assert.deepEqual(results.matchDevice({term:'OOB-01'},group).children,[option]);
    assert.equal(results.matchDevice({term:'missing'},group),null);
    assert.equal(results.matchDevice({term:''},group),group);
});
