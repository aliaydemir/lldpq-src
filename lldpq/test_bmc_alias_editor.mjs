import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const editor = require('../html/css/bmc-alias-editor.js');

test('aliases retain canonical keys and trim editable labels without changing mappings', () => {
    const rows = [[' OOB-SW1 ',' OOB 1 '],[' swp1 ',' BMC-PORT '],['','']];
    assert.deepEqual(editor.collectPairs(rows),{'OOB-SW1':'OOB 1',swp1:'BMC-PORT'});
    assert.equal(rows[0][0],' OOB-SW1 ');
});

test('partial aliases and duplicate canonical names are rejected before saving', () => {
    assert.throws(() => editor.collectPairs([['oob-01','']]),/Complete or remove/);
    assert.throws(() => editor.collectPairs([['','OOB-01']]),/Complete or remove/);
    assert.throws(() => editor.collectPairs([['oob-01','A'],['OOB-01','B']]),/Duplicate canonical name/);
});

test('bulk imports follow the Results editor order: display name then real name', () => {
    assert.deepEqual(editor.parseBulk('OOB-01\toob-sw1\r\n\nBMC-PORT,swp1\nHOST-01 server-01'),{
        'oob-sw1':'OOB-01',swp1:'BMC-PORT','server-01':'HOST-01'
    });
});

test('a malformed bulk line rejects the whole import instead of discarding existing aliases', () => {
    assert.throws(() => editor.parseBulk('OOB-01 oob-sw1\ntruncated'),/two names per line/);
    assert.throws(() => editor.parseBulk('OOB-01 oob-sw1 extra'),/two names per line/);
    assert.throws(() => editor.parseBulk('OOB-01 oob-sw1\nOOB-02 OOB-SW1'),/Duplicate canonical name/);
});

test('special property names remain literal canonical names', () => {
    const aliases = editor.collectPairs([['__proto__','BMC-01'],['constructor','BMC-02']]);
    assert.equal(Object.getPrototypeOf(aliases),Object.prototype);
    assert.equal(Object.hasOwn(aliases,'__proto__'),true);
    assert.equal(JSON.parse(JSON.stringify(aliases)).__proto__,'BMC-01');
});
