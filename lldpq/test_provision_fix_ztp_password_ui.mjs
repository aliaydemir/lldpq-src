// Quick Settings must not show, lose or re-type the stored ZTP password.
//
// cumulus-ztp.sh now stores the cumulus password as a crypt hash
// ("echo 'cumulus:<hash>' | chpasswd -e"), so the page can no longer read it
// back into the password field. The real functions are run out of
// provision.html against a stub DOM: a blank field has to keep the stored
// line byte for byte (also when the template is regenerated), a typed
// password has to replace either form, and after a save the editor has to
// show what the server stored instead of the clear text that was submitted.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const page = fs.readFileSync(new URL('../html/provision.html', import.meta.url), 'utf8');
const addresses = fs.readFileSync(new URL('../html/css/ip-address.js', import.meta.url), 'utf8');
const shipped = fs.readFileSync(new URL('../html/cumulus-ztp.sh', import.meta.url), 'utf8');
const start = page.indexOf('// ===================== GLOBAL STATE');
const script = page.slice(start, page.indexOf('</script>', start));

// Every "$" of the hash has to survive the page's string handling.
const HASHED_LINE = `echo 'cumulus:$6$saltSALT./012345$${'Qh'.repeat(43)}' | chpasswd -e`;
const BUILT_IN_DEFAULT = page.match(/const pwRaw = [^\n]*\|\| '([^']+)';/)[1];

function savedScript(passwordLine, version = 3) {
    const filled = shipped
        .replace('__TARGET_OS_VERSION__', '5.16.0')
        .replace('__IMAGE_SERVER_IP__', '192.0.2.250')
        .replace('LLDPQ_ZTP_TEMPLATE_VERSION=3', `LLDPQ_ZTP_TEMPLATE_VERSION=${version}`);
    let found = false;
    const replaced = filled.replace(/^(\s*)echo '[^'\n]*' \| chpasswd(?: -e)?$/m,
        (_match, indent) => { found = true; return indent + passwordLine; });
    assert.ok(found, 'the shipped template has no set-password line');
    return replaced;
}

function passwordLines(content) {
    return content.split('\n').filter(line => line.includes('chpasswd')).map(line => line.trim());
}

function harness(content) {
    const elements = new Map();
    const events = [], requests = [], confirmations = [];
    let reply = { success: true };
    function element(id) {
        if (!elements.has(id)) elements.set(id, {
            value: '', checked: false, disabled: false, style: {}, textContent: '', innerHTML: '',
            placeholder: '', dataset: {}, classList: { add() {}, remove() {} },
            focus() {}, click() {}, appendChild() {},
        });
        return elements.get(id);
    }
    const context = vm.createContext({
        document: { getElementById: element, addEventListener() {}, querySelectorAll() { return []; }, querySelector: element, createElement: element },
        window: { addEventListener() {} }, console, setTimeout() {}, clearTimeout() {}, setInterval() {}, clearInterval() {},
    });
    vm.runInContext(addresses, context);
    vm.runInContext(script, context);
    context.showToast = (message, kind) => events.push({ message, kind });
    context.showConfirmModal = (title, message, callback) => confirmations.push({ title, message, callback });
    context.apiCall = async (action, payload) => { requests.push({ action, payload }); return reply; };
    vm.runInContext('ztpLoaded = true;', context);
    // What loadZTPScript does once the script arrived.
    element('ztpEditor').value = content;
    context.parseQuickSettings(content);
    return {
        context, element, events, requests, confirmations,
        editor: () => element('ztpEditor').value,
        type(password) { element('ztpPassword').value = password; },
        replyWith(value) { reply = value; },
    };
}

test('a stored hash is reported as set and never put into the field', () => {
    const h = harness(savedScript(HASHED_LINE));
    assert.equal(h.element('ztpPassword').value, '');
    assert.match(h.element('ztpPasswordStatus').innerHTML, /Password is set/);
    assert.match(h.element('ztpPasswordStatus').innerHTML, /hash/);
    assert.match(h.element('ztpPassword').placeholder, /leave blank to keep/);
    assert.equal(h.element('ztpTargetOS').value, '5.16.0');
    assert.equal(h.element('ztpImageServer').value, '192.0.2.250');
});

test('a clear-text password saved by an earlier version is not shown either', () => {
    const h = harness(savedScript("echo 'cumulus:Old$ecret1' | chpasswd"));
    assert.equal(h.element('ztpPassword').value, '');
    assert.match(h.element('ztpPasswordStatus').innerHTML, /clear text/);
    assert.match(h.element('ztpPasswordStatus').innerHTML, /Save the script/);
    assert.doesNotMatch(h.element('ztpPasswordStatus').innerHTML, /Old\$ecret1/);
    assert.match(h.element('ztpPassword').placeholder, /leave blank to keep/);
});

test('a script without a password line keeps the old default-password prompt', () => {
    const h = harness('#!/bin/bash\n# CUMULUS-AUTOPROVISIONING\n# Edit this script from the Provision page\n');
    assert.equal(h.element('ztpPassword').value, '');
    assert.equal(h.element('ztpPassword').placeholder, 'Default password');
    assert.match(h.element('ztpPasswordStatus').innerHTML, /No password line/);
});

test('a previous status is replaced when another script is loaded', () => {
    const h = harness(savedScript(HASHED_LINE));
    h.type('typed but never applied');
    h.context.parseQuickSettings('#!/bin/bash\n# CUMULUS-AUTOPROVISIONING\n');
    assert.equal(h.element('ztpPassword').value, '');
    assert.equal(h.element('ztpPassword').placeholder, 'Default password');
});

test('a blank field keeps the stored hash byte for byte', () => {
    const before = savedScript(HASHED_LINE);
    const h = harness(before);
    assert.equal(h.context.applyQuickSettings(), true);
    assert.equal(h.editor(), before);
    assert.deepEqual(passwordLines(h.editor()), [HASHED_LINE]);
});

test('a blank field keeps a legacy clear-text line for the server to hash on save', () => {
    const legacy = "echo 'cumulus:Old$ecret1' | chpasswd";
    const before = savedScript(legacy);
    const h = harness(before);
    assert.equal(h.context.applyQuickSettings(), true);
    assert.equal(h.editor(), before);
});

test('a typed password replaces a stored hash with the form the server hashes', () => {
    const h = harness(savedScript(HASHED_LINE));
    h.type("N3w $& it's");
    assert.equal(h.context.applyQuickSettings(), true);
    assert.deepEqual(passwordLines(h.editor()), ["echo 'cumulus:N3w $& it'\\''s' | chpasswd"]);
    assert.ok(!h.editor().includes('$6$saltSALT'));
});

test('a typed password replaces a legacy clear-text line as before', () => {
    const h = harness(savedScript("echo 'cumulus:Old$ecret1' | chpasswd"));
    h.type('Fresh1');
    assert.equal(h.context.applyQuickSettings(), true);
    assert.deepEqual(passwordLines(h.editor()), ["echo 'cumulus:Fresh1' | chpasswd"]);
});

test('regenerating a legacy template carries the stored hash over, dollars intact', () => {
    const h = harness(savedScript(HASHED_LINE, 2));
    assert.equal(h.context.applyQuickSettings(), false);
    assert.equal(h.confirmations.length, 1);
    assert.match(h.confirmations[0].message, /password/);
    h.confirmations[0].callback();
    assert.match(h.editor(), /# LLDPQ_ZTP_TEMPLATE_VERSION=3\n/);
    assert.deepEqual(passwordLines(h.editor()), [HASHED_LINE]);
    assert.ok(!h.editor().includes(BUILT_IN_DEFAULT));
    assert.match(h.editor(), /\n {8}echo 'cumulus:\$6\$/);
});

test('the confirmed upgrade path used by "Use for ZTP" keeps the stored hash too', () => {
    const h = harness(savedScript(HASHED_LINE, 2));
    assert.equal(h.context.applyQuickSettings(null, true), true);
    assert.match(h.editor(), /# LLDPQ_ZTP_TEMPLATE_VERSION=3\n/);
    assert.deepEqual(passwordLines(h.editor()), [HASHED_LINE]);
});

test('regenerating a legacy template with a typed password uses the typed one', () => {
    const h = harness(savedScript(HASHED_LINE, 2));
    h.type('Typed1');
    h.context.applyQuickSettings(null, true);
    assert.deepEqual(passwordLines(h.editor()), ["echo 'cumulus:Typed1' | chpasswd"]);
});

test('a script that never had a password still gets the built-in default', () => {
    const h = harness('#!/bin/bash\n# CUMULUS-AUTOPROVISIONING\n# Edit this script from the Provision page\n');
    h.element('ztpTargetOS').value = '5.16.0';
    h.element('ztpImageServer').value = '192.0.2.250';
    assert.equal(h.context.applyQuickSettings(), true);
    // Written in the form the server turns into a hash when the script is saved.
    assert.deepEqual(passwordLines(h.editor()), [`echo 'cumulus:${BUILT_IN_DEFAULT}' | chpasswd`]);
});

test('after a save the editor shows the stored script and the field is cleared', async () => {
    const submitted = savedScript("echo 'cumulus:Typed1' | chpasswd");
    const stored = savedScript(HASHED_LINE);
    const h = harness(savedScript(HASHED_LINE));
    h.type('Typed1');
    h.element('ztpEditor').value = submitted;
    h.replyWith({ success: true, message: 'ZTP script saved', content: stored });
    assert.equal(await h.context.saveZTPScript(), true);
    assert.deepEqual(JSON.parse(JSON.stringify(h.requests)), [{ action: 'save-ztp-script', payload: { content: submitted } }]);
    assert.equal(h.editor(), stored);
    assert.ok(!h.editor().includes('Typed1'));
    assert.equal(h.element('ztpPassword').value, '');
    assert.match(h.element('ztpPasswordStatus').innerHTML, /stored as a hash/);
    assert.deepEqual(h.events.at(-1), { message: 'ZTP script saved', kind: 'success' });
});

test('a typed password that was never applied is kept in the field and reported after a save', async () => {
    // Typed in Quick Settings, then the editor's Save without "Apply to Script":
    // the editor still carries the old hash, so that is what the server stores.
    const stored = savedScript(HASHED_LINE);
    const h = harness(stored);
    h.type('BrandNew1');
    h.replyWith({ success: true, message: 'ZTP script saved', content: stored });
    assert.equal(await h.context.saveZTPScript(), true);
    assert.deepEqual(passwordLines(h.requests[0].payload.content), [HASHED_LINE]);
    assert.equal(h.element('ztpPassword').value, 'BrandNew1');
    assert.equal(h.events.length, 1);
    assert.equal(h.events[0].kind, 'error');
    assert.match(h.events[0].message, /typed password was NOT applied/);
    assert.match(h.events[0].message, /Apply to Script/);
    assert.ok(!h.events[0].message.includes('BrandNew1'));
    // Doing what the message says stores the typed password and clears the field.
    assert.equal(h.context.applyQuickSettings(), true);
    assert.deepEqual(passwordLines(h.editor()), ["echo 'cumulus:BrandNew1' | chpasswd"]);
    assert.equal(await h.context.saveZTPScript(), true);
    assert.equal(h.element('ztpPassword').value, '');
    assert.deepEqual(h.events.at(-1), { message: 'ZTP script saved', kind: 'success' });
});

test('a password changed again after "Apply to Script" is not treated as applied', async () => {
    const h = harness(savedScript(HASHED_LINE));
    h.type('First1');
    assert.equal(h.context.applyQuickSettings(), true);
    h.type('Second2');
    h.replyWith({ success: true, message: 'ZTP script saved', content: savedScript(HASHED_LINE) });
    assert.equal(await h.context.saveZTPScript(), true);
    assert.equal(h.element('ztpPassword').value, 'Second2');
    assert.equal(h.events.at(-1).kind, 'error');
    assert.match(h.events.at(-1).message, /NOT applied/);
});

test('apply then save clears the field for quoted passwords and regenerated templates', async () => {
    for (const [version, confirmed] of [[3, false], [2, true]]) {
        const h = harness(savedScript(HASHED_LINE, version));
        h.type("  N3w $& it's  ");
        assert.equal(h.context.applyQuickSettings(null, confirmed), true);
        assert.deepEqual(passwordLines(h.editor()), ["echo 'cumulus:N3w $& it'\\''s' | chpasswd"]);
        h.replyWith({ success: true, message: 'ZTP script saved', content: savedScript(HASHED_LINE) });
        assert.equal(await h.context.saveZTPScript(), true);
        assert.equal(h.element('ztpPassword').value, '');
        assert.deepEqual(h.events.at(-1), { message: 'ZTP script saved', kind: 'success' });
    }
});

test('a save with a blank field reports plain success', async () => {
    const stored = savedScript(HASHED_LINE);
    const h = harness(stored);
    h.replyWith({ success: true, message: 'ZTP script saved', content: stored });
    assert.equal(await h.context.saveZTPScript(), true);
    assert.equal(h.element('ztpPassword').value, '');
    assert.deepEqual(h.events, [{ message: 'ZTP script saved', kind: 'success' }]);
});

test('a failed save leaves the editor and the typed password alone', async () => {
    const submitted = savedScript("echo 'cumulus:Typed1' | chpasswd");
    const h = harness(savedScript(HASHED_LINE));
    h.type('Typed1');
    h.element('ztpEditor').value = submitted;
    h.replyWith({ success: false, error: 'ZTP script was not saved: Could not hash the cumulus password' });
    assert.equal(await h.context.saveZTPScript(), false);
    assert.equal(h.editor(), submitted);
    assert.equal(h.element('ztpPassword').value, 'Typed1');
    assert.match(h.events.at(-1).message, /Could not hash/);
});

test('the stored-line pattern accepts both forms and nothing else', () => {
    const pattern = vm.runInNewContext(script.match(/const ZTP_PASSWORD_LINE = (\/.*\/m);/)[1]);
    assert.ok(pattern.test("    echo 'cumulus:Plain1' | chpasswd"));
    assert.ok(pattern.test(`        ${HASHED_LINE}`));
    assert.ok(!pattern.test("    echo 'root:Plain1' | chpasswd"));
    assert.ok(!pattern.test("    # echo 'cumulus:Plain1' | chpasswd"));
    assert.ok(!pattern.test("    echo 'cumulus:Plain1' | chpasswd -c SHA512"));
});
