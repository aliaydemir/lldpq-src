/* The Results display-alias editor, backed by the shared display-aliases.json.
 * Integration: LLDPqBMCAliasEditor.open({ onSaved(aliases) { ... } }).
 * The callback also runs after a successful save whose editor has since closed.
 */
(function (root, factory) {
    'use strict';
    const api = factory(root);
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.LLDPqBMCAliasEditor = api;
}(typeof window === 'undefined' ? globalThis : window, function (root) {
    'use strict';
    function collectPairs(pairs) {
        const entries = [], seen = new Set();
        pairs.forEach(([key, label]) => {
            key = String(key || '').trim(); label = String(label || '').trim();
            if (!key && !label) return;
            if (!key || !label) throw new Error('Complete or remove every alias row.');
            if (seen.has(key.toLowerCase())) throw new Error('Duplicate canonical name: ' + key);
            seen.add(key.toLowerCase()); entries.push([key, label]);
        });
        return Object.fromEntries(entries);
    }
    function parseBulk(value) {
        const pairs = String(value || '').split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => {
            const parts = line.split(/[\s,]+/).filter(Boolean);
            if (parts.length !== 2) throw new Error('Use two names per line: P2P-name, then real-name.');
            return [parts[1], parts[0]];
        });
        return collectPairs(pairs);
    }
    function publishUpdate(revision) {
        try { root.localStorage.setItem('lldpq_aliases_revision', (revision || 'saved') + ':' + Date.now()); } catch (_) {}
        try {
            const channel = new root.BroadcastChannel('lldpq-aliases');
            channel.postMessage({ type:'updated' }); channel.close();
        } catch (_) {}
        root.dispatchEvent(new root.CustomEvent('lldpq-aliases-updated'));
    }
    let editor = null;
    function createEditor() {
        const doc = root.document;
        const modal = doc.createElement('div');
        modal.id = 'bmcAliasModal';
        modal.style.cssText = 'display:none; position:fixed; inset:0; background:rgba(0,0,0,0.6); z-index:1000; align-items:center; justify-content:center;';
        // Keep the markup and inline styles aligned with lldp.html's portAliasModal.
        modal.innerHTML = `
            <div role="dialog" aria-modal="true" aria-labelledby="bmcAliasTitle" style="background:#1e1e1e; border:1px solid #444; border-radius:8px; width:620px; max-width:92vw; max-height:88vh; display:flex; flex-direction:column;">
                <div style="display:flex; align-items:center; justify-content:space-between; padding:14px 18px; border-bottom:1px solid #333;">
                    <div id="bmcAliasTitle" style="color:#fff; font-weight:bold;">Display Aliases (P2P / field names)</div>
                    <button type="button" data-close aria-label="Close" style="background:none; border:none; color:#888; font-size:24px; cursor:pointer; line-height:1;">&times;</button>
                </div>
                <div style="padding:12px 18px 4px; color:#aaa; font-size:13px;">Map real names to P2P/field labels shown on this page (display only — validation is unaffected).</div>
                <div style="overflow:auto; flex:1; padding:0 18px;">
                    <div style="color:#76b900; font-weight:bold; font-size:13px; margin:10px 0 6px;">Device names
                        <span style="color:#777; font-weight:normal;">&nbsp;e.g. tan-spine-01 &rarr; SPINE-01</span></div>
                    <div id="bmcDeviceAliasRows"></div>
                    <div style="display:flex; gap:8px; align-items:flex-start; margin-top:6px;">
                        <button data-add="devices" class="btn btn-gray" type="button">+ Add device</button>
                        <textarea id="bmcDeviceBulk" rows="2" aria-label="Bulk device aliases" placeholder="Bulk paste: P2P-name &lt;tab&gt; real-name  (one per line) — replaces rows" style="flex:1; background:#2d2d2d; color:#d4d4d4; border:1px solid #555; border-radius:4px; padding:6px 8px; font-size:12px; resize:vertical; outline:none;"></textarea>
                        <button data-import="devices" class="btn btn-gray" type="button">Import</button>
                    </div>
                    <div style="color:#76b900; font-weight:bold; font-size:13px; margin:18px 0 6px;">Port names
                        <span style="color:#777; font-weight:normal;">&nbsp;e.g. enP22p3s0f0np0 &rarr; M1</span></div>
                    <div id="bmcPortAliasRows"></div>
                    <div style="display:flex; gap:8px; align-items:flex-start; margin:6px 0 12px;">
                        <button data-add="interfaces" class="btn btn-gray" type="button">+ Add port</button>
                        <textarea id="bmcPortBulk" rows="2" aria-label="Bulk port aliases" placeholder="Bulk paste: P2P-name &lt;tab&gt; real-name  (one per line) — replaces rows" style="flex:1; background:#2d2d2d; color:#d4d4d4; border:1px solid #555; border-radius:4px; padding:6px 8px; font-size:12px; resize:vertical; outline:none;"></textarea>
                        <button data-import="interfaces" class="btn btn-gray" type="button">Import</button>
                    </div>
                </div>
                <div style="display:flex; justify-content:flex-end; gap:8px; padding:12px 18px; border-top:1px solid #333;">
                    <span id="bmcAliasStatus" role="status" style="color:#888; font-size:12px; align-self:center; margin-right:auto;"></span>
                    <button data-close class="btn btn-gray" type="button">Cancel</button>
                    <button id="bmcAliasSave" type="button" style="background:#76b900; color:#000; border:none; padding:8px 16px; border-radius:4px; cursor:pointer; font-weight:bold;">Save</button>
                </div>
            </div>`;
        doc.body.append(modal);
        const status = modal.querySelector('#bmcAliasStatus'), saveButton = modal.querySelector('#bmcAliasSave');
        const sections = {
            devices:{ rows:modal.querySelector('#bmcDeviceAliasRows'), bulk:modal.querySelector('#bmcDeviceBulk'), placeholders:['tan-spine-01','SPINE-01'] },
            interfaces:{ rows:modal.querySelector('#bmcPortAliasRows'), bulk:modal.querySelector('#bmcPortBulk'), placeholders:['enP22p3s0f0np0','M1'] }
        };
        let operation = 0, editVersion = 0, savedVersion = 0, revision = null, ready = false;
        let aliases = { devices:{}, interfaces:{} }, onSaved = null, opener = null;
        const visible = () => modal.style.display !== 'none';
        const dirty = () => visible() && editVersion !== savedVersion;
        const report = (message, color = '#888') => { status.textContent = message; status.style.color = color; };
        const setReady = value => { ready = value; saveButton.disabled = !value; };
        function addRow(section, key = '', label = '') {
            const { rows, placeholders } = sections[section];
            const row = doc.createElement('div'); row.className = 'alias-row';
            row.style.cssText = 'display:flex; gap:8px; align-items:center; margin-bottom:8px;';
            const real = doc.createElement('input'); real.type = 'text'; real.className = 'alias-os';
            real.placeholder = placeholders[0]; real.value = key; real.autocomplete = 'off'; real.setAttribute('aria-label','Canonical name');
            real.style.cssText = 'flex:1; height:32px; padding:0 8px; background:#2d2d2d; color:#d4d4d4; border:1px solid #555; border-radius:4px; outline:none;';
            const arrow = doc.createElement('span'); arrow.style.color = '#76b900'; arrow.textContent = '→'; arrow.setAttribute('aria-hidden','true');
            const display = doc.createElement('input'); display.type = 'text'; display.className = 'alias-label';
            display.placeholder = placeholders[1]; display.value = label; display.autocomplete = 'off'; display.setAttribute('aria-label','Display alias');
            display.style.cssText = 'width:140px; height:32px; padding:0 8px; background:#2d2d2d; color:#d4d4d4; border:1px solid #555; border-radius:4px; outline:none;';
            const remove = doc.createElement('button'); remove.type = 'button'; remove.title = 'Remove'; remove.textContent = '×'; remove.setAttribute('aria-label','Remove alias row');
            remove.style.cssText = 'background:#555; color:#fff; border:none; width:30px; height:30px; border-radius:4px; cursor:pointer; font-size:16px; line-height:1;';
            remove.addEventListener('click', () => { row.remove(); editVersion++; });
            row.append(real, arrow, display, remove); rows.append(row);
        }
        function fillSection(section, values) {
            sections[section].rows.replaceChildren();
            const entries = Object.entries(values || {});
            (entries.length ? entries : [['','']]).forEach(([key,label]) => addRow(section,key,label));
        }
        function fillAll(values) {
            Object.keys(sections).forEach(section => { fillSection(section,values[section]); sections[section].bulk.value = ''; });
        }
        function finishClose() {
            operation++; setReady(false); modal.style.display = 'none'; opener?.focus();
        }
        function close() {
            if (!visible()) return;
            if (!dirty()) { finishClose(); return; }
            const closingOperation = operation;
            const confirmClose = () => { if (operation === closingOperation) finishClose(); };
            if (root.lldpqConfirm) root.lldpqConfirm('Discard changes', 'Discard your unsaved display alias changes?', confirmClose);
            else if (root.confirm('Discard your unsaved display alias changes?')) confirmClose();
        }
        async function request(body) {
            const controller = new root.AbortController(), timer = root.setTimeout(() => controller.abort(),20000);
            try {
                const response = await root.fetch('/setup-api.sh', { method:'POST', credentials:'same-origin', cache:'no-store', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body), signal:controller.signal });
                const data = await response.json();
                if (!response.ok) throw new Error(data.error || 'Could not access display aliases.');
                return data;
            } finally { root.clearTimeout(timer); }
        }
        async function open(options = {}) {
            if (visible()) { modal.querySelector('[data-close]').focus(); return; }
            const op = ++operation;
            const auth = typeof LLDPqAuth !== 'undefined' ? LLDPqAuth : root.LLDPqAuth;
            if (!auth || !await auth.check() || !auth.isAdmin() || op !== operation) return;
            opener = doc.activeElement; onSaved = options.onSaved;
            revision = null; editVersion = 0; savedVersion = 0; setReady(false);
            fillAll(aliases); report('Loading current aliases...');
            modal.style.display = 'flex'; modal.querySelector('[data-close]').focus();
            const startedVersion = editVersion;
            try {
                const data = await request({action:'get-aliases'});
                if (op !== operation) return;
                if (!data.success || typeof data.revision !== 'string') throw new Error(data.error || 'Could not load current aliases');
                aliases = data.aliases || {devices:{},interfaces:{}}; revision = data.revision;
                if (editVersion !== startedVersion) {
                    report('Current aliases loaded, but edits made during loading were kept. Close and reopen before saving.', '#ffb74d'); return;
                }
                fillAll(aliases); setReady(true); report('');
            } catch (error) {
                if (op === operation) report(error.message || 'Could not load current aliases','#ef5350');
            }
        }
        async function save() {
            if (!ready || typeof revision !== 'string') return;
            let submitted;
            try {
                submitted = Object.fromEntries(Object.entries(sections).map(([section,{rows}]) => [section,collectPairs(Array.from(rows.children).map(row => [row.querySelector('.alias-os').value,row.querySelector('.alias-label').value]))]));
                if (Object.values(sections).some(section => section.bulk.value.trim())) throw new Error('Import or clear the bulk paste text before saving.');
            } catch (error) { report(error.message,'#ef5350'); return; }
            const op = ++operation, startedVersion = editVersion, callback = onSaved;
            setReady(false); report('Saving...');
            try {
                const data = await request({ action:'set-aliases', aliases:submitted, expected_revision:revision });
                if (data.success) {
                    publishUpdate(data.revision);
                    try { callback?.(data.aliases || submitted); } catch (error) { root.console?.error(error); }
                }
                if (op !== operation) return;
                if (!data.success) {
                    setReady(!data.conflict);
                    report((data.error || 'Save failed') + (data.conflict ? ' Close and reopen to load the current aliases.' : ''),'#ef5350'); return;
                }
                aliases = data.aliases || submitted; revision = data.revision || revision; savedVersion = startedVersion;
                if (editVersion === startedVersion) {
                    report('Saved','#76b900');
                    root.setTimeout(() => { if (op === operation && editVersion === startedVersion) finishClose(); else if (op === operation) setReady(true); },600);
                } else {
                    setReady(true); report('Saved the submitted aliases; newer edits remain unsaved.','#ffb74d');
                }
            } catch (error) { if (op === operation) { setReady(true); report(error.message || 'Save failed','#ef5350'); } }
        }
        modal.addEventListener('input', () => { editVersion++; });
        modal.querySelectorAll('[data-close]').forEach(button => button.addEventListener('click',close));
        modal.querySelectorAll('[data-add]').forEach(button => button.addEventListener('click', () => { addRow(button.dataset.add); editVersion++; }));
        modal.querySelectorAll('[data-import]').forEach(button => button.addEventListener('click', () => {
            const section = button.dataset.import;
            try {
                const imported = parseBulk(sections[section].bulk.value);
                if (!Object.keys(imported).length) throw new Error('Paste aliases before importing.');
                fillSection(section,imported); sections[section].bulk.value = ''; editVersion++; report('');
            } catch (error) { report(error.message,'#ef5350'); }
        }));
        saveButton.addEventListener('click',save);
        modal.addEventListener('keydown', event => {
            if (doc.querySelector('.lldpq-modal.visible')) return;
            if (event.key === 'Escape') { event.preventDefault(); event.stopPropagation(); close(); }
            if (event.key === 'Tab') {
                const controls = Array.from(modal.querySelectorAll('button:not([disabled]),input,textarea'));
                if (event.shiftKey && doc.activeElement === controls[0]) { event.preventDefault(); controls.at(-1).focus(); }
                else if (!event.shiftKey && doc.activeElement === controls.at(-1)) { event.preventDefault(); controls[0].focus(); }
            }
        });
        root.addEventListener('beforeunload', event => { if (dirty()) { event.preventDefault(); event.returnValue = ''; } });
        return {open, close, hasUnsavedChanges:dirty};
    }
    return { collectPairs, parseBulk, open:options => (editor || (editor = createEditor())).open(options), close:() => editor?.close(), hasUnsavedChanges:() => !!editor?.hasUnsavedChanges() };
}));
