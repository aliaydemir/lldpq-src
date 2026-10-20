/* Shared BMC mappings editor and result view. All inventory values render as text. */
(function (root, factory) {
    'use strict';
    const api = factory(root);
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.LLDPqBMC = api;
}(typeof window === 'undefined' ? globalThis : window, function (root) {
    'use strict';
    const COLUMNS = ['switch', 'port', 'expected_mac', 'hostname', 'vlan', 'bmc_ip', 'enabled'];
    const STATUSES = ['MATCH', 'MISMATCH', 'WRONG PORT', 'NOT SEEN', 'PORT DOWN', 'UNKNOWN', 'STALE', 'DISABLED'];
    const str = value => value === null || value === undefined ? '' : String(value);
    const statusOf = row => str(row.status || 'UNKNOWN').replace(/_/g, ' ').toUpperCase();
    const isProblem = row => !['MATCH', 'DISABLED'].includes(statusOf(row));
    function normalizeMac(value) {
        const clean = str(value).trim().replace(/[:.\-]/g, '');
        return /^[0-9a-f]{12}$/i.test(clean) ? clean.toLowerCase().match(/../g).join(':') : str(value).trim();
    }
    function mapping(row) {
        return {
            switch: str(row.switch).trim(), port: str(row.port).trim(), expected_mac: normalizeMac(row.expected_mac),
            hostname: str(row.hostname).trim(), vlan: row.vlan === '' || row.vlan == null ? null : Number(row.vlan),
            bmc_ip: str(row.bmc_ip).trim(), enabled: row.enabled !== false
        };
    }
    function parseCSV(text) {
        text = str(text).replace(/^\uFEFF/, '');
        const rows = []; let row = [], field = '', quoted = false, afterQuote = false;
        const finishField = () => { row.push(field); field = ''; afterQuote = false; };
        const finishRow = () => { finishField(); if (row.some(value => value.trim())) rows.push(row); row = []; };
        for (let i = 0; i < text.length; i++) {
            const ch = text[i];
            if (quoted) {
                if (ch === '"' && text[i + 1] === '"') { field += '"'; i++; }
                else if (ch === '"') { quoted = false; afterQuote = true; }
                else field += ch;
            } else if (ch === ',') finishField();
            else if (ch === '\r' || ch === '\n') { if (ch === '\r' && text[i + 1] === '\n') i++; finishRow(); }
            else if (ch === '"') { if (field || afterQuote) throw new Error('Unexpected quote in CSV.'); quoted = true; }
            else { if (afterQuote) throw new Error('Unexpected text after a quoted CSV field.'); field += ch; }
        }
        if (quoted) throw new Error('CSV contains an unclosed quoted field.');
        if (field || row.length || afterQuote) finishRow();
        if (!rows.length) throw new Error('The CSV file is empty.');
        const headers = rows.shift().map(value => value.trim().toLowerCase().replace(/[ -]+/g, '_'));
        if (new Set(headers).size !== headers.length) throw new Error('CSV contains duplicate column names.');
        for (const required of COLUMNS.slice(0, 4)) if (!headers.includes(required)) throw new Error('Missing CSV column: ' + required);
        const unknown = headers.filter(header => !COLUMNS.includes(header));
        if (unknown.length) throw new Error('Unknown CSV column: ' + unknown.join(', '));
        return rows.map((values, index) => {
            if (values.length !== headers.length) throw new Error('CSV row ' + (index + 2) + ' has the wrong number of columns.');
            const item = Object.fromEntries(headers.map((header, i) => [header, values[i].trim()]));
            if (item.enabled && !/^(true|false|1|0|yes|no)$/i.test(item.enabled)) throw new Error('Invalid enabled value on CSV row ' + (index + 2) + '.');
            item.enabled = !/^(false|0|no)$/i.test(item.enabled || 'true');
            if (item.vlan && (!/^\d+$/.test(item.vlan) || Number(item.vlan) < 1 || Number(item.vlan) > 4094)) throw new Error('Invalid VLAN on CSV row ' + (index + 2) + '.');
            if (COLUMNS.slice(0, 4).some(key => !item[key])) throw new Error('Missing required value on CSV row ' + (index + 2) + '.');
            if (!/^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(normalizeMac(item.expected_mac))) throw new Error('Invalid MAC on CSV row ' + (index + 2) + '.');
            return mapping(item);
        });
    }
    function toCSV(rows, columns = COLUMNS) {
        const quote = value => '"' + str(value).replace(/"/g, '""') + '"';
        return [columns, ...rows.map(row => columns.map(key => Array.isArray(row[key]) ? row[key].join('; ') : row[key]))].map(row => row.map(quote).join(',')).join('\r\n') + '\r\n';
    }
    function filterRows(rows, filters = {}) {
        const search = str(filters.search).trim().toLowerCase();
        const statusMatches = row => !filters.status || (filters.status === '__connection'
            ? ['MISMATCH','WRONG PORT','PORT DOWN'].includes(statusOf(row))
            : filters.status === '__unknown' ? !['MATCH','MISMATCH','WRONG PORT','PORT DOWN','NOT SEEN'].includes(statusOf(row))
            : statusOf(row) === filters.status);
        return rows.filter(row => (!filters.switch || row.switch === filters.switch) &&
            statusMatches(row) && (!filters.problems || isProblem(row)) &&
            (!search || [row.switch, row.port, row.expected_mac, ...(row.active_macs || []), row.hostname, row.detail].some(value => str(value).toLowerCase().includes(search))));
    }
    function summarize(rows) {
        return rows.reduce((counts, row) => {
            counts.total++;
            const status = statusOf(row);
            if (status === 'MATCH') counts.match++;
            else if (['MISMATCH', 'WRONG PORT', 'PORT DOWN'].includes(status)) counts.problem++;
            else if (status === 'NOT SEEN') counts.notSeen++;
            else counts.unknown++;
            return counts;
        }, { total:0, match:0, problem:0, notSeen:0, unknown:0 });
    }
    function requestGate() {
        let epoch = 0;
        return { next: () => ++epoch, current: token => token === epoch, invalidate: () => { epoch++; } };
    }
    function paginate(rows, page, pageSize = 50) {
        const size = Math.max(1, Math.floor(Number(pageSize) || 50));
        const pages = Math.max(1, Math.ceil(rows.length / size));
        const current = Math.min(Math.max(0, Math.floor(Number(page) || 0)), pages - 1);
        const start = current * size;
        return { page:current, pages, start, end:Math.min(start + size, rows.length), items:rows.slice(start,start + size) };
    }
    function el(tag, className, text) {
        const node = root.document.createElement(tag);
        if (className) node.className = className;
        if (text !== undefined) node.textContent = text;
        return node;
    }
    function button(label, kind, handler) {
        const node = el('button', 'btn ' + kind, label); node.type = 'button';
        node.addEventListener('click', handler); return node;
    }
    function download(name, text) {
        const url = URL.createObjectURL(new Blob(['\uFEFF', text], { type:'text/csv;charset=utf-8' }));
        const a = el('a'); a.href = url; a.download = name; a.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
    async function confirmAction(message) {
        return new Promise(resolve => {
            const overlay = el('div','bmc-editor'); overlay.style.zIndex = '1200';
            const dialog = el('div','bmc-editor-dialog'); dialog.style.maxWidth = '520px';
            dialog.setAttribute('role','alertdialog'); dialog.setAttribute('aria-modal','true'); dialog.setAttribute('aria-label','Confirm changes');
            const header = el('div','bmc-editor-header'); header.append(el('h2','','Confirm changes'));
            const body = el('div','bmc-editor-body',message); const footer = el('div','bmc-editor-footer');
            const previous = root.document.activeElement;
            const finish = value => { overlay.remove(); previous?.focus(); resolve(value); };
            const cancel = button('Cancel','secondary',() => finish(false));
            const confirm = button('Confirm','danger',() => finish(true)); footer.append(cancel,confirm);
            dialog.append(header,body,footer); overlay.append(dialog); root.document.body.append(overlay); cancel.focus();
            overlay.addEventListener('keydown',event => {
                if (event.key === 'Escape') { event.preventDefault(); finish(false); }
                if (event.key === 'Tab') { event.preventDefault(); (root.document.activeElement === cancel ? confirm : cancel).focus(); }
            });
        });
    }
    async function apiRequest(action, body, endpoint = '/bmc-api.sh') {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 20000);
        try {
            const response = await root.fetch(endpoint + '?action=' + action, {
                cache:'no-store', signal:controller.signal, credentials:'same-origin',
                ...(body === undefined ? {} : { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) })
            });
            if (response.status === 401) {
                if (typeof LLDPqAuth !== 'undefined') LLDPqAuth.redirectToLogin();
                throw new Error('Your session has expired. Sign in again.');
            }
            const data = await response.json();
            if (!response.ok || data.success === false) {
                const error = new Error(data.error || ('Request failed (HTTP ' + response.status + ').'));
                error.conflict = response.status === 409 || data.conflict === true;
                throw error;
            }
            return data;
        } catch (error) {
            if (error.name === 'AbortError') throw new Error('The request timed out. Refresh to check the current state.');
            throw error;
        } finally { clearTimeout(timer); }
    }
    function timestamp(value) {
        if (!value) return 'Never';
        const date = new Date(typeof value === 'number' ? value * 1000 : value);
        return Number.isNaN(date.getTime()) ? str(value) : date.toLocaleString();
    }

    let editor = null;
    function createEditor() {
        const overlay = el('div', 'bmc-editor'); overlay.hidden = true;
        const dialog = el('div', 'bmc-editor-dialog'); dialog.setAttribute('role', 'dialog'); dialog.setAttribute('aria-modal', 'true'); dialog.setAttribute('aria-labelledby', 'bmc-editor-title');
        const header = el('div', 'bmc-editor-header'); const title = el('h2', '', 'BMC Mappings'); title.id = 'bmc-editor-title';
        const body = el('div', 'bmc-editor-body');
        const note = el('p', 'bmc-note', 'Define where each BMC should be connected. Switch, Port, Expected-MAC and Hostname are required. VLAN and BMC-IP are optional. Saving updates the comparison using the latest observations.');
        const toolbar = el('div', 'bmc-toolbar');
        const tableWrap = el('div', 'bmc-table-wrap'); const table = el('table', 'bmc-table'); const thead = el('thead'); const headings = el('tr');
        ['Switch', 'Port', 'Expected-MAC', 'Hostname', 'VLAN', 'BMC-IP', 'Enabled', ''].forEach(value => headings.append(el('th', '', value)));
        const tbody = el('tbody'); thead.append(headings); table.append(thead, tbody); tableWrap.append(table);
        const switchOptions = el('datalist'); switchOptions.id = 'bmc-switch-options';
        const pagination = el('div','bmc-pagination'); const pageLabel = el('div','bmc-count'); pageLabel.setAttribute('aria-live','polite');
        const pageActions = el('div','bmc-toolbar');
        const empty = el('p', 'bmc-note', 'No mappings yet. Add a row or import a CSV file.');
        const preview = el('div', 'bmc-preview'); preview.hidden = true;
        const footer = el('div', 'bmc-editor-footer'); const status = el('div', 'bmc-editor-status'); status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite');
        const gate = requestGate(); let rows = [], revision = null, switches = [], dirty = false, busy = false, focusReturn = null, editorPage = 0;
        function updatePagination() {
            const current = paginate(rows,editorPage);
            editorPage = current.page;
            pageLabel.textContent = rows.length ? 'Rows ' + (current.start + 1) + '–' + current.end + ' of ' + rows.length : '0 mappings';
            pageActions.hidden = current.pages <= 1;
            previousPage.disabled = busy || current.page === 0;
            nextPage.disabled = busy || current.page === current.pages - 1;
        }
        const setStatus = (text, kind = '') => { status.textContent = text; status.className = 'bmc-editor-status ' + kind; };
        const setBusy = value => {
            busy = value; overlay.setAttribute('aria-busy', String(value));
            overlay.querySelectorAll('input,select,button').forEach(node => { node.disabled = value; });
            save.disabled = value || revision === null;
            updatePagination();
        };
        const changed = () => { dirty = true; preview.hidden = true; setStatus('Unsaved changes'); };
        function render(selected) {
            tbody.replaceChildren(); empty.hidden = rows.length > 0;
            if (selected) {
                const index = rows.findIndex(row => row.switch === selected.switch && row.port === selected.port);
                if (index >= 0) editorPage = Math.floor(index / 50);
            }
            const current = paginate(rows,editorPage); editorPage = current.page;
            current.items.forEach((row, offset) => {
                const index = current.start + offset;
                const tr = el('tr');
                if (selected && row.switch === selected.switch && row.port === selected.port) tr.classList.add('bmc-selected');
                COLUMNS.forEach(key => {
                    const td = el('td'); let field;
                    if (key === 'switch') {
                        // One shared suggestion list avoids rebuilding the whole
                        // switch inventory for each visible mapping row.
                        field = el('input'); field.type = 'text'; field.setAttribute('list',switchOptions.id);
                        field.value = row.switch; field.placeholder = 'Select switch'; field.autocomplete = 'off';
                    } else {
                        field = el('input'); field.type = key === 'enabled' ? 'checkbox' : key === 'vlan' ? 'number' : 'text';
                        if (key === 'enabled') field.checked = row.enabled !== false;
                        else field.value = str(row[key]);
                        if (key === 'vlan') { field.min = '1'; field.max = '4094'; field.className = 'bmc-vlan-input'; }
                        if (key === 'port') { field.placeholder = 'swp1'; field.className = 'bmc-port-input'; }
                        if (key === 'expected_mac') { field.placeholder = 'aa:bb:cc:dd:ee:ff'; field.className = 'bmc-mac-input'; }
                        if (key === 'hostname') field.className = 'bmc-hostname-input';
                        if (key === 'bmc_ip') field.placeholder = 'Optional';
                        if (key !== 'enabled') field.autocomplete = 'off';
                    }
                    field.setAttribute('aria-label', key.replace(/_/g, ' ') + ', row ' + (index + 1));
                    field.addEventListener(key === 'enabled' ? 'change' : 'input', () => {
                        row[key] = key === 'enabled' ? field.checked : field.value; changed();
                    });
                    if (key === 'expected_mac') field.addEventListener('blur', () => { field.value = normalizeMac(field.value); row[key] = field.value; });
                    td.append(field); tr.append(td);
                });
                const actions = el('td'); const remove = button('Remove', 'secondary small', () => { rows.splice(index, 1); changed(); render(); });
                remove.setAttribute('aria-label', 'Remove mapping row ' + (index + 1)); actions.append(remove); tr.append(actions); tbody.append(tr);
            });
            updatePagination();
            if (selected) setTimeout(() => tbody.querySelector('.bmc-selected')?.scrollIntoView({ block:'nearest' }), 0);
        }
        async function load(selected) {
            const token = gate.next(); setBusy(true); setStatus('Loading mappings…');
            try {
                const data = await apiRequest('config'); if (!gate.current(token)) return;
                if (!Array.isArray(data.mappings) || data.revision == null) throw new Error('The BMC configuration response is invalid.');
                rows = (data.mappings || []).map(mapping); revision = data.revision; switches = data.switches || []; editorPage = 0;
                switchOptions.replaceChildren();
                [...new Set(switches.map(item => typeof item === 'string' ? item : item.hostname).filter(Boolean))].sort().forEach(name => switchOptions.append(new Option(name,name)));
                dirty = false; preview.hidden = true; render(selected); setStatus(rows.length + ' saved mapping(s).');
            } catch (error) { if (gate.current(token)) setStatus(error.message, 'error'); }
            finally { if (gate.current(token)) setBusy(false); }
        }
        async function close() {
            if (busy) return;
            if (dirty && !await confirmAction('Discard your unsaved BMC mapping changes?')) return;
            dirty = false; gate.invalidate(); overlay.hidden = true; preview.hidden = true; focusReturn?.focus();
        }
        const previousPage = button('Previous Rows','secondary small',() => { if (editorPage > 0) editorPage--; render(); });
        const nextPage = button('Next Rows','secondary small',() => { editorPage++; render(); });
        pageActions.append(previousPage,nextPage); pagination.append(pageLabel,pageActions);
        const add = button('Add Row', 'secondary', () => { rows.push(mapping({enabled:true})); editorPage = Math.floor((rows.length - 1) / 50); changed(); render(); tbody.lastElementChild?.querySelector('input')?.focus(); });
        const file = el('input'); file.type = 'file'; file.accept = '.csv,text/csv'; file.hidden = true;
        file.addEventListener('change', async () => {
            const chosen = file.files[0]; file.value = ''; if (!chosen) return;
            const token = gate.next();
            try {
                if (chosen.size > 2 * 1024 * 1024) throw new Error('CSV file is too large (maximum 2 MB).');
                const imported = parseCSV(await chosen.text()); if (!gate.current(token) || overlay.hidden) return;
                if (!imported.length) throw new Error('CSV has no mapping rows.');
                preview.replaceChildren(el('p', '', imported.length + ' mapping(s) ready to import. Choose how to apply them to your current ' + rows.length + ' row(s). Nothing is saved until Save Mappings.'));
                const previewWrap = el('div','bmc-table-wrap'); const previewTable = el('table','bmc-table');
                const previewHead = el('thead'); const previewHeaders = el('tr');
                ['Switch','Port','Expected-MAC','Hostname','VLAN','BMC-IP','Enabled'].forEach(label => previewHeaders.append(el('th','',label)));
                previewHead.append(previewHeaders); const previewBody = el('tbody');
                imported.slice(0,5).forEach(item => { const tr = el('tr'); COLUMNS.forEach(key => tr.append(el('td','',str(item[key])))); previewBody.append(tr); });
                previewTable.append(previewHead,previewBody); previewWrap.append(previewTable); preview.append(previewWrap);
                if (imported.length > 5) preview.append(el('p','','Showing the first 5 of ' + imported.length + ' imported rows.'));
                const actions = el('div', 'bmc-toolbar');
                actions.append(button('Append Rows', 'secondary', () => { rows = rows.concat(imported.map(mapping)); changed(); render(); }),
                    button('Replace All Rows', 'danger', async () => {
                        if (!await confirmAction('Replace all ' + rows.length + ' current mapping rows with the ' + imported.length + ' imported rows?')) return;
                        rows = imported.map(mapping); changed(); render();
                    }), button('Cancel Import', 'secondary', () => { preview.hidden = true; }));
                preview.append(actions); preview.hidden = false; setStatus('CSV preview ready.');
            } catch (error) { if (gate.current(token)) setStatus(error.message, 'error'); }
        });
        const reload = button('Reload Saved', 'secondary', async () => {
            if (dirty && !await confirmAction('Discard your unsaved changes and reload the saved BMC mappings?')) return;
            await load();
        });
        const save = button('Save Mappings', 'primary', async () => {
            if (busy || revision === null) return;
            const token = gate.next(); setBusy(true); setStatus('Saving mappings…');
            try {
                const data = await apiRequest('save', {revision, mappings:rows.map(mapping)}); if (!gate.current(token)) return;
                revision = data.revision; rows = (data.mappings || rows).map(mapping); dirty = false; render();
                setStatus('Mappings saved. Results use the latest collected switch data.', 'ok');
                root.document.dispatchEvent(new CustomEvent('bmc-mappings-saved'));
            } catch (error) {
                if (gate.current(token)) setStatus(error.conflict ? 'Mappings changed elsewhere. Your edits are preserved. Export CSV to keep a copy, then Reload Saved before saving again.' : error.message, 'error');
            } finally { if (gate.current(token)) setBusy(false); }
        });
        toolbar.append(add, button('Import CSV', 'secondary', () => file.click()), file,
            button('Export CSV', 'secondary', () => download('bmc-mappings.csv', toCSV(rows))),
            button('CSV Template', 'secondary', () => download('bmc-mappings-template.csv', toCSV([]))), reload);
        const closeButton = button('Close', 'secondary', close); header.append(title, closeButton);
        footer.append(status, button('Cancel', 'secondary', close), save); body.append(note, toolbar, preview, empty, switchOptions, tableWrap, pagination);
        dialog.append(header, body, footer); overlay.append(dialog); root.document.body.append(overlay);
        overlay.addEventListener('keydown', event => {
            if (event.key === 'Escape') { event.preventDefault(); close(); }
            if (event.key === 'Tab') {
                const focusable = [...dialog.querySelectorAll('button,input,select')].filter(node => !node.disabled && !node.hidden && node.offsetParent !== null);
                if (!focusable.length) return;
                const first = focusable[0], last = focusable[focusable.length - 1];
                if (event.shiftKey && root.document.activeElement === first) { event.preventDefault(); last.focus(); }
                else if (!event.shiftKey && root.document.activeElement === last) { event.preventDefault(); first.focus(); }
            }
        });
        root.addEventListener('beforeunload', event => { if (dirty) { event.preventDefault(); event.returnValue = ''; } });
        return { isDirty: () => dirty, open: async selected => { focusReturn = root.document.activeElement; overlay.hidden = false; await load(selected); closeButton.focus(); } };
    }
    async function openEditor(selected) {
        if (typeof LLDPqAuth === 'undefined' || !LLDPqAuth.isAdmin()) return;
        if (!editor) editor = createEditor();
        return editor.open(selected);
    }

    async function initResults() {
        const doc = root.document, get = id => doc.getElementById(id);
        const errorNode = get('bmc-error');
        const showError = message => { errorNode.textContent = message; errorNode.hidden = !message; };
        if (typeof LLDPqAuth === 'undefined' || !await LLDPqAuth.checkWithRetry()) {
            get('bmc-loading').hidden = true; showError(typeof LLDPqAuth !== 'undefined' ? LLDPqAuth.lastCheckMessage() : 'Authentication is unavailable.'); return;
        }
        const admin = LLDPqAuth.isAdmin(); get('bmc-edit').hidden = !admin; get('bmc-actions-heading').hidden = !admin;
        const gate = requestGate(); let rows = [], visible = [], loaded = false, scanTimer = null, scanning = false, page = 0;
        const pageSize = 100;
        let scope = 'all'; try { scope = root.sessionStorage.getItem('lldpq_tracking_view') || 'all'; } catch (_) {}
        if (!['all','commissioning','handed_over'].includes(scope)) scope = 'all';
        let scopeHosts = null;
        const filters = () => ({search:get('bmc-search').value, switch:get('bmc-switch').value, status:get('bmc-status').value, problems:get('bmc-problems').checked});
        function render() {
            visible = filterRows(rows, filters()); const tbody = get('bmc-rows'); tbody.replaceChildren();
            page = Math.min(page, Math.max(0, Math.ceil(visible.length / pageSize) - 1));
            const counts = summarize(rows); const summary = get('bmc-summary'); summary.replaceChildren();
            [['Total Ports','total','total',''],['Matching Ports','match','excellent','MATCH'],['Connection Problems','problem','critical','__connection'],['Not Seen','notSeen','warning','NOT SEEN'],['Unknown / Stale / Disabled','unknown','info','__unknown']].forEach(([label, key, color, filter]) => {
                const card = el('button', 'summary-card card-' + color); card.type = 'button';
                const active = get('bmc-status').value === filter && !get('bmc-problems').checked;
                card.classList.toggle('active',active); card.setAttribute('aria-pressed',String(active));
                card.append(el('div','card-value',str(counts[key])), el('div','card-label',label));
                card.addEventListener('click', () => {
                    get('bmc-status').value = filter;
                    get('bmc-problems').checked = false;
                    page = 0;
                    render();
                }); summary.append(card);
            });
            visible.slice(page * pageSize, (page + 1) * pageSize).forEach(row => {
                const tr = el('tr'); tr.dataset.device = row.switch;
                [row.switch,row.port,row.expected_mac,(row.active_macs || []).join('\n') || '—',row.hostname].forEach((value,index) => {
                    const td = el('td', index === 2 || index === 3 ? 'mono' : '', str(value));
                    if (index === 3) td.style.whiteSpace = 'pre-line';
                    if (index === 1 && row.vlan != null) td.append(el('div','bmc-subtext','VLAN ' + row.vlan));
                    tr.append(td);
                });
                const status = statusOf(row); const cell = el('td','bmc-status-cell');
                const color = status === 'MATCH' ? 'green' : ['MISMATCH','WRONG PORT','PORT DOWN'].includes(status) ? 'red' : status === 'NOT SEEN' ? 'orange' : 'gray';
                cell.append(el('span','badge badge-' + color,status));
                if (row.detail) cell.append(el('div','bmc-subtext',str(row.detail)));
                if (row.warnings?.length) {
                    const labels = {MULTIPLE_MACS:'Multiple MACs learned on this port',AMBIGUOUS:'Expected MAC appears on multiple mapped ports'};
                    cell.append(el('div','bmc-subtext',row.warnings.map(value => labels[value] || value).join('; ')));
                }
                if (row.observed_locations?.length && status === 'WRONG PORT') cell.append(el('div','bmc-subtext','Seen at: ' + row.observed_locations.map(item => typeof item === 'string' ? item : str(item.switch) + ' / ' + str(item.port)).join(', ')));
                cell.append(el('div','bmc-subtext','Link: ' + (row.link_state || 'unknown') + ' · Checked: ' + timestamp(row.observed_at)), el('div','bmc-subtext','Last seen: ' + timestamp(row.last_seen)));
                tr.append(cell);
                if (admin) { const td = el('td'); td.append(button('Edit', 'secondary small', () => openEditor(row))); tr.append(td); }
                tbody.append(tr);
            });
            get('bmc-table-wrap').hidden = !visible.length; get('bmc-empty').hidden = !loaded || visible.length > 0;
            get('bmc-empty').textContent = rows.length ? 'No connections match these filters.' : scope !== 'all' ? 'No BMC mappings in the selected switch scope.' : 'No BMC mappings configured. ' + (admin ? 'Use Edit Mappings to add rows or import CSV.' : 'Ask an administrator to configure BMC mappings.');
            get('bmc-count').textContent = loaded ? visible.length + ' of ' + rows.length + ' mapping(s)' + (visible.length > pageSize ? ' · Rows ' + (page * pageSize + 1) + '–' + Math.min((page + 1) * pageSize,visible.length) : '') + (scope !== 'all' ? ' · Scope: ' + scope.replace(/_/g,' ') : '') : '';
            get('bmc-pagination-controls').hidden = visible.length <= pageSize;
            get('bmc-previous').disabled = page === 0;
            get('bmc-next').disabled = (page + 1) * pageSize >= visible.length;
            get('bmc-export').disabled = !loaded || !visible.length;
        }
        async function loadResults() {
            const token = gate.next(); get('bmc-refresh').disabled = true; showError('');
            try {
                if (scope !== 'all' && scopeHosts === null) {
                    const data = await apiRequest('status', undefined, '/tracking-api.sh');
                    if (!Array.isArray(data.devices)) throw new Error('Switch scope is unavailable.');
                    if (!gate.current(token)) return;
                    scopeHosts = new Set(data.devices.filter(item => item.state === scope).map(item => str(item.hostname).toLowerCase()));
                }
                const data = await apiRequest('results'); if (!gate.current(token)) return;
                if (!Array.isArray(data.rows)) throw new Error('The BMC result response is invalid.');
                rows = data.rows.filter(row => !scopeHosts || scopeHosts.has(str(row.switch).toLowerCase())); loaded = true; page = 0;
                const selected = get('bmc-switch').value; get('bmc-switch').replaceChildren(new Option('All switches',''));
                [...new Set(rows.map(row => row.switch))].sort().forEach(name => get('bmc-switch').append(new Option(name,name)));
                if ([...get('bmc-switch').options].some(option => option.value === selected)) get('bmc-switch').value = selected;
                get('bmc-updated').textContent = 'Last comparison: ' + timestamp(data.generated_at) + (data.observed_at ? ' · Observations: ' + timestamp(data.observed_at) : '');
                render();
            } catch (error) { if (gate.current(token)) showError(error.message + (loaded ? ' The displayed results are from the previous refresh.' : '')); }
            finally { if (gate.current(token)) { get('bmc-loading').hidden = true; get('bmc-refresh').disabled = false; } }
        }
        STATUSES.forEach(status => get('bmc-status').append(new Option(status,status)));
        get('bmc-status').append(new Option('Connection Problems','__connection'),new Option('Unknown / Stale / Disabled','__unknown'));
        ['bmc-search','bmc-switch','bmc-status','bmc-problems'].forEach(id => get(id).addEventListener(id === 'bmc-search' ? 'input' : 'change',() => { page = 0; render(); }));
        get('bmc-clear').addEventListener('click', () => { get('bmc-search').value = ''; get('bmc-switch').value = ''; get('bmc-status').value = ''; get('bmc-problems').checked = false; page = 0; render(); });
        get('bmc-previous').addEventListener('click',() => { if (page > 0) page--; render(); });
        get('bmc-next').addEventListener('click',() => { if ((page + 1) * pageSize < visible.length) page++; render(); });
        get('bmc-refresh').addEventListener('click',loadResults);
        get('bmc-edit').addEventListener('click', () => openEditor());
        get('bmc-export').addEventListener('click', () => download('bmc-results.csv', toCSV(visible,['switch','port','expected_mac','active_macs','hostname','status','vlan','link_state','observed_at','last_seen','detail'])));
        doc.addEventListener('bmc-mappings-saved',loadResults);
        const scan = button('Run Scan', 'secondary', async () => {
            if (scanning) return; scanning = true; scan.disabled = true; scan.textContent = 'Scanning…'; showError('');
            const stop = () => { clearTimeout(scanTimer); scanning = false; scan.disabled = false; scan.textContent = 'Run Scan'; };
            try {
                const baseline = await apiRequest('scan-status',undefined,'/search-api.sh');
                await apiRequest('run-scan',undefined,'/search-api.sh');
                const started = Date.now();
                const poll = async () => {
                    try {
                        const latest = await apiRequest('scan-status',undefined,'/search-api.sh');
                        if (latest.timestamp && latest.timestamp !== baseline.timestamp) { stop(); await loadResults(); return; }
                        if (Date.now() - started >= 600000) { stop(); showError('No completed scan was observed within 10 minutes. The scan may still be running. Refresh to check the latest data.'); return; }
                    } catch (error) { stop(); showError('Scan status unavailable: ' + error.message + ' Refresh to check the latest data.'); return; }
                    scanTimer = setTimeout(poll,5000);
                };
                scanTimer = setTimeout(poll,5000);
            } catch (error) { stop(); showError('Scan could not be started: ' + error.message); }
        });
        get('bmc-refresh').after(scan);
        root.addEventListener('pagehide', () => { clearTimeout(scanTimer); gate.invalidate(); });
        await loadResults();
    }
    return { normalizeMac, parseCSV, toCSV, filterRows, summarize, mapping, statusOf, requestGate, paginate, openEditor, initResults, hasUnsavedChanges: () => !!editor?.isDirty() };
}));
