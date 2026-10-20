/* BMC results use the same device picker, header funnels and row density as LLDP. */
(function (root, factory) {
    'use strict';
    const api = factory(root);
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.LLDPqBMCResults = api;
}(typeof window === 'undefined' ? globalThis : window, function (root) {
    'use strict';
    const text = value => value == null ? '' : String(value);
    const statusOf = row => text(row.status || 'UNKNOWN').replace(/_/g, ' ').toUpperCase();
    const byName = (a, b) => text(a).localeCompare(text(b), undefined, { numeric:true, sensitivity:'base' });
    const statusOrder = new Map(['PORT DOWN','MISMATCH','WRONG PORT','NOT SEEN','UNKNOWN','STALE','DISABLED','MATCH'].map((status, index) => [status,index]));
    function aliasMaps(data = {}) {
        const lookup = source => new Map(Object.entries(source && typeof source === 'object' && !Array.isArray(source) ? source : {})
            .filter(([key,value]) => key && typeof value === 'string' && value.trim()).map(([key,value]) => [key.toLowerCase(),value]));
        return { devices:lookup(data?.devices), interfaces:lookup(data?.interfaces) };
    }
    function aliasLabel(value, aliases, namespace, enabled = true) {
        const canonical = text(value);
        return enabled ? aliases?.[namespace]?.get(canonical.toLowerCase()) || canonical : canonical;
    }
    const valuesFor = (row, aliases, enabled = true) => [aliasLabel(row.switch,aliases,'devices',enabled),aliasLabel(row.port,aliases,'interfaces',enabled),text(row.expected_mac),(row.active_macs || []).join('; ') || '—',aliasLabel(row.hostname,aliases,'devices',enabled),statusOf(row)];
    function exportRows(rows, aliases, enabled) {
        return rows.map(row => ({...row, switch:aliasLabel(row.switch,aliases,'devices',enabled),port:aliasLabel(row.port,aliases,'interfaces',enabled),hostname:aliasLabel(row.hostname,aliases,'devices',enabled)}));
    }
    // Select2 groups need recursive matching; both real names and aliases are
    // searchable while each option retains its canonical inventory identity.
    function matchDevice(params, data) {
        const term = text(params.term).trim().toLowerCase();
        if (!term) return data;
        if (data.children) {
            const children = data.children.map(child => matchDevice(params,child)).filter(Boolean);
            return children.length ? {...data,children} : null;
        }
        return [data.text,data.element?.dataset?.alias].some(value => text(value).toLowerCase().includes(term)) ? data : null;
    }
    function filterDevices(rows, devices) {
        const selected = new Set(devices || []);
        return selected.size ? rows.filter(row => selected.has(row.switch) || selected.has(row.hostname)) : rows;
    }
    function sortRows(rows, column, descending = false, aliases, enabled = true) {
        if (column < 0) return rows.slice();
        const direction = descending ? -1 : 1;
        return rows.slice().sort((a,b) => {
            if (column === 5) {
                const severity = (statusOrder.get(statusOf(a)) ?? 99) - (statusOrder.get(statusOf(b)) ?? 99);
                if (severity) return severity * direction;
            }
            return byName(valuesFor(a,aliases,enabled)[column],valuesFor(b,aliases,enabled)[column]) * direction;
        });
    }
    function deviceOptions(rows) {
        const switches = [...new Set(rows.map(row => row.switch).filter(Boolean))].sort(byName);
        const local = new Set(switches);
        const hosts = [...new Set(rows.map(row => row.hostname).filter(value => value && !local.has(value)))].sort(byName);
        return { switches, hosts };
    }
    function displayedRows(table) {
        return Array.from(table.tBodies[0]?.rows || []).filter(row => row._bmcRow && !row.hidden && row.style.display !== 'none' && !row.classList.contains('tf-hidden') && !row.classList.contains('lldpq-lifecycle-hidden')).map(row => row._bmcRow);
    }

    // This capture listener is registered before table-filter.js. A funnel
    // opened while progressive rendering is pending must see every row/value.
    let flushForFilter = null;
    if (root.document) root.document.addEventListener('click', event => {
        if (event.target.closest?.('#bmc-table .tf-btn')) flushForFilter?.();
    }, true);

    async function initResults(shared) {
        const doc = root.document, get = id => doc.getElementById(id);
        if (!get('bmc-table') || get('bmc-table').dataset.bmcInitialized) return;
        get('bmc-table').dataset.bmcInitialized = '1';
        const { apiRequest, requestGate, timestamp, filterRows, summarize, openEditor, toCSV, download } = shared;
        const table = get('bmc-table'), tbody = get('bmc-rows'), gate = requestGate();
        const showError = message => { get('bmc-error').textContent = message; get('bmc-error').hidden = !message; };
        get('bmc-run').disabled = true;
        // Older auth.js bundles expose only a global lexical const.
        const auth = typeof LLDPqAuth !== 'undefined' ? LLDPqAuth : root.LLDPqAuth;
        if (!auth || !await auth.checkWithRetry()) {
            get('bmc-loading').hidden = true;
            showError(auth ? auth.lastCheckMessage() : 'Authentication is unavailable.');
            return;
        }
        const admin = auth.isAdmin(); get('bmc-edit').hidden = !admin; get('port-alias-btn').hidden = !admin; get('bmc-run').disabled = false;
        let rows = [], ordered = [], selectedDevices = [], status = '', loaded = false, scanning = false, scanTimer = null;
        let currentSort = { column:-1, descending:false }, pendingRender = null, generation = 0;
        let aliases = aliasMaps(), p2pNamesOn = true, alive = true, aliasChannel = null;
        const aliasGate = requestGate();
        try { p2pNamesOn = root.localStorage.getItem('lldpq_port_alias_on') !== 'false'; } catch (_) {}
        let scope = 'all', scopeHosts = null;
        try { scope = root.sessionStorage.getItem('lldpq_tracking_view') || 'all'; } catch (_) {}
        if (!['all','commissioning','handed_over'].includes(scope)) scope = 'all';
        const create = (tag, className, content) => {
            const element = doc.createElement(tag);
            if (className) element.className = className;
            if (content !== undefined) element.textContent = content;
            return element;
        };
        const empty = create('div','loading'); empty.id = 'bmc-empty'; empty.hidden = true; table.parentElement.after(empty);
        const statusLabels = { 'MATCH':'Successful', '__connection':'Failed', 'NOT SEEN':'Warning', '__unknown':'No Information' };
        function updateVisibility() {
            if (!loaded) return;
            const visible = displayedRows(table);
            const funnelActive = !!table.querySelector('.tf-active');
            const filtered = !!status || selectedDevices.length > 0 || funnelActive;
            get('filter-info').hidden = !filtered;
            get('filter-text').textContent = 'Showing ' + visible.length + (status ? ' ' + statusLabels[status] : '') + ' Ports' + (selectedDevices.length ? ' for ' + selectedDevices.join(', ') : '') + (funnelActive ? ' with column filters' : '');
            get('clearSearchBtn').hidden = !selectedDevices.length;
            empty.hidden = !!visible.length || !!pendingRender;
            empty.textContent = rows.length ? 'No connections match these filters.' : scope !== 'all' ? 'No BMC mappings in the selected switch scope.' : 'No BMC mappings configured. ' + (admin ? 'Use Edit Mappings to add rows or import CSV.' : 'Ask an administrator to configure BMC mappings.');
            get('bmc-count').textContent = visible.length + ' of ' + rows.length + ' mapping(s)' + (pendingRender ? ' · Loading rows…' : '') + (scope !== 'all' ? ' · Scope: ' + scope.replace(/_/g,' ') : '');
            get('bmc-export').disabled = !visible.length || !!pendingRender;
            get('bmc-export').setAttribute('aria-busy',String(!!pendingRender));
        }
        function diagnostic(row) {
            const warningNames = { MULTIPLE_MACS:'Multiple MACs learned on this port', AMBIGUOUS:'Expected MAC appears on multiple mapped ports' };
            const lines = [row.detail, ...(row.warnings || []).map(warning => warningNames[warning] || warning)];
            if (row.observed_locations?.length && statusOf(row) === 'WRONG PORT') lines.push('Seen at: ' + row.observed_locations.map(item => typeof item === 'string' ? item : text(item.switch) + ' / ' + text(item.port)).join(', '));
            if (statusOf(row) === 'NOT SEEN') lines.push('An idle BMC can age out of the MAC table. This does not confirm the BMC is offline.');
            lines.push('Link: ' + (row.link_state || 'unknown'), 'Checked: ' + timestamp(row.observed_at), 'Last seen: ' + timestamp(row.last_seen));
            return lines.filter(Boolean).join('\n');
        }
        function buildRow(row) {
            const tr = create('tr'); tr.dataset.device = row.switch; tr._bmcRow = row;
            const canonical = valuesFor(row);
            valuesFor(row,aliases,p2pNamesOn).forEach((value,index) => {
                const td = create('td', index === 2 || index === 3 ? 'mac-cell' : '');
                // Stable filter keys prevent a display toggle from changing
                // which physical mappings are selected by the header funnels.
                td.dataset.filter = canonical[index];
                td.dataset.filterLabel = value;
                if (value !== canonical[index]) td.title = canonical[index];
                if (index === 5) {
                    const color = value === 'MATCH' ? 'green' : ['MISMATCH','WRONG PORT','PORT DOWN'].includes(value) ? 'red' : value === 'NOT SEEN' ? 'orange' : 'gray';
                    const badge = create('span','badge badge-' + color,value); badge.title = diagnostic(row); badge.tabIndex = 0;
                    td.append(badge); td.title = badge.title;
                } else td.textContent = value;
                tr.append(td);
            });
            if (admin) {
                tr.className = 'bmc-row-edit'; tr.title = 'Double-click to edit this mapping';
            }
            return tr;
        }
        function appendChunk(job, schedule = true) {
            if (!job || job !== pendingRender || job.generation !== generation) return;
            const fragment = doc.createDocumentFragment(), end = Math.min(job.next + 500,job.rows.length);
            for (let index = job.next; index < end; index++) fragment.append(buildRow(job.rows[index]));
            tbody.append(fragment); job.next = end;
            if (job.next >= job.rows.length) pendingRender = null;
            root.TableFilter?.refresh(table);
            updateVisibility();
            if (pendingRender && schedule) root.requestAnimationFrame(() => appendChunk(job));
        }
        function flushRows() {
            while (pendingRender) appendChunk(pendingRender,false);
            root.TableFilter?.refresh(table);
            updateVisibility();
        }
        flushForFilter = flushRows;
        function render() {
            ordered = sortRows(filterDevices(filterRows(rows,{status}),selectedDevices),currentSort.column,currentSort.descending,aliases,p2pNamesOn);
            const counts = summarize(rows);
            ['total','match','problem','notSeen','unknown'].forEach(key => { get('bmc-' + key).textContent = counts[key]; });
            get('bmc-summary').querySelectorAll('.summary-card').forEach(card => {
                // Match LLDP: the initial all-ports view has no selected card.
                const active = !!status && card.dataset.status === status;
                card.classList.toggle('active',active); card.setAttribute('aria-pressed',String(active));
            });
            table.querySelectorAll('th.sortable').forEach(th => {
                const active = Number(th.dataset.column) === currentSort.column;
                th.classList.toggle('asc',active && !currentSort.descending); th.classList.toggle('desc',active && currentSort.descending);
                th.setAttribute('aria-sort',active ? currentSort.descending ? 'descending' : 'ascending' : 'none');
            });
            tbody.replaceChildren();
            pendingRender = { rows:ordered, next:0, generation:++generation };
            appendChunk(pendingRender);
        }
        // Header filters modify row classes themselves. Read those changes to
        // keep result counts, empty state and CSV availability in sync.
        const observer = new root.MutationObserver(() => updateVisibility());
        observer.observe(table,{ subtree:true, attributes:true, attributeFilter:['class'] });
        const jq = root.jQuery;
        if (jq?.fn?.select2) {
            jq(get('deviceSearch')).select2({ placeholder:'Search devices…', allowClear:false, width:'auto', dropdownAutoWidth:true, closeOnSelect:false, matcher:matchDevice });
            jq(get('deviceSearch')).on('change',() => { selectedDevices = jq(get('deviceSearch')).val() || []; render(); });
        } else get('deviceSearch').addEventListener('change',() => { selectedDevices = Array.from(get('deviceSearch').selectedOptions).map(option => option.value); render(); });
        function syncDeviceOptions() {
            const options = deviceOptions(rows), available = new Set([...options.switches,...options.hosts]);
            selectedDevices = selectedDevices.filter(device => available.has(device));
            const select = get('deviceSearch'); select.replaceChildren();
            for (const [label,names] of [['Switches',options.switches],['Hosts',options.hosts]]) {
                if (!names.length) continue;
                const group = create('optgroup'); group.label = label;
                names.forEach(name => {
                    const option = new Option(name,name); option.selected = selectedDevices.includes(name);
                    const alias = aliases.devices.get(name.toLowerCase()); if (alias) option.dataset.alias = alias;
                    group.append(option);
                }); select.append(group);
            }
            if (jq?.fn?.select2) jq(select).trigger('change.select2');
        }
        function updateP2pToggleUI() {
            get('p2p-toggle-text').textContent = p2pNamesOn ? 'P2P: On' : 'P2P: Off';
            get('p2p-toggle').setAttribute('aria-pressed',String(p2pNamesOn));
            get('p2p-toggle').style.borderColor = p2pNamesOn ? '#76b900' : '';
        }
        async function refreshAliases() {
            const token = aliasGate.next();
            let data = {};
            try {
                const response = await root.fetch('/display-aliases.json',{cache:'no-store'});
                if (response.ok) data = await response.json();
            } catch (_) { /* Aliases are optional; canonical names remain usable. */ }
            if (!alive || !aliasGate.current(token)) return;
            aliases = aliasMaps(data);
            syncDeviceOptions();
            if (loaded) render();
        }
        function aliasStorageChanged(event) {
            if (event.key === 'lldpq_port_alias_on') {
                p2pNamesOn = event.newValue !== 'false'; updateP2pToggleUI(); if (loaded) render();
            } else if (event.key === 'lldpq_aliases_revision') refreshAliases();
        }
        get('p2p-toggle').addEventListener('click',() => {
            p2pNamesOn = !p2pNamesOn;
            try { root.localStorage.setItem('lldpq_port_alias_on',String(p2pNamesOn)); } catch (_) {}
            updateP2pToggleUI(); if (loaded) render();
        });
        get('port-alias-btn').addEventListener('click',() => root.LLDPqBMCAliasEditor.open());
        root.addEventListener('storage',aliasStorageChanged);
        root.addEventListener('lldpq-aliases-updated',refreshAliases);
        try {
            aliasChannel = new root.BroadcastChannel('lldpq-aliases');
            aliasChannel.onmessage = event => { if (event.data?.type === 'updated') refreshAliases(); };
        } catch (_) { /* Storage events remain available. */ }
        updateP2pToggleUI();
        async function loadResults() {
            const token = gate.next(); get('bmc-refresh').disabled = true; showError('');
            try {
                if (scope !== 'all') {
                    const data = await apiRequest('status',undefined,'/tracking-api.sh');
                    if (!Array.isArray(data.devices)) throw new Error('Switch scope is unavailable.');
                    if (!gate.current(token)) return;
                    scopeHosts = new Set(data.devices.filter(item => item.state === scope).map(item => text(item.hostname).toLowerCase()));
                }
                const data = await apiRequest('results'); if (!gate.current(token)) return;
                if (!Array.isArray(data.rows)) throw new Error('The BMC result response is invalid.');
                rows = data.rows.filter(row => !scopeHosts || scopeHosts.has(text(row.switch).toLowerCase())); loaded = true;
                syncDeviceOptions();
                get('bmc-updated').textContent = 'Last Updated: ' + timestamp(data.observed_at || data.generated_at);
                get('bmc-updated').title = 'Last comparison: ' + timestamp(data.generated_at) + '\nObservations: ' + timestamp(data.observed_at);
                render();
            } catch (error) { if (gate.current(token)) showError(error.message + (loaded ? ' The displayed results are from the previous refresh.' : '')); }
            finally { if (gate.current(token)) { get('bmc-loading').hidden = true; get('bmc-refresh').disabled = false; } }
        }
        function clearDevices() {
            selectedDevices = [];
            if (jq?.fn?.select2) jq(get('deviceSearch')).val(null).trigger('change.select2');
            else Array.from(get('deviceSearch').options).forEach(option => { option.selected = false; });
        }
        get('clearSearchBtn').addEventListener('click',() => { clearDevices(); render(); });
        get('bmc-clear').addEventListener('click',() => { status = ''; clearDevices(); root.TableFilter?.clearAll(table); render(); });
        get('bmc-summary').querySelectorAll('.summary-card').forEach(card => {
            const activate = () => { status = card.dataset.status; render(); };
            card.addEventListener('click',activate);
            card.addEventListener('keydown',event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); activate(); } });
        });
        table.querySelectorAll('th.sortable').forEach(th => {
            const sort = () => {
                const column = Number(th.dataset.column);
                currentSort = { column, descending:currentSort.column === column && !currentSort.descending }; render();
            };
            th.addEventListener('click',event => { if (!event.target.closest('.tf-btn')) sort(); });
            th.addEventListener('keydown',event => { if (event.target === th && (event.key === 'Enter' || event.key === ' ')) { event.preventDefault(); sort(); } });
        });
        tbody.addEventListener('dblclick',event => { const row = event.target.closest('tr'); if (admin && row?._bmcRow) openEditor(row._bmcRow); });
        get('bmc-refresh').addEventListener('click',loadResults);
        get('bmc-edit').addEventListener('click',() => openEditor());
        get('bmc-export').addEventListener('click',() => {
            flushRows();
            download('bmc-results.csv',toCSV(exportRows(displayedRows(table),aliases,p2pNamesOn),['switch','port','expected_mac','active_macs','hostname','status']));
        });
        doc.addEventListener('bmc-mappings-saved',loadResults);
        get('bmc-run').addEventListener('click',async () => {
            if (scanning) return;
            scanning = true; get('bmc-run').disabled = true; get('bmc-run-text').textContent = 'Checking…'; showError('');
            const stop = () => { clearTimeout(scanTimer); scanning = false; get('bmc-run').disabled = false; get('bmc-run-text').textContent = 'Run BMC Check'; };
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
        root.addEventListener('pagehide',() => {
            alive = false; clearTimeout(scanTimer); gate.invalidate(); aliasGate.invalidate(); generation++; pendingRender = null; observer.disconnect(); flushForFilter = null;
            root.removeEventListener('storage',aliasStorageChanged); root.removeEventListener('lldpq-aliases-updated',refreshAliases); aliasChannel?.close();
        });
        root.TableFilter?.attach(table);
        await Promise.all([loadResults(),refreshAliases()]);
    }
    return { initResults, filterDevices, sortRows, deviceOptions, displayedRows, valuesFor, aliasMaps, aliasLabel, exportRows, matchDevice };
}));
