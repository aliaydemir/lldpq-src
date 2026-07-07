/*
 * lifecycle-scope.js -- apply the outer-shell Analysis Scope to report pages.
 *
 * Collection remains fabric-wide. This module partitions the already-generated,
 * same-origin report DOM by switch lifecycle. Scope lives in sessionStorage, so
 * it is private to the current browser tab and cannot affect other users/tabs.
 */
(function () {
    'use strict';

    if (window.LLDPqLifecycleScope) return;

    var STORAGE_KEY = 'lldpq_tracking_view';
    var VALID_SCOPES = new Set(['all', 'commissioning', 'handed_over']);
    var HIDDEN_CLASS = 'lldpq-lifecycle-hidden';
    var GLOBAL_CLASS = 'lldpq-lifecycle-global-only';
    var state = {
        scope: 'all', devices: [], byName: new Map(), selected: new Set(),
        observer: null, timer: null, applying: false
    };

    function currentScope() {
        var value = 'all';
        try { value = sessionStorage.getItem(STORAGE_KEY) || 'all'; } catch (_) {}
        return VALID_SCOPES.has(value) ? value : 'all';
    }

    function supportedPath() {
        var path = location.pathname.toLowerCase();
        return [
            '/lldp.html', '/bgp-analysis.html', '/duplicate-analysis.html',
            '/link-flap-analysis.html', '/optical-analysis.html', '/ber-analysis.html',
            '/pfc-ecn-analysis.html', '/hardware-analysis.html', '/log-analysis.html',
            '/assets.html', '/transceiver.html'
        ].some(function (suffix) { return path.endsWith(suffix); });
    }

    function canonicalText(element) {
        if (!element) return '';
        var explicit = element.matches && element.matches('[data-p2p-orig]')
            ? element : (element.querySelector && element.querySelector('[data-p2p-orig]'));
        if (explicit) return explicit.getAttribute('data-p2p-orig') || '';
        var keyed = element.matches && element.matches('[data-p2p-key]')
            ? element : (element.querySelector && element.querySelector('[data-p2p-key]'));
        if (keyed) return keyed.getAttribute('data-p2p-key') || keyed.textContent || '';
        // lldp.html owns its alias renderer and stores the raw device/port in
        // the cell title while an alias is displayed.
        if (element.getAttribute && element.getAttribute('title')) {
            return element.getAttribute('title');
        }
        return element.getAttribute && (
            element.getAttribute('data-csv-value') || element.getAttribute('data-sort')
        ) || element.textContent || '';
    }

    function normalize(value) {
        return String(value || '').replace(/[▲▼↕]/g, '').replace(/\s+/g, ' ').trim().toLowerCase();
    }

    function deviceColumn(table) {
        if (!table || !table.tHead || !table.tHead.rows.length) return -1;
        var row = table.tHead.rows[table.tHead.rows.length - 1];
        var preferred = [
            'local device', 'device', 'device name', 'switch', 'hostname',
            'owner (local)', 'local on (switch:port)'
        ];
        for (var p = 0; p < preferred.length; p++) {
            for (var i = 0; i < row.cells.length; i++) {
                if (normalize(row.cells[i].textContent) === preferred[p]) return i;
            }
        }
        return -1;
    }

    function addKnownNames(value, output) {
        value = String(value || '').trim();
        if (!value) return;
        var pieces = value.split(/[\s,;|/<>]+/);
        pieces.push(value);
        pieces.forEach(function (piece) {
            var candidate = String(piece || '').trim().replace(/^['"(]+|['"),]+$/g, '');
            var colon = candidate.indexOf(':');
            if (colon > 0) candidate = candidate.slice(0, colon);
            var known = state.byName.get(candidate.toLowerCase());
            if (known) output.add(known);
        });
    }

    function hostsForRow(row, table) {
        var hosts = new Set();
        ['devices', 'device', 'deviceKey', 'canonicalDevice', 'parentDeviceKey'].forEach(function (key) {
            if (row.dataset && row.dataset[key]) addKnownNames(row.dataset[key], hosts);
        });
        if (hosts.size) return hosts;
        var index = deviceColumn(table);
        if (index >= 0 && row.cells && row.cells[index]) addKnownNames(canonicalText(row.cells[index]), hosts);
        return hosts;
    }

    function rowHasIdentity(row, table) {
        var keys = ['devices', 'device', 'deviceKey', 'canonicalDevice', 'parentDeviceKey'];
        if (keys.some(function (key) { return row.dataset && row.dataset[key]; })) return true;
        var index = deviceColumn(table);
        return index >= 0 && row.cells && row.cells[index] && canonicalText(row.cells[index]).trim() !== '';
    }

    function hostsInElement(element) {
        var hosts = new Set();
        if (!element) return hosts;
        ['devices', 'device', 'deviceKey', 'canonicalDevice', 'parentDeviceKey'].forEach(function (key) {
            if (element.dataset && element.dataset[key]) addKnownNames(element.dataset[key], hosts);
        });
        var text = canonicalText(element);
        state.devices.forEach(function (device) {
            var escaped = device.hostname.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            var pattern = new RegExp('(^|[^A-Za-z0-9_.()-])' + escaped + '($|[^A-Za-z0-9_.()-])', 'i');
            if (pattern.test(text)) hosts.add(device.hostname);
        });
        return hosts;
    }

    function isSelected(hosts) {
        if (state.scope === 'all' || !hosts.size) return true;
        for (var hostname of hosts) {
            if (state.selected.has(hostname.toLowerCase())) return true;
        }
        return false;
    }

    function filterTables() {
        document.querySelectorAll('table').forEach(function (table) {
            var column = deviceColumn(table);
            var explicit = table.querySelector('tbody tr[data-device], tbody tr[data-devices], ' +
                'tbody tr[data-device-key], tbody tr[data-canonical-device], tbody tr[data-parent-device-key]');
            if (column < 0 && !explicit) return;
            table.querySelectorAll('tbody tr').forEach(function (row) {
                var hosts = hostsForRow(row, table);
                var identified = rowHasIdentity(row, table);
                // A stale/unknown hostname must not leak into a named scope.
                // Rows without a device identity (for example empty-state and
                // threshold rows) are presentation, not monitoring records.
                row.classList.toggle(HIDDEN_CLASS, identified && (hosts.size === 0 || !isSelected(hosts)));
                if (identified) row.setAttribute('data-lifecycle-scoped-row', '1');
            });
        });
    }

    function filterCardsAndOptions() {
        document.querySelectorAll('.anomaly-card').forEach(function (card) {
            // Analyzer pages intentionally emit only a fabric-wide top-N anomaly
            // sample. Filtering that incomplete sample would produce a false
            // scoped count, so hide its whole section and keep the authoritative
            // scoped main table/summary instead.
            var section = card.closest('.dashboard-section');
            if (section) section.classList.add(GLOBAL_CLASS);
        });
        document.querySelectorAll('select option').forEach(function (option) {
            if (!option.value) return;
            var hosts = new Set();
            addKnownNames(option.value, hosts);
            if (!hosts.size) addKnownNames(option.textContent, hosts);
            var select = option.closest('select');
            var isDeviceSelector = select && /device/i.test((select.id || '') + ' ' + (select.name || ''));
            var excluded = (hosts.size > 0 && !isSelected(hosts)) || (isDeviceSelector && hosts.size === 0);
            if (excluded && !option.hasAttribute('data-lifecycle-option')) {
                option.setAttribute('data-lifecycle-option', '1');
                option.setAttribute('data-lifecycle-hidden-original', option.hidden ? '1' : '0');
                option.setAttribute('data-lifecycle-disabled-original', option.disabled ? '1' : '0');
            }
            if (excluded) {
                option.hidden = true;
                option.disabled = true;
            } else if (option.hasAttribute('data-lifecycle-option')) {
                option.hidden = option.getAttribute('data-lifecycle-hidden-original') === '1';
                option.disabled = option.getAttribute('data-lifecycle-disabled-original') === '1';
                option.removeAttribute('data-lifecycle-option');
                option.removeAttribute('data-lifecycle-hidden-original');
                option.removeAttribute('data-lifecycle-disabled-original');
            }
        });
    }

    function metricElement(element, value) {
        if (!element) return;
        if (!element.hasAttribute('data-lifecycle-original')) {
            element.setAttribute('data-lifecycle-original', element.textContent || '');
        }
        value = String(value);
        if (element.textContent !== value) element.textContent = value;
        var card = element.closest && element.closest('[data-metric-value]');
        if (card) {
            if (!card.hasAttribute('data-lifecycle-metric-original')) {
                card.setAttribute('data-lifecycle-metric-original', card.getAttribute('data-metric-value') || '');
            }
            var metricValue = value.replace(/%$/, '');
            if (card.getAttribute('data-metric-value') !== metricValue) {
                card.setAttribute('data-metric-value', metricValue);
            }
        }
    }

    function metric(selector, value) {
        metricElement(document.querySelector(selector), value);
    }

    function restoreMetrics() {
        document.querySelectorAll('[data-lifecycle-original]').forEach(function (element) {
            element.textContent = element.getAttribute('data-lifecycle-original');
            element.removeAttribute('data-lifecycle-original');
        });
        document.querySelectorAll('[data-lifecycle-metric-original]').forEach(function (element) {
            element.setAttribute('data-metric-value', element.getAttribute('data-lifecycle-metric-original'));
            element.removeAttribute('data-lifecycle-metric-original');
        });
    }

    function scopedRows(selector) {
        return Array.from(document.querySelectorAll(selector)).filter(function (row) {
            return row.getAttribute('data-lifecycle-scoped-row') === '1' &&
                !row.classList.contains(HIDDEN_CLASS);
        });
    }

    function textAt(row, index) {
        return normalize(row && row.cells && row.cells[index] ? row.cells[index].textContent : '');
    }

    function uniqueDevices(rows) {
        var values = new Set();
        rows.forEach(function (row) {
            hostsForRow(row, row.closest('table')).forEach(function (host) { values.add(host.toLowerCase()); });
        });
        return values.size;
    }

    function numberAt(row, index) {
        var text = String(row && row.cells && row.cells[index] ? row.cells[index].textContent : '')
            .replace(/,/g, '').trim();
        var value = Number(text);
        return Number.isFinite(value) ? value : 0;
    }

    function updateLLDP() {
        var rows = scopedRows('#lldp-data > tr');
        var counts = { success: 0, failed: 0, warning: 0, 'no info': 0 };
        rows.forEach(function (row) {
            var status = textAt(row, 7);
            if (Object.prototype.hasOwnProperty.call(counts, status)) counts[status]++;
        });
        metric('#total-connections', rows.length);
        metric('#success-connections', counts.success);
        metric('#failed-connections', counts.failed);
        metric('#warning-connections', counts.warning);
        metric('#no-info-connections', counts['no info']);
    }

    function updateBGP() {
        var rows = scopedRows('#bgp-data > tr');
        var established = 0, problems = 0;
        rows.forEach(function (row) {
            var stateText = textAt(row, 3);
            var health = textAt(row, 9);
            if (stateText === 'established') established++;
            if (health === 'critical' || health === 'warning') problems++;
        });
        metric('#total-devices', state.selected.size);
        metric('#total-neighbors', rows.length);
        metric('#established-neighbors', established);
        metric('#down-neighbors', problems);
        metric('#health-ratio', rows.length ? (100 * established / rows.length).toFixed(1) + '%' : 'N/A');
        // EVPN and collection-coverage totals cannot be reconstructed from the
        // neighbor rows. Hide fabric-wide EVPN cards and mark coverage unknown
        // rather than presenting global numbers under a scoped selector.
        document.querySelectorAll('#evpn').forEach(function (section) { section.classList.add(GLOBAL_CLASS); });
        metric('#stale-devices', '—');
        metric('#unknown-devices', '—');
    }

    function updateFlap() {
        var rows = scopedRows('#flap-data > tr');
        var stable = rows.filter(function (row) { return row.dataset.flapStatus === 'ok'; }).length;
        metric('#total-devices', uniqueDevices(rows));
        metric('#total-ports', rows.length);
        metric('#stable-ports', stable);
        metric('#problematic-ports', rows.length - stable);
        metric('#stability-ratio', rows.length ? (100 * stable / rows.length).toFixed(1) + '%' : 'N/A');
    }

    function updateGradeReport(tableSelector, unit, statuses) {
        var rows = scopedRows(tableSelector + ' tbody > tr');
        var counts = {};
        statuses.forEach(function (status) { counts[status] = 0; });
        rows.forEach(function (row) {
            var status = String(row.dataset.status || row.dataset.health || '').toLowerCase();
            if (Object.prototype.hasOwnProperty.call(counts, status)) counts[status]++;
        });
        metric('#total-' + unit, rows.length);
        statuses.forEach(function (status) { metric('#' + status + '-' + unit, counts[status]); });
    }

    function updateLogs() {
        var rows = scopedRows('#log-table > tbody > tr[data-device-key]');
        var totals = [0, 0, 0, 0];
        rows.forEach(function (row) {
            for (var i = 0; i < totals.length; i++) totals[i] += numberAt(row, i + 1);
        });
        metric('#total-devices', rows.length);
        metric('#critical-logs', totals[0]);
        metric('#warning-logs', totals[1]);
        metric('#error-logs', totals[2]);
        metric('#info-logs', totals[3]);
    }

    function updateAssets() {
        var rows = scopedRows('#assets-table > tbody > tr');
        var counts = { success: 0, failed: 0, warning: 0, 'no-info': 0 };
        rows.forEach(function (row) {
            var category = row.dataset.statusCategory || 'warning';
            if (Object.prototype.hasOwnProperty.call(counts, category)) counts[category]++;
        });
        metric('#total-devices', rows.length);
        metric('#success-count', counts.success);
        metric('#fail-count', counts.failed);
        metric('#warning-count', counts.warning);
        metric('#no-info-count', counts['no-info']);
    }

    function updatePFC() {
        var rows = scopedRows('#ports > tbody > tr');
        function flag(name) {
            return rows.filter(function (row) { return row.dataset[name] === '1'; }).length;
        }
        metric('#devices-card .metric', uniqueDevices(rows));
        metric('#ports-card .metric', rows.length);
        metric('#exact-card .metric', flag('exact') + '/' + rows.length);
        metric('#ecn-card .metric', flag('ecnActive'));
        metric('#rx-card .metric', flag('rxActive'));
        metric('#tx-card .metric', flag('txActive'));
        metric('#loss-card .metric', flag('lossActive'));
        metric('#attention-card .metric', flag('attention'));
    }

    function updateDuplicate() {
        var ipRows = scopedRows('#ipt > tbody > tr');
        var macRows = scopedRows('#mact > tbody > tr');
        var apipaRows = scopedRows('#apt > tbody > tr');
        var vlans = new Set();
        ipRows.concat(macRows).forEach(function (row) {
            var match = (row.cells[1]?.textContent || '').match(/\bvlan\s+(\S+)/i);
            if (match) vlans.add(match[1]);
        });
        apipaRows.forEach(function (row) {
            var match = (row.cells[2]?.textContent || '').match(/\bvlan\s+(\S+)/i);
            if (match) vlans.add(match[1]);
        });
        var values = {
            'active ip duplicates': ipRows.filter(function (row) { return row.dataset.sev === '0'; }).length,
            'quiesced ip duplicates': ipRows.filter(function (row) { return row.dataset.sev !== '0'; }).length,
            'confirmed mac conflicts': macRows.filter(function (row) { return row.dataset.kind === 'confirmed'; }).length,
            'mac dad findings': macRows.filter(function (row) { return row.dataset.kind === 'dad'; }).length,
            'active mac mobility': macRows.filter(function (row) {
                return row.dataset.kind === 'mobility' && row.dataset.mobilityActive === 'true';
            }).length,
            'mac mobility signals': macRows.filter(function (row) { return row.dataset.kind === 'mobility'; }).length,
            'apipa (dhcp failed)': apipaRows.length,
            'vlans with findings': vlans.size
        };
        document.querySelectorAll('.summary-card').forEach(function (card) {
            var label = normalize(card.querySelector('.metric-label')?.textContent);
            var target = card.querySelector('.metric, .card-value');
            if (Object.prototype.hasOwnProperty.call(values, label)) metricElement(target, values[label]);
            else if (label === 'dup-detect disabled') metricElement(target, '—');
        });
    }

    function updateTransceiver() {
        var rows = scopedRows('#module-table > tr');
        var models = new Set(), devices = new Set(), firmware = new Map();
        rows.forEach(function (row) {
            devices.add(textAt(row, 0));
            var model = textAt(row, 4), fw = textAt(row, 7);
            if (model) models.add(model);
            if (model && fw) {
                if (!firmware.has(model)) firmware.set(model, new Set());
                firmware.get(model).add(fw);
            }
        });
        metric('#total-modules', rows.length);
        metric('#unique-models', models.size);
        metric('#devices-count', devices.size);
        var mixed = 0;
        firmware.forEach(function (values) { if (values.size > 1) mixed++; });
        metric('#mixed-fw', mixed);
    }

    function updateSummaries() {
        var path = location.pathname.toLowerCase();
        if (path.endsWith('/lldp.html')) return updateLLDP();
        if (path.endsWith('/bgp-analysis.html')) return updateBGP();
        if (path.endsWith('/duplicate-analysis.html')) return updateDuplicate();
        if (path.endsWith('/link-flap-analysis.html')) return updateFlap();
        if (path.endsWith('/optical-analysis.html')) {
            return updateGradeReport('#optical-table', 'ports', ['excellent', 'good', 'warning', 'critical', 'down']);
        }
        if (path.endsWith('/ber-analysis.html')) {
            return updateGradeReport('#ber-table', 'ports', ['excellent', 'good', 'warning', 'critical', 'unknown']);
        }
        if (path.endsWith('/hardware-analysis.html')) {
            return updateGradeReport('#hardware-table', 'devices', ['excellent', 'good', 'warning', 'critical', 'unknown']);
        }
        if (path.endsWith('/log-analysis.html')) return updateLogs();
        if (path.endsWith('/pfc-ecn-analysis.html')) return updatePFC();
        if (path.endsWith('/assets.html')) return updateAssets();
        if (path.endsWith('/transceiver.html')) return updateTransceiver();
    }

    function clearScope() {
        document.querySelectorAll('.' + HIDDEN_CLASS).forEach(function (element) {
            element.classList.remove(HIDDEN_CLASS);
        });
        document.querySelectorAll('.' + GLOBAL_CLASS).forEach(function (element) {
            element.classList.remove(GLOBAL_CLASS);
        });
        document.querySelectorAll('[data-lifecycle-scoped-row]').forEach(function (row) {
            row.removeAttribute('data-lifecycle-scoped-row');
        });
        document.querySelectorAll('select option[data-lifecycle-option]').forEach(function (option) {
            option.hidden = option.getAttribute('data-lifecycle-hidden-original') === '1';
            option.disabled = option.getAttribute('data-lifecycle-disabled-original') === '1';
            option.removeAttribute('data-lifecycle-option');
            option.removeAttribute('data-lifecycle-hidden-original');
            option.removeAttribute('data-lifecycle-disabled-original');
        });
        document.body.classList.remove('lldpq-lifecycle-failed');
        document.getElementById('lldpq-lifecycle-error')?.remove();
    }

    function isDownloadControl(target) {
        var control = target && target.closest && target.closest('button, a');
        if (!control) return false;
        if (control.id === 'download-csv') return true;
        var onclick = control.getAttribute('onclick') || '';
        return /downloadcsv\s*\(/i.test(onclick) || /download csv/i.test(control.textContent || '');
    }

    function scopedTableForPath() {
        var path = location.pathname.toLowerCase();
        if (path.endsWith('/lldp.html')) return document.querySelector('#lldp-table');
        if (path.endsWith('/bgp-analysis.html')) return document.querySelector('#bgp-table');
        if (path.endsWith('/duplicate-analysis.html')) return document.querySelector('#ipt');
        if (path.endsWith('/link-flap-analysis.html')) return document.querySelector('#flap-table');
        if (path.endsWith('/optical-analysis.html')) return document.querySelector('#optical-table');
        if (path.endsWith('/ber-analysis.html')) return document.querySelector('#ber-table');
        if (path.endsWith('/pfc-ecn-analysis.html')) return document.querySelector('#ports');
        if (path.endsWith('/hardware-analysis.html')) return document.querySelector('#hardware-table');
        if (path.endsWith('/log-analysis.html')) return document.querySelector('#log-table');
        if (path.endsWith('/assets.html')) return document.querySelector('#assets-table');
        if (path.endsWith('/transceiver.html')) return document.querySelector('#module-table')?.closest('table');
        return null;
    }

    function csvEscape(value) {
        value = String(value == null ? '' : value).replace(/\r?\n/g, ' ').trim();
        if (/^[=+\-@\t\r]/.test(value)) value = "'" + value;
        return '"' + value.replace(/"/g, '""') + '"';
    }

    function downloadTransceiverScope(table) {
        if (!table) return;
        var header = Array.from(table.querySelectorAll('thead th')).map(function (cell) {
            return normalize(cell.textContent).replace(/\b[a-z]/g, function (letter) { return letter.toUpperCase(); });
        });
        var rows = scopedRows('#module-table > tr').filter(function (row) {
            return getComputedStyle(row).display !== 'none';
        });
        var lines = [header].concat(rows.map(function (row) {
            return Array.from(row.cells).map(function (cell) { return canonicalText(cell).trim(); });
        })).map(function (row) { return row.map(csvEscape).join(','); });
        var blob = new Blob([lines.join('\n') + '\n'], { type: 'text/csv;charset=utf-8' });
        var url = URL.createObjectURL(blob);
        var link = document.createElement('a');
        link.href = url;
        link.download = 'transceiver_inventory_' + state.scope + '.csv';
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    }

    function prepareScopedCSV(event) {
        if (state.scope === 'all' || !isDownloadControl(event.target)) return;
        var table = scopedTableForPath();
        if (!table) return;
        var path = location.pathname.toLowerCase();
        if (path.endsWith('/transceiver.html')) {
            event.preventDefault();
            event.stopImmediatePropagation();
            downloadTransceiverScope(table);
            return;
        }
        var excluded = Array.from(table.querySelectorAll('tbody tr.' + HIDDEN_CLASS));
        var previous = excluded.map(function (row) {
            return { row: row, display: row.style.display, hidden: row.hidden };
        });
        excluded.forEach(function (row) {
            row.style.display = 'none';
            row.hidden = true;
        });
        // Existing report exporters run synchronously in the same click event.
        // Restore native filter state on the next task.
        setTimeout(function () {
            previous.forEach(function (item) {
                item.row.style.display = item.display;
                item.row.hidden = item.hidden;
            });
        }, 0);
    }

    function failClosed(error) {
        document.body.classList.add('lldpq-lifecycle-failed');
        if (!document.getElementById('lldpq-lifecycle-error')) {
            var warning = document.createElement('div');
            warning.id = 'lldpq-lifecycle-error';
            warning.setAttribute('role', 'alert');
            warning.textContent = 'Analysis Scope could not be verified. Report data is hidden to prevent an unfiltered view. Refresh the page or choose All Switches.';
            document.body.insertBefore(warning, document.body.firstChild);
        }
        console.warn('LLDPq lifecycle scope was not applied:', error);
    }

    function applyNow() {
        if (state.applying) return;
        state.applying = true;
        if (state.observer) state.observer.disconnect();
        try {
            state.scope = currentScope();
            if (state.scope === 'all') {
                clearScope();
                restoreMetrics();
                return;
            }
            filterTables();
            filterCardsAndOptions();
            updateSummaries();
        } finally {
            state.applying = false;
            if (state.observer && document.body) {
                state.observer.observe(document.body, { childList: true, subtree: true });
            }
        }
    }

    function scheduleApply() {
        clearTimeout(state.timer);
        state.timer = setTimeout(applyNow, 40);
    }

    async function load() {
        if (!supportedPath()) return;
        state.scope = currentScope();
        if (state.scope === 'all') return applyNow();
        try {
            var response = await fetch('/tracking-api.sh?action=status&_=' + Date.now(), {
                cache: 'no-store', headers: { Accept: 'application/json' }
            });
            var payload = await response.json();
            if (!response.ok || payload.success !== true || !Array.isArray(payload.devices)) {
                throw new Error(payload.error || 'tracking response is invalid');
            }
            state.devices = payload.devices.filter(function (device) { return device && device.hostname; });
            state.byName = new Map(state.devices.map(function (device) {
                return [String(device.hostname).toLowerCase(), String(device.hostname)];
            }));
            state.selected = new Set(state.devices.filter(function (device) {
                return device.state === state.scope;
            }).map(function (device) { return String(device.hostname).toLowerCase(); }));
            document.body.classList.remove('lldpq-lifecycle-failed');
            document.getElementById('lldpq-lifecycle-error')?.remove();
            applyNow();
            state.observer = new MutationObserver(scheduleApply);
            state.observer.observe(document.body, { childList: true, subtree: true });
        } catch (error) {
            failClosed(error);
        }
    }

    var style = document.createElement('style');
    style.textContent =
        '.' + HIDDEN_CLASS + ',.' + GLOBAL_CLASS + '{display:none!important}' +
        '#lldpq-lifecycle-error{margin:14px;padding:12px 14px;color:#ffcc80;background:#332b20;' +
        'border:1px solid #8a5b19;border-left:4px solid #ff9800;border-radius:4px;font:13px/1.45 sans-serif}' +
        '.lldpq-lifecycle-failed>*:not(#lldpq-lifecycle-error):not(script):not(style),' +
        '.lldpq-lifecycle-failed .dashboard-section,.lldpq-lifecycle-failed .table-container{' +
        'display:none!important}';
    document.head.appendChild(style);
    document.addEventListener('click', prepareScopedCSV, true);
    window.LLDPqLifecycleScope = { apply: scheduleApply, currentScope: currentScope };
    load();
}());
