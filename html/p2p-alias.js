/*
 * p2p-alias.js — shared "P2P / field names" display toggle.
 *
 * Drop-in for any LLDPq report page (analysis pages, transceiver, assets, ...):
 *   <script src="/p2p-alias.js"></script>
 *
 * What it does:
 *   - Loads /display-aliases.json ({ interfaces:{os->label}, devices:{real->label} }).
 *   - Auto-mounts a "P2P: On/Off" toggle into the page toolbar (.action-buttons).
 *   - When ON, walks the page's table cells and replaces any leaf cell whose exact
 *     trimmed text matches a real name with its alias (e.g. tan-spine-01 -> SPINE-01,
 *     enP22p3s0f0np0 -> M1). Renderers can opt in explicitly with data-p2p-key and
 *     can provide the canonical display value in data-p2p-orig. This is useful for
 *     compound cells such as "switch:port", where host and port are separate spans.
 *     Renderers can set data-p2p-namespace="devices" or "interfaces" when the
 *     column name does not make the namespace clear.
 *     The canonical value is retained so toggling OFF and CSV exports remain stable.
 *   - Re-applies after client-side table rebuilds (MutationObserver, debounced).
 *   - State lives in localStorage ('lldpq_port_alias_on') so it is shared across every
 *     page and persists; a 'storage' listener keeps other open tabs in sync live.
 *
 * Display-only: never touches the underlying data, sorting or filtering. CSV code can
 * use data-csv-value or LLDPqP2P.canonicalText(element) to read canonical values even
 * while aliases are visible.
 */
(function () {
    'use strict';
    var KEY = 'lldpq_port_alias_on';
    var on = true;                                  // default ON
    try { on = localStorage.getItem(KEY) !== 'false'; } catch (e) {}
    var deviceMap = {};                              // lower(realName) -> device alias
    var interfaceMap = {};                           // lower(realName) -> interface alias
    var fallbackMap = {};                            // only keys unambiguous across both maps
    var loaded = false;
    var observer = null;
    var pending = false;
    var aliasLoadSeq = 0;

    function loadAliases(done) {
        var seq = ++aliasLoadSeq;
        fetch('/display-aliases.json', { cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : {}; })
            .then(function (d) {
                if (seq !== aliasLoadSeq) return;
                d = (d && typeof d === 'object') ? d : {};
                var devices = {};
                var interfaces = {};
                // Key by lower(realName) so matching is case-INSENSITIVE. This fully
                // decouples the alias from the server-side canonical casing
                // (device_names.py rewrites device cells to the topology.dot spelling):
                // the alias matches whether the cell shows MEL01-... or mel01-...
                var rawDevices = d.devices;
                var rawInterfaces = d.interfaces;
                if (rawDevices && typeof rawDevices === 'object') {
                    Object.keys(rawDevices).forEach(function (k) { if (k && rawDevices[k]) devices[String(k).toLowerCase()] = rawDevices[k]; });
                }
                if (rawInterfaces && typeof rawInterfaces === 'object') {
                    Object.keys(rawInterfaces).forEach(function (k) { if (k && rawInterfaces[k]) interfaces[String(k).toLowerCase()] = rawInterfaces[k]; });
                }
                var fallback = {};
                var keys = Object.keys(devices).concat(Object.keys(interfaces));
                keys.forEach(function (key) {
                    var inDevices = Object.prototype.hasOwnProperty.call(devices, key);
                    var inInterfaces = Object.prototype.hasOwnProperty.call(interfaces, key);
                    // If both namespaces define the same canonical text differently,
                    // an untyped cell is intentionally left canonical.
                    if (!inDevices || !inInterfaces || devices[key] === interfaces[key]) {
                        fallback[key] = inDevices ? devices[key] : interfaces[key];
                    }
                });
                deviceMap = devices; interfaceMap = interfaces; fallbackMap = fallback;
                loaded = true; if (done) done();
            })
            .catch(function () {
                if (seq !== aliasLoadSeq) return;
                deviceMap = {}; interfaceMap = {}; fallbackMap = {}; loaded = true; if (done) done();
            });
    }

    // Explicitly tagged elements may live inside a compound table cell. Untagged
    // pages keep the legacy exact-leaf matching behaviour.
    function leafCells() {
        var out = [];
        var seen = new Set();
        var explicit = document.querySelectorAll('[data-p2p-key]');
        for (var e = 0; e < explicit.length; e++) {
            out.push(explicit[e]);
            seen.add(explicit[e]);
        }
        var tds = document.querySelectorAll('table td, table th');
        for (var i = 0; i < tds.length; i++) {
            var td = tds[i];
            if (td.childElementCount === 0) {
                if (!seen.has(td)) out.push(td);
                continue;
            }
            var kids = td.querySelectorAll('*');
            for (var j = 0; j < kids.length; j++) {
                if (kids[j].childElementCount === 0 && !seen.has(kids[j])) {
                    out.push(kids[j]);
                }
            }
        }
        return out;
    }

    function saveTitle(el, canonical) {
        if (!el.hasAttribute('data-p2p-title-saved')) {
            el.setAttribute('data-p2p-title-saved', '1');
            el.setAttribute('data-p2p-title-orig', el.getAttribute('title') || '');
        }
        el.title = canonical;
    }

    function restoreTitle(el) {
        if (!el.hasAttribute('data-p2p-title-saved')) return;
        var original = el.getAttribute('data-p2p-title-orig') || '';
        if (original) el.setAttribute('title', original);
        else el.removeAttribute('title');
        el.removeAttribute('data-p2p-title-saved');
        el.removeAttribute('data-p2p-title-orig');
    }

    function canonicalText(el) {
        if (!el) return '';
        if (el.hasAttribute && el.hasAttribute('data-p2p-orig')) {
            return el.getAttribute('data-p2p-orig');
        }
        // A table cell can contain multiple explicitly aliased spans. Resolve them on
        // a detached clone so callers get canonical CSV text without changing the UI.
        var clone = el.cloneNode ? el.cloneNode(true) : null;
        if (!clone || !clone.querySelectorAll) return el.textContent || '';
        var aliased = clone.querySelectorAll('[data-p2p-orig]');
        for (var i = 0; i < aliased.length; i++) {
            aliased[i].textContent = aliased[i].getAttribute('data-p2p-orig');
        }
        return clone.textContent || '';
    }

    function normalizeNamespace(value) {
        value = String(value || '').toLowerCase();
        if (value === 'device' || value === 'devices' || value === 'host' || value === 'hosts') return 'devices';
        if (value === 'interface' || value === 'interfaces' || value === 'port' || value === 'ports') return 'interfaces';
        return '';
    }

    function headerTextForCell(cell, context) {
        if (!cell || typeof cell.cellIndex !== 'number') return '';
        var table = cell.closest ? cell.closest('table') : null;
        if (!table) return '';
        var cached = context && context.headersByTable.get(table);
        if (cached) return cached[cell.cellIndex] || '';
        var rows = table.querySelectorAll('thead tr');
        if (!rows.length) return '';
        var headerRow = rows[rows.length - 1];
        var headers = [];
        if (headerRow.cells) {
            for (var i = 0; i < headerRow.cells.length; i++) {
                headers[i] = headerRow.cells[i].textContent || '';
            }
        }
        if (context) context.headersByTable.set(table, headers);
        return headers[cell.cellIndex] || '';
    }

    function namespaceForElement(el, context) {
        if (!el) return '';
        var owner = context && !context.hasExplicitNamespaces
            ? null
            : (el.closest ? el.closest('[data-p2p-namespace]') : null);
        var explicit = normalizeNamespace(owner && owner.getAttribute('data-p2p-namespace'));
        if (explicit) return explicit;
        var tag = String(el.tagName || '').toLowerCase();
        var cell = (tag === 'td' || tag === 'th') ? el : (el.closest ? el.closest('td,th') : null);
        var hint = [
            el.id || '', el.className || '',
            cell ? (cell.id || '') : '', cell ? (cell.className || '') : '',
            headerTextForCell(cell, context)
        ].join(' ').toLowerCase();
        if (/(^|[^a-z])(port|ports|interface|interfaces|ifname|iface)([^a-z]|$)/.test(hint)) return 'interfaces';
        if (/(^|[^a-z])(device|devices|switch|switches|host|hostname|neighbor|node|peer)([^a-z]|$)/.test(hint)) return 'devices';
        return '';
    }

    function aliasForElement(el, canonical, context) {
        var key = String(canonical || '').toLowerCase();
        // Most cells in analysis tables are metrics, timestamps or status text. Do
        // not perform DOM/header discovery unless the text can actually be aliased.
        var hasDevice = Object.prototype.hasOwnProperty.call(deviceMap, key);
        var hasInterface = Object.prototype.hasOwnProperty.call(interfaceMap, key);
        if (!hasDevice && !hasInterface) return '';
        var namespace = namespaceForElement(el, context);
        if (namespace === 'devices') return deviceMap[key] || '';
        if (namespace === 'interfaces') return interfaceMap[key] || '';
        return fallbackMap[key] || '';
    }

    function restoreAppliedElement(el) {
        if (!el || el.getAttribute('data-p2p-applied') !== 'true') return;
        el.textContent = el.getAttribute('data-p2p-orig');
        el.removeAttribute('data-p2p-applied');
        restoreTitle(el);
        if (el.getAttribute('data-p2p-orig-auto') === 'true') {
            el.removeAttribute('data-p2p-orig');
            el.removeAttribute('data-p2p-orig-auto');
        }
        if (el.getAttribute('data-p2p-csv-auto') === 'true') {
            el.removeAttribute('data-csv-value');
            el.removeAttribute('data-p2p-csv-auto');
        }
    }

    function restoreAllApplied() {
        if (observer) observer.disconnect();
        var applied = document.querySelectorAll('[data-p2p-applied="true"]');
        for (var i = 0; i < applied.length; i++) restoreAppliedElement(applied[i]);
    }

    function apply() {
        if (!loaded) return;
        if (observer) observer.disconnect();      // avoid reacting to our own edits
        if (!on) {
            restoreAllApplied();
            connectObserver();
            return;
        }
        var context = {
            headersByTable: new WeakMap(),
            hasExplicitNamespaces: !!document.querySelector('[data-p2p-namespace]')
        };
        var cells = leafCells();
        for (var i = 0; i < cells.length; i++) {
            var el = cells[i];
            if (el.getAttribute('data-p2p-applied') === 'true') continue;
            var explicitKey = (el.getAttribute('data-p2p-key') || '').trim();
            var original = el.hasAttribute('data-p2p-orig')
                ? el.getAttribute('data-p2p-orig')
                : el.textContent;
            var t = (explicitKey || original || '').trim();
            var alias = t ? aliasForElement(el, t, context) : '';    // case-insensitive, namespace-aware lookup
            if (alias) {
                if (!el.hasAttribute('data-p2p-orig')) {
                    el.setAttribute('data-p2p-orig', original);
                    el.setAttribute('data-p2p-orig-auto', 'true');
                }
                if (!el.hasAttribute('data-csv-value')) {
                    el.setAttribute('data-csv-value', original);
                    el.setAttribute('data-p2p-csv-auto', 'true');
                }
                el.textContent = alias;
                el.setAttribute('data-p2p-applied', 'true');
                saveTitle(el, original);
            }
        }
        connectObserver();
    }

    function scheduleApply() {
        if (pending) return;
        pending = true;
        setTimeout(function () { pending = false; apply(); }, 150);
    }

    function connectObserver() {
        if (!observer) observer = new MutationObserver(scheduleApply);
        observer.observe(document.body, { childList: true, subtree: true });
    }

    function setOn(v) {
        on = !!v;
        try { localStorage.setItem(KEY, on ? 'true' : 'false'); } catch (e) {}
        updateBtn();
        apply();
    }

    function reloadAliases() {
        restoreAllApplied();
        loaded = false;
        loadAliases(apply);
    }

    function updateBtn() {
        var b = document.getElementById('p2pAliasToggle');
        if (!b) return;
        b.textContent = on ? '\u21C4 P2P: On' : '\u21C4 P2P: Off';
        b.style.borderColor = on ? '#76b900' : '#555';
        b.style.color = on ? '#cfe9a0' : '#d4d4d4';
        b.setAttribute('aria-pressed', on ? 'true' : 'false');
        b.setAttribute('aria-label', on
            ? 'P2P and field aliases are on; show canonical names'
            : 'P2P and field aliases are off; show aliases');
    }

    function mountToggle() {
        if (document.getElementById('p2pAliasToggle')) return;
        if (!document.getElementById('p2pAliasFocusStyle')) {
            var focusStyle = document.createElement('style');
            focusStyle.id = 'p2pAliasFocusStyle';
            focusStyle.textContent = '#p2pAliasToggle:focus-visible{outline:2px solid #76b900;outline-offset:2px;}';
            document.head.appendChild(focusStyle);
        }
        var btn = document.createElement('button');
        btn.id = 'p2pAliasToggle';
        btn.type = 'button';
        btn.title = 'Toggle device/interface names between real and P2P/field labels';
        btn.setAttribute('aria-pressed', on ? 'true' : 'false');
        btn.style.cssText = 'display:inline-flex; align-items:center; gap:6px; height:34px; ' +
            'padding:0 12px; background:#3c3c3c; color:#d4d4d4; border:1px solid #555; ' +
            'border-radius:4px; font-size:13px; cursor:pointer; white-space:nowrap;';
        btn.onclick = function () { setOn(!on); };
        var slot = document.querySelector('.page-header .action-buttons') ||
                   document.querySelector('.action-buttons');
        if (slot) {
            // Place the toggle right AFTER the device search box (nicer than far-left).
            var search = slot.querySelector('.device-search-container, .device-search');
            if (search && search.parentNode === slot) {
                search.insertAdjacentElement('afterend', btn);
            } else {
                slot.insertBefore(btn, slot.firstChild);
            }
        } else {
            btn.style.position = 'fixed';
            btn.style.top = '10px';
            btn.style.right = '14px';
            btn.style.zIndex = '9999';
            document.body.appendChild(btn);
        }
        updateBtn();
    }

    // Live sync across tabs/pages sharing the same browser.
    window.addEventListener('storage', function (e) {
        if (e.key === KEY) { on = (e.newValue !== 'false'); updateBtn(); apply(); }
        else if (e.key === 'lldpq_aliases_revision') reloadAliases();
    });
    window.addEventListener('lldpq-aliases-updated', reloadAliases);
    try {
        var aliasChannel = new BroadcastChannel('lldpq-aliases');
        aliasChannel.onmessage = function (e) {
            if (e && e.data && e.data.type === 'updated') reloadAliases();
        };
    } catch (e) { /* BroadcastChannel is optional; storage events remain available. */ }

    // Stable public hook for CSV/table exporters. It deliberately returns canonical
    // text without toggling the visible page or the persisted user preference.
    window.LLDPqP2P = {
        canonicalText: canonicalText,
        isEnabled: function () { return on; },
        apply: apply,
        reload: reloadAliases
    };

    function init() {
        mountToggle();
        loadAliases(apply);
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
