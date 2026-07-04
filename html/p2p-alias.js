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
    var amap = {};                                   // lower(realName) -> alias (devices + interfaces)
    var loaded = false;
    var observer = null;
    var pending = false;

    function loadAliases(done) {
        fetch('/display-aliases.json', { cache: 'no-store' })
            .then(function (r) { return r.ok ? r.json() : {}; })
            .then(function (d) {
                d = (d && typeof d === 'object') ? d : {};
                var m = {};
                // Key by lower(realName) so matching is case-INSENSITIVE. This fully
                // decouples the alias from the server-side canonical casing
                // (device_names.py rewrites device cells to the topology.dot spelling):
                // the alias matches whether the cell shows MEL01-... or mel01-...
                ['interfaces', 'devices'].forEach(function (sec) {
                    var o = d[sec];
                    if (o && typeof o === 'object') {
                        Object.keys(o).forEach(function (k) { if (k && o[k]) m[String(k).toLowerCase()] = o[k]; });
                    }
                });
                amap = m; loaded = true; if (done) done();
            })
            .catch(function () { amap = {}; loaded = true; if (done) done(); });
    }

    // Explicitly tagged elements may live inside a compound table cell. Untagged
    // pages keep the legacy exact-leaf matching behaviour.
    function leafCells() {
        var out = [];
        var seen = [];
        var explicit = document.querySelectorAll('[data-p2p-key]');
        for (var e = 0; e < explicit.length; e++) {
            out.push(explicit[e]);
            seen.push(explicit[e]);
        }
        var tds = document.querySelectorAll('table td, table th');
        for (var i = 0; i < tds.length; i++) {
            var td = tds[i];
            var kids = td.querySelectorAll('*');
            if (kids.length === 0) {
                if (seen.indexOf(td) === -1) out.push(td);
                continue;
            }
            for (var j = 0; j < kids.length; j++) {
                if (kids[j].children.length === 0 && seen.indexOf(kids[j]) === -1) {
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

    function apply() {
        if (!loaded) return;
        if (observer) observer.disconnect();      // avoid reacting to our own edits
        var cells = leafCells();
        for (var i = 0; i < cells.length; i++) {
            var el = cells[i];
            if (on) {
                if (el.getAttribute('data-p2p-applied') === 'true') continue;
                var explicitKey = (el.getAttribute('data-p2p-key') || '').trim();
                var original = el.hasAttribute('data-p2p-orig')
                    ? el.getAttribute('data-p2p-orig')
                    : el.textContent;
                var t = (explicitKey || original || '').trim();
                var alias = t ? amap[t.toLowerCase()] : '';     // case-insensitive lookup
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
            } else if (el.getAttribute('data-p2p-applied') === 'true') {
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
    });

    // Stable public hook for CSV/table exporters. It deliberately returns canonical
    // text without toggling the visible page or the persisted user preference.
    window.LLDPqP2P = {
        canonicalText: canonicalText,
        isEnabled: function () { return on; },
        apply: apply
    };

    function init() {
        mountToggle();
        loadAliases(apply);
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
