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
 *     enP22p3s0f0np0 -> M1). The real name is kept in a tooltip + data attribute so
 *     toggling OFF restores it. Element structure (links, badges, hrefs) is preserved
 *     because only the text node value changes.
 *   - Re-applies after client-side table rebuilds (MutationObserver, debounced).
 *   - State lives in localStorage ('lldpq_port_alias_on') so it is shared across every
 *     page and persists; a 'storage' listener keeps other open tabs in sync live.
 *
 * Display-only: never touches the underlying data, sorting, filtering or CSV export.
 */
(function () {
    'use strict';
    var KEY = 'lldpq_port_alias_on';
    var on = localStorage.getItem(KEY) !== 'false'; // default ON
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

    // Leaf elements inside tables (the element that actually holds the name text).
    function leafCells() {
        var out = [];
        var tds = document.querySelectorAll('table td, table th');
        for (var i = 0; i < tds.length; i++) {
            var td = tds[i];
            var kids = td.querySelectorAll('*');
            if (kids.length === 0) { out.push(td); continue; }
            for (var j = 0; j < kids.length; j++) {
                if (kids[j].children.length === 0) out.push(kids[j]);
            }
        }
        return out;
    }

    function apply() {
        if (!loaded) return;
        if (observer) observer.disconnect();      // avoid reacting to our own edits
        var cells = leafCells();
        for (var i = 0; i < cells.length; i++) {
            var el = cells[i];
            if (on) {
                if (el.hasAttribute('data-p2p-orig')) continue; // already aliased
                var t = (el.textContent || '').trim();
                var alias = t ? amap[t.toLowerCase()] : '';     // case-insensitive lookup
                if (alias) {
                    el.setAttribute('data-p2p-orig', el.textContent);
                    el.textContent = alias;
                    el.title = t;
                }
            } else if (el.hasAttribute('data-p2p-orig')) {
                el.textContent = el.getAttribute('data-p2p-orig');
                el.removeAttribute('data-p2p-orig');
                el.removeAttribute('title');
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
        localStorage.setItem(KEY, on ? 'true' : 'false');
        updateBtn();
        apply();
    }

    function updateBtn() {
        var b = document.getElementById('p2pAliasToggle');
        if (!b) return;
        b.textContent = on ? '\u21C4 P2P: On' : '\u21C4 P2P: Off';
        b.style.borderColor = on ? '#76b900' : '#555';
        b.style.color = on ? '#cfe9a0' : '#d4d4d4';
    }

    function mountToggle() {
        if (document.getElementById('p2pAliasToggle')) return;
        var btn = document.createElement('button');
        btn.id = 'p2pAliasToggle';
        btn.type = 'button';
        btn.title = 'Toggle device/interface names between real and P2P/field labels';
        btn.style.cssText = 'display:inline-flex; align-items:center; gap:6px; height:34px; ' +
            'padding:0 12px; background:#3c3c3c; color:#d4d4d4; border:1px solid #555; ' +
            'border-radius:4px; font-size:13px; cursor:pointer; outline:none; white-space:nowrap;';
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

    function init() {
        mountToggle();
        loadAliases(apply);
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
