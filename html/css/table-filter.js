/* table-filter.js - Excel-style per-column header filters for lldpq tables.
 * Auto-attaches to any table containing th.sortable, plus table[data-filterable].
 * Hides rows only via the .tf-hidden class so it composes with page-level
 * filters that use row.style.display. No dependencies.
 */
(function () {
    'use strict';

    var MAX_LIST = 300;          // checkbox entries rendered without a search term
    var NON_DATA_RE = /(detail|details|empty-row|no-data)/i;

    var tableStates = new WeakMap();   // table -> { filters: Map<col, Set<string>> }
    var registry = {};                 // table key -> filters Map (survives re-render)
    var openPopup = null;              // { el, th, table, col }
    var tfSeq = 0;

    function tableKey(table) {
        if (table.id) return 'id:' + table.id;
        if (table.dataset.tfId) return 'tf:' + table.dataset.tfId;
        table.dataset.tfId = String(++tfSeq);
        return 'tf:' + table.dataset.tfId;
    }

    function getState(table) {
        var st = tableStates.get(table);
        if (!st) {
            var key = tableKey(table);
            st = { filters: registry[key] || new Map() };
            registry[key] = st.filters;
            tableStates.set(table, st);
        }
        return st;
    }

    function isDataRow(row, table) {
        if (!row.parentElement || row.parentElement.tagName !== 'TBODY') return false;
        if (NON_DATA_RE.test(row.className)) return false;
        var first = row.cells[0];
        if (first && first.colSpan > 1) {
            var headCells = headerRow(table);
            if (headCells && first.colSpan >= headCells.cells.length - 1) return false;
        }
        return true;
    }

    function headerRow(table) {
        var thead = table.tHead;
        if (!thead || !thead.rows.length) return null;
        return thead.rows[thead.rows.length - 1];
    }

    function cellValue(row, col) {
        var cell = row.cells[col];
        if (!cell) return '';
        var v = cell.dataset && cell.dataset.sort != null && cell.dataset.sort !== ''
            ? cell.dataset.sort : cell.textContent;
        return v.replace(/\s+/g, ' ').trim();
    }

    function dataRows(table) {
        var rows = [];
        var bodies = table.tBodies;
        for (var b = 0; b < bodies.length; b++) {
            var trs = bodies[b].rows;
            for (var i = 0; i < trs.length; i++) {
                if (isDataRow(trs[i], table)) rows.push(trs[i]);
            }
        }
        return rows;
    }

    function applyFilters(table) {
        var st = getState(table);
        var filters = st.filters;
        var bodies = table.tBodies;
        for (var b = 0; b < bodies.length; b++) {
            var trs = bodies[b].rows;
            var parentHidden = false;
            for (var i = 0; i < trs.length; i++) {
                var row = trs[i];
                if (!isDataRow(row, table)) {
                    // glue: non-data rows follow visibility of the preceding data row
                    row.classList.toggle('tf-hidden', parentHidden);
                    continue;
                }
                var hide = false;
                filters.forEach(function (set, col) {
                    if (hide || !set) return;
                    if (!set.has(cellValue(row, col))) hide = true;
                });
                row.classList.toggle('tf-hidden', hide);
                parentHidden = hide;
            }
        }
        updateButtons(table);
    }

    function updateButtons(table) {
        var st = getState(table);
        var head = headerRow(table);
        if (!head) return;
        for (var i = 0; i < head.cells.length; i++) {
            var btn = head.cells[i].querySelector('.tf-btn');
            if (btn) {
                btn.classList.toggle('tf-active', st.filters.has(i));
            }
        }
    }

    var FUNNEL_SVG = '<svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true">' +
        '<path fill="currentColor" d="M1.5 2h13a.5.5 0 0 1 .39.812L10 9.05V13.5a.5.5 0 0 1-.276.447' +
        'l-3 1.5A.5.5 0 0 1 6 15V9.05L1.11 2.812A.5.5 0 0 1 1.5 2z"/></svg>';

    function injectButtons(table) {
        var head = headerRow(table);
        if (!head) return;
        for (var i = 0; i < head.cells.length; i++) {
            var th = head.cells[i];
            if (th.querySelector('.tf-btn')) continue;
            if (!th.textContent.trim()) continue;   // skip empty/action columns
            var btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'tf-btn';
            btn.setAttribute('aria-label', 'Filter column');
            btn.title = 'Filter';
            btn.innerHTML = FUNNEL_SVG;
            th.classList.add('tf-th');
            th.appendChild(btn);
        }
        updateButtons(table);
    }

    /* ---------- popup ---------- */

    function closePopup() {
        if (openPopup) {
            openPopup.el.remove();
            openPopup = null;
        }
    }

    function collectValues(table, col) {
        var rows = dataRows(table);
        var seen = new Set();
        for (var i = 0; i < rows.length; i++) seen.add(cellValue(rows[i], col));
        var values = Array.from(seen);
        values.sort(function (a, b) {
            if (a === '') return -1;
            if (b === '') return 1;
            return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
        });
        return values;
    }

    function openFilterPopup(th, table) {
        var col = th.cellIndex;
        if (openPopup && openPopup.th === th) { closePopup(); return; }
        closePopup();

        var st = getState(table);
        var active = st.filters.get(col) || null;   // null => no filter (all)
        var values = collectValues(table, col);

        var popup = document.createElement('div');
        popup.className = 'tf-popup';
        popup.innerHTML =
            '<input type="text" class="tf-search" placeholder="Search...">' +
            '<div class="tf-actions">' +
            '<a href="#" class="tf-select-all">Select all</a>' +
            '<a href="#" class="tf-clear">Clear</a>' +
            '</div>' +
            '<div class="tf-list"></div>';
        document.body.appendChild(popup);

        var searchEl = popup.querySelector('.tf-search');
        var listEl = popup.querySelector('.tf-list');

        function renderList() {
            var term = searchEl.value.trim().toLowerCase();
            var shown = term
                ? values.filter(function (v) { return v.toLowerCase().indexOf(term) !== -1; })
                : values;
            var capped = false;
            if (shown.length > MAX_LIST) { shown = shown.slice(0, MAX_LIST); capped = true; }
            var html = '';
            if (!values.length) {
                html = '<div class="tf-note">(no values)</div>';
            } else {
                if (capped) {
                    html += '<div class="tf-note">' + values.length +
                        ' values — type to narrow down</div>';
                }
                for (var i = 0; i < shown.length; i++) {
                    var v = shown[i];
                    var checked = active === null || active.has(v);
                    html += '<label class="tf-item"><input type="checkbox" value="' +
                        v.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;') +
                        '"' + (checked ? ' checked' : '') + '> <span>' +
                        (v === '' ? '(Blanks)'
                            : v.replace(/&/g, '&amp;').replace(/</g, '&lt;')) +
                        '</span></label>';
                }
            }
            listEl.innerHTML = html;
        }

        function applyFromList() {
            var boxes = listEl.querySelectorAll('input[type=checkbox]');
            var term = searchEl.value.trim();
            var next = active === null ? new Set(values) : new Set(active);
            boxes.forEach(function (cb) {
                if (cb.checked) next.add(cb.value); else next.delete(cb.value);
            });
            // no-op guard: everything selected and no search restriction => remove filter
            if (!term && next.size >= values.length) {
                st.filters.delete(col);
                active = null;
            } else {
                st.filters.set(col, next);
                active = next;
            }
            applyFilters(table);
        }

        searchEl.addEventListener('input', renderList);
        listEl.addEventListener('change', applyFromList);
        popup.querySelector('.tf-select-all').addEventListener('click', function (e) {
            e.preventDefault();
            st.filters.delete(col);
            active = null;
            applyFilters(table);
            renderList();
        });
        popup.querySelector('.tf-clear').addEventListener('click', function (e) {
            e.preventDefault();
            st.filters.set(col, new Set());
            active = st.filters.get(col);
            applyFilters(table);
            renderList();
        });
        popup.addEventListener('click', function (e) { e.stopPropagation(); });

        renderList();

        // position under the header cell, clamped to viewport
        var rect = th.getBoundingClientRect();
        popup.style.top = Math.min(rect.bottom + 2, window.innerHeight - 40) + 'px';
        var left = Math.max(4, Math.min(rect.left, window.innerWidth - popup.offsetWidth - 8));
        popup.style.left = left + 'px';

        openPopup = { el: popup, th: th, table: table, col: col };
        searchEl.focus();
    }

    /* ---------- attach / observe ---------- */

    function attach(table) {
        if (!table || table.dataset.tfAttached === '1') { if (table) injectButtons(table); return; }
        table.dataset.tfAttached = '1';
        getState(table);
        injectButtons(table);
        applyFilters(table);

        // survive tbody/thead re-renders on dynamic pages
        var observer = new MutationObserver(function (muts) {
            for (var i = 0; i < muts.length; i++) {
                if (muts[i].addedNodes.length || muts[i].removedNodes.length) {
                    injectButtons(table);
                    applyFilters(table);
                    return;
                }
            }
        });
        observer.observe(table, { childList: true, subtree: true });
    }

    function scan(root) {
        var tables = (root || document).querySelectorAll('table');
        tables.forEach(function (t) {
            if (t.dataset.tfAttached === '1') return;
            if (t.hasAttribute('data-filterable') || t.querySelector('th.sortable')) attach(t);
        });
    }

    document.addEventListener('click', function (e) {
        var btn = e.target.closest ? e.target.closest('.tf-btn') : null;
        if (btn) {
            e.preventDefault();
            e.stopPropagation();
            var th = btn.closest('th');
            var table = btn.closest('table');
            if (th && table) openFilterPopup(th, table);
            return;
        }
        if (openPopup && !openPopup.el.contains(e.target)) closePopup();
    }, true);

    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') closePopup();
    });

    window.TableFilter = {
        attach: attach,
        refresh: function (table) {
            if (table) { injectButtons(table); applyFilters(table); }
            else scan();
        },
        clearAll: function (table) {
            var st = getState(table);
            st.filters.clear();
            applyFilters(table);
        },
        isHidden: function (row) { return row.classList.contains('tf-hidden'); }
    };

    function init() {
        scan();
        // late-rendered tables (client-side pages building tables after load)
        var bodyObserver = new MutationObserver(function () { scan(); });
        bodyObserver.observe(document.body, { childList: true, subtree: true });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
