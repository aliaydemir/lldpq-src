import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('../html/css/table-filter.js', import.meta.url), 'utf8');
const decode = text => text.replace(/&quot;/g, '"').replace(/&lt;/g, '<').replace(/&amp;/g, '&');

// Exercise the public DOM events without adding a browser dependency to Node tests.
function harness(cells) {
    const listeners = () => ({
        events: new Map(),
        addEventListener(name, fn) { this.events.set(name, fn); },
        dispatch(name, fields = {}) { this.events.get(name)?.({ preventDefault() {}, stopPropagation() {}, ...fields }); }
    });
    const classes = () => {
        const names = new Set();
        return { add: value => names.add(value), contains: value => names.has(value),
            toggle(value, on) { if (on) names.add(value); else names.delete(value); } };
    };
    const tbody = { tagName:'TBODY', rows:[] };
    const rows = cells.map(cell => ({
        cells:[{ colSpan:1, textContent:cell.text ?? cell.value ?? '', dataset:{
            ...(cell.value === undefined ? {} : {filter:cell.value}),
            ...(cell.sort === undefined ? {} : {sort:cell.sort}),
            ...(cell.label === undefined ? {} : {filterLabel:cell.label})
        }}], parentElement:tbody, className:'', classList:classes()
    }));
    tbody.rows = rows;
    const table = { id:'test-table', dataset:{}, tBodies:[tbody] };
    const th = { cellIndex:0, querySelector:() => button, classList:classes(), textContent:'Switch',
        getBoundingClientRect:() => ({ bottom:30, left:10 }) };
    const button = { classList:classes(), closest: selector => selector === '.tf-btn' ? button : selector === 'th' ? th : table };
    table.tHead = { rows:[{ cells:[th] }] };
    let popup;
    const document = { ...listeners(), readyState:'loading',
        body:{ appendChild(node) { popup = node; } },
        createElement() {
            const search = { ...listeners(), value:'', focus() {} };
            const list = { ...listeners(), boxes:[],
                set innerHTML(value) {
                    this.html = value;
                    this.boxes = Array.from(value.matchAll(/<input type="checkbox" value="([^"]*)"( checked)?>/g), match =>
                        ({ value:decode(match[1]), checked:!!match[2] }));
                },
                get innerHTML() { return this.html; },
                querySelectorAll() { return this.boxes; }
            };
            const children = { '.tf-search':search, '.tf-list':list, '.tf-select-all':listeners(), '.tf-clear':listeners() };
            return { ...listeners(), style:{}, offsetWidth:240, innerHTML:'', querySelector:selector => children[selector],
                contains:() => false, remove() { popup = null; } };
        }
    };
    const window = { innerHeight:800, innerWidth:1200 };
    vm.runInNewContext(source, { document, window, MutationObserver:class { observe() {} } });
    window.TableFilter.attach(table);
    const open = () => { document.dispatch('click', { target:button }); return popup; };
    return { rows, table, api:window.TableFilter, open,
        close:() => document.dispatch('keydown', { key:'Escape' }),
        hidden:() => rows.map(row => window.TableFilter.isHidden(row)) };
}

test('legacy tables retain raw labels, natural ordering, blanks, and select-all behavior', () => {
    const h = harness([{value:'swp10'}, {value:'swp2'}, {text:''}, {value:'swp2'}, {sort:'7',text:'Seven'}]);
    const popup = h.open(), list = popup.querySelector('.tf-list');
    assert.deepEqual(list.boxes.map(box => box.value), ['', '7', 'swp2', 'swp10']);
    assert.match(list.innerHTML, /\(Blanks\)/);
    popup.querySelector('.tf-clear').dispatch('click');
    assert.deepEqual(h.hidden(), [true,true,true,true,true]);
    popup.querySelector('.tf-select-all').dispatch('click');
    assert.deepEqual(h.hidden(), [false,false,false,false,false]);
});

test('alias labels sort and search visibly while checkbox values retain canonical identities', () => {
    const h = harness([{value:'switch-a',label:'RACK 10'}, {value:'switch-z',label:'RACK 2'}]);
    const popup = h.open(), list = popup.querySelector('.tf-list'), search = popup.querySelector('.tf-search');
    assert.deepEqual(list.boxes.map(box => box.value), ['switch-z','switch-a']);
    assert.match(list.innerHTML, /RACK 2/);
    search.value = 'rack 10'; search.dispatch('input');
    assert.deepEqual(list.boxes.map(box => box.value), ['switch-a']);
    search.value = 'SWITCH-Z'; search.dispatch('input');
    assert.deepEqual(list.boxes.map(box => box.value), ['switch-z']);
});

test('a selected canonical row survives alias toggling and tbody replacement', () => {
    const h = harness([{value:'switch-a',label:'RACK A'}, {value:'switch-b',label:'RACK B'}]);
    let popup = h.open(), list = popup.querySelector('.tf-list');
    popup.querySelector('.tf-clear').dispatch('click');
    list.boxes.find(box => box.value === 'switch-a').checked = true;
    list.dispatch('change');
    assert.deepEqual(h.hidden(), [false,true]);
    h.rows.forEach(row => { row.cells[0].dataset.filterLabel = row.cells[0].dataset.filter; });
    h.api.refresh(h.table);
    assert.deepEqual(h.hidden(), [false,true]);
    h.close(); popup = h.open(); list = popup.querySelector('.tf-list');
    assert.deepEqual(list.boxes.map(box => [box.value,box.checked]), [['switch-a',true],['switch-b',false]]);
    assert.doesNotMatch(list.innerHTML, /RACK/);
    const replacement = harness([{value:'switch-a',label:'NEW A'}, {value:'switch-b',label:'NEW B'}]).rows;
    h.table.tBodies[0].rows = replacement;
    h.api.refresh(h.table);
    assert.deepEqual(replacement.map(row => h.api.isHidden(row)), [false,true]);
});

test('duplicate alias labels distinguish canonical names and remain independently selectable', () => {
    const h = harness([{value:'switch-a',label:'OOB'}, {value:'switch-b',label:'OOB'}, {value:'switch-b',label:'OOB'}]);
    const popup = h.open(), list = popup.querySelector('.tf-list');
    assert.equal(list.boxes.length, 2);
    assert.match(list.innerHTML, /OOB \(switch-a\)/);
    assert.match(list.innerHTML, /OOB \(switch-b\)/);
    list.boxes.find(box => box.value === 'switch-b').checked = false;
    list.dispatch('change');
    assert.deepEqual(h.hidden(), [false,true,true]);
});

test('untrusted labels stay escaped text and search does not select or discard hidden options', () => {
    const h = harness([{value:'switch-a',label:'<img src=x> & OOB'}, {value:'switch-b',label:'Other'}]);
    const popup = h.open(), list = popup.querySelector('.tf-list'), search = popup.querySelector('.tf-search');
    assert.doesNotMatch(list.innerHTML, /<img/);
    assert.match(list.innerHTML, /&lt;img src=x> &amp; OOB/);
    search.value = 'oob'; search.dispatch('input');
    assert.deepEqual(h.hidden(), [false,false]);
    list.boxes[0].checked = false; list.dispatch('change');
    assert.deepEqual(h.hidden(), [true,false]);
});
