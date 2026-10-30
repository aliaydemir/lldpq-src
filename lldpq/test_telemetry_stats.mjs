import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const html = fs.readFileSync(new URL('../html/telemetry.html', import.meta.url), 'utf8');
const source = html.slice(html.indexOf('        let statsRequestId ='),
                          html.indexOf('        async function updateTotalThroughputChart('));
function setup(queryPrometheus) {
    const cards = {};
    const context = vm.createContext({queryPrometheus, document: {querySelector(id) {
        return cards[id] ||= {textContent: 'old', innerHTML: 'old', title: ''};
    }}});
    vm.runInContext(source, context);
    return {context, cards};
}
const reading = value => ({success: true, data: {result: [{value: [123, value]}]}});

test('failed, empty and invalid measurements are unavailable, never zero or old', async () => {
    for (const response of [{success: false}, {success: true, data: {result: []}}, reading('NaN'), reading(null)]) {
        const {context, cards} = setup(async () => response);
        await context.updateStats('all', '15m');
        assert.equal(Object.keys(cards).length, 5);
        for (const card of Object.values(cards)) {
            assert.equal(card.textContent, '—');
            assert.equal(card.title, 'Measurement unavailable');
        }
    }
});
test('a real zero remains a healthy zero', async () => {
    const {context, cards} = setup(async () => reading('0'));
    await context.updateStats('all', '15m');
    assert.equal(cards['#statErrors .value'].innerHTML, '0.0<span class="unit">/s</span>');
    assert.equal(cards['#statErrors .value'].title, '');
});
test('an older refresh cannot overwrite a newer reading', async () => {
    const waiting = [];
    let calls = 0;
    const {context, cards} = setup(() => ++calls <= 5 ? new Promise(resolve => waiting.push(resolve)) : Promise.resolve(reading('7')));
    const old = context.updateStats('all', '15m');
    await context.updateStats('all', '15m');
    waiting.forEach(resolve => resolve({success: false}));
    await old;
    assert.equal(cards['#statErrors .value'].innerHTML, '7.0<span class="unit">/s</span>');
    assert.equal(cards['#statErrors .value'].title, '');
});
