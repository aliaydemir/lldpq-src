import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const consoleHtml = fs.readFileSync(
  new URL('../html/console.html', import.meta.url),
  'utf8',
);

function extractBroadcastSend() {
  const match = consoleHtml.match(
    /    function broadcastSend\(\) \{([\s\S]*?)\n    \}\n\n    function esc/,
  );
  assert.ok(match, 'broadcastSend function should be present');
  return `function broadcastSend() {${match[1]}\n}`;
}

function createHarness(inputValue) {
  const input = { value: inputValue };
  const sent = [[], []];
  const confirmations = [];
  const toasts = [];
  const context = {
    document: {
      getElementById(id) {
        assert.equal(id, 'bcastInput');
        return input;
      },
    },
    sessions: {
      first: {
        ws: {
          readyState: 1,
          send(payload) { sent[0].push(JSON.parse(payload)); },
        },
      },
      second: {
        ws: {
          readyState: 1,
          send(payload) { sent[1].push(JSON.parse(payload)); },
        },
      },
    },
    WebSocket: { OPEN: 1 },
    requestConfirmation(...args) { confirmations.push(args); },
    showToast(...args) { toasts.push(args); },
  };
  vm.runInNewContext(
    `${extractBroadcastSend()}\nglobalThis.runBroadcast = broadcastSend;`,
    context,
  );
  return { input, sent, confirmations, toasts, run: context.runBroadcast };
}

test('broadcast sends a command to every connected target without confirmation', () => {
  const harness = createHarness('show clock');

  harness.run();

  assert.deepEqual(harness.confirmations, []);
  assert.deepEqual(harness.sent, [
    [{ t: 'i', d: 'show clock\r' }],
    [{ t: 'i', d: 'show clock\r' }],
  ]);
  assert.equal(harness.input.value, '');
});

test('empty broadcast sends Enter to every connected target', () => {
  const harness = createHarness('');

  harness.run();

  assert.deepEqual(harness.confirmations, []);
  assert.deepEqual(harness.sent, [
    [{ t: 'i', d: '\r' }],
    [{ t: 'i', d: '\r' }],
  ]);
});
