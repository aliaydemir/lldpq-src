import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const aiHtml = fs.readFileSync(new URL('../html/ai.html', import.meta.url), 'utf8');

class FakeElement {
  constructor(tagName) {
    this.tagName = tagName;
    this.children = [];
    this.className = '';
    this._textContent = '';
  }

  appendChild(child) {
    this.children.push(child);
    return child;
  }

  set textContent(value) {
    this._textContent = String(value);
    this.children = [];
  }

  get textContent() {
    return this._textContent + this.children.map(child => child.textContent).join('');
  }

  set innerHTML(_value) {
    throw new Error('structured evidence must never use innerHTML');
  }
}

function createRendererHarness() {
  const match = aiHtml.match(
    /function compactDisplay\([\s\S]*?(?=\n\/\/ One-click remediation buttons)/,
  );
  assert.ok(match, 'evidence and timeline renderer functions should be present');
  const context = {
    document: {
      createElement(tagName) { return new FakeElement(tagName); },
    },
  };
  vm.runInNewContext(
    `${match[0]}\nglobalThis.renderEvidence = renderEvidencePanel; globalThis.renderEvents = renderTimeline;`,
    context,
  );
  return context;
}

function createContextBudgetHarness() {
  const match = aiHtml.match(
    /const MAX_CHAT_MESSAGE_CHARS = 12000;[\s\S]*?(?=\nfunction sanitizeStoredChatMessage)/,
  );
  assert.ok(match, 'outbound context budget helpers should be present');
  const context = {};
  vm.runInNewContext(
    `${match[0]}
globalThis.truncate = truncateContextText;
globalThis.buildHistory = buildHistoryPayload;
globalThis.attachLogs = buildAttachedLogContext;`,
    context,
  );
  return context;
}

test('evidence renderer keeps backend-controlled values inert', () => {
  const renderer = createRendererHarness();
  const attack = '<img src=x onerror="globalThis.pwned=true">';

  const panel = renderer.renderEvidence([
    {
      kind: 'source',
      label: attack,
      source: 'bgp_history.json',
      observed_at: 1_700_000_000,
      age_seconds: 42,
      freshness: 'current',
      coverage: '10/10',
      detail: '<script>alert(1)</script>',
    },
  ], { level: 'high', reason: '<svg onload=alert(1)>', complete: true });

  assert.equal(panel.tagName, 'details');
  assert.equal(panel.className, 'tool-trace');
  assert.match(panel.textContent, /Evidence — 1 record · HIGH confidence/);
  assert.match(panel.textContent, /<img src=x onerror=/);
  assert.match(panel.textContent, /<script>alert\(1\)<\/script>/);
  assert.equal(renderer.pwned, undefined);
});

test('timeline renderer shows correlations, events, coverage, and truncation', () => {
  const renderer = createRendererHarness();
  const panel = renderer.renderEvents({
    window: '24h',
    truncated: true,
    events: [{
      ts: 1_700_000_000,
      category: 'bgp',
      severity: 'critical',
      device: 'leaf01',
      summary: 'session dropped <b>now</b>',
      source: 'bgp_history.json',
    }],
    correlations: [{
      start_ts: 1_700_000_000,
      devices: ['leaf01'],
      categories: ['link', 'bgp'],
      summary: 'Events coincide; causation is not proven.',
      confidence: 'medium',
    }],
    coverage: [{ source: 'BGP', status: 'current' }],
  });

  assert.match(panel.textContent, /Timeline — 1 event · 1 correlation · 24h · truncated/);
  assert.match(panel.textContent, /Events coincide; causation is not proven\./);
  assert.match(panel.textContent, /session dropped <b>now<\/b>/);
  assert.match(panel.textContent, /BGP: current/);
  assert.ok(panel.children[1].children.some(row => row.className.includes('fail')));
  assert.ok(panel.children[1].children.some(row => row.className.includes('warn')));
});

test('chat persistence and prompt chips include evidence and timeline fields', () => {
  assert.match(aiHtml, /const limits = \{ tools: 20, fixes: 10, followups: 8, consoles: 20, evidence: 40 \}/);
  assert.match(aiHtml, /MAX_STORED_CHAT_CHARS = 1500000/);
  assert.match(aiHtml, /timeline\.events\.slice\(0, 120\)/);
  assert.match(aiHtml, /confidence: data\.confidence/);
  assert.match(aiHtml, /timeline: data\.timeline/);
  assert.match(aiHtml, /chip: 'What changed \(1h\)'/);
  assert.match(aiHtml, /chip: 'Correlate events \(24h\)'/);
});

test('outbound history keeps newest complete turns within backend budgets', () => {
  const budget = createContextBudgetHarness();
  const history = [];
  for (let turn = 0; turn < 5; turn++) {
    history.push({
      role: 'user',
      content: `user-${turn}-head:` + 'u'.repeat(15_000) + `:user-${turn}-tail`,
    });
    history.push({
      role: 'assistant',
      content: `assistant-${turn}-head:` + 'a'.repeat(15_000) + `:assistant-${turn}-tail`,
    });
  }
  const originalLastLength = history.at(-1).content.length;
  const payload = budget.buildHistory(history);

  assert.equal(payload.length, 4, 'two newest user/assistant turns fit under 50k');
  assert.deepEqual(Array.from(payload, item => item.role), [
    'user', 'assistant', 'user', 'assistant',
  ]);
  assert.match(payload[0].content, /^user-3-head:/);
  assert.match(payload[0].content, /:user-3-tail$/);
  assert.match(payload.at(-1).content, /^assistant-4-head:/);
  assert.match(payload.at(-1).content, /:assistant-4-tail$/);
  assert.ok(payload.every(item => item.content.length <= 12_000));
  assert.ok(payload.every(item => item.content.includes('middle omitted to fit context budget')));
  assert.ok(payload.reduce((total, item) => total + item.content.length, 0) <= 50_000);
  assert.equal(history.at(-1).content.length, originalLastLength,
    'building the outbound copy must not mutate displayed/stored history');
});

test('attached logs obey line, character, and total message budgets', () => {
  const budget = createContextBudgetHarness();
  const message = 'Investigate leaf01';
  const logData = {
    totals: { critical: 2, error: 250, warning: 4 },
    messages: {
      leaf01: Array.from(
        { length: 250 },
        (_, index) => `event-${index}\n` + 'x'.repeat(1_000),
      ),
    },
  };
  const result = budget.attachLogs(message, logData);

  assert.equal(result.attached, true);
  assert.equal(result.omitted, true);
  assert.ok(result.finalMessage.length <= 12_000);
  assert.ok(result.finalMessage.endsWith(message));
  assert.match(result.finalMessage, /additional attached logs omitted to fit request budget/);
  const attachedPart = result.finalMessage.slice(0, -message.length);
  const deviceLines = attachedPart.split('\n').filter(line => line.startsWith('leaf01:'));
  assert.ok(deviceLines.length <= 200);
  assert.ok(deviceLines.every(line => line.length <= 600));
  assert.ok(deviceLines.every(line => !line.includes('\tevent') && !line.includes('\nevent')));

  const almostFull = 'q'.repeat(11_990);
  const noRoom = budget.attachLogs(almostFull, logData);
  assert.equal(noRoom.attached, false);
  assert.equal(noRoom.omitted, true);
  assert.equal(noRoom.finalMessage, almostFull);
  assert.ok(noRoom.finalMessage.length <= 12_000);
});

test('oversized user input is rejected before streaming state is claimed', async () => {
  const match = aiHtml.match(
    /async function sendMessage\(\) \{[\s\S]*?(?=\nfunction sendSuggestion)/,
  );
  assert.ok(match, 'sendMessage should be present');
  const input = {
    value: 'x'.repeat(12_001),
    focused: false,
    focus() { this.focused = true; },
  };
  const context = {
    input,
    document: { getElementById() { return input; } },
    toast: null,
  };
  vm.runInNewContext(
    `let isStreaming = false;
let isAnalysisRunning = false;
const MAX_CHAT_MESSAGE_CHARS = 12000;
function showToast(message, type) { globalThis.toast = { message, type }; }
${match[0]}
globalThis.invokeSend = sendMessage;
globalThis.streamingState = () => isStreaming;`,
    context,
  );

  await context.invokeSend();
  assert.equal(context.streamingState(), false);
  assert.equal(input.focused, true);
  assert.equal(context.toast.type, 'error');
  assert.match(context.toast.message, /limit is 12,000/);
  assert.match(aiHtml, /const historyPayload = buildHistoryPayload\(chatHistory\)/);
});
