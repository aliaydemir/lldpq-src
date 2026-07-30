import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import vm from 'node:vm';

// The PFC/ECN page is generated, not static: render it once through the real
// analyzer so the extracted JS is exactly what a browser executes.
const rendered = spawnSync('python3', ['-c', `
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(${JSON.stringify(new URL('.', import.meta.url).pathname)})))
import process_pfc_ecn_data as m
print(json.dumps({
    "html": m.render_report([]),
    "history_dir": m.HISTORY_DIR_NAME,
    "detail_samples": m.HISTORY_DETAIL_SAMPLES,
}))
`], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
assert.equal(rendered.status, 0, rendered.stderr);
const page = JSON.parse(rendered.stdout);

function createTrailHarness() {
  const match = page.html.match(
    /const PFC_DETAIL_SAMPLES = \d+;[\s\S]*?function pfcTrail\(samples\) \{[\s\S]*?\n\}/,
  );
  assert.ok(match, 'PFC_DETAIL_SAMPLES and pfcTrail should be present in the page');
  const context = { fetch: () => { throw new Error('pfcTrail must not fetch'); } };
  vm.runInNewContext(`${match[0]}\nglobalThis.trail = pfcTrail;`, context);
  return context;
}

test('shard fetch path matches the Python shard directory constant', () => {
  assert.ok(
    page.html.includes(`fetch('${page.history_dir}/'`),
    'detail panels must fetch from the directory the shard writer uses',
  );
  assert.ok(
    page.html.includes(`const PFC_DETAIL_SAMPLES = ${page.detail_samples};`),
    'panel sample bound must be injected from HISTORY_DETAIL_SAMPLES',
  );
  assert.ok(
    !page.html.includes('pfc-history-data'),
    'the fabric-wide inline history blob must stay removed',
  );
});

test('pfcTrail projects slim shard records into panel fields', () => {
  const { trail } = createTrailHarness();
  const [sample] = trail([{
    timestamp: 1753246265,
    sample_duration_seconds: 594.2,
    sample_status: 'analyzed',
    signal: 'ecn',
    deltas: { ecn_marked_frames: 7, rx_pause_frames: 1, tx_pause_frames: 2 },
    ecn_share_percent: 0.5,
    loss_delta: 3,
  }]);
  assert.equal(sample.t, new Date(1753246265 * 1000).toISOString());
  assert.equal(sample.status, 'analyzed');
  assert.equal(sample.signal, 'ecn');
  assert.equal(sample.ecn, 7);
  assert.equal(sample.rx, 1);
  assert.equal(sample.tx, 2);
  assert.equal(sample.loss, 3);
  assert.equal(sample.share, 0.5);
  assert.equal(sample.dur, 594.2);
});

test('pfcTrail keeps the legacy timestamp_iso fallback for pre-slim records', () => {
  const { trail } = createTrailHarness();
  const [sample] = trail([{
    timestamp_iso: '2026-07-23T04:51:05+00:00',
    sample_status: 'analyzed',
    signal: 'quiet',
  }]);
  assert.equal(sample.t, '2026-07-23T04:51:05+00:00');
  // Slim records drop None-valued delta keys entirely; missing fields must
  // surface as undefined (rendered as em dash), not throw.
  assert.equal(sample.ecn, undefined);
});

test('pfcTrail bounds the panel to the newest PFC_DETAIL_SAMPLES entries', () => {
  const context = createTrailHarness();
  const bound = Number(page.detail_samples);
  const records = Array.from({ length: bound + 10 }, (_, i) => ({
    timestamp: 1000 + i,
    sample_status: 'analyzed',
  }));
  const projected = context.trail(records);
  assert.equal(projected.length, bound);
  assert.equal(projected[projected.length - 1].t, new Date((1000 + bound + 9) * 1000).toISOString());
});

test('pfcTrail tolerates malformed shard content', () => {
  const { trail } = createTrailHarness();
  // Cross-realm arrays from the vm context fail deepEqual on prototype
  // identity; length checks assert the same behavior.
  assert.equal(trail(undefined).length, 0);
  assert.equal(trail({ not: 'a list' }).length, 0);
  assert.equal(trail([null, 'text', 42]).length, 0);
});
