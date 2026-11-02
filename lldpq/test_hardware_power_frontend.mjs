import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import vm from 'node:vm';

// Render the real page from the reported PSU failure and a virtual switch.
// Only local temporary files are used; no device or notification access.
const rendered = spawnSync('python3', ['-c', `
import contextlib, io, os, sys, tempfile
from pathlib import Path
from unittest import mock
sys.path.insert(0, ${JSON.stringify(new URL('.', import.meta.url).pathname)})
import generate_hardware_html as hardware
from test_hardware_power_status import SENSORS, REPORTED, section
from test_hardware_fan_status import POWER_OK, REPORTED_FANS, PHANTOM_RPM, fan_section
with tempfile.TemporaryDirectory() as tmp:
    os.chdir(tmp)
    raw = Path('monitor-results/hardware-data')
    raw.mkdir(parents=True)
    (raw / 'i04csw4_hardware.txt').write_text(SENSORS + section(REPORTED))
    (raw / 'virtual_hardware.txt').write_text(SENSORS.replace('PLATFORM_VIRT: none', 'PLATFORM_VIRT: kvm'))
    (raw / 'inetsw2_hardware.txt').write_text(SENSORS + POWER_OK + fan_section(REPORTED_FANS) + PHANTOM_RPM)
    with mock.patch.object(hardware, 'read_asset_snapshot', return_value=({}, 0, False)), \\
         mock.patch.object(hardware, 'read_collection_outcomes', return_value=None), \\
         mock.patch.object(hardware, 'is_current_collection', return_value=True), \\
         contextlib.redirect_stdout(io.StringIO()):
        hardware.generate_hardware_html()
    print(Path('monitor-results/hardware-analysis.html').read_text())
`], { encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
assert.equal(rendered.status, 0, rendered.stderr);
const page = rendered.stdout;
const details = JSON.parse(page.match(/window\.HW_DETAILS = (.*?);<\/script>/)[1]);
const start = page.indexOf('function hwEsc(');
const end = page.indexOf('function toggleHwDetails(', start);
assert.ok(start >= 0 && end > start);
const context = {};
vm.runInNewContext(page.slice(start, end) + '\nglobalThis.renderPanel = buildDetailPanel;', context);

test('hardware details show failed supplies and redundancy alongside 95% efficiency', () => {
  const device = details.i04csw4;
  assert.equal(device.health, 'CRITICAL');
  assert.equal(device.psu_efficiency, 95);
  const panel = context.renderPanel(device);
  assert.match(panel, /Power Supplies &amp; Redundancy/);
  assert.match(panel, /PSU3: bad; PSU4: bad/);
  assert.match(panel, /2 good \/ 4 required/);
  for (const name of ['PSU1', 'PSU2', 'PSU3', 'PSU4', 'POWER', 'SYSTEM']) {
    assert.ok(panel.includes(`<span>${name}</span>`));
  }
  assert.match(panel, /colspan="10"/);
  assert.doesNotMatch(panel, /could not be fully verified/);
});

test('partial power coverage is visible while reported component text stays literal', () => {
  const device = structuredClone(details.i04csw4);
  device.power_status.complete = false;
  device.power_status.psus[0].name = 'PSU <1>';
  const panel = context.renderPanel(device);
  assert.match(panel, /Power status could not be fully verified/);
  assert.match(panel, /PSU &lt;1&gt;/);
});

test('virtual switches show power as not applicable instead of a collection problem', () => {
  const panel = context.renderPanel(details.virtual);
  assert.equal(details.virtual.health, 'EXCELLENT');
  assert.match(panel, /Not applicable on this virtualized platform/);
  assert.doesNotMatch(panel, /could not be fully verified/);
});

test('absent fan is visible as critical with no phantom RPM or duplicate healthy row', () => {
  const device = details.inetsw2;
  assert.equal(device.health, 'CRITICAL');
  assert.equal(device.fan_health.grade, 'CRITICAL');
  const panel = context.renderPanel(device);
  assert.match(panel, /<th>State<\/th>/);
  assert.match(panel, /FAN3\/1: absent/);
  assert.match(panel, /<td>FAN3\/1<\/td><td>absent<\/td><td>—<\/td>.*?g-critical">CRITICAL/);
  assert.doesNotMatch(panel, /Chassis Fan Drawer-3|10320 RPM|null RPM/);
});
