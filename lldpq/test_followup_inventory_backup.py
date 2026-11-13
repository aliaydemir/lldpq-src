"""Setup -> Backup & Restore on a deployment whose inventory has no devices.

The Docker image ships an inventory with an empty device map.  The export loop
in html/setup-api.sh validates every file the way restore does, restore rejects
an inventory without devices, and the loop then dropped the whole bundle: a new
deployment could not export its other settings until a device was added.

The export now leaves that one file out and says so in its response.  It does
not put an empty inventory into a bundle: restore, in this release and in
4.2.x, rejects a bundle that carries one, and that rule stays.  A bundle
without devices.yaml is a shape that already existed (a missing file is
skipped), and restoring it leaves the target's inventory as it is.

Setup's real export and restore handlers run here against isolated files,
through the fixture of test_bmc_api.py.
"""

import base64
import io
from pathlib import Path
import sys
import tarfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import backup_import  # noqa: E402
import test_bmc_api as backup_fixture  # noqa: E402


REPO = Path(__file__).resolve().parent.parent

# The shape the image ships: comments, defaults and an empty device map.
EMPTY = ('# LLDPq device inventory\n'
         'defaults:\n  username: cumulus\n'
         '# No devices yet.\n'
         'devices: {}\n')
POPULATED = 'defaults:\n  username: cumulus\ndevices:\n  192.0.2.10: leaf01 @leaf\n'
TRACKING = 'version: 1\ndefault_state: commissioning\nswitches: {}\n'
OTHER_TRACKING = 'version: 1\ndefault_state: production\nswitches: {}\n'
LEFT_OUT = 'devices.yaml was left out of the bundle: it has no devices.'


def members(exported):
    with tarfile.open(fileobj=io.BytesIO(base64.b64decode(exported['data'])),
                      mode='r:gz') as archive:
        return {member.name: archive.extractfile(member).read() for member in archive}


def bundle(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
        for name, content in files.items():
            backup_import.add_regular_tar_member(archive, name, content.encode())
    return base64.b64encode(buffer.getvalue()).decode()


class EmptyInventoryBackupTest(backup_fixture.BMCSetupBackupRoundTripTest):
    # The fixture's own test runs in its own file.
    test_setup_export_then_restore_preserves_bmc_mappings_and_managed_link = None

    def setUp(self):
        super().setUp()
        # An inventory with devices is checked with the installation's parser.
        for name in ('parse_devices.py', 'addressing.py'):
            (self.application / name).symlink_to(REPO / 'lldpq' / name)
        self.inventory = self.application / 'devices.yaml'
        self.tracking = self.application / 'tracking.yaml'

    def export(self):
        return self.call_setup('backup-export', {'include_key': False})

    def test_export_leaves_an_empty_inventory_out_and_says_so(self):
        self.inventory.write_text(EMPTY)
        self.tracking.write_text(TRACKING)
        exported = self.export()
        self.assertTrue(exported['success'], exported)
        self.assertEqual(exported['files'], ['tracking.yaml'])
        self.assertEqual(exported['warnings'], [LEFT_OUT])
        self.assertEqual(members(exported), {'tracking.yaml': TRACKING.encode()})
        # The export reads; the live inventory is as it was.
        self.assertEqual(self.inventory.read_text(), EMPTY)

    def test_restoring_that_bundle_leaves_the_targets_inventory_untouched(self):
        self.inventory.write_text(EMPTY)
        self.tracking.write_text(TRACKING)
        exported = self.export()
        self.assertTrue(exported['success'], exported)
        # The target may be the same deployment later on, or another one; in the
        # image its inventory is a link into the config volume.
        for name, text, linked in (('populated', POPULATED, False),
                                   ('populated, linked', POPULATED, True),
                                   ('still empty', EMPTY, False)):
            with self.subTest(target=name):
                self.inventory.unlink()
                target = self.inventory
                if linked:
                    target = self.application / 'config/devices.yaml'
                    target.parent.mkdir(exist_ok=True)
                    self.inventory.symlink_to(target)
                target.write_text(text)
                self.tracking.write_text(OTHER_TRACKING)
                restored = self.call_setup('backup-import', {'data': exported['data']})
                self.assertTrue(restored['success'], restored)
                self.assertEqual(restored['restored'], ['tracking.yaml'])
                self.assertEqual(self.tracking.read_text(), TRACKING)
                self.assertEqual(target.read_text(), text)
                self.assertEqual(self.inventory.is_symlink(), linked)
                self.assertFalse((self.home / '.lldpq-state/.backup-import-recovery').exists())

    def test_inventory_with_devices_is_exported_and_restored_as_before(self):
        self.inventory.write_text(POPULATED)
        self.tracking.write_text(TRACKING)
        exported = self.export()
        self.assertTrue(exported['success'], exported)
        self.assertEqual(exported['files'], ['devices.yaml', 'tracking.yaml'])
        self.assertEqual(exported['warnings'], [])
        self.assertEqual(members(exported)['devices.yaml'], POPULATED.encode())
        self.inventory.write_text(EMPTY)
        restored = self.call_setup('backup-import', {'data': exported['data']})
        self.assertTrue(restored['success'], restored)
        self.assertEqual(restored['restored'], ['devices.yaml', 'tracking.yaml'])
        self.assertEqual(self.inventory.read_text(), POPULATED)

    def test_inventories_that_are_not_an_empty_map_still_refuse_the_export(self):
        # Only a mapping whose devices mapping is empty is "no devices yet";
        # anything else is the drift the export has always refused to bundle.
        self.tracking.write_text(TRACKING)
        for name, text in (('devices is null', 'defaults:\n  username: cumulus\ndevices:\n'),
                           ('devices is an empty list', 'devices: []\n'),
                           ('no devices key', 'defaults:\n  username: cumulus\n'),
                           ('empty file', ''),
                           ('not YAML', 'devices: {\n'),
                           ('devices key given twice', 'devices:\n  192.0.2.10: leaf01\ndevices: {}\n'),
                           ('invalid device', 'devices:\n  192.0.2.10: {role: leaf}\n')):
            with self.subTest(inventory=name):
                self.inventory.write_text(text)
                exported = self.export()
                self.assertFalse(exported['success'], exported)
                self.assertTrue(exported['error'].startswith('Bundle failed: '), exported)
                self.assertIn('devices.yaml', exported['error'])
                self.assertNotIn('data', exported)

    def test_nothing_else_to_export_says_why(self):
        self.inventory.write_text(EMPTY)
        exported = self.export()
        self.assertEqual(exported, {
            'success': False, 'error': 'No config files found to back up. ' + LEFT_OUT})

    def test_bundle_carrying_an_empty_inventory_is_still_refused_on_restore(self):
        # The rule the export works around stays: this is what 4.2.x does with
        # such a bundle too, so the export must never produce one.
        self.inventory.write_text(POPULATED)
        self.tracking.write_text(OTHER_TRACKING)
        restored = self.call_setup('backup-import', {
            'data': bundle({'devices.yaml': EMPTY, 'tracking.yaml': TRACKING})})
        self.assertFalse(restored['success'], restored)
        self.assertIn("devices.yaml must contain a non-empty 'devices' mapping", restored['error'])
        self.assertEqual(self.inventory.read_text(), POPULATED)
        self.assertEqual(self.tracking.read_text(), OTHER_TRACKING)


if __name__ == '__main__':
    unittest.main()
