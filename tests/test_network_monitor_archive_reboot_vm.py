"""Portable safety, export, and chain checks for archived history reboot."""
import copy
import hashlib
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import network_monitor_archive_reboot_vm as lab
from test_network_monitor_archive_vm import archive_bytes, archive_fixture


class ArchiveRebootHostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='archive-reboot-host-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()

    def test_mac_guard_precedes_output_source_and_vm_creation(self):
        output = self.root / 'absent'
        with patch.object(lab.sys, 'platform', 'darwin'), patch.object(lab, 'source_identity') as source, \
             patch.object(lab, 'DisposableVM') as vm:
            with self.assertRaisesRegex(RuntimeError, 'does not run on macOS'):
                lab.run(output)
        source.assert_not_called(); vm.assert_not_called(); self.assertFalse(output.exists())

    def test_unsupported_architecture_refused(self):
        with patch.object(lab.sys, 'platform', 'linux'), patch.object(lab.reboot.platform, 'machine', return_value='aarch64'), \
             patch.object(lab.reboot, 'preflight') as setup:
            with self.assertRaisesRegex(RuntimeError, 'x86-64'):
                lab.preflight()
        setup.assert_not_called()

    def test_source_archive_uploads_only_six_fixed_guest_files(self):
        for name in lab.EXTRA_GUEST_FILES:
            file = self.root / name; file.parent.mkdir(exist_ok=True, parents=True); file.write_text(name)
        (self.root / 'private-key').write_text('not uploaded')
        raw = lab.extra_source_archive(self.root)
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            self.assertEqual(archive.getnames(), list(lab.EXTRA_GUEST_FILES))
            for entry in archive.getmembers():
                self.assertTrue(entry.isfile()); self.assertEqual(entry.mode, 0o644)
                self.assertEqual(archive.extractfile(entry).read(), entry.name.encode())
        self.assertEqual(len(lab.GUEST_SOURCE_FILES), 18)
        self.assertEqual(len(lab.SOURCE_FILES), 20)

    def test_preboot_and_final_exports_require_exact_inventories(self):
        self.assertEqual(len(lab.PREBOOT_FILES), 13)
        self.assertEqual(len(lab.GUEST_FILES), 22)
        self.assertEqual(len(lab.PUBLIC_FILES) + 1, 26)
        for names in (lab.PREBOOT_FILES, lab.GUEST_FILES):
            files = {n: n.encode() for n in names}
            self.assertEqual(lab.extract_guest_export(archive_bytes(files), names), files)
            for extra in ('private-key', '../escape', names[0]):
                with self.subTest(extra=extra), self.assertRaisesRegex(RuntimeError, 'allowlist'):
                    lab.extract_guest_export(archive_bytes(files, extra=extra), names)
            missing = dict(files); missing.pop(names[0])
            with self.assertRaisesRegex(RuntimeError, 'allowlist'):
                lab.extract_guest_export(archive_bytes(missing), names)

    def test_export_rejects_links_oversize_and_private_markers(self):
        files = {n: b'fixture' for n in lab.GUEST_FILES}
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.DIRTYPE):
            with self.subTest(kind=kind), self.assertRaisesRegex(RuntimeError, 'Unsafe'):
                lab.extract_guest_export(archive_bytes(files, changed_type=('BEFORE.json', kind)))
        with patch.object(lab, 'MAX_FILE', 3):
            with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
                lab.extract_guest_export(archive_bytes(files))
        for value in (b'-----BEGIN PRIVATE KEY-----', b'/Users/private'):
            bad = {**files, 'BEFORE.json': value}
            with self.assertRaisesRegex(RuntimeError, 'private marker'):
                lab.extract_guest_export(archive_bytes(bad))

    def test_history_checks_chain_segment_bytes_and_descriptors(self):
        report, files = archive_fixture(); history = report['journal']
        self.assertEqual(lab.validate_history(history, files, 2), history['rows'])
        mutations = (
            lambda h: h.update(history_complete=False),
            lambda h: h['identity'].update(segment_rows=256),
            lambda h: h['rows'][128].update(previous_digest='0' * 64),
            lambda h: h['rows'][129].update(request_id=h['rows'][128]['request_id']),
            lambda h: h['rows'][200]['evaluation'].update(status='forged'),
            lambda h: h['archive_descriptors'][0].update(byte_count=0),
        )
        for index, change in enumerate(mutations):
            bad = copy.deepcopy(history); change(bad)
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                lab.validate_history(bad, files, 2)
        bad_files = {**files, lab.SEGMENT_FILES[0]: files[lab.SEGMENT_FILES[0]] + b' '}
        with self.assertRaisesRegex(RuntimeError, 'Archive bytes'):
            lab.validate_history(history, bad_files, 2)

    def test_host_held_preboot_bytes_cannot_be_replaced_by_new_hashes(self):
        held = {name: name.encode() for name in lab.PREBOOT_FILES}
        files = {name: name.encode() for name in lab.GUEST_FILES}
        files['archive-segment-000001.json'] = b'altered with new local manifest'
        with self.assertRaisesRegex(RuntimeError, 'host-held preboot'):
            lab.validate_guest(held, files, {}, {})
        with self.assertRaisesRegex(RuntimeError, 'host-held preboot'):
            lab.validate_guest({}, files, {}, {})

    def test_guest_errors_keep_diagnostics_bounded_and_transport_private(self):
        vm = lab.DisposableVM({}); vm.directory = self.root
        message = 'x' * 16000 + ' archive integrity failed ' + vm.token + ' ' + str(self.root)
        result = subprocess.CompletedProcess([], 1, stdout=b'', stderr=message.encode())
        with patch.object(vm, 'ssh', return_value=result):
            with self.assertRaises(RuntimeError) as caught:
                vm.guest('after')
        self.assertIn('archive integrity failed', str(caught.exception))
        self.assertNotIn(vm.token, str(caught.exception)); self.assertNotIn(str(self.root), str(caught.exception))
        self.assertLess(len(str(caught.exception)), 12500)

    def test_ci_upload_inventory_and_required_job_are_exact(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/ci.yml').read_text()
        job = workflow.split('\n  monitor_archive_reboot:\n')[1].split('\n  reviewer:\n')[0]
        raw = job.split('          path: |\n')[1].split('          if-no-files-found:')[0]
        names = [line.strip().removeprefix('work/monitor-archive-reboot/publish/') for line in raw.splitlines()]
        self.assertEqual(set(names), set(lab.PUBLIC_FILES) | {'MANIFEST.json'})
        self.assertEqual(len(names), len(lab.PUBLIC_FILES) + 1)
        self.assertIn('scripts/network_monitor_archive_reboot_vm.py', job)
        self.assertNotIn('continue-on-error', job)


if __name__ == '__main__':
    unittest.main()
