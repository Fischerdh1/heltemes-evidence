"""Portable host-harness checks; actual guest boot evidence comes from Linux CI."""
import copy
import io
import json
from pathlib import Path
import socket
import subprocess
import tarfile
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from scripts import network_monitor_reboot_vm as lab

TOOLS = {name: '/tools/' + name for name in ('qemu-system-x86_64', 'qemu-img', 'cloud-localds', 'ssh', 'ssh-keygen', 'curl', 'git')}
BOOT_A = '11111111-1111-4111-8111-111111111111'
BOOT_B = '22222222-2222-4222-8222-222222222222'


def reboot_fixture():
    before = {'boot_id': BOOT_A, 'uptime_seconds': 50.0, 'qemu_pid': 123,
              'disk_identity': {'device': 1, 'inode': 2}, 'observed_elapsed_seconds': 20.0}
    after = {**copy.deepcopy(before), 'boot_id': BOOT_B, 'uptime_seconds': 3.0, 'observed_elapsed_seconds': 30.0}
    events = [{'event': 'RESET', 'data': {'guest': True, 'reason': 'guest-reset'}, 'observed_elapsed_seconds': 25.0}]
    return {'before': before, 'after': after, 'ssh_unavailable_observed': True, 'qmp_events': events,
            'reboot_requested_elapsed_seconds': 21.0, 'ready_elapsed_seconds': 30.0,
            'same_qemu_process': True, 'same_disk': True, 'reboot_command': 'systemctl reboot'}


def public_fixture():
    source = {'commit': 'a' * 40, 'tree': 'b' * 40, 'github': None,
              'source_sha256': {name: 'c' * 64 for name in lab.SOURCE_FILES}}
    hashes = {key: value for key, value in source['source_sha256'].items() if key != lab.SOURCE_FILES[-1]}
    original = {'identity': {'database_id': 'd' * 32}, 'rows': [{'sequence': i} for i in range(1, 6)]}
    automatic = {'identity': copy.deepcopy(original['identity']), 'rows': original['rows'] + [{'sequence': 6}]}
    final = {'identity': copy.deepcopy(original['identity']), 'rows': automatic['rows'] + [{'sequence': 7}, {'sequence': 8}]}
    before = {'boot': {'boot_id': BOOT_A}, 'source_sha256': hashes, 'journal': original, 'critical_incident_id': 'critical#1'}
    after = {'boot': {'boot_id': BOOT_B}, 'source_sha256': hashes, 'journal': final, 'critical_incident_id': 'critical#1',
             'automatic_start': {'journal': automatic, 'no_manual_service_start': True,
                                 'status': {'current_evaluation': {'status': 'unknown'}}},
             'final_status': {'current_evaluation': {'status': 'healthy'}}}
    files = {name: b'fixture' for name in lab.GUEST_FILES}
    files['BEFORE.json'], files['AFTER.json'] = json.dumps(before).encode(), json.dumps(after).encode()
    return source, files


def archive_bytes(files, *, extra=None, link=None):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w:gz') as archive:
        for name, value in files.items():
            entry = tarfile.TarInfo(name)
            if name == link:
                entry.type, entry.linkname = tarfile.SYMTYPE, '/private/other'
                archive.addfile(entry)
            else:
                entry.size = len(value)
                archive.addfile(entry, io.BytesIO(value))
        if extra:
            entry = tarfile.TarInfo(extra)
            archive.addfile(entry, io.BytesIO())
    return result.getvalue()


class VMHostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='reboot-host-tests-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()

    def test_mac_guard_refuses_before_source_or_output(self):
        output = self.directory / 'not-created'
        with patch.object(lab.sys, 'platform', 'darwin'), patch.object(lab, 'source_identity') as source:
            with self.assertRaisesRegex(RuntimeError, 'does not run on macOS'):
                lab.run(output)
        source.assert_not_called()
        self.assertFalse(output.exists())

    def test_preflight_requires_architecture_and_host_tools(self):
        with patch.object(lab.sys, 'platform', 'linux'), patch.object(lab.platform, 'machine', return_value='aarch64'):
            with self.assertRaises(RuntimeError):
                lab.preflight()
        with patch.object(lab.sys, 'platform', 'linux'), patch.object(lab.platform, 'machine', return_value='x86_64'), \
             patch.object(lab.shutil, 'which', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'Install QEMU'):
                lab.preflight()

    def test_cloud_seed_pins_host_key_disables_password_and_marks_only_guest(self):
        config = lab.cloud_configuration('a' * 32, 'ssh-ed25519 client', 'PRIVATE HOST FIXTURE', 'ssh-ed25519 host')
        self.assertFalse(config['ssh_pwauth'])
        self.assertTrue(config['disable_root'])
        self.assertTrue(config['users'][0]['lock_passwd'])
        self.assertEqual(config['ssh_genkeytypes'], [])
        self.assertEqual(config['ssh_keys']['ed25519_public'], 'ssh-ed25519 host')
        self.assertEqual(config['write_files'][0]['permissions'], '0600')
        marker = json.loads(config['write_files'][0]['content'])
        self.assertEqual(marker, {'format': 'heltemes-disposable-reboot-vm', 'version': 1, 'token': 'a' * 32})
        with self.assertRaises(RuntimeError):
            lab.cloud_configuration('../not-token', '', '', '')

    def test_source_package_excludes_host_program_and_unrelated_private_files(self):
        for name in lab.SOURCE_FILES:
            path = self.directory / name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_text(name)
        (self.directory / 'private-key').write_text('must not copy')
        data = lab.source_archive(self.directory)
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            self.assertEqual(archive.getnames(), list(lab.SOURCE_FILES[:-1]))
            self.assertEqual(len(archive.getmembers()), 12)
            for entry in archive.getmembers():
                self.assertTrue(entry.isfile())
                self.assertEqual(entry.mode, 0o644)
                self.assertEqual(archive.extractfile(entry).read().decode(), entry.name)

    def test_ssh_transport_uses_only_disposable_identity_and_pinned_key(self):
        vm = lab.DisposableVM(TOOLS)
        vm.directory, vm.port = self.directory, 12345
        with patch.object(vm, 'command', return_value=subprocess.CompletedProcess([], 0, b'{}', b'')) as command:
            vm.ssh('cat /proc/sys/kernel/random/boot_id')
        arguments = command.call_args.args[0]
        for value in ('/dev/null', 'BatchMode=yes', 'IdentityAgent=none', 'IdentitiesOnly=yes',
                      'StrictHostKeyChecking=yes', 'GlobalKnownHostsFile=/dev/null', 'lab@127.0.0.1'):
            self.assertIn(value, arguments)
        self.assertIn('UserKnownHostsFile=' + str(self.directory / 'known_hosts'), arguments)
        self.assertEqual(arguments[-1], 'cat /proc/sys/kernel/random/boot_id')

    def test_error_redaction_removes_private_directory_and_token(self):
        vm = lab.DisposableVM(TOOLS)
        vm.directory = self.directory
        value = vm.redact('failure ' + str(self.directory / 'client') + ' --token ' + vm.token)
        self.assertNotIn(str(self.directory), value)
        self.assertNotIn(vm.token, value)
        self.assertIn('<private-vm>', value)
        self.assertIn('<run-token>', value)

    def test_failed_image_checksum_stops_before_key_or_vm_creation(self):
        vm = lab.DisposableVM(TOOLS)
        def command(arguments, **kwargs):
            (self.directory / 'base.img').write_bytes(b'wrong image')
            return subprocess.CompletedProcess(arguments, 0, b'', b'')
        with patch.object(lab.tempfile, 'mkdtemp', return_value=str(self.directory)), patch.object(vm, 'command', side_effect=command) as call:
            with self.assertRaisesRegex(RuntimeError, 'pinned SHA-256'):
                vm.prepare()
        self.assertEqual(call.call_count, 1)
        self.assertIsNone(vm.process)
        self.assertFalse((self.directory / 'client').exists())

    def test_full_boot_requires_outage_reset_and_unchanged_vm_disk(self):
        evidence = reboot_fixture()
        lab.validate_reboot(evidence['before'], evidence['after'], True, evidence['qmp_events'], 21)
        mutations = [
            ('boot', lambda x: x['after'].update(boot_id=BOOT_A)),
            ('pid', lambda x: x['after'].update(qemu_pid=999)),
            ('disk', lambda x: x['after']['disk_identity'].update(inode=999)),
            ('outage', lambda x: x.update(ssh_unavailable_observed=False)),
            ('reset', lambda x: x.update(qmp_events=[])),
            ('host-reset', lambda x: x['qmp_events'][0]['data'].update(guest=False)),
            ('old-reset', lambda x: x['qmp_events'][0].update(observed_elapsed_seconds=10)),
            ('future-reset', lambda x: x['qmp_events'][0].update(observed_elapsed_seconds=40)),
            ('time', lambda x: x.update(reboot_requested_elapsed_seconds=50)),
        ]
        for name, change in mutations:
            with self.subTest(name=name):
                bad = copy.deepcopy(evidence); change(bad)
                with self.assertRaises(RuntimeError):
                    lab.validate_reboot(bad['before'], bad['after'], bad['ssh_unavailable_observed'],
                                        bad['qmp_events'], bad['reboot_requested_elapsed_seconds'])

    def test_failed_qmp_constructor_closes_its_socket(self):
        connection = Mock()
        connection.connect.side_effect = OSError('controlled connection failure')
        with patch.object(lab.socket, 'socket', return_value=connection):
            with self.assertRaises(OSError):
                lab.QMP(Path('/tmp/he-rb-owned/qmp.sock'), time.monotonic())
        connection.close.assert_called_once_with()

    def test_qmp_reads_complete_frames_and_records_reset_event(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close); self.addCleanup(right.close)
        qmp = lab.QMP.__new__(lab.QMP)
        qmp.connection, qmp.buffer, qmp.events, qmp.started = left, bytearray(), [], time.monotonic()
        event = {'event': 'RESET', 'data': {'guest': True}}
        right.sendall((json.dumps(event) + '\r\n' + json.dumps({'return': {}, 'id': 'next'}) + '\r\n').encode())
        self.assertEqual(qmp.read(1), event)
        self.assertEqual(qmp.read(1), {'return': {}, 'id': 'next'})
        self.assertEqual(qmp.events[0]['event'], 'RESET')
        self.assertGreaterEqual(qmp.events[0]['observed_elapsed_seconds'], 0)

    def test_qmp_disconnect_fails_instead_of_inventing_reset(self):
        left, right = socket.socketpair()
        self.addCleanup(left.close)
        qmp = lab.QMP.__new__(lab.QMP)
        qmp.connection, qmp.buffer, qmp.events, qmp.started = left, bytearray(), [], time.monotonic()
        right.close()
        with self.assertRaisesRegex(RuntimeError, 'disconnected'):
            qmp.read(1)
        self.assertEqual(qmp.events, [])

    def test_guest_export_accepts_only_fixed_ordinary_public_files(self):
        _, files = public_fixture()
        self.assertEqual(lab.extract_guest_export(archive_bytes(files)), files)
        for name, data in [
            ('extra', archive_bytes(files, extra='private-key')),
            ('traversal', archive_bytes(files, extra='../outside')),
            ('link', archive_bytes(files, link='BEFORE.json')),
            ('private', archive_bytes({**files, 'monitor.service': b'-----BEGIN PRIVATE KEY-----'})),
            ('personal-path', archive_bytes({**files, 'monitor.service': b'/Users/private/user'})),
        ]:
            with self.subTest(name=name):
                with self.assertRaises(RuntimeError):
                    lab.extract_guest_export(data)

    def test_guest_export_refuses_duplicate_names(self):
        _, files = public_fixture()
        with self.assertRaisesRegex(RuntimeError, 'inventory'):
            lab.extract_guest_export(archive_bytes(files, extra='BEFORE.json'))

    def test_preserved_history_is_compared_to_host_held_reference(self):
        source, files = public_fixture()
        reference = files['BEFORE.json']
        lab.validate_preserved_history(reference, files, source, reboot_fixture())
        changed = json.loads(reference); changed['journal']['rows'][0]['sequence'] = 100
        bad = {**files, 'BEFORE.json': json.dumps(changed).encode()}
        with self.assertRaisesRegex(RuntimeError, 'preboot reference changed'):
            lab.validate_preserved_history(reference, bad, source, reboot_fixture())

    def test_reopened_identity_prefix_source_and_status_must_match(self):
        source, files = public_fixture()
        mutations = [
            ('identity', lambda x: x['journal']['identity'].update(database_id='new')),
            ('prefix', lambda x: x['journal']['rows'][0].update(sequence=100)),
            ('duplicate', lambda x: x['journal']['rows'].append({'sequence': 9})),
            ('source', lambda x: x['source_sha256'].update({lab.SOURCE_FILES[0]: '0' * 64})),
            ('manual', lambda x: x['automatic_start'].update(no_manual_service_start=False)),
            ('false-healthy', lambda x: x['automatic_start']['status']['current_evaluation'].update(status='healthy')),
            ('incident', lambda x: x.update(critical_incident_id='new#1')),
            ('boot', lambda x: x['boot'].update(boot_id=BOOT_A)),
        ]
        for name, change in mutations:
            with self.subTest(name=name):
                after = json.loads(files['AFTER.json']); change(after)
                bad = {**files, 'AFTER.json': json.dumps(after).encode()}
                with self.assertRaises(RuntimeError):
                    lab.validate_preserved_history(files['BEFORE.json'], bad, source, reboot_fixture())

    def test_cleanup_stops_only_owned_process_before_removing_private_disk(self):
        vm = lab.DisposableVM(TOOLS)
        vm.directory = Path('/tmp/he-rb-owned-test')
        vm.process = Mock()
        vm.process.poll.side_effect = [None, 0]
        with patch.object(Path, 'exists', side_effect=[True, False]), \
             patch.object(Path, 'is_symlink', return_value=False), patch.object(lab.shutil, 'rmtree') as remove:
            result = vm.cleanup()
        vm.process.terminate.assert_called_once_with()
        vm.process.wait.assert_called_once_with(timeout=15)
        remove.assert_called_once_with(vm.directory)
        self.assertTrue(result['private_ssh_keys_seed_disk_removed'])

    def test_cleanup_refuses_unowned_runtime_path(self):
        vm = lab.DisposableVM(TOOLS)
        vm.directory = self.directory
        with self.assertRaisesRegex(RuntimeError, 'outside the owned'):
            vm.cleanup()
        self.assertTrue(self.directory.exists())

    def test_guest_stage_allowlist_rejects_arbitrary_command(self):
        vm = lab.DisposableVM(TOOLS)
        with patch.object(vm, 'ssh') as ssh:
            with self.assertRaisesRegex(RuntimeError, 'Unknown guest stage'):
                vm.guest('start; reboot host')
        ssh.assert_not_called()

    def test_boot_snapshot_parses_kernel_identity_and_keeps_pid_disk_reference(self):
        vm = lab.DisposableVM(TOOLS)
        vm.directory = self.directory
        (self.directory / 'disk.qcow2').write_bytes(b'fixture disk')
        vm.process = Mock(pid=123, poll=Mock(return_value=None))
        reply = subprocess.CompletedProcess([], 0, (BOOT_A + '\n12.34\n').encode(), b'')
        with patch.object(vm, 'ssh', return_value=reply):
            result = vm.boot_snapshot()
        self.assertEqual(result['boot_id'], BOOT_A)
        self.assertEqual(result['qemu_pid'], 123)
        self.assertEqual(result['disk_identity']['inode'], (self.directory / 'disk.qcow2').stat().st_ino)
        with patch.object(vm, 'ssh', return_value=subprocess.CompletedProcess([], 255, b'', b'')):
            self.assertIsNone(vm.boot_snapshot())

    def test_publication_waits_for_guest_and_host_cleanup(self):
        source, files = public_fixture()
        vm = Mock(token='a' * 32, kvm_status={'enabled': False, 'present': True})
        vm.prepare.return_value = {'accelerator': 'tcg'}
        vm.guest.side_effect = [dict(ok=True, boot_id=BOOT_A), dict(ok=True, boot_id=BOOT_B), dict(ok=True)]
        vm.ssh.return_value = subprocess.CompletedProcess([], 0, files['BEFORE.json'], b'')
        vm.reboot.return_value = reboot_fixture()
        vm.export_guest.return_value = files
        vm.cleanup.return_value = {'ok': True, 'vm_stopped': True, 'private_runtime_removed': True}
        with patch.object(lab, 'preflight', return_value=TOOLS), patch.object(lab, 'source_identity', return_value=source), \
             patch.object(lab, 'DisposableVM', return_value=vm):
            output = self.directory / 'publication'
            result = lab.run(output)
        self.assertTrue(result['ok'])
        self.assertEqual({path.name for path in (output / 'publish').iterdir()}, set(lab.PUBLIC_FILES) | {'MANIFEST.json'})
        self.assertEqual(len(json.loads((output / 'publish/MANIFEST.json').read_text())), 19)
        vm.cleanup.assert_called_once_with()
        self.assertEqual(vm.guest.call_args_list[-1].args, ('cleanup',))

    def test_failed_vm_cleanup_never_publishes_success_artifact(self):
        source, _ = public_fixture()
        vm = Mock()
        vm.prepare.side_effect = RuntimeError('controlled setup failure')
        vm.redact.side_effect = str
        vm.cleanup.return_value = {'ok': False, 'vm_stopped': False}
        with patch.object(lab, 'preflight', return_value=TOOLS), patch.object(lab, 'source_identity', return_value=source), \
             patch.object(lab, 'DisposableVM', return_value=vm):
            output = self.directory / 'failed'
            with self.assertRaisesRegex(RuntimeError, 'controlled setup failure'):
                lab.run(output)
        self.assertFalse((output / 'publish').exists())
        self.assertFalse(json.loads((output / 'staging/REPORT.json').read_text())['ok'])
        vm.cleanup.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
