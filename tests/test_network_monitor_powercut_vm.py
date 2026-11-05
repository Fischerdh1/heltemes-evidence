"""Portable checks for the owned whole-VM power-cut host controller."""
import copy
import io
import json
from pathlib import Path
import signal
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import network_monitor_powercut_vm as lab

TOOLS = {name: '/tools/' + name for name in ('qemu-system-x86_64', 'qemu-img', 'cloud-localds', 'ssh', 'ssh-keygen', 'curl', 'git')}
BOOT_A = '11111111-1111-4111-8111-111111111111'
BOOT_B = '22222222-2222-4222-8222-222222222222'
BOOT_C = '33333333-3333-4333-8333-333333333333'


def observation(name):
    return {'phase': name, 'observed_at_utc': '2026-11-05T00:00:00+00:00', 'ruleset': None,
            'collection_error': 'test', 'probes': []}


def row(sequence, request_id, kind='observation'):
    obs = observation(request_id)
    value = {'sequence': sequence, 'request_id': request_id, 'request': {'kind': kind, 'observation': obs},
             'sample': {**obs, 'sequence': sequence, 'elapsed_seconds': sequence * 1.},
             'evaluation': {'status': 'unknown', 'phase': request_id, 'sequence': sequence},
             'events': [], 'previous_digest': '0' * 64}
    return {**value, 'row_digest': lab.digest(value)}


def old_rows():
    return [row(i, 'before-' + str(i)) for i in range(1, 6)]


def startup_row(sequence):
    return row(sequence, 'monitor_restart', 'restart')


def boundary_fixture(point='before_commit'):
    first = point == 'before_commit'
    count, boot, pid, instance = (5, BOOT_A, 100, 'a' * 32) if first else (6, BOOT_B, 200, 'b' * 32)
    request_id = lab.REQUEST_IDS[point]
    prior = old_rows() + ([] if first else [startup_row(6)])
    request = {'command': 'observe', 'request_id': request_id, 'observation': observation(request_id)}
    return {'ok': True, 'stage': 'arm-before' if first else 'arm-after', 'boot_id': boot,
            'worker_state': 'T', 'worker_process_state': 'T', 'worker_stopped_observed': True,
            'response_received': False, 'ready_marker_filesystem': 'tmpfs',
            'manager': {'MainPID': pid, 'InvocationID': instance, 'NRestarts': 0, 'ActiveState': 'active', 'UnitFileState': 'enabled'},
            'boundary': {'format': 'heltemes-powercut-boundary', 'version': 1, 'point': point,
                         'request_id': request_id, 'request': request, 'observation_sha256': lab.digest(request['observation']),
                         'boot_id': boot, 'process_id': pid, 'instance_id': instance, 'in_transaction': first,
                         'accepted_in_memory_count': count, 'database_view_rows': prior + [row(count + 1, request_id)],
                         'synchronous': 3, 'journal_mode': 'delete'}}


def cut_fixture():
    before = {'boot_id': BOOT_A, 'uptime_seconds': 50., 'qemu_pid': 123,
              'disk_identity': {'device': 1, 'inode': 2}, 'observed_elapsed_seconds': 20.}
    after = {**copy.deepcopy(before), 'boot_id': BOOT_B, 'qemu_pid': 456,
             'uptime_seconds': 3., 'observed_elapsed_seconds': 30.}
    return {'point': 'before_commit', 'boundary': boundary_fixture(), 'boundary_recheck': boundary_fixture(), 'before': before, 'after': after,
            'disk_cache_before_cut': lab.cache_evidence(block_fixture()),
            'signal': 'SIGKILL', 'qemu_wait_returncode': -9, 'old_qemu_reaped': True,
            'power_cut_elapsed_seconds': 21., 'qemu_terminated_elapsed_seconds': 22.,
            'cold_launch_elapsed_seconds': 23.,
            'ssh_unavailable_observed': True, 'new_qemu_process': True, 'same_disk': True,
            'guest_shutdown_requested': False, 'qemu_graceful_exit_requested': False}


def block_fixture():
    return [{'device': 'he-monitor-disk', 'inserted': {'drv': 'qcow2', 'ro': False, 'cache': dict(lab.CACHE)}}]


def public_fixture():
    cuts = [cut_fixture()]
    second = copy.deepcopy(cuts[0])
    second.update(point='after_commit_before_ack', boundary=boundary_fixture('after_commit_before_ack'),
                  boundary_recheck=boundary_fixture('after_commit_before_ack'),
                  before={**cuts[0]['after'], 'observed_elapsed_seconds': 40.},
                  after={**cuts[0]['after'], 'boot_id': BOOT_C, 'qemu_pid': 789, 'observed_elapsed_seconds': 50.},
                  power_cut_elapsed_seconds=41., qemu_terminated_elapsed_seconds=42., cold_launch_elapsed_seconds=43.)
    cuts.append(second)
    source = {'source_sha256': {name: 'c' * 64 for name in lab.SOURCE_FILES}}
    hashes = {name: source['source_sha256'][name] for name in lab.GUEST_SOURCE_FILES}
    identity, storage = {'database_id': 'd' * 32}, {'target': '/', 'source': '/dev/vda1', 'fstype': 'ext4', 'uuid': 'original'}
    original_rows = old_rows()
    first_rows = original_rows + [startup_row(6)]
    accepted_rows = second['boundary']['boundary']['database_view_rows'] + [startup_row(8)]
    final_rows = accepted_rows + [row(9, 'after_reference'), row(10, 'after_interval'), row(11, 'after_canaries')]
    def journal(rows):
        return {'identity': identity, 'approved_policy': {}, 'rows': rows, 'events': []}
    def status(count, pid, instance, health='unknown'):
        return {'process_id': pid, 'instance_id': instance, 'committed_count': count,
                'current_evaluation': {'status': health, 'phase': 'monitor_restart'},
                'alerts': [{'id': 'critical#1', 'state': 'open' if health != 'healthy' else 'resolved', 'severity': 'critical'}]}
    unit = b'public synthetic unit'
    def record(boot, rows, pid, instance):
        return {'boot': {'boot_id': boot}, 'source_sha256': hashes, 'journal': journal(rows),
                'critical_incident_id': 'critical#1', 'storage': storage, 'volatile_markers_absent': True,
                'unit_sha256': lab.hashlib.sha256(unit).hexdigest(),
                'manager': {'MainPID': pid, 'InvocationID': instance, 'NRestarts': 0, 'ActiveState': 'active', 'UnitFileState': 'enabled'},
                'final_status': status(len(rows), pid, instance)}
    before = record(BOOT_A, original_rows, 100, 'a' * 32)
    middle = record(BOOT_B, first_rows, 200, 'b' * 32)
    after = record(BOOT_C, final_rows, 300, 'c' * 32)
    middle['automatic_start'] = {'journal': middle['journal'], 'status': middle['final_status'],
                                 'manager': middle['manager'], 'no_manual_service_start': True}
    after['automatic_start'] = {'journal': journal(accepted_rows), 'status': status(8, 300, 'c' * 32),
                                'manager': after['manager'], 'no_manual_service_start': True}
    after['final_status'] = status(11, 300, 'c' * 32, 'healthy')
    after['journal']['events'] = [{'key': 'forbidden_path_open:user->app:9090', 'action': 'resolved',
                                  'sequence': 11, 'phase': 'after_canaries'}]
    after['lost_ack_retry'] = {'request': second['boundary']['boundary']['request'], 'history_unchanged': True,
                               'response': {'ok': True, 'duplicate': True, 'result_is_historical': True,
                                            'committed_sequence': 7, 'evaluation': accepted_rows[6]['evaluation'],
                                            'current_status': status(8, 300, 'c' * 32)}}
    files = {name: b'public fixture' for name in lab.GUEST_FILES}
    for phase, record in (('before', before), ('after', after)):
        record['capture_sha256'] = {name: lab.hashlib.sha256(files[name]).hexdigest()
                                    for name in files if name.startswith(phase + '-')}
    files.update({'BEFORE.json': json.dumps(before).encode(), 'AFTER_BEFORE.json': json.dumps(middle).encode(),
                  'AFTER.json': json.dumps(after).encode(), 'monitor.service': unit})
    references = {name: files[name] for name in ('BEFORE.json', 'AFTER_BEFORE.json')}
    return references, files, source, cuts


def archive_bytes(files, extra=None, link=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name, content in files.items():
            entry = tarfile.TarInfo(name)
            if name == link:
                entry.type, entry.linkname = tarfile.SYMTYPE, '/outside'
                archive.addfile(entry)
            else:
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
        if extra:
            archive.addfile(tarfile.TarInfo(extra), io.BytesIO())
    return output.getvalue()


class PowercutHostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='powercut-host-tests-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()

    def test_mac_guard_precedes_source_and_output_creation(self):
        output = self.directory / 'not-created'
        with patch.object(lab.sys, 'platform', 'darwin'), patch.object(lab, 'source_identity') as source:
            with self.assertRaisesRegex(RuntimeError, 'does not run on macOS'):
                lab.run(output)
        source.assert_not_called()
        self.assertFalse(output.exists())

    def test_non_x86_host_rejected(self):
        with patch.object(lab.sys, 'platform', 'linux'), patch.object(lab.reboot.platform, 'machine', return_value='aarch64'):
            with self.assertRaisesRegex(RuntimeError, 'x86-64'):
                lab.preflight()

    def test_source_upload_exactly_excludes_hosts_and_private_material(self):
        for name in lab.SOURCE_FILES:
            path = self.directory / name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_text(name)
        (self.directory / 'private-key').write_text('do not upload')
        with tarfile.open(fileobj=io.BytesIO(lab.source_archive(self.directory)), mode='r:gz') as archive:
            self.assertEqual(archive.getnames(), list(lab.GUEST_SOURCE_FILES))
            self.assertEqual(len(archive.getmembers()), 13)
            self.assertTrue(all(member.isfile() and member.mode == 0o644 for member in archive.getmembers()))
            self.assertNotIn('scripts/network_monitor_reboot_vm.py', archive.getnames())
            self.assertNotIn('scripts/network_monitor_powercut_vm.py', archive.getnames())

    def test_disk_cache_requires_observed_direct_io_and_flushes(self):
        blocks = block_fixture()
        self.assertEqual(lab.cache_evidence(blocks)['cache'], lab.CACHE)
        for key in ('direct', 'no-flush'):
            with self.subTest(key=key):
                bad = copy.deepcopy(blocks)
                bad[0]['inserted']['cache'][key] = not bad[0]['inserted']['cache'][key]
                with self.assertRaisesRegex(RuntimeError, 'direct I/O'):
                    lab.cache_evidence(bad)
        for bad in ([], blocks * 2, [{'device': 'another-disk', 'inserted': blocks[0]['inserted']}], [{}]):
            with self.assertRaises(RuntimeError):
                lab.cache_evidence(bad)

    def test_guest_negotiated_writethrough_is_recorded_without_relaxing_direct_io_or_flushes(self):
        blocks = block_fixture()
        blocks[0]['inserted']['cache']['writeback'] = False
        evidence = lab.cache_evidence(blocks)
        self.assertIs(evidence['cache']['writeback'], False)
        self.assertIs(evidence['cache']['direct'], True)
        self.assertIs(evidence['cache']['no-flush'], False)
        lab.validate_cache_record(evidence)
        for value in (None, 0, 1, 'false', []):
            blocks[0]['inserted']['cache']['writeback'] = value
            with self.assertRaises(RuntimeError):
                lab.cache_evidence(blocks)

    def test_cache_failure_diagnostics_select_safe_fields_and_never_private_paths(self):
        blocks = block_fixture()
        blocks[0]['inserted'].update(file='/private/disk-key', backing_file='/private/base-key',
                                     drv='/private/invalid-driver')
        blocks[0]['inserted']['cache']['writeback'] = '/private/invalid-value'
        with self.assertRaises(RuntimeError) as caught:
            lab.cache_evidence(blocks)
        message = str(caught.exception)
        self.assertIn('invalid-or-missing', message)
        self.assertIn('"direct": true', message)
        self.assertIn('"no-flush": false', message)
        self.assertNotIn('/private/', message)

    def test_pre_cut_cache_readback_cannot_disable_flushes_after_boot(self):
        value = cut_fixture()
        value['disk_cache_before_cut']['cache']['no-flush'] = True
        with self.assertRaisesRegex(RuntimeError, 'flush settings'):
            lab.validate_power_cut(value)

    def test_cut_requires_stopped_worker_bound_to_current_boot_and_point(self):
        lab.validate_boundary(boundary_fixture(), 'before_commit', BOOT_A)
        mutations = [lambda x: x.update(worker_state='S'), lambda x: x.update(boot_id=BOOT_B),
                     lambda x: x['boundary'].update(boot_id=BOOT_B),
                     lambda x: x['boundary'].update(point='after_commit_before_ack'),
                     lambda x: x.update(ok=False)]
        for change in mutations:
            bad = boundary_fixture(); change(bad)
            with self.assertRaises(RuntimeError):
                lab.validate_boundary(bad, 'before_commit', BOOT_A)

    def test_lifecycle_rejects_graceful_exit_same_vm_disk_replacement_and_wrong_order(self):
        lab.validate_power_cut(cut_fixture())
        changes = [lambda x: x['after'].update(boot_id=BOOT_A),
                   lambda x: x['after'].update(qemu_pid=123),
                   lambda x: x['after']['disk_identity'].update(inode=44),
                   lambda x: x.update(signal='SIGTERM'), lambda x: x.update(qemu_wait_returncode=0),
                   lambda x: x.update(old_qemu_reaped=False), lambda x: x.update(ssh_unavailable_observed=False),
                   lambda x: x.update(guest_shutdown_requested=True), lambda x: x.update(qemu_graceful_exit_requested=True),
                   lambda x: x.update(power_cut_elapsed_seconds=19), lambda x: x.update(qemu_terminated_elapsed_seconds=31)]
        for change in changes:
            bad = cut_fixture(); change(bad)
            with self.assertRaises(RuntimeError):
                lab.validate_power_cut(bad)

    def test_power_cut_kills_only_owned_process_and_retains_disk_until_cold_boot(self):
        vm = lab.DisposableVM(TOOLS)
        vm.directory = self.directory
        (self.directory / 'disk.qcow2').write_bytes(b'synthetic owned disk')
        old = Mock(pid=123)
        old.poll.side_effect = [None, -signal.SIGKILL]
        old.wait.return_value = -signal.SIGKILL
        vm.process, vm.qmp, vm.log = old, Mock(), Mock()
        vm.qmp.command.return_value = block_fixture()
        evidence = cut_fixture()
        def launch(previous):
            self.assertIsNone(vm.process)
            self.assertTrue((self.directory / 'disk.qcow2').exists())
            self.assertEqual(previous, evidence['before'])
            vm.last_launch_started = 23.
            return evidence['after']
        with patch.object(vm, 'boot_snapshot', return_value=evidence['before']), \
             patch.object(vm, 'guest', return_value=boundary_fixture()) as guest, \
             patch.object(vm, 'ssh', return_value=subprocess.CompletedProcess([], 255, b'', b'')) as ssh, \
             patch.object(vm, 'launch', side_effect=launch), \
             patch.object(lab.time, 'monotonic', side_effect=[vm.started + 21, vm.started + 22]):
            actual = vm.power_cut('before_commit', boundary_fixture())
        old.kill.assert_called_once_with()
        old.terminate.assert_not_called()
        old.wait.assert_called_once_with(timeout=15)
        ssh.assert_called_once_with('true', timeout=8, check=False)
        guest.assert_called_once_with('inspect-before')
        self.assertEqual(actual['qemu_wait_returncode'], -9)
        self.assertEqual((self.directory / 'disk.qcow2').read_bytes(), b'synthetic owned disk')

    def test_wrong_termination_status_cannot_be_reported_as_power_cut(self):
        vm = lab.DisposableVM(TOOLS)
        vm.process, vm.qmp, vm.log = Mock(), Mock(), Mock()
        vm.qmp.command.return_value = block_fixture()
        vm.process.poll.return_value = None
        vm.process.wait.return_value = 0
        with patch.object(vm, 'boot_snapshot', return_value=cut_fixture()['before']), \
             patch.object(vm, 'guest', return_value=boundary_fixture()), patch.object(vm, 'launch') as launch:
            with self.assertRaisesRegex(RuntimeError, 'SIGKILL'):
                vm.power_cut('before_commit', boundary_fixture())
        launch.assert_not_called()

    def test_cold_launch_requires_old_resources_closed_and_installed_disk(self):
        vm = lab.DisposableVM(TOOLS)
        vm.directory = self.directory
        with self.assertRaisesRegex(RuntimeError, 'already installed'):
            vm.launch(previous=cut_fixture()['before'])
        vm.process = Mock()
        with self.assertRaisesRegex(RuntimeError, 'no live previous'):
            vm.launch()

    def test_fixed_public_export_excludes_extra_paths_links_and_private_markers(self):
        files = {name: b'synthetic' for name in lab.GUEST_FILES}
        self.assertEqual(lab.extract_guest_export(archive_bytes(files)), files)
        self.assertEqual(len(files), 17)
        bad_archives = [archive_bytes(files, extra='private-key'), archive_bytes(files, extra='../outside'),
                        archive_bytes(files, link='BEFORE.json'),
                        archive_bytes({**files, 'monitor.service': b'-----BEGIN PRIVATE KEY-----'}),
                        archive_bytes({**files, 'BEFORE.json': b'/Users/private'})]
        for archive in bad_archives:
            with self.assertRaises(RuntimeError):
                lab.extract_guest_export(archive)

    def test_host_held_history_exact_candidate_and_retry_are_checked(self):
        arguments = public_fixture()
        lab.validate_preserved_history(*arguments)
        for name, mutate in [
            ('changed reference bytes', lambda refs, files, source, cuts: files.update({'BEFORE.json': files['BEFORE.json'] + b' '})),
            ('changed candidate', lambda refs, files, source, cuts: cuts[1]['boundary']['boundary']['database_view_rows'][-1].update(row_digest='f' * 64)),
            ('wrong source', lambda refs, files, source, cuts: source['source_sha256'].update({'scripts/network_monitor_store.py': 'f' * 64})),
        ]:
            with self.subTest(name=name):
                args = copy.deepcopy(arguments); mutate(*args)
                with self.assertRaises(RuntimeError):
                    lab.validate_preserved_history(*args)

    def test_damaged_capture_cannot_be_blessed_by_a_later_manifest(self):
        references, files, source, cuts = public_fixture()
        files['before-user.pcap'] = b'valid prefix' + bytes(512)
        with self.assertRaisesRegex(RuntimeError, 'before capture bytes'):
            lab.validate_preserved_history(references, files, source, cuts)
        # Rewriting the guest report to accept the damaged file still conflicts
        # with the exact report bytes retained on the host before either cut.
        before = json.loads(files['BEFORE.json'])
        before['capture_sha256']['before-user.pcap'] = lab.hashlib.sha256(files['before-user.pcap']).hexdigest()
        files['BEFORE.json'] = json.dumps(before).encode()
        with self.assertRaisesRegex(RuntimeError, 'retained outside'):
            lab.validate_preserved_history(references, files, source, cuts)

    def test_capture_fingerprint_inventory_must_include_all_six_completed_files(self):
        for phase, report in (('before', 'BEFORE.json'), ('after', 'AFTER.json')):
            references, files, source, cuts = public_fixture()
            value = json.loads(files[report]); del value['capture_sha256'][phase + '-user-packets.txt']
            files[report] = json.dumps(value).encode()
            if report in references:
                references[report] = files[report]
            with self.assertRaisesRegex(RuntimeError, 'capture bytes'):
                lab.validate_preserved_history(references, files, source, cuts)

    def test_self_consistent_guest_cannot_replace_host_recorded_committed_row(self):
        references, files, source, cuts = public_fixture()
        after = json.loads(files['AFTER.json'])
        for journal in (after['automatic_start']['journal'], after['journal']):
            journal['rows'][6]['sample']['elapsed_seconds'] = 999.
            journal['rows'][6]['row_digest'] = lab.digest({k: v for k, v in journal['rows'][6].items() if k != 'row_digest'})
        files['AFTER.json'] = json.dumps(after).encode()
        with self.assertRaisesRegex(RuntimeError, 'host-held candidate'):
            lab.validate_preserved_history(references, files, source, cuts)

    def test_retry_cannot_claim_current_health_or_append_a_new_commit(self):
        for field, value in [('duplicate', False), ('result_is_historical', False), ('committed_sequence', 9)]:
            with self.subTest(field=field):
                references, files, source, cuts = public_fixture()
                after = json.loads(files['AFTER.json']); after['lost_ack_retry']['response'][field] = value
                files['AFTER.json'] = json.dumps(after).encode()
                with self.assertRaisesRegex(RuntimeError, 'historical and idempotent'):
                    lab.validate_preserved_history(references, files, source, cuts)
        references, files, source, cuts = public_fixture()
        after = json.loads(files['AFTER.json'])
        after['lost_ack_retry']['response']['current_status']['current_evaluation']['status'] = 'healthy'
        files['AFTER.json'] = json.dumps(after).encode()
        with self.assertRaisesRegex(RuntimeError, 'historical and idempotent'):
            lab.validate_preserved_history(references, files, source, cuts)


if __name__ == '__main__':
    unittest.main()
