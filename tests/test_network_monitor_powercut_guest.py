"""Portable boundary/replay checks; real guest power cuts are a separate CI VM test."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import network_monitor_powercut_guest as guest
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store

spec = importlib.util.spec_from_file_location('powercut_network_fixture', Path(__file__).with_name('test_network_monitor_reboot_guest.py'))
fixtures = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixtures)


class SimulatedCut(BaseException):
    pass


class PowerCutRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='guest-powercut-tests-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.state = self.directory / 'state'
        self.journal = self.worker = None
        self.token = 'a' * 32
        self.storage = {'target': '/', 'source': '/dev/vda1', 'fstype': 'ext4', 'options': 'rw,relatime', 'uuid': 'disk-uuid'}
        self.hashes = {'scripts/example.py': 'a' * 64}
        self.boots = [{'boot_id': str(n) * 8 + '-1111-4111-8111-' + str(n) * 12, 'uptime_seconds': 25} for n in (1, 2, 3)]
        self.addCleanup(self.close); self.addCleanup(patch.stopall)
        patch.object(guest, 'request', side_effect=self.request).start()
        patch.object(guest, 'manager', side_effect=self.manager).start()
        patch.object(guest, 'ready', side_effect=lambda *a: (self.request({'command': 'status'}), self.manager())).start()
        patch.object(guest, 'install', side_effect=self.install).start()
        patch.object(guest, 'VOLATILE', self.directory / 'volatile').start()
        patch.object(guest, 'BOUNDARY', self.directory / 'boundary').start()

    def close(self):
        if self.journal:
            self.journal.close()
            self.journal = None

    def start_worker(self):
        self.close(); self.journal = store.Journal(self.state)
        self.worker = service.Service(self.journal, test_pause=self.pause)

    def install(self, approved, token):
        store.initialize(self.state, approved); self.start_worker()
        return self.request({'command': 'status'}), self.manager()

    def request(self, payload):
        return self.worker.dispatch(payload)

    def manager(self, *args):
        return {'LoadState': 'loaded', 'ActiveState': 'active', 'MainPID': os.getpid(), 'NRestarts': 0,
                'InvocationID': self.worker.instance_id, 'UnitFileState': 'enabled'}

    def pause(self, worker, point, payload):
        self.boundary = {'point': point, 'in_transaction': worker.journal.connection.in_transaction,
                         'rows': guest.sql_rows(worker.journal.connection), 'accepted_count': len(worker.journal.rows)}
        raise SimulatedCut

    def before(self):
        result = guest.run_before(fixtures.NetworkFixture(), self.token)
        return {**result, 'boot': self.boots[0], 'storage': self.storage, 'source_sha256': self.hashes}

    def first_cut(self):
        before = self.before()
        self.before_payload = guest.cut_payload('before_commit')
        with self.assertRaises(SimulatedCut):
            self.request(self.before_payload)
        self.assertTrue(self.boundary['in_transaction'])
        self.assertEqual(len(self.boundary['rows']), 6)
        self.assertEqual(self.boundary['accepted_count'], 5)
        self.start_worker()
        result = guest.after_first(before, self.boots[1], self.hashes, self.storage, self.token)
        return before, {**result, 'boot': self.boots[1], 'storage': self.storage, 'source_sha256': self.hashes}

    def second_cut(self):
        before, intermediate = self.first_cut()
        self.after_payload = guest.cut_payload('after_commit_before_ack')
        with self.assertRaises(SimulatedCut):
            self.request(self.after_payload)
        self.assertFalse(self.boundary['in_transaction'])
        self.assertEqual(len(self.boundary['rows']), 7)
        self.assertEqual(self.boundary['accepted_count'], 6)
        self.start_worker()
        return before, intermediate

    def test_two_boundary_recoveries_preserve_prefix_and_lost_ack_retry_is_historical(self):
        before, intermediate = self.second_cut()
        after = guest.run_after(fixtures.NetworkFixture(), intermediate, self.boots[2], self.hashes, self.storage, self.token)
        self.assertEqual([len(before['journal']['rows']), len(intermediate['journal']['rows']),
                          len(after['automatic_start']['journal']['rows']), len(after['journal']['rows'])], [5, 6, 8, 11])
        self.assertEqual(after['journal']['rows'][:5], before['journal']['rows'])
        self.assertEqual(after['journal']['identity'], before['journal']['identity'])
        self.assertFalse(any(row['request_id'] == 'powercut-uncommitted' for row in after['journal']['rows']))
        self.assertEqual(sum(row['request_id'] == 'powercut-committed' for row in after['journal']['rows']), 1)
        retry = after['lost_ack_retry']['response']
        self.assertTrue(retry['duplicate']); self.assertTrue(retry['result_is_historical'])
        self.assertEqual(retry['committed_sequence'], 7)
        self.assertEqual(retry['current_status']['committed_count'], 8)
        self.assertEqual(retry['current_status']['current_evaluation']['status'], 'unknown')
        self.assertEqual(after['final_status']['current_evaluation']['status'], 'healthy')
        events = [event for event in after['journal']['events'] if event['key'] == guest.CRITICAL]
        self.assertEqual([(event['action'], event['sequence']) for event in events], [('opened', 5), ('resolved', 11)])
        guest.install.assert_called_once()

    def test_delayed_cold_boot_keeps_30_second_bound_and_requires_fresh_interval(self):
        _, intermediate = self.second_cut(); self.worker.started -= 31
        after = guest.run_after(fixtures.NetworkFixture(), intermediate, self.boots[2], self.hashes, self.storage, self.token)
        delayed, baseline, recovered = after['journal']['rows'][8:]
        self.assertFalse(delayed['evaluation']['telemetry_valid'])
        self.assertEqual(delayed['evaluation']['status'], 'unknown')
        self.assertTrue(baseline['evaluation']['telemetry_valid'])
        self.assertTrue(all(value is None for value in baseline['evaluation']['counter_deltas'].values()))
        self.assertIn(guest.CRITICAL, baseline['evaluation']['active_alert_keys'])
        self.assertEqual(recovered['evaluation']['status'], 'healthy')
        self.assertEqual(self.journal.engine.max_gap_seconds, 30)

    def verify(self, previous, point='after_commit_before_ack', **overrides):
        args = {'boot': self.boots[2], 'status': self.request({'command': 'status'}), 'properties': self.manager(),
                'journal': self.request({'command': 'export'}), 'storage': self.storage, 'hashes': self.hashes, 'point': point}
        args.update(overrides); guest.verify_start(previous, **args)

    def test_changed_boot_prefix_identity_incident_or_source_cannot_pass(self):
        _, previous = self.second_cut()
        cases = [({'boot': previous['boot']}, 'new Linux boot'), ({'hashes': {}}, 'source changed'),
                 ({'storage': {**self.storage, 'uuid': 'other'}}, 'filesystem changed'),
                 ({'properties': previous['manager']}, 'new boot instance')]
        changed = self.request({'command': 'export'}); changed['rows'][0]['row_digest'] = 'f' * 64
        cases.append(({'journal': changed}, 'Committed prefix'))
        changed = self.request({'command': 'export'}); changed['identity']['database_id'] = 'b' * 32
        cases.append(({'journal': changed}, 'Journal identity'))
        changed = self.request({'command': 'status'}); changed['alerts'] = []
        cases.append(({'status': changed}, 'incident'))
        changed = self.request({'command': 'status'}); changed['current_evaluation']['status'] = 'healthy'
        cases.append(({'status': changed}, 'Startup'))
        for override, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                self.verify(previous, **override)

    def test_persistent_volatile_marker_blocks_recovery(self):
        _, previous = self.second_cut()
        for path in (guest.VOLATILE, guest.BOUNDARY):
            path.write_text('stale')
            with self.assertRaisesRegex(RuntimeError, 'volatile markers'):
                self.verify(previous)
            path.unlink()

    def test_missing_committed_transaction_is_not_treated_as_success(self):
        _, previous = self.second_cut()
        changed = self.request({'command': 'export'}); changed['rows'].pop(-2)
        with self.assertRaisesRegex(RuntimeError, 'Committed prefix'):
            self.verify(previous, journal=changed)

    def test_wrong_retry_content_rejects_without_advancing_journal(self):
        self.second_cut()
        payload = {key: value for key, value in self.after_payload.items() if key != 'test_pause'}
        payload['observation']['phase'] = 'changed'
        with self.assertRaisesRegex(ValueError, 'conflicts'):
            self.request(payload)
        self.assertEqual(self.request({'command': 'status'})['committed_count'], 8)

    def test_no_network_setup_before_automatic_start_verification(self):
        _, previous = self.second_cut()
        network = fixtures.NetworkFixture(); network.setup = Mock(side_effect=AssertionError('no network'))
        with self.assertRaisesRegex(RuntimeError, 'new Linux boot'):
            guest.run_after(network, previous, previous['boot'], self.hashes, self.storage, self.token)
        network.setup.assert_not_called()

    def test_pause_disabled_by_default_and_cannot_combine_crash_or_null_pause(self):
        self.before(); self.worker.test_pause = None
        payload = guest.cut_payload('before_commit')
        for changed in (payload, {**payload, 'test_pause': None}, {**payload, 'test_crash': 'before_commit'}):
            with self.subTest(), self.assertRaises(ValueError):
                self.request(changed)
        self.assertEqual(self.request({'command': 'status'})['committed_count'], 5)

    def test_returning_pause_callback_cannot_acknowledge_or_accept_transaction(self):
        self.before(); self.worker.test_pause = Mock()
        with self.assertRaisesRegex(RuntimeError, 'must not return'):
            self.request(guest.cut_payload('before_commit'))
        self.assertEqual(len(self.journal.rows), 5)
        self.assertEqual(self.journal.connection.execute('SELECT COUNT(*) FROM observations').fetchone(), (5,))

    def test_extra_synchronization_is_enabled_again_after_each_reopen(self):
        self.before()
        self.assertEqual(self.journal.connection.execute('PRAGMA synchronous').fetchone(), (3,))
        self.journal.connection.execute('PRAGMA synchronous=FULL')
        self.start_worker()
        self.assertEqual(self.journal.connection.execute('PRAGMA synchronous').fetchone(), (3,))


class PowerCutBoundaryTests(unittest.TestCase):
    def test_mac_guard_refuses_before_any_marker_or_command_access(self):
        with patch.object(guest.reboot.sys, 'platform', 'darwin'), patch.object(guest.reboot, 'ordinary') as ordinary, \
             patch.object(guest.reboot, 'command') as command:
            with self.assertRaisesRegex(RuntimeError, 'disposable Linux guest'):
                guest.guard('a' * 32)
        ordinary.assert_not_called(); command.assert_not_called()

    def test_unit_boots_existing_state_and_enables_pause_only_in_guarded_worker(self):
        text = guest.unit_text('a' * 32)
        self.assertIn('network_monitor_powercut_guest.py worker', text)
        self.assertNotIn(' init ', text); self.assertNotIn('a' * 32, text)
        self.assertIn('RuntimeDirectory=heltemes-powercut-lab', text)
        self.assertIn('RuntimeDirectoryMode=0700', text)
        self.assertIn('ReadWritePaths=/var/lib/heltemes-powercut-lab/state /run/heltemes-powercut-lab', text)
        self.assertIn('WantedBy=multi-user.target', text)
        with self.assertRaises(RuntimeError):
            guest.unit_text('bad')

    def test_public_inventory_and_source_inventory_are_bounded(self):
        self.assertEqual(len(guest.SOURCE_FILES), 13)
        self.assertEqual(len(guest.PUBLIC_FILES), 17)
        self.assertEqual(len(set(guest.PUBLIC_FILES)), 17)
        self.assertEqual(sum(name.endswith('.pcap') for name in guest.PUBLIC_FILES), 6)
        self.assertFalse(any(marker in name for name in guest.PUBLIC_FILES for marker in ('sqlite', 'token', '.key', 'stderr')))

    def test_boundary_rejects_different_request_worker_or_prefix(self):
        payload = guest.cut_payload('before_commit')
        row = {'request_id': payload['request_id']}
        previous = {'boot': {'boot_id': 'boot'}, 'journal': {'rows': []}}
        status = {'process_id': 42, 'instance_id': 'instance'}
        marker = {'point': 'before_commit', 'request_id': payload['request_id'],
                  'request': {key: value for key, value in payload.items() if key != 'test_pause'},
                  'observation_sha256': store.digest(payload['observation']), 'process_id': 42,
                  'instance_id': 'instance', 'boot_id': 'boot', 'in_transaction': True,
                  'accepted_in_memory_count': 0, 'database_view_rows': [row], 'synchronous': 3, 'journal_mode': 'delete'}
        guest.validate_boundary(marker, 'before_commit', payload, status, previous)
        for key, value in [('point', 'after_commit_before_ack'), ('process_id', 43), ('boot_id', 'old'),
                           ('observation_sha256', 'bad'), ('in_transaction', False),
                           ('accepted_in_memory_count', 1), ('database_view_rows', []), ('synchronous', 2), ('journal_mode', 'wal')]:
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                guest.validate_boundary({**marker, key: value}, 'before_commit', payload, status, previous)

    def test_pause_writes_current_boundary_to_tmpfs_before_sigstop_and_cannot_resume(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary).resolve(); runtime.chmod(0o700)
            boundary = runtime / 'boundary.json'
            worker = Mock(); worker.journal.rows = []; worker.instance_id = 'instance'
            worker.journal.connection.in_transaction = True
            worker.journal.connection.execute.side_effect = [Mock(fetchone=lambda: (3,)), Mock(fetchone=lambda: ('delete',))]
            payload = guest.cut_payload('before_commit')
            real_read = Path.read_text
            def read(path, *args, **kwargs):
                return 'boot\n' if str(path) == '/proc/sys/kernel/random/boot_id' else real_read(path, *args, **kwargs)
            effects = []
            with patch.object(guest, 'RUNTIME', runtime), patch.object(guest, 'BOUNDARY', boundary), \
                 patch.object(guest, 'STATE', runtime), patch.object(guest, 'command', return_value=subprocess.CompletedProcess([], 0, 'tmpfs\n', '')), \
                 patch.object(guest, 'sql_rows', return_value=[{'request_id': payload['request_id']}]), \
                 patch.object(Path, 'read_text', read), patch.object(guest.os, 'kill', side_effect=lambda pid, sig: effects.append((pid, sig, boundary.exists()))), \
                 patch.object(guest.os, '_exit', side_effect=SimulatedCut):
                with self.assertRaises(SimulatedCut):
                    guest.pause_worker(worker, 'before_commit', payload)
            self.assertEqual(effects, [(os.getpid(), signal.SIGSTOP, True)])
            marker = json.loads(boundary.read_text())
            self.assertTrue(marker['in_transaction']); self.assertEqual(marker['synchronous'], 3)
            self.assertEqual(marker['accepted_in_memory_count'], 0)
            self.assertEqual(marker['request'], {key: value for key, value in payload.items() if key != 'test_pause'})

    def test_missing_state_is_not_initialized_by_worker_cli(self):
        result = subprocess.run([os.sys.executable, '-I', '-S', '-B', str(guest.ROOT / 'scripts/network_monitor_powercut_guest.py'), 'worker'], capture_output=True)
        if os.sys.platform == 'darwin':
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'Disposable Linux guest required', result.stderr)


class CaptureDurabilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='powercut-capture-tests-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.staging, self.publish = self.directory / 'staging', self.directory / 'publish'
        self.staging.mkdir(mode=0o700); self.publish.mkdir(mode=0o700)
        patcher = patch.object(guest, 'PUBLISH', self.publish); patcher.start(); self.addCleanup(patcher.stop)
        self.contents = {name: ('completed synthetic bytes for ' + name).encode() for name in guest.CAPTURE_FILES}
        for name, data in self.contents.items():
            (self.staging / name).write_bytes(data)

    def test_each_completed_file_is_synced_before_rename_then_both_parents_sync(self):
        events = []
        inodes = {(self.staging / name).stat().st_ino: name for name in guest.CAPTURE_FILES}
        real_fsync, real_rename, real_sync_directory = os.fsync, Path.rename, store.sync_directory
        def fsync(descriptor):
            info = os.fstat(descriptor)
            if stat.S_ISREG(info.st_mode):
                events.append(('file_sync', inodes[info.st_ino]))
            return real_fsync(descriptor)
        def rename(source, destination):
            events.append(('rename', source.name)); return real_rename(source, destination)
        def sync_directory(path):
            events.append(('directory_sync', path.name)); return real_sync_directory(path)
        with patch.object(guest.os, 'fsync', side_effect=fsync), patch.object(Path, 'rename', rename), \
             patch.object(guest.store, 'sync_directory', side_effect=sync_directory):
            checksums = guest.seal_captures(self.staging, 'before')
        expected = [event for name in guest.CAPTURE_FILES for event in [('file_sync', name), ('rename', name)]]
        self.assertEqual(events, expected + [('directory_sync', 'staging'), ('directory_sync', 'publish')])
        self.assertEqual(checksums, {'before-' + name: hashlib.sha256(data).hexdigest() for name, data in self.contents.items()})
        self.assertEqual(guest.verify_captures({'capture_sha256': checksums}, 'before'), checksums)

    def test_fsync_failure_stops_before_rename_or_reference_acceptance(self):
        with patch.object(guest.os, 'fsync', side_effect=OSError('simulated failed flush')), \
             patch.object(Path, 'rename') as rename, self.assertRaisesRegex(OSError, 'failed flush'):
            guest.seal_captures(self.staging, 'before')
        rename.assert_not_called()
        self.assertEqual(list(self.publish.iterdir()), [])
        self.assertEqual(len(list(self.staging.iterdir())), 6)

    def test_zero_filled_capture_tail_is_rejected_against_pre_cut_fingerprint(self):
        checksums = guest.seal_captures(self.staging, 'before')
        path = self.publish / 'before-user.pcap'; original = path.read_bytes()
        path.write_bytes(original[:10] + bytes(len(original) - 10))
        with self.assertRaisesRegex(RuntimeError, 'capture bytes changed'):
            guest.verify_captures({'capture_sha256': checksums}, 'before')
        path.write_bytes(original)
        self.assertEqual(guest.verify_captures({'capture_sha256': checksums}, 'before'), checksums)

    def test_reference_requires_exact_six_stage_names_and_valid_fingerprints(self):
        checksums = guest.seal_captures(self.staging, 'before')
        missing = dict(checksums); missing.pop('before-user.pcap')
        wrong = dict(checksums); wrong['before-user.pcap'] = 'wrong'
        extra = {**checksums, '../outside': 'a' * 64}
        for changed in (None, missing, wrong, extra):
            with self.subTest(changed=changed), self.assertRaisesRegex(RuntimeError, 'exact six'):
                guest.verify_captures({'capture_sha256': changed}, 'before')
        with self.assertRaisesRegex(RuntimeError, 'exact six'):
            guest.verify_captures({'capture_sha256': checksums}, 'after')

    def test_symlink_and_hardlink_captures_are_rejected_before_sync(self):
        first = self.staging / guest.CAPTURE_FILES[0]
        original = first.read_bytes(); first.unlink()
        other = self.directory / 'other'; other.write_bytes(original)
        for linked in ('symlink', 'hardlink'):
            if linked == 'symlink':
                first.symlink_to(other)
            else:
                os.link(other, first)
            with patch.object(guest.os, 'fsync') as fsync, self.assertRaisesRegex(RuntimeError, 'singly linked regular'):
                guest.seal_captures(self.staging, 'before')
            fsync.assert_not_called(); first.unlink()

    def test_both_post_cut_stages_verify_old_capture_bytes_before_recovery(self):
        for stage in ('after-before', 'after-after'):
            with patch.object(guest, 'guard', return_value='qemu'), patch.object(guest.reboot, 'boot_info', return_value={}), \
                 patch.object(guest, 'source_hashes', return_value={}), patch.object(guest.store, 'state_path'), \
                 patch.object(guest, 'read_report', return_value={'capture_sha256': {}}), \
                 patch.object(guest, 'verify_captures', side_effect=RuntimeError('changed saved capture')) as verify, \
                 patch.object(guest, 'after_first') as first, patch.object(guest, 'run_after') as second:
                with self.assertRaisesRegex(RuntimeError, 'changed saved capture'):
                    guest.stage(stage, 'a' * 32)
                verify.assert_called_once_with({'capture_sha256': {}}, 'before')
                first.assert_not_called(); second.assert_not_called()


if __name__ == '__main__':
    unittest.main()
