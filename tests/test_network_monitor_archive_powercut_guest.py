"""Portable archive crash boundaries; actual VM cold starts are a separate test."""
import copy
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import network_monitor_archive as archive
from scripts import network_monitor_archive_powercut_guest as guest
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store
from test_network_monitor import Fixture, ruleset


class SimulatedCut(BaseException):
    pass


class ArchivePowerCutGuestTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='archive-cut-guest-'); self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve(); self.state = self.base / 'state'; self.runtime = self.base / 'run'
        self.runtime.mkdir(mode=0o700); self.fixture = Fixture(); self.fixture.time = datetime.now(timezone.utc); self.journal = None
        self.stack = ExitStack(); self.addCleanup(self.stack.close); self.addCleanup(self.close)
        for name, value in {'STATE': self.state, 'RUNTIME': self.runtime, 'ARM': self.runtime / 'arm.json',
                            'BOUNDARY': self.runtime / 'boundary.json', 'VOLATILE': self.runtime / 'volatile',
                            'BOUNDARY_WRITING': self.runtime / 'boundary.json.writing', 'PROGRESS': self.runtime / 'boundary-progress.json',
                            'PROGRESS_WRITING': self.runtime / 'boundary-progress.json.writing'}.items():
            self.stack.enter_context(patch.object(guest, name, value))
        self.stack.enter_context(patch.object(guest.reboot, 'ordinary', side_effect=lambda p, **kw: store.ordinary(p)))
        self.stack.enter_context(patch.object(guest, 'command', return_value=Mock(stdout='tmpfs\n')))
        original_read = Path.read_text
        self.boot_id = '11111111-1111-4111-8111-111111111111'
        def read(path, *args, **kwargs):
            return self.boot_id if str(path) == '/proc/sys/kernel/random/boot_id' else original_read(path, *args, **kwargs)
        self.stack.enter_context(patch.object(Path, 'read_text', read))
        self.stack.enter_context(patch.object(guest.os, 'kill', side_effect=self.cut))
        self.stack.enter_context(patch.object(guest, 'request', side_effect=lambda payload: self.worker.dispatch(payload)))
        archive.initialize(self.state, ruleset(), segment_rows=128, max_rows=2048)
        self.start()

    def close(self):
        if self.journal is not None:
            self.journal.close(); self.journal = None

    def start(self):
        self.close(); self.journal = guest.ExerciseJournal(self.state); self.worker = service.Service(self.journal)

    def cut(self, pid, sig):
        self.assertEqual((pid, sig), (os.getpid(), signal.SIGSTOP)); raise SimulatedCut

    def fill(self, count):
        while self.journal.total_count < count:
            sample = self.fixture.sample()
            self.worker.dispatch({'command': 'observe', 'request_id': f'fill-{self.journal.total_count + 1}',
                                  'observation': {k: sample[k] for k in store.OBSERVATION_KEYS}})

    def reach_cut(self, key):
        self.fill(guest.HEADS[key] - 1); previous = self.journal.export()
        payload = guest.boundary_payload(key)
        store.write_new(guest.ARM, (store.encoded({'key': key, 'request': payload, 'instance_id': self.worker.instance_id}) + '\n').encode())
        with self.assertRaises(SimulatedCut):
            self.worker.dispatch(payload)
        marker = store.parse(store.read_private(guest.BOUNDARY)); self.close()
        return previous, payload, marker

    def clear_volatile(self):
        for path in (guest.ARM, guest.BOUNDARY, guest.VOLATILE, guest.BOUNDARY_WRITING, guest.PROGRESS, guest.PROGRESS_WRITING):
            if path.exists():
                path.unlink()

    def test_all_three_handoffs_recover_once_and_fourth_rollover_continues(self):
        original_identity = self.journal.identity.copy()
        previous_marker = None
        for index, key in enumerate(guest.POINTS, 1):
            prior, payload, marker = self.reach_cut(key)
            self.assertFalse(marker['in_transaction']); self.assertEqual(marker['synchronous'], 3)
            self.assertEqual(marker['journal_mode'], 'delete'); self.assertEqual(marker['rows'][:-1], prior['rows'])
            self.assertEqual(marker['active_sql_rows'], 0 if key == 'metadata' else 128)
            self.assertEqual(len(marker['archive_descriptors']), index if key == 'metadata' else index - 1)
            self.assertEqual(marker['pending_file'] is not None, key == 'staging')
            self.assertEqual(marker['final_file'] is not None, key != 'staging')
            if previous_marker:
                self.assertEqual(marker['rows'][:len(previous_marker['rows'])], previous_marker['rows'])
            self.clear_volatile(); self.start(); recovered = self.journal.export()
            self.assertEqual(recovered['identity'], original_identity)
            self.assertEqual(recovered['rows'][:-1], marker['rows'])
            self.assertEqual(recovered['rows'][-1]['request']['kind'], 'restart')
            self.assertEqual(self.journal.status()['current_evaluation']['status'], 'unknown')
            retry = guest.retry_boundary(recovered)
            self.assertEqual(retry['response']['committed_sequence'], index * 128)
            self.assertEqual(self.journal.export(), recovered)
            expected = ([{'action': 'rebuilt_verified_staging_prefix', 'segment_index': 1,
                          'staged_bytes': marker['pending_file']['bytes']}] if key == 'staging' else
                        [{'action': 'accepted_exact_uncommitted_segment', 'segment_index': 2}] if key == 'file' else [])
            self.assertEqual(self.journal.recovery_actions, expected)
            previous_marker = marker
        self.fill(520)
        final = self.journal.export(); self.assertEqual(len(final['archive_descriptors']), 4)
        self.assertEqual(final['rows'][:384], previous_marker['rows'])
        self.assertEqual(self.journal.status()['archives']['active_rows'], 8)
        self.assertEqual([r['sequence'] for r in final['rows'] if r['request']['kind'] == 'restart'], [1, 129, 257, 385])
        self.close()
        with archive.ArchiveJournal(self.state) as reopened:
            self.assertEqual(reopened.export(), final)

    def test_staged_filename_can_disappear_and_exact_committed_prefix_is_rebuilt(self):
        prior, payload, marker = self.reach_cut('staging')
        pending = self.state / 'archives' / 'segment-000001.json.pending'
        pending.unlink()  # Synthetic directory-entry loss; no production path involved.
        self.clear_volatile(); self.start()
        self.assertEqual(self.journal.recovery_actions, [])
        self.assertEqual(self.journal.export()['rows'][:128], marker['rows'])
        final = self.state / 'archives' / 'segment-000001.json'
        self.assertEqual(hashlib.sha256(final.read_bytes()).hexdigest(), marker['pending_file']['sha256'])
        self.assertEqual(self.worker.dispatch(payload)['committed_sequence'], 128)
        self.assertEqual(self.journal.total_count, 129)

    def test_changed_staging_bytes_stop_recovery(self):
        self.reach_cut('staging')
        path = self.state / 'archives' / 'segment-000001.json.pending'
        path.write_bytes(path.read_bytes().replace(b'"rows"', b'"ruws"', 1)); path.chmod(0o600)
        self.clear_volatile()
        with self.assertRaisesRegex(ValueError, 'staging bytes differ'):
            self.start()

    def test_changed_published_uncommitted_segment_stops_recovery(self):
        self.fill(255); self.reach_cut('file')
        path = self.state / 'archives' / 'segment-000002.json'
        path.write_bytes(path.read_bytes().replace(b'"rows"', b'"ruws"', 1)); path.chmod(0o600)
        self.clear_volatile()
        with self.assertRaisesRegex(ValueError, 'Uncommitted archive differs'):
            self.start()

    def test_missing_committed_archive_stops_recovery(self):
        self.fill(383); self.reach_cut('metadata')
        (self.state / 'archives' / 'segment-000003.json').unlink(); self.clear_volatile()
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.start()

    def test_boundary_marker_is_only_written_to_volatile_storage_after_exact_hook(self):
        self.fill(127); payload = guest.boundary_payload('staging')
        store.write_new(guest.ARM, (store.encoded({'key': 'staging', 'request': payload, 'instance_id': self.worker.instance_id}) + '\n').encode())
        original = store.write_new; destinations = []
        def write(path, data):
            destinations.append(path); return original(path, data)
        with patch.object(store, 'write_new', side_effect=write), patch.object(store, 'sync_directory', wraps=store.sync_directory) as sync:
            with self.assertRaises(SimulatedCut):
                self.worker.dispatch(payload)
        self.assertEqual(destinations, [self.state / 'archives' / 'segment-000001.json.pending',
            guest.PROGRESS_WRITING, guest.PROGRESS_WRITING, guest.PROGRESS_WRITING,
            guest.BOUNDARY_WRITING, guest.PROGRESS_WRITING])
        self.assertFalse(guest.BOUNDARY_WRITING.exists())
        self.assertEqual(store.parse(guest.PROGRESS.read_bytes())['phase'], 'marker_published')
        sync.assert_not_called()

    def test_boundary_refuses_nonvolatile_marker_filesystem(self):
        self.fill(127); payload = guest.boundary_payload('staging')
        store.write_new(guest.ARM, (store.encoded({'key': 'staging', 'request': payload, 'instance_id': self.worker.instance_id}) + '\n').encode())
        with patch.object(guest, 'command', return_value=Mock(stdout='ext4\n')):
            with self.assertRaisesRegex(RuntimeError, 'tmpfs'):
                self.worker.dispatch(payload)
        self.assertFalse(guest.BOUNDARY.exists())

    def test_hook_captures_exact_bytes_without_repeating_semantic_replay(self):
        self.fill(127)
        with (patch.object(guest, 'history_from_connection', side_effect=AssertionError('full projection inside hook')),
              patch.object(guest.archive, 'StreamingMonitor', side_effect=AssertionError('replay inside hook'))):
            _, _, marker = self.reach_cut('staging')
        self.assertEqual(marker['head_sequence'], 128)
        self.assertEqual(marker['head_digest'], marker['rows'][-1]['row_digest'])

    def test_atomic_marker_publication_hides_partial_content(self):
        raw = b'{"complete":true}\n'; original = store.write_new
        def write(path, data):
            self.assertEqual(path, guest.BOUNDARY_WRITING)
            self.assertFalse(guest.BOUNDARY.exists())
            original(path, data)
            self.assertFalse(guest.BOUNDARY.exists())
        with patch.object(store, 'write_new', side_effect=write), patch.object(store, 'sync_directory') as sync:
            guest.publish_boundary(raw)
        self.assertEqual(guest.BOUNDARY.read_bytes(), raw); self.assertFalse(guest.BOUNDARY_WRITING.exists())
        sync.assert_not_called()

    def test_failed_marker_publication_never_exposes_a_partial_boundary(self):
        with patch.object(guest.os, 'rename', side_effect=OSError('test failure')):
            with self.assertRaises(OSError):
                guest.publish_boundary(b'{"complete":true}\n')
        self.assertFalse(guest.BOUNDARY.exists()); self.assertTrue(guest.BOUNDARY_WRITING.exists())
        with self.assertRaisesRegex(RuntimeError, 'Stale boundary'):
            guest.publish_boundary(b'{}')

    def test_timeout_keeps_original_bound_and_reports_only_bounded_control_state(self):
        progress = {'point': 'archive_metadata_committed', 'phase': 'snapshot_captured', 'process_id': 123,
                    'expected_head': 384, 'elapsed_ms': 44000, 'marker_bytes': 0}
        store.write_new(guest.PROGRESS, store.encoded(progress).encode())
        output = 'ActiveState=failed\nSubState=failed\nMainPID=0\nNRestarts=1\nResult=exit-code\nExecMainCode=1\nExecMainStatus=74\nPRIVATE=do-not-publish\n'
        with (patch.object(guest.time, 'monotonic', side_effect=[0.0, 44.999, 45.0]),
              patch.object(guest.time, 'sleep') as sleep,
              patch.object(guest, 'command', return_value=Mock(stdout=output))):
            with self.assertRaisesRegex(RuntimeError, 'Exact stopped archive boundary') as caught:
                guest.wait_for_boundary('arm-metadata', 'metadata', {}, {}, {'MainPID': 123})
        sleep.assert_called_once_with(0.05)
        diagnostic = json.loads(str(caught.exception).split(': ', 1)[1])
        self.assertEqual(diagnostic['progress'], progress)
        self.assertEqual(diagnostic['manager']['ExecMainStatus'], 74)
        self.assertEqual(diagnostic['files']['marker'], {'exists': False})
        self.assertLess(len(str(caught.exception)), 1500)
        self.assertNotIn('do-not-publish', str(caught.exception)); self.assertNotIn(str(self.base), str(caught.exception))

    def test_untrusted_progress_content_is_omitted_from_failure_diagnostic(self):
        store.write_new(guest.PROGRESS, b'{"phase":"secret-payload"}')
        diagnostic = guest.boundary_diagnostic(123)
        self.assertEqual(diagnostic['files']['progress'], {'inspection_error': 'RuntimeError'})
        self.assertNotIn('secret-payload', json.dumps(diagnostic))

    def test_boundary_refuses_a_different_request_than_the_armed_one(self):
        self.fill(127); payload = guest.boundary_payload('staging')
        store.write_new(guest.ARM, (store.encoded({'key': 'staging', 'request': payload, 'instance_id': self.worker.instance_id}) + '\n').encode())
        altered = copy.deepcopy(payload); altered['observation']['collection_error'] = 'changed'
        with self.assertRaisesRegex(RuntimeError, 'arm request differs'):
            self.worker.dispatch(altered)
        self.assertFalse(guest.BOUNDARY.exists())

    def test_readonly_history_matches_export_and_never_runs_recovery(self):
        self.fill(270); before = self.journal.export()
        with (patch.object(guest.archive, 'initialize', side_effect=AssertionError('no initialization')),
              patch.object(guest.archive.ArchiveJournal, '__init__', side_effect=AssertionError('no writer open'))):
            after = guest.readonly_history()
        self.assertEqual(after, before)

    def test_readonly_history_rejects_committed_archive_tamper(self):
        self.fill(130); path = self.state / 'archives' / 'segment-000001.json'
        raw = path.read_bytes(); path.write_bytes(raw.replace(b'"rows"', b'"ruws"', 1)); path.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError, 'archive bytes differ'):
            guest.readonly_history()

    def test_readonly_history_rejects_recomputed_row_with_wrong_evaluation(self):
        self.fill(2)
        row = self.journal.rows[-1]; changed = copy.deepcopy(row); changed['evaluation']['status'] = 'healthy'
        changed['row_digest'] = store.digest({k: v for k, v in changed.items() if k != 'row_digest'})
        self.journal.connection.execute('UPDATE observations SET evaluation=?,row_digest=? WHERE sequence=?',
            (store.encoded(changed['evaluation']), changed['row_digest'], changed['sequence']))
        self.journal.connection.execute('UPDATE config SET head_digest=? WHERE id=1', (changed['row_digest'],))
        with self.assertRaisesRegex(RuntimeError, 'replay differs'):
            guest.readonly_history()

    def test_retry_rejects_a_new_observation_or_changed_current_status(self):
        _, _, marker = self.reach_cut('staging'); self.clear_volatile(); self.start()
        history = self.journal.export(); original = self.worker.dispatch
        def changed(payload):
            result = original(payload)
            if payload['command'] == 'observe':
                result['duplicate'] = False
            return result
        with patch.object(guest, 'request', side_effect=changed), self.assertRaisesRegex(RuntimeError, 'Retry differs'):
            guest.retry_boundary(history)

    def test_startup_requires_new_boot_original_incident_and_exact_recovered_prefix(self):
        self.fill(2)  # A fresh rule baseline precedes the forbidden-path observation.
        sample = self.fixture.sample(rows=(('user', 'app', 9090),), bad=True)
        self.worker.dispatch({'command': 'observe', 'request_id': 'original-incident',
                              'observation': {k: sample[k] for k in store.OBSERVATION_KEYS}})
        self.fill(127)
        old_status = self.worker.dispatch({'command': 'status'})
        incident = guest.reboot.critical(old_status)['id']
        storage = {'target': '/', 'source': '/dev/vda1', 'fstype': 'ext4', 'uuid': 'same-disk'}
        hashes = {'source.py': 'a' * 64}
        previous = {'boot': {'boot_id': self.boot_id}, 'storage': storage, 'source_sha256': hashes,
                    'final_status': old_status, 'manager': {'InvocationID': self.worker.instance_id},
                    'critical_incident_id': incident}
        old, _, marker = self.reach_cut('staging'); self.clear_volatile(); self.start()
        args = {'previous': previous, 'old': old, 'boot': {'boot_id': '22222222-2222-4222-8222-222222222222'},
                'status': self.worker.dispatch({'command': 'status'}), 'properties': {'InvocationID': self.worker.instance_id},
                'history': self.journal.export(), 'storage': copy.deepcopy(storage), 'hashes': copy.deepcopy(hashes), 'key': 'staging'}
        guest.verify_start(**args)
        changes = (
            lambda a: a['boot'].update(boot_id=self.boot_id),
            lambda a: a['storage'].update(uuid='replacement'),
            lambda a: a['hashes'].update({'source.py': 'b' * 64}),
            lambda a: a['properties'].update(InvocationID=previous['manager']['InvocationID']),
            lambda a: a['status']['current_evaluation'].update(status='healthy'),
            lambda a: a['history']['rows'][0].update(row_digest='f' * 64),
            lambda a: a['history']['rows'][-2].update(request_id='fabricated-boundary'),
            lambda a: a['status']['archives'].update(active_rows=0),
            lambda a: a['status']['archives'].update(recovery_actions=[{'action': 'invented'}]),
            lambda a: a['previous'].update(critical_incident_id='replacement-incident'),
        )
        for index, change in enumerate(changes):
            modified = copy.deepcopy(args); change(modified)
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                guest.verify_start(**modified)
        store.write_new(guest.VOLATILE, b'stale')
        with self.assertRaisesRegex(RuntimeError, 'volatile boundary'):
            guest.verify_start(**args)

    def test_boundary_validation_rejects_changed_request_process_and_handoff_phase(self):
        self.fill(127)
        previous = {'final_status': self.worker.dispatch({'command': 'status'}), 'boot': {'boot_id': self.boot_id}}
        old, _, marker = self.reach_cut('staging')
        guest.validate_boundary(marker, 'staging', previous, old)
        changes = (lambda m: m.update(in_transaction=True), lambda m: m.update(synchronous=2),
                   lambda m: m.update(active_sql_rows=0), lambda m: m.update(pending_file=None),
                   lambda m: m.update(process_id=os.getpid() + 1), lambda m: m.update(instance_id='a' * 32),
                   lambda m: m.update(observation_sha256='a' * 64),
                   lambda m: m['rows'][0].update(row_digest='a' * 64))
        for index, change in enumerate(changes):
            modified = copy.deepcopy(marker); change(modified)
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                guest.validate_boundary(modified, 'staging', previous, old)

    def test_guest_entrypoint_refuses_macos_before_state_access(self):
        with patch.object(guest.reboot.sys, 'platform', 'darwin'), patch.object(guest.reboot.os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(RuntimeError, 'Linux guest'):
                guest.guard('a' * 32)

    def test_service_is_boot_enabled_and_confined_to_disposable_state(self):
        unit = guest.unit_text()
        self.assertIn('WantedBy=multi-user.target', unit); self.assertIn('ProtectSystem=strict', unit)
        self.assertIn('RestrictAddressFamilies=AF_UNIX', unit); self.assertIn('network_monitor_archive_powercut_guest.py worker', unit)
        self.assertNotIn('/Users/', unit); self.assertNotIn('HELTEMES Evidence', unit)

    def test_manager_accepts_cleared_inactive_identity_but_rejects_active_without_identity(self):
        path = self.base / 'monitor.service'; path.write_text(guest.unit_text()); path.chmod(0o600)
        values = {'LoadState': 'loaded', 'ActiveState': 'inactive', 'SubState': 'dead', 'MainPID': '0', 'NRestarts': '0',
                  'ExecMainStartTimestampMonotonic': '0', 'InvocationID': '', 'UnitFileState': 'enabled', 'FragmentPath': str(path)}
        def run(args, **kwargs):
            return Mock(stdout='\n'.join(k + '=' + v for k, v in values.items()))
        with patch.object(guest, 'UNIT_FILE', path), patch.object(guest, 'command', side_effect=run):
            self.assertEqual(guest.manager()['MainPID'], 0)
            values['ActiveState'] = 'active'; values['MainPID'] = '123'
            with self.assertRaisesRegex(RuntimeError, 'invocation identity'):
                guest.manager()

    def test_fixture_source_allowlist_matches_host(self):
        from scripts import network_monitor_archive_powercut_vm as host
        self.assertEqual(guest.SOURCE_FILES, host.GUEST_SOURCE_FILES)
        self.assertEqual(set(guest.PUBLIC_FILES), set(host.GUEST_FILES))


if __name__ == '__main__':
    unittest.main()
