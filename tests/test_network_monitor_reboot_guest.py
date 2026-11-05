"""Portable guest-controller checks; real OS reboot and packets are verified in VM CI."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import network_monitor_reboot_guest as guest

spec = importlib.util.spec_from_file_location('reboot_network_fixture', Path(__file__).with_name('test_network_monitoring_lab.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class NetworkFixture(fixtures.ScenarioFixture):
    def __init__(self):
        super().__init__()
        self.next_source_port = 40000

    def probe(self, *args, **kwargs):
        probe = super().probe(*args, **kwargs)
        probe['source_port'] = self.next_source_port
        self.next_source_port += 1
        return probe

    def stop_captures(self):
        return {'ok': True, 'routed_flows_verified': len([p for p in self.probes if p['from'] != p['to']])}


class GuestControllerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='guest-reboot-tests-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.state = self.directory / 'state'
        self.journal = self.worker = None
        self.addCleanup(self.close)
        self.storage = {'target': '/', 'source': '/dev/vda1', 'fstype': 'ext4', 'options': 'rw,relatime', 'uuid': 'disk-uuid'}
        self.hashes = {'scripts/example.py': 'a' * 64}
        self.before_boot = {'boot_id': '11111111-1111-4111-8111-111111111111', 'uptime_seconds': 25}
        self.after_boot = {'boot_id': '22222222-2222-4222-8222-222222222222', 'uptime_seconds': 10}
        self.addCleanup(patch.stopall)
        patch.object(guest, 'request', side_effect=self.request).start()
        patch.object(guest, 'manager', side_effect=self.manager).start()
        patch.object(guest, 'ready', side_effect=lambda: (self.request({'command': 'status'}), self.manager())).start()
        patch.object(guest, 'install', side_effect=self.install).start()
        patch.object(guest, 'VOLATILE', self.directory / 'volatile').start()

    def close(self):
        if self.journal:
            self.journal.close()

    def start_worker(self):
        self.close()
        self.journal = guest.store.Journal(self.state)
        self.worker = guest.service.Service(self.journal)

    def install(self, approved):
        guest.store.initialize(self.state, approved)
        self.start_worker()
        return self.request({'command': 'status'}), self.manager()

    def request(self, payload):
        return self.worker.dispatch(payload)

    def manager(self):
        return {'LoadState': 'loaded', 'ActiveState': 'active', 'MainPID': os.getpid(), 'NRestarts': 0,
                'InvocationID': self.worker.instance_id, 'UnitFileState': 'enabled'}

    def before(self):
        result = guest.run_before(NetworkFixture())
        return {**result, 'boot': self.before_boot, 'storage': self.storage, 'source_sha256': self.hashes}

    def test_exact_journal_prefix_survives_boot_and_recovery_requires_new_canaries(self):
        before = self.before()
        self.assertEqual(len(before['journal']['rows']), 5)
        self.assertEqual(before['critical_incident_id'], 'forbidden_path_open:user->app:9090#1')
        self.start_worker()  # Portable simulation only; actual reboot is the separate QEMU test.
        after = guest.run_after(NetworkFixture(), before, self.after_boot, self.hashes, self.storage)
        startup = after['automatic_start']
        self.assertEqual(startup['status']['current_evaluation']['status'], 'unknown')
        self.assertEqual(len(startup['journal']['rows']), 6)
        self.assertEqual(startup['journal']['rows'][:5], before['journal']['rows'])
        self.assertEqual(after['journal']['identity'], before['journal']['identity'])
        self.assertEqual(len(after['journal']['rows']), 9)
        self.assertEqual(after['final_status']['current_evaluation']['status'], 'healthy')
        events = [e for e in after['journal']['events'] if e['key'] == guest.CRITICAL]
        self.assertEqual([(e['action'], e['phase'], e['sequence']) for e in events],
                         [('opened', 'before_forbidden', 5), ('resolved', 'after_canaries', 9)])
        self.assertEqual([r['request']['observation']['phase'] for r in after['observations']],
                         ['after_reference', 'after_interval', 'after_canaries'])

    def test_slow_boot_keeps_sampling_bound_and_requires_fresh_interval_before_recovery(self):
        before = self.before(); self.start_worker()
        # Deterministically advance service elapsed time without sleeping or
        # changing the monitor's 30-second bound. This models slow VM boot/setup.
        self.worker.started -= 31
        after = guest.run_after(NetworkFixture(), before, self.after_boot, self.hashes, self.storage)
        rows = after['journal']['rows']
        delayed, interval, recovered = rows[6:]
        self.assertGreater(delayed['sample']['elapsed_seconds'] - rows[5]['sample']['elapsed_seconds'], 30)
        self.assertEqual(delayed['evaluation']['status'], 'unknown')
        self.assertFalse(delayed['evaluation']['telemetry_valid'])
        self.assertIn('Observation gap exceeds the sampling bound or skips a sequence.', delayed['evaluation']['diagnostics'])
        self.assertIn(guest.CRITICAL, delayed['evaluation']['active_alert_keys'])
        self.assertEqual(interval['sample']['phase'], 'after_interval')
        self.assertTrue(interval['evaluation']['telemetry_valid'])
        self.assertTrue(interval['evaluation']['policy_matches'])
        self.assertTrue(all(value is None for value in interval['evaluation']['counter_deltas'].values()))
        self.assertIn(guest.CRITICAL, interval['evaluation']['active_alert_keys'])
        self.assertEqual(recovered['sequence'], 9)
        self.assertEqual(recovered['evaluation']['status'], 'healthy')
        self.assertGreater(recovered['evaluation']['counter_deltas']['drop_user_app_9090'], 0)
        self.assertNotIn(guest.CRITICAL, recovered['evaluation']['active_alert_keys'])
        self.assertEqual(self.worker.journal.engine.max_gap_seconds, 30)
        self.assertEqual(len(after['automatic_start']['journal']['rows']), 6)
        self.assertEqual(after['capture']['routed_flows_verified'], 3)

    def test_recovery_failure_reports_only_selected_evaluation_diagnostics(self):
        before = self.before(); self.start_worker()
        original = guest.observe
        def false_recovery(*args, **kwargs):
            result = original(*args, **kwargs)
            if args[2] == 'after_canaries':
                result['current_evaluation']['status'] = 'unknown'
                result['current_evaluation']['diagnostics'] = ['test incomplete coverage']
                result['private_detail'] = 'must not be printed'
            return result
        with patch.object(guest, 'observe', side_effect=false_recovery), self.assertRaises(RuntimeError) as caught:
            guest.run_after(NetworkFixture(), before, self.after_boot, self.hashes, self.storage)
        message = str(caught.exception)
        self.assertIn('Fresh committed checks', message)
        self.assertIn('test incomplete coverage', message)
        self.assertIn('after_canaries', message)
        self.assertNotIn('must not be printed', message)

    def verify(self, before, **overrides):
        args = {'boot': self.after_boot, 'status': self.request({'command': 'status'}),
                'properties': self.manager(), 'journal': self.request({'command': 'export'}),
                'storage': self.storage, 'hashes': self.hashes}
        args.update(overrides)
        guest.verify_reboot(before, **args)

    def test_same_boot_id_is_not_a_vm_reboot(self):
        before = self.before(); self.start_worker()
        with self.assertRaisesRegex(RuntimeError, 'full Linux boot change'):
            self.verify(before, boot=self.before_boot)

    def test_persistent_runtime_marker_invalidates_reboot_claim(self):
        before = self.before(); self.start_worker()
        guest.VOLATILE.write_text('old')
        with self.assertRaisesRegex(RuntimeError, 'volatile preboot marker survived'):
            self.verify(before)

    def test_source_filesystem_and_instance_substitution_stop_recovery(self):
        before = self.before(); self.start_worker()
        variants = [({'hashes': {'scripts/example.py': 'b' * 64}}, 'source changed'),
                    ({'storage': {**self.storage, 'uuid': 'other-disk'}}, 'original filesystem'),
                    ({'properties': before['manager']}, 'new boot instance')]
        for change, message in variants:
            with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                self.verify(before, **change)

    def test_missing_or_changed_preboot_prefix_is_rejected(self):
        before = self.before(); self.start_worker()
        exported = self.request({'command': 'export'})
        changes = []
        changed = copy.deepcopy(exported); changed['rows'].pop(0); changes.append(changed)
        changed = copy.deepcopy(exported); changed['rows'][2]['row_digest'] = 'f' * 64; changes.append(changed)
        changed = copy.deepcopy(exported); changed['identity']['database_id'] = 'a' * 32; changes.append(changed)
        for changed in changes:
            with self.subTest(rows=len(changed['rows'])), self.assertRaises(RuntimeError):
                self.verify(before, journal=changed)

    def test_cached_healthy_state_or_lost_incident_is_not_ready_recovery(self):
        before = self.before(); self.start_worker()
        status = self.request({'command': 'status'})
        healthy = copy.deepcopy(status); healthy['current_evaluation']['status'] = 'healthy'
        empty = copy.deepcopy(status); empty['alerts'] = []
        for value in (healthy, empty):
            with self.subTest(), self.assertRaises(RuntimeError):
                self.verify(before, status=value)

    def test_after_inspection_precedes_network_setup_and_never_reinitializes(self):
        before = self.before(); self.start_worker()
        network = NetworkFixture()
        network.setup = Mock(side_effect=AssertionError('must not start network'))
        before['boot'] = self.after_boot
        with self.assertRaisesRegex(RuntimeError, 'full Linux boot change'):
            guest.run_after(network, before, self.after_boot, self.hashes, self.storage)
        network.setup.assert_not_called()
        guest.install.assert_called_once()  # Only the original before stage initialized.

    def test_missing_journal_does_not_get_recreated_for_boot(self):
        self.before(); self.close()
        (self.state / 'monitor.sqlite3').unlink()
        with self.assertRaises(FileNotFoundError):
            self.start_worker()
        self.assertFalse((self.state / 'monitor.sqlite3').exists())

    def test_missing_live_capture_flow_fails_both_stages(self):
        before = self.before(); self.start_worker()
        network = NetworkFixture(); network.stop_captures = lambda: {'routed_flows_verified': 2}
        with self.assertRaisesRegex(RuntimeError, 'Postboot capture coverage'):
            guest.run_after(network, before, self.after_boot, self.hashes, self.storage)

    def test_probe_omission_or_wrong_outcome_cannot_pass_inventory(self):
        network = NetworkFixture()
        before = guest.run_before(network)
        observation = copy.deepcopy(before['observations'])
        observation[1]['request']['observation']['probes'].pop()
        with self.assertRaises(RuntimeError):
            guest.inventory(network, observation, 'before')
        network.probes[-1]['outcome'] = 'connect_timeout'
        with self.assertRaises(RuntimeError):
            guest.inventory(network, before['observations'], 'before')


class GuestBoundaryTests(unittest.TestCase):
    def test_unit_only_serves_existing_persistent_state_and_is_enabled_at_boot(self):
        text = guest.unit_text()
        self.assertIn('WantedBy=multi-user.target', text)
        self.assertIn('After=local-fs.target', text)
        self.assertIn('serve --state /var/lib/heltemes-reboot-lab/state', text)
        self.assertNotIn(' init ', text)
        self.assertNotIn('--allow-test-crashes', text)
        self.assertIn('ProtectSystem=strict', text)
        self.assertIn('RestrictAddressFamilies=AF_UNIX', text)
        self.assertNotIn('StateDirectory=', text)  # Boot must not silently manufacture an empty state directory.

    def test_mac_guard_refuses_before_reading_marker_or_running_commands(self):
        with patch.object(guest.sys, 'platform', 'darwin'), patch.object(guest, 'command') as command, \
             patch.object(guest, 'ordinary') as ordinary:
            with self.assertRaisesRegex(RuntimeError, 'disposable Linux guest'):
                guest.guard('a' * 32)
        command.assert_not_called(); ordinary.assert_not_called()

    def test_marker_token_and_vm_identity_are_required(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / 'marker.json'
            marker.write_text(json.dumps({'format': 'heltemes-disposable-reboot-vm', 'version': 1, 'token': 'a' * 32}))
            with patch.object(guest.sys, 'platform', 'linux'), patch.object(guest.os, 'geteuid', return_value=0), \
                 patch.object(guest, 'ROOT', guest.INSTALL), patch.object(guest, 'MARKER', marker), \
                 patch.object(guest, 'ordinary'), patch.object(guest, 'command') as command:
                with self.assertRaisesRegex(RuntimeError, 'explicitly marked'):
                    guest.guard('b' * 32)
                command.assert_not_called()
                command.return_value = subprocess.CompletedProcess([], 0, 'docker\n', '')
                with self.assertRaisesRegex(RuntimeError, 'QEMU disposable guest'):
                    guest.guard('a' * 32)

    def test_disk_mount_rejects_tmpfs_and_missing_uuid_or_readonly(self):
        good = {'target': '/', 'source': '/dev/vda1', 'fstype': 'ext4', 'options': 'rw,relatime', 'uuid': 'abc'}
        for changed in ({**good, 'fstype': 'tmpfs'}, {**good, 'uuid': None}, {**good, 'options': 'ro'}):
            response = subprocess.CompletedProcess([], 0, json.dumps({'filesystems': [changed]}), '')
            with patch.object(guest, 'command', return_value=response), self.assertRaisesRegex(RuntimeError, 'persistent disk'):
                guest.storage_info()
        with patch.object(guest, 'command', return_value=subprocess.CompletedProcess([], 0, json.dumps({'filesystems': [good]}), '')):
            self.assertEqual(guest.storage_info(), good)

    def test_service_start_must_be_inside_current_boot_uptime(self):
        self.assertEqual(guest.process_boot_timing({'ExecMainStartTimestampMonotonic': 2_000_000}, 3),
                         {'ExecMainStartTimestampMonotonic': 2_000_000, 'inspected_uptime_seconds': 3})
        for start, uptime in ((0, 3), (4_000_000, 3), (True, 3), (1, 0), (1, float('nan'))):
            with self.subTest(start=start), self.assertRaisesRegex(RuntimeError, 'observed running boot'):
                guest.process_boot_timing({'ExecMainStartTimestampMonotonic': start}, uptime)

    def test_public_inventory_excludes_database_keys_and_private_logs(self):
        self.assertEqual(len(guest.PUBLIC_FILES), len(set(guest.PUBLIC_FILES)))
        self.assertEqual(len(guest.PUBLIC_FILES), 16)
        self.assertEqual(sum(p.endswith('.pcap') for p in guest.PUBLIC_FILES), 6)
        self.assertEqual(len(guest.SOURCE_FILES), 12)
        self.assertFalse(any(s in name for name in guest.PUBLIC_FILES for s in ('sqlite', '.key', 'stderr', 'token')))

    def test_cleanup_does_not_remove_unexpected_unit(self):
        with tempfile.TemporaryDirectory() as temporary:
            unit = Path(temporary) / 'unit.service'; unit.write_text('unexpected')
            with patch.object(guest, 'guard'), patch.object(guest, 'UNIT_FILE', unit), \
                 patch.object(guest, 'ordinary'), patch.object(guest, 'command') as command:
                with self.assertRaisesRegex(RuntimeError, 'unexpected unit'):
                    guest.cleanup('a' * 32)
            command.assert_not_called(); self.assertTrue(unit.exists())


if __name__ == '__main__':
    unittest.main()
