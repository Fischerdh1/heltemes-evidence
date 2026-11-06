"""Portable archive replay checks. Actual packets and OS reboot belong to VM CI."""
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import network_monitor_archive_reboot_guest as guest

spec = importlib.util.spec_from_file_location('archive_reboot_fixture', Path(__file__).with_name('test_network_monitoring_lab.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class NetworkFixture(fixtures.ScenarioFixture):
    def probe(self, *args):
        value = super().probe(*args)
        value['source_port'] = self.next_source_port
        self.next_source_port += 1
        return value


class GuestContractTests(unittest.TestCase):
    def test_harness_refuses_new_observations_and_live_export(self):
        for name in ('observe', 'export', 'initialize'):
            with self.subTest(name=name), patch.object(guest.service, 'request') as request:
                with self.assertRaisesRegex(RuntimeError, 'fabricate'):
                    guest.request(name)
                request.assert_not_called()

    def test_fixed_inventory_and_units_separate_automatic_monitor_from_manual_collector(self):
        self.assertEqual(len(guest.BEFORE_FILES), 13)
        self.assertEqual(len(guest.PUBLIC_FILES), 22)
        self.assertEqual(len(set(guest.PUBLIC_FILES)), 22)
        self.assertEqual(len(guest.SOURCE_FILES), 18)
        self.assertEqual(set(guest.source_hashes()), set(guest.SOURCE_FILES))
        monitor, collector = guest.unit_text(guest.MONITOR_UNIT), guest.unit_text(guest.COLLECTOR_UNIT)
        self.assertIn('RuntimeDirectory=heltemes-archive-reboot-lab', monitor)
        self.assertIn('RestrictAddressFamilies=AF_UNIX', monitor)
        self.assertIn('network_monitor_archive_reboot_guest.py worker', monitor)
        self.assertIn('network_monitor_archive_reboot_collector.py serve', collector)
        self.assertNotIn('Requires=' + guest.MONITOR_UNIT, collector)
        with self.assertRaisesRegex(RuntimeError, 'Unknown'):
            guest.unit_path('unrelated.service')

    def test_guard_refuses_macos_before_reading_installation(self):
        with patch.object(guest.reboot.sys, 'platform', 'darwin'), patch.object(guest.reboot, 'ordinary') as ordinary:
            with self.assertRaisesRegex(RuntimeError, 'disposable Linux'):
                guest.guard('1' * 32)
            ordinary.assert_not_called()

    def test_after_stage_never_starts_monitor_or_reinitializes_archive(self):
        import inspect
        source = inspect.getsource(guest.run_after)
        self.assertNotIn('archive.initialize', source)
        self.assertNotIn("['systemctl', 'start', MONITOR_UNIT]", source)
        self.assertIn("['systemctl', 'start', COLLECTOR_UNIT]", source)

    def statuses(self):
        def status(count, digest):
            return {'committed_count': count, 'head_digest': digest,
                    'current_evaluation': {'status': 'unknown', 'phase': 'collector_missing',
                                           'active_alert_keys': ['telemetry_gap:collector']},
                    'freshness': {'last_accepted_request_id': None}}
        return status(272, 'a' * 64), status(273, 'b' * 64)

    def test_startup_snapshot_retries_freshness_timer_race_without_mixing_heads(self):
        old, new = self.statuses()
        snapshot = {'head_sequence': 273, 'head_digest': 'b' * 64}
        with patch.object(guest, 'request', side_effect=[old, new, new, new]), \
             patch.object(guest, 'readonly_history', return_value=snapshot):
            accepted, actual = guest.startup_snapshot()
        self.assertEqual((accepted, actual), (new, snapshot))

    def test_archived_retry_records_only_independent_missing_gap_race_then_rechecks_stable_head(self):
        old, new = self.statuses()
        first = {'request': {'command': 'observe', 'request_id': 'old'}, 'committed_sequence': 2, 'evaluation': {'sequence': 2}}
        result = {'ok': True, 'duplicate': True, 'committed_sequence': 2, 'evaluation': first['evaluation']}
        gap = {'sequence': 273, 'row_digest': 'b' * 64, 'previous_digest': 'a' * 64,
               'sample': {'phase': 'collector_missing', 'collection_error': 'freshness_deadline_exceeded', 'ruleset': None, 'probes': []},
               'evaluation': {'status': 'unknown'}}
        snapshot = {'head_sequence': 273, 'head_digest': 'b' * 64, 'rows': [gap]}
        with patch.object(guest, 'request', side_effect=[old, new, new, new]), \
             patch.object(guest, 'readonly_history', return_value=snapshot), \
             patch.object(guest.service, 'request', return_value=result) as request:
            accepted = guest.archived_retry(first)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(accepted['before_status'], accepted['after_status'])
        self.assertEqual(len(accepted['independent_gap_during_prior_attempt']), 1)
        gap['sample']['phase'] = 'fabricated_sample'
        with patch.object(guest, 'request', side_effect=[old, new]), \
             patch.object(guest, 'readonly_history', return_value=snapshot), \
             patch.object(guest.service, 'request', return_value=result):
            with self.assertRaisesRegex(RuntimeError, 'unexpectedly changed'):
                guest.archived_retry(first)


class ReplayAcrossRestartTests(unittest.TestCase):
    """One finite synthetic fixture exercises the real journal, service and collector."""
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='archive-reboot-fixture-')
        cls.directory = Path(cls.temporary.name).resolve()
        cls.state, cls.private = cls.directory / 'state', cls.directory / 'collector'
        cls.private.mkdir(mode=0o700)
        cls.boots = {'before': '11111111-1111-4111-8111-111111111111', 'after': '22222222-2222-4222-8222-222222222222'}
        cls.storage = {'target': '/', 'source': '/dev/vda1', 'fstype': 'ext4', 'uuid': 'test-disk', 'options': 'rw'}
        cls.hashes = {'scripts/test.py': 'a' * 64}
        first_lab = NetworkFixture()
        guest.archive.initialize(cls.state, first_lab.ruleset(), segment_rows=128, max_rows=2048)
        records = []
        with guest.archive.ArchiveJournal(cls.state) as journal:
            worker = guest.service.Service(journal, freshness_seconds=20)
            allocation = guest.collector.Allocation(cls.private)
            try:
                producer = guest.collector.Collector(first_lab, allocation, state=cls.state, boot_id=cls.boots['before'], phase='before')
                with patch.object(guest.collector.service, 'request', side_effect=lambda state, payload, **kw: worker.dispatch(payload)):
                    for cycle in range(1, 271):
                        if cycle == 4:
                            first_lab.apply_policy('misconfigured')
                        records.append(producer.collect())
                cls.before_history = journal.export()
                cls.before_status = worker.status()
            finally:
                allocation.close()
        cls.segment_bytes = {p.name: p.read_bytes() for p in (cls.state / 'archives').glob('segment-*.json')}
        with patch.object(guest.reboot, 'ordinary', side_effect=lambda p, **kw: p.stat()):
            cls.before = {'boot': {'boot_id': cls.boots['before']}, 'storage': cls.storage, 'source_sha256': cls.hashes,
                'manager': {'InvocationID': '1' * 32}, 'final_status': cls.before_status,
                'critical_incident_id': guest.reboot.critical(cls.before_status)['id'],
                'archive_files': [{'public_name': guest.ARCHIVE_FILES[index - 1], **guest.file_proof(cls.state / 'archives' / f'segment-{index:06d}.json')}
                                  for index in (1, 2)]}
        with guest.archive.ArchiveJournal(cls.state) as journal:
            worker = guest.service.Service(journal, freshness_seconds=20)
            cls.startup = worker.status()
            with patch.object(guest, 'STATE', cls.state), patch.object(guest.reboot, 'ordinary', side_effect=lambda p, **kw: p.stat()):
                cls.snapshot = guest.readonly_history()
                database_before = hashlib.sha256((cls.state / 'monitor.sqlite3').read_bytes()).hexdigest()
                guest.readonly_history()
                cls.database_after_read = hashlib.sha256((cls.state / 'monitor.sqlite3').read_bytes()).hexdigest()
                cls.database_before_read = database_before
                with patch.object(guest, 'request', side_effect=lambda name: worker.status()), \
                     patch.object(guest.service, 'request', side_effect=lambda state, payload, **kw: worker.dispatch(payload)):
                    cls.retry = guest.archived_retry(records[0])
            second_lab = NetworkFixture()
            allocation = guest.collector.Allocation(cls.private)
            try:
                producer = guest.collector.Collector(second_lab, allocation, state=cls.state, boot_id=cls.boots['after'], phase='after')
                with patch.object(guest.collector.service, 'request', side_effect=lambda state, payload, **kw: worker.dispatch(payload)):
                    for unused in range(130):
                        records.append(producer.collect())
                cls.after_history = journal.export()
                cls.final = worker.status()
            finally:
                allocation.close()
        cls.records = records

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def verify(self, **changes):
        values = {'before': self.before, 'before_history': self.before_history, 'boot': {'boot_id': self.boots['after']},
                  'status': self.startup, 'properties': {'InvocationID': '2' * 32}, 'snapshot': self.snapshot,
                  'storage': self.storage, 'hashes': self.hashes}
        values.update(changes)
        with patch.object(guest, 'STATE', self.state), patch.object(guest, 'VOLATILE', self.directory / 'absent-marker'), \
             patch.object(guest.reboot, 'ordinary', side_effect=lambda p, **kw: p.stat()):
            guest.verify_reboot(**values)

    def test_archive_identity_prefix_and_two_original_segment_bytes_survive_restart(self):
        self.verify()
        self.assertEqual(len(self.before_history['rows']), 271)
        self.assertEqual(len(self.after_history['rows']), 402)
        self.assertEqual(self.after_history['rows'][:271], self.before_history['rows'])
        self.assertEqual(self.after_history['identity'], self.before_history['identity'])
        for name, raw in self.segment_bytes.items():
            self.assertEqual((self.state / 'archives' / name).read_bytes(), raw)
        self.assertEqual(len(self.after_history['archive_descriptors']), 3)
        self.assertLess(len(guest.store.encoded(self.after_history).encode()), 16 * 1024 * 1024)

    def test_readonly_sql_snapshot_has_exact_active_prefix_and_does_not_write_database(self):
        self.assertEqual(self.snapshot['rows'][:15], self.before_history['rows'][256:])
        self.assertEqual(self.snapshot['rows'][-1]['request']['kind'], 'restart')
        self.assertEqual(self.snapshot['head_sequence'], 272)
        self.assertEqual(self.database_before_read, self.database_after_read)

    def test_restart_resets_counter_reference_and_only_fresh_canaries_resolve_original_incident(self):
        first, second, canaries = self.records[270:273]
        for record in (first, second):
            self.assertEqual(record['request']['observation']['probes'], [])
            self.assertIn(guest.reboot.CRITICAL, record['evaluation']['active_alert_keys'])
        self.assertTrue(all(v is None for v in first['evaluation']['counter_deltas'].values()))
        self.assertTrue(second['evaluation']['telemetry_valid'])
        self.assertEqual(canaries['evaluation']['status'], 'healthy')
        resolutions = [e for e in self.after_history['events'] if e['key'] == guest.reboot.CRITICAL and e['action'] == 'resolved']
        self.assertEqual(len(resolutions), 1)
        self.assertEqual(resolutions[0]['sequence'], canaries['committed_sequence'])
        self.assertEqual(self.final['current_evaluation']['status'], 'healthy')

    def test_archived_duplicate_does_not_renew_current_boot_freshness(self):
        self.assertTrue(self.retry['result']['duplicate'])
        self.assertEqual(self.retry['result']['committed_sequence'], 2)
        self.assertEqual(self.retry['before_status']['head_digest'], self.retry['after_status']['head_digest'])
        self.assertIsNone(self.retry['after_status']['freshness']['last_accepted_request_id'])
        self.assertEqual(self.retry['after_status']['current_evaluation']['status'], 'unknown')

    def test_global_cycle_boot_identity_and_source_port_inventory_accepts_exact_receipts(self):
        probes = guest.validate_inventory(self.after_history, self.records, self.boots)
        self.assertEqual(len({p['source_port'] for p in probes}), len(probes))

    def test_same_boot_source_filesystem_or_invocation_substitution_fails(self):
        for change, message in (
            ({'boot': self.before['boot']}, 'full Linux'),
            ({'hashes': {'scripts/test.py': 'b' * 64}}, 'source changed'),
            ({'storage': {**self.storage, 'uuid': 'wrong'}}, 'filesystem'),
            ({'properties': self.before['manager']}, 'new boot'),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                self.verify(**change)

    def test_mutated_active_prefix_identity_and_descriptor_fail(self):
        for field, message in (('rows', 'prefix'), ('identity', 'identity'), ('segments', 'descriptors')):
            snapshot = copy.deepcopy(self.snapshot)
            if field == 'rows':
                snapshot['rows'][0]['row_digest'] = 'f' * 64
            elif field == 'identity':
                snapshot['identity']['database_id'] = 'f' * 32
            else:
                snapshot['segments'][0]['file_digest'] = 'f' * 64
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, message):
                self.verify(snapshot=snapshot)

    def test_changed_producer_boot_or_reused_port_receipt_is_rejected(self):
        altered = copy.deepcopy(self.records)
        altered[270]['boot_id'] = self.boots['before']
        with self.assertRaisesRegex(RuntimeError, 'unexpected boot'):
            guest.validate_inventory(self.after_history, altered, self.boots)
        altered = copy.deepcopy(self.records)
        altered[272]['request']['observation']['probes'][0]['source_port'] = altered[2]['request']['observation']['probes'][0]['source_port']
        with self.assertRaisesRegex(RuntimeError, 'differs from committed'):
            guest.validate_inventory(self.after_history, altered, self.boots)


if __name__ == '__main__':
    unittest.main()
