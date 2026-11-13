"""Finite boot-bound collection, durable allocation, and exact historical retry."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import network_monitor_archive as archive
from scripts import network_monitor_archive_reboot_collector as collector
from test_network_monitor import ruleset

BOOT_A = '12345678-1234-1234-1234-123456789abc'
BOOT_B = '87654321-4321-4321-4321-cba987654321'


class ArchivedRebootCollectorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.directory.chmod(0o700)

    def allocation(self):
        value = collector.Allocation(self.directory)
        self.addCleanup(value.close)
        return value

    def lab(self):
        lab = Mock()
        lab.ruleset.return_value = ruleset()
        def probe(source, target, port):
            value = {'from': source, 'to': target, 'port': port, 'source_port': lab.next_source_port,
                     'outcome': 'connect_timeout' if (source, target, port) == ('user', 'app', 9090) else 'response'}
            lab.next_source_port += 1
            return value
        lab.probe.side_effect = probe
        return lab

    def worker(self, *, allocation=None, boot_id=BOOT_A, phase='before'):
        return collector.Collector(self.lab(), allocation or self.allocation(), boot_id=boot_id,
                                   phase=phase, state=self.directory / 'journal')

    def response(self, payload, *, duplicate=False):
        cycle = int(payload['request_id'].rsplit('_', 1)[1])
        return {'ok': True, 'duplicate': duplicate, 'committed_sequence': cycle + 1,
                'evaluation': {'status': 'healthy' if payload['observation']['probes'] else 'unknown'}}

    def transport(self, state, payload, **_):
        return self.response(payload)

    def test_config_requires_exact_current_boot_and_finite_phase_boundary(self):
        config = {'version': 1, 'interval_seconds': 1.0, 'canary_every': 16, 'max_cycles': 512,
                  'namespaces': {r: 'he-seg-0123456789-' + r for r in ('user', 'app', 'management', 'router')},
                  'boot_id': BOOT_A, 'phase': 'before', 'stop_after_cycle': 270}
        self.assertEqual(collector.validate_config(config, boot_id=BOOT_A), config['namespaces'])
        with self.assertRaisesRegex(RuntimeError, 'earlier boot'):
            collector.validate_config(config, boot_id=BOOT_B)
        for key, value in (('stop_after_cycle', 400), ('phase', 'any'), ('max_cycles', 10000),
                           ('interval_seconds', 5), ('boot_id', ''), ('version', True), ('canary_every', True)):
            invalid = copy.deepcopy(config); invalid[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                collector.validate_config(invalid)
        config.update(phase='after', stop_after_cycle=400, boot_id=BOOT_B)
        self.assertEqual(collector.validate_config(config, boot_id=BOOT_B), config['namespaces'])

    def test_global_port_reservations_continue_exactly_and_are_bounded(self):
        allocation = self.allocation()
        reservations = [allocation.reserve() for _ in range(collector.MAX_CYCLES)]
        self.assertEqual(reservations[269], (270, 43614))
        self.assertEqual(reservations[270], (271, 43620))
        self.assertEqual(reservations[399], (400, 44394))
        self.assertEqual(allocation.read(), {'cycles': 512, 'next_port': 45072})
        self.assertEqual(len({port for _, port in reservations}), 512)
        self.assertLess(allocation.read()['next_port'], 50000)
        with self.assertRaisesRegex(RuntimeError, 'exhausted'):
            allocation.reserve()

    def test_allocation_rejects_rewound_or_boolean_port_values(self):
        allocation = self.allocation()
        for value in ({'cycles': 10, 'next_port': 42000}, {'cycles': True, 'next_port': 42006},
                      {'cycles': 513, 'next_port': 45078}):
            collector.ordinary.replace_private(allocation.path, value)
            with self.subTest(value=value), self.assertRaisesRegex(RuntimeError, 'invalid'):
                allocation.reserve()

    def test_first_two_samples_in_each_process_are_rules_only(self):
        first = self.worker()
        with patch.object(collector.service, 'request', side_effect=self.transport):
            records = [first.collect() for _ in range(18)]
        self.assertEqual([r['cycle'] for r in records if r['request']['observation']['probes']], [3, 16])
        self.assertEqual(first.lab.ruleset.call_count, 18)
        # A replacement does not reuse the previous process's baseline cadence.
        second = self.worker(allocation=first.allocation, boot_id=BOOT_B)
        with patch.object(collector.service, 'request', side_effect=self.transport):
            restarted = [second.collect() for _ in range(3)]
        self.assertEqual([r['cycle'] for r in restarted], [19, 20, 21])
        self.assertEqual([r['process_cycle'] for r in restarted], [1, 2, 3])
        self.assertEqual([bool(r['request']['observation']['probes']) for r in restarted], [False, False, True])
        self.assertTrue(all(r['boot_id'] == BOOT_B == r['delivery_boot_id'] for r in restarted))

    def test_postboot_cadence_starts_with_two_baselines_and_ends_on_full_canaries(self):
        self.assertFalse(collector.canary_cycle(271, 1))
        self.assertFalse(collector.canary_cycle(272, 2))
        self.assertTrue(collector.canary_cycle(273, 3))
        self.assertTrue(collector.canary_cycle(288, 18))
        self.assertTrue(collector.canary_cycle(400, 130))

    def test_lost_ack_retries_identical_payload_without_resending_probes(self):
        worker = self.worker()
        with patch.object(collector.service, 'request', side_effect=self.transport):
            worker.collect(); worker.collect()
        sent = []
        def request(state, payload, **_):
            sent.append(copy.deepcopy(payload))
            self.assertEqual(json.loads(worker.pending.read_text())['request'], payload)
            if len(sent) == 1:
                raise ConnectionResetError('lost acknowledgement')
            return self.response(payload, duplicate=True)
        with patch.object(collector.service, 'request', side_effect=request), patch.object(collector.time, 'sleep'):
            receipt = worker.collect()
        self.assertEqual(sent[0], sent[1])
        self.assertEqual(worker.lab.ruleset.call_count, 3)
        self.assertEqual(worker.lab.probe.call_count, 4)
        self.assertEqual(receipt['transport_failures'], ['ConnectionResetError'])
        self.assertTrue(receipt['duplicate_acknowledgement'])
        self.assertFalse(worker.pending.exists())

    def test_transient_rejection_retries_the_same_durable_observation(self):
        worker = self.worker()
        for reason in sorted(collector.service.RETRYABLE_REJECTIONS):
            with self.subTest(reason=reason):
                pending = worker.prepare()
                expected_request = collector.store.encoded(pending['request'])
                attempts = []

                def transport(state, payload, **options):
                    attempts.append(collector.store.encoded(payload))
                    self.assertEqual(json.loads(worker.pending.read_text()), pending)
                    if len(attempts) == 1:
                        return {'ok': False, 'error': 'request_rejected', 'reason': reason}
                    return self.transport(state, payload, **options)

                with patch.object(collector.service, 'request', side_effect=transport), patch.object(collector.time, 'sleep'):
                    receipt = worker.collect()
                self.assertEqual(attempts, [expected_request, expected_request])
                self.assertEqual(receipt['delivery_attempts'], 2)
                self.assertEqual(receipt['transport_failures'], [reason])
                self.assertFalse(worker.pending.exists())

    def test_retry_diagnostic_has_only_bounded_categories_not_private_error_text(self):
        import errno
        diagnostic = collector.transport_diagnostic(PermissionError(errno.EACCES, 'private token value', '/private/key'))
        self.assertEqual(diagnostic, {'error_type': 'PermissionError', 'errno': errno.EACCES, 'reason': 'os_error'})
        self.assertEqual(collector.transport_diagnostic(ValueError('Connection closed before a complete response.'))['reason'],
                         'incomplete_response')
        self.assertEqual(collector.transport_diagnostic(ValueError('arbitrary private response'))['reason'], 'invalid_response')

    def test_retry_deadline_retains_pending_and_reports_stuck_cycle_and_reason(self):
        worker = self.worker()
        pending = worker.prepare()
        # Inject elapsed time, not a longer production request timeout.
        with patch.object(collector.service, 'request', side_effect=TimeoutError('private text')) as request, \
             patch.object(collector.time, 'monotonic', side_effect=[10.0, 56.0]):
            with self.assertRaisesRegex(RuntimeError, '"reason":"timeout"') as caught:
                worker.collect()
        request.assert_called_once_with(worker.state, pending['request'], timeout=3)
        self.assertNotIn('private text', str(caught.exception))
        self.assertEqual(json.loads(worker.pending.read_text()), pending)
        diagnostic = json.loads((self.directory / 'transport.json').read_text())
        self.assertEqual(diagnostic, {'cycle': 1, 'attempts': 1, 'deadline_exceeded': True,
                                     'error_type': 'TimeoutError', 'errno': None, 'reason': 'timeout'})
        self.assertEqual(list(self.directory.glob('receipt-*.json')), [])

    def test_preboot_run_completes_exact_durable_boundary_with_no_pending(self):
        worker = self.worker()
        collector.ordinary.replace_private(worker.allocation.path, {'cycles': 269, 'next_port': 43614})
        with patch.object(collector.service, 'request', side_effect=self.transport):
            worker.run()
        runtime = json.loads((self.directory / 'runtime.json').read_text())
        self.assertEqual(runtime['state'], 'complete')
        self.assertEqual(runtime['cycle'], 270)
        self.assertEqual(runtime['boot_id'], BOOT_A)
        self.assertEqual(worker.allocation.read(), {'cycles': 270, 'next_port': 43620})
        self.assertFalse(worker.pending.exists())
        with self.assertRaisesRegex(RuntimeError, 'unfinished phase'):
            self.worker(allocation=worker.allocation).run()

    def test_after_phase_refuses_missing_preboot_allocation(self):
        worker = self.worker(phase='after', boot_id=BOOT_B)
        with self.assertRaisesRegex(RuntimeError, 'unfinished phase'):
            worker.run()
        worker.lab.ruleset.assert_not_called()

    def test_pending_requires_exact_durable_reservation_and_is_never_regenerated(self):
        worker = self.worker()
        pending = worker.prepare()
        collector.ordinary.replace_private(worker.allocation.path, {'cycles': 2, 'next_port': 42012})
        with self.assertRaisesRegex(RuntimeError, 'durable allocation'):
            worker.prepare()
        self.assertEqual(json.loads(worker.pending.read_text()), pending)
        self.assertEqual(worker.lab.ruleset.call_count, 1)

    def test_committed_archived_pending_survives_startup_without_renewing_freshness(self):
        worker = self.worker()
        archive.initialize(worker.state, ruleset(), segment_rows=32, max_rows=128)
        pending = None
        with archive.ArchiveJournal(worker.state) as journal:
            original = collector.service.Service(journal, freshness_seconds=20)
            pending = worker.prepare()
            acknowledged = original.dispatch(pending['request'])
            self.assertFalse(acknowledged['duplicate'])
            for number in range(30):
                payload = {'command': 'observe', 'request_id': f'other-{number}',
                           'observation': {'phase': f'other-{number}', 'observed_at_utc': collector.reboot.timestamp(),
                                           'ruleset': ruleset(), 'probes': [], 'collection_error': None}}
                original.dispatch(payload)
            self.assertEqual(journal.status()['archives']['sealed_segments'], 1)
        replacement = self.worker(allocation=worker.allocation, boot_id=BOOT_B)
        with archive.ArchiveJournal(worker.state) as journal:
            restarted = collector.service.Service(journal, freshness_seconds=20)
            before = restarted.status()
            with patch.object(collector.service, 'request', side_effect=lambda state, payload, **_: restarted.dispatch(payload)):
                receipt = replacement.collect()
            for key in ('committed_count', 'head_digest', 'current_evaluation', 'alerts'):
                self.assertEqual(restarted.status()[key], before[key])
            self.assertEqual(restarted.status()['current_evaluation']['status'], 'unknown')
            self.assertIsNone(restarted.last_accepted)
        self.assertEqual(receipt['request'], pending['request'])
        self.assertEqual(receipt['boot_id'], BOOT_A)
        self.assertEqual(receipt['delivery_boot_id'], BOOT_B)
        self.assertTrue(receipt['duplicate_acknowledgement'])
        self.assertEqual(receipt['committed_sequence'], 2)
        replacement.lab.ruleset.assert_not_called()
        replacement.lab.probe.assert_not_called()

    def test_uncommitted_old_pending_is_rejected_after_startup_and_preserved_exactly(self):
        worker = self.worker()
        archive.initialize(worker.state, ruleset(), segment_rows=32, max_rows=128)
        with archive.ArchiveJournal(worker.state) as journal:
            collector.service.Service(journal, freshness_seconds=20)
            pending = worker.prepare()
        replacement = self.worker(allocation=worker.allocation, boot_id=BOOT_B)
        with archive.ArchiveJournal(worker.state) as journal:
            restarted = collector.service.Service(journal, freshness_seconds=20)
            before = restarted.status()
            with self.assertRaisesRegex(ValueError, 'boundary'):
                restarted.dispatch(pending['request'])
            def transport(state, payload, **_):
                try:
                    return restarted.dispatch(payload)
                except ValueError:
                    return {'ok': False, 'error': 'request_rejected'}
            with patch.object(collector.service, 'request', side_effect=transport):
                with self.assertRaisesRegex(RuntimeError, 'rejected'):
                    replacement.collect()
            for key in ('committed_count', 'head_digest', 'current_evaluation', 'alerts'):
                self.assertEqual(restarted.status()[key], before[key])
        self.assertEqual(json.loads(worker.pending.read_text()), pending)
        self.assertEqual(list(self.directory.glob('receipt-*.json')), [])
        replacement.lab.ruleset.assert_not_called()

    def test_existing_receipt_survives_duplicate_pending_after_new_boot(self):
        worker = self.worker()
        pending = worker.prepare()
        with patch.object(collector.service, 'request', side_effect=self.transport):
            receipt = worker.collect()
        collector.ordinary.replace_private(worker.pending, pending)
        replacement = self.worker(allocation=worker.allocation, boot_id=BOOT_B)
        with patch.object(collector.service, 'request', side_effect=lambda state, payload, **_: self.response(payload, duplicate=True)):
            actual = replacement.collect()
        self.assertEqual(actual, receipt)
        self.assertEqual(actual['delivery_boot_id'], BOOT_A)
        self.assertFalse(worker.pending.exists())


    def test_run_deadline_crossing_and_missed_slots_preserve_cadence(self):
        allocation = self.allocation()
        interval = collector.INTERVAL
        due = 10.0 + interval
        late = 10.0 + 3.25 * interval
        scenarios = [
            ('crossed_deadline', [10.0, 10.0, 10.0, due - 0.05, due + 0.05, due + 0.05],
             [0.05], due, due + interval),
            ('exact_deadline', [10.0, 10.0, 10.0, due, due], [], due, due + interval),
            ('capped_wait', [10.0, 10.0, 10.0, due - 0.5, due, due],
             [0.1], due, due + interval),
            ('missed_slots', [10.0, 10.0, late, late, late, late, 10.0 + 4 * interval,
                              10.0 + 4 * interval], [], 10.0 + 4 * interval, 10.0 + 5 * interval),
        ]
        for name, clock, expected_sleeps, second_due, next_due in scenarios:
            with self.subTest(name=name):
                worker = self.worker(allocation=allocation)
                collection_dues, sleeps = [], []
                def collect_then_stop():
                    runtime = json.loads((self.directory / 'runtime.json').read_text())
                    collection_dues.append(runtime['next_due_monotonic'])
                    if len(collection_dues) == 2:
                        worker.stop()
                    return {'committed_sequence': len(collection_dues) + 1, 'cycle': len(collection_dues),
                            'completed_at_utc': 'timestamp', 'evaluation': {'status': 'healthy'}}
                def checked_sleep(duration):
                    # A plain sleep mock would hide the original negative-duration exception.
                    if duration < 0:
                        raise ValueError('sleep length must be non-negative')
                    self.assertGreater(duration, 0)
                    self.assertLessEqual(duration, 0.1)
                    sleeps.append(duration)
                with patch.object(worker, 'collect', side_effect=collect_then_stop), \
                     patch.object(collector.time, 'monotonic', side_effect=clock), \
                     patch.object(collector.time, 'sleep', side_effect=checked_sleep):
                    worker.run()
                self.assertEqual(collection_dues, [10.0, second_due])
                self.assertEqual(len(sleeps), len(expected_sleeps))
                for actual, expected in zip(sleeps, expected_sleeps):
                    self.assertAlmostEqual(actual, expected)
                runtime = json.loads((self.directory / 'runtime.json').read_text())
                self.assertEqual(runtime['state'], 'idle')
                self.assertEqual(runtime['next_due_monotonic'], next_due)
                self.assertEqual(runtime['committed_sequence'], 3)


if __name__ == '__main__':
    unittest.main()
