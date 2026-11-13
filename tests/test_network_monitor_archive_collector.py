"""Bounded archive collection and exact lost-acknowledgement retry checks."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import network_monitor_archive_collector as collector


class ArchiveCollectorTests(unittest.TestCase):
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
        lab.ruleset.return_value = {'nftables': ['real adapter return placeholder']}
        def probe(source, target, port):
            result = {'from': source, 'to': target, 'port': port, 'source_port': lab.next_source_port,
                      'outcome': 'connect_timeout' if (source, target, port) == ('user', 'app', 9090) else 'response'}
            lab.next_source_port += 1
            return result
        lab.probe.side_effect = probe
        return lab

    def response(self, payload, *, duplicate=False):
        cycle = int(payload['request_id'].rsplit('_', 1)[1])
        return {'ok': True, 'duplicate': duplicate, 'committed_sequence': cycle + 1,
                'evaluation': {'status': 'healthy' if payload['observation']['probes'] else 'unknown'}}

    def test_extended_reservations_are_durable_bounded_and_below_namespace_port_limit(self):
        allocation = self.allocation()
        reservations = [allocation.reserve() for _ in range(collector.MAX_CYCLES)]
        self.assertEqual(reservations[0], (1, 42000))
        self.assertEqual(reservations[256], (257, 43536))
        self.assertLess(reservations[-1][1] + collector.PORT_BLOCK, 50000)
        with self.assertRaisesRegex(RuntimeError, 'exhausted'):
            allocation.reserve()
        self.assertEqual(json.loads(allocation.path.read_text())['cycles'], 320)

    def test_schedule_has_real_rules_every_cycle_and_full_sparse_canaries(self):
        worker = collector.Collector(self.lab(), self.allocation(), state=self.directory)
        records = []
        with patch.object(collector.service, 'request', side_effect=lambda state, payload, **kwargs: self.response(payload)):
            for _ in range(18):
                records.append(worker.collect())
        self.assertEqual(worker.lab.ruleset.call_count, 18)
        self.assertEqual([r['cycle'] for r in records if r['request']['observation']['probes']], [2, 16])
        self.assertEqual(worker.lab.probe.call_count, 8)
        self.assertEqual(records[1]['request']['observation']['probes'][1]['destination_health']['from'], 'app')
        self.assertFalse(worker.pending.exists())

    def test_lost_ack_retries_exact_persisted_payload_without_resending_packets(self):
        worker = collector.Collector(self.lab(), self.allocation(), state=self.directory)
        # Move to a full canary cycle so packet duplication would be observable.
        worker.allocation.reserve()
        sent = []
        def transport(state, payload, **kwargs):
            sent.append(copy.deepcopy(payload))
            self.assertEqual(json.loads(worker.pending.read_text())['request'], payload)
            if len(sent) == 1:
                raise ConnectionResetError('monitor crashed after commit')
            return self.response(payload, duplicate=True)
        with patch.object(collector.service, 'request', side_effect=transport), patch.object(collector.time, 'sleep'):
            receipt = worker.collect()
        self.assertEqual(sent[0], sent[1])
        self.assertEqual(worker.lab.ruleset.call_count, 1)
        self.assertEqual(worker.lab.probe.call_count, 4)
        self.assertTrue(receipt['duplicate_acknowledgement'])
        self.assertEqual(receipt['delivery_attempts'], 2)
        self.assertEqual(receipt['transport_failures'], ['ConnectionResetError'])
        self.assertFalse(worker.pending.exists())
        self.assertEqual(json.loads((self.directory / 'receipt-0003.json').read_text()), receipt)

    def test_replacement_collector_preserves_pending_source_time_and_producer_identity(self):
        first = collector.Collector(self.lab(), self.allocation(), state=self.directory)
        pending = first.prepare()
        replacement = collector.Collector(self.lab(), first.allocation, state=self.directory)
        with patch.object(collector.service, 'request', side_effect=lambda state, payload, **kwargs: self.response(payload, duplicate=True)):
            receipt = replacement.collect()
        self.assertEqual(receipt['request'], pending['request'])
        self.assertEqual(receipt['instance_id'], first.instance_id)
        self.assertNotEqual(replacement.instance_id, first.instance_id)
        replacement.lab.ruleset.assert_not_called()
        replacement.lab.probe.assert_not_called()
        self.assertEqual(json.loads(first.allocation.path.read_text())['cycles'], 1)

    def test_rejected_old_sample_is_retained_without_forging_time_or_success(self):
        worker = collector.Collector(self.lab(), self.allocation(), state=self.directory)
        pending = worker.prepare()
        with patch.object(collector.service, 'request', return_value={'ok': False}):
            with self.assertRaisesRegex(RuntimeError, 'rejected'):
                worker.collect()
        self.assertEqual(json.loads(worker.pending.read_text()), pending)
        self.assertEqual(list(self.directory.glob('receipt-*.json')), [])

    def test_retry_failure_categories_do_not_include_private_exception_text(self):
        import errno
        value = collector.transport_diagnostic(PermissionError(errno.EACCES, 'private value', '/private/key'))
        self.assertEqual(value, {'error_type': 'PermissionError', 'errno': errno.EACCES, 'reason': 'os_error'})
        self.assertEqual(collector.transport_diagnostic(ValueError('Connection closed before a complete response.'))['reason'],
                         'incomplete_response')
        self.assertEqual(collector.transport_diagnostic(ValueError('private response'))['reason'], 'invalid_response')

    def test_retry_deadline_reports_stuck_cycle_without_changing_payload_or_timeout(self):
        worker = collector.Collector(self.lab(), self.allocation(), state=self.directory)
        pending = worker.prepare()
        with patch.object(collector.service, 'request', side_effect=TimeoutError('private text')) as request, \
             patch.object(collector.time, 'monotonic', side_effect=[10.0, 56.0]):
            with self.assertRaisesRegex(RuntimeError, '"reason":"timeout"') as caught:
                worker.collect()
        request.assert_called_once_with(worker.state, pending['request'], timeout=3)
        self.assertNotIn('private text', str(caught.exception))
        self.assertIn('"cycle":1', str(caught.exception))
        self.assertIn('"attempts":1', str(caught.exception))
        self.assertEqual(json.loads(worker.pending.read_text()), pending)
        self.assertEqual(list(self.directory.glob('receipt-*.json')), [])

    def test_valid_receipt_survives_crash_before_pending_removal(self):
        worker = collector.Collector(self.lab(), self.allocation(), state=self.directory)
        pending = worker.prepare()
        with patch.object(collector.service, 'request', side_effect=lambda state, payload, **kwargs: self.response(payload)):
            receipt = worker.collect()
        collector.ordinary.replace_private(worker.pending, pending)
        with patch.object(collector.service, 'request', side_effect=lambda state, payload, **kwargs: self.response(payload, duplicate=True)):
            retried = worker.collect()
        self.assertEqual(retried, receipt)
        self.assertFalse(worker.pending.exists())
        self.assertEqual(worker.lab.ruleset.call_count, 1)

    def test_autonomous_finish_freezes_first_full_healthy_cycle_after_minimum(self):
        worker = collector.Collector(self.lab(), self.allocation(), state=self.directory)
        receipt = {'committed_sequence': 275, 'cycle': 272, 'evaluation': {'status': 'healthy'},
                   'completed_at_utc': '2026-11-05T00:00:00+00:00'}
        with patch.object(worker, 'collect', return_value=receipt) as collect:
            worker.run()
        collect.assert_called_once()
        self.assertTrue(worker.stopping)
        self.assertEqual(json.loads((self.directory / 'runtime.json').read_text())['state'], 'idle')

    def test_explicit_archive_configuration_does_not_accept_ordinary_defaults(self):
        config = {'version': 1, 'interval_seconds': 1.0, 'canary_every': 16, 'max_cycles': 320,
                  'namespaces': {r: 'he-seg-0123456789-' + r for r in ('user', 'app', 'management', 'router')}}
        self.assertEqual(collector.validate_config(config), config['namespaces'])
        for key, value in (('interval_seconds', 5), ('canary_every', 1), ('max_cycles', 10000)):
            invalid = copy.deepcopy(config); invalid[key] = value
            with self.assertRaises(RuntimeError):
                collector.validate_config(invalid)


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
                worker = collector.Collector(self.lab(), allocation, state=self.directory)
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
