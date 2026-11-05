"""Portable checks for collector allocation, real adapter calls, and process identity."""
import copy
import json
import os
from pathlib import Path
import tempfile
import subprocess
import unittest
from unittest.mock import Mock, patch

from scripts import network_monitor_collector as collector


class CollectorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()
        self.directory.chmod(0o700)

    def allocation(self):
        value = collector.Allocation(self.directory)
        self.addCleanup(value.close)
        return value

    def test_ports_are_reserved_durably_before_use_and_across_restart(self):
        first = collector.Allocation(self.directory)
        self.assertEqual(first.reserve(), 42000)
        self.assertEqual(json.loads((self.directory / 'allocation.json').read_text()), {'next_port': 42006, 'cycles': 1})
        first.close()  # An unused reservation is deliberately skipped after a crash.
        second = self.allocation()
        self.assertEqual(second.reserve(), 42006)
        self.assertEqual(second.reserve(), 42012)

    def test_single_writer_and_malformed_or_linked_allocations_are_refused(self):
        first = self.allocation()
        with self.assertRaises(BlockingIOError):
            collector.Allocation(self.directory)
        first.reserve()
        collector.replace_private(self.directory / 'allocation.json', {'next_port': 42000, 'cycles': 1})
        with self.assertRaisesRegex(RuntimeError, 'invalid'):
            first.reserve()
        (self.directory / 'allocation.json').unlink()
        (self.directory / 'target').write_text('{}')
        (self.directory / 'allocation.json').symlink_to('target')
        with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
            first.reserve()

    def test_reservation_failure_prevents_packets(self):
        lab, allocation = Mock(), Mock()
        allocation.reserve.side_effect = RuntimeError('disk unavailable')
        worker = collector.Collector(lab, allocation)
        with self.assertRaisesRegex(RuntimeError, 'disk unavailable'):
            worker.collect()
        lab.probe.assert_not_called()
        lab.ruleset.assert_not_called()

    def test_config_limits_namespaces_to_one_synthetic_lab(self):
        config = {'version': 1, 'interval_seconds': 5.0,
                  'namespaces': {r: 'he-seg-0123456789-' + r for r in ('user', 'app', 'management', 'router')}}
        self.assertEqual(collector.validate_config(config), config['namespaces'])
        for key, value in [('interval_seconds', 0), ('namespaces', {'router': 'default'})]:
            invalid = copy.deepcopy(config); invalid[key] = value
            with self.assertRaises(RuntimeError):
                collector.validate_config(invalid)
        invalid = copy.deepcopy(config); invalid['namespaces']['user'] = 'he-seg-9876543210-user'
        with self.assertRaisesRegex(RuntimeError, 'different labs'):
            collector.validate_config(invalid)

    def test_attached_reader_uses_delegated_names_without_namespace_ownership(self):
        config = {'version': 1, 'interval_seconds': 5.0,
                  'namespaces': {r: 'he-seg-0123456789-' + r for r in ('user', 'app', 'management', 'router')}}
        tools = {'ip': '/tools/ip', 'nft': '/tools/nft'}
        lab = collector.AttachedLab(tools, self.directory, config)
        self.assertEqual(lab.created_names, [])
        # Exercise the real ruleset -> run_in -> namespace_command chain. The
        # previous constructor-only mock hid the empty-created_names failure.
        with patch.object(collector.reboot.base.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '{"nftables": []}', '')) as run:
            self.assertEqual(lab.ruleset(), {'nftables': []})
        self.assertEqual(run.call_args.args[0], ['/tools/ip', 'netns', 'exec', config['namespaces']['router'],
                                               '/tools/nft', '-j', '-a', 'list', 'ruleset'])
        with self.assertRaisesRegex(RuntimeError, 'cannot create'):
            lab.setup()
        with self.assertRaisesRegex(RuntimeError, 'does not own'):
            lab.cleanup()
        with self.assertRaisesRegex(RuntimeError, 'only reads'):
            lab.apply_policy()
        with self.assertRaisesRegex(RuntimeError, 'only reads'):
            lab.namespace_command('user', ['touch', '/unrelated'])
        probe = [collector.sys.executable, '-I', '-S', '-B', '-c', collector.monitoring.segmentation.PROBE_CODE,
                 collector.monitoring.segmentation.ZONES['app'], '9090', collector.monitoring.segmentation.ZONES['user'], '42006']
        self.assertEqual(lab.namespace_command('user', probe)[:4], ['/tools/ip', 'netns', 'exec', config['namespaces']['user']])
        lab.names['router'] = 'unrelated-router'
        with self.assertRaisesRegex(RuntimeError, 'delegated'):
            lab.ruleset()
        # The original owner class still refuses commands in adopted namespaces.
        owner = collector.monitoring.MonitoringLab(tools, self.directory)
        owner.names = config['namespaces']
        with self.assertRaisesRegex(RuntimeError, 'exclusively created'):
            owner.ruleset()

    def test_reference_then_all_live_canaries_and_health_control_are_committed(self):
        allocation = self.allocation()
        lab = Mock()
        lab.ruleset.return_value = {'nftables': ['actual adapter result']}
        def probe(source, destination, port):
            result = {'from': source, 'to': destination, 'port': port,
                      'outcome': 'connect_timeout' if (source, destination, port) == ('user', 'app', 9090) else 'response',
                      'source_port': lab.next_source_port}
            lab.next_source_port += 1
            return result
        lab.probe.side_effect = probe
        worker = collector.Collector(lab, allocation, state=self.directory)
        submitted = []
        def commit(state, payload, **kwargs):
            submitted.append(copy.deepcopy(payload))
            return {'ok': True, 'duplicate': False, 'committed_sequence': len(submitted) + 1,
                    'evaluation': {'status': 'unknown' if len(submitted) == 1 else 'healthy'}}
        with patch.object(collector.service, 'request', side_effect=commit):
            one, two = worker.collect(), worker.collect()
        self.assertEqual(one['request']['observation']['probes'], [])
        self.assertEqual(lab.ruleset.call_count, 2)
        self.assertEqual(lab.probe.call_args_list[0].args, ('user', 'app', 8080))
        self.assertEqual(lab.probe.call_count, 4)
        self.assertEqual(len(two['request']['observation']['probes']), 3)
        self.assertEqual(two['request']['observation']['probes'][1]['destination_health']['from'], 'app')
        self.assertNotEqual(one['request']['request_id'], two['request']['request_id'])
        self.assertEqual(one['process_id'], os.getpid())
        self.assertEqual(one['instance_id'], two['instance_id'])
        self.assertEqual(json.loads((self.directory / 'receipt-0003.json').read_text()), two)
        self.assertLessEqual(two['started_monotonic'], two['completed_monotonic'])

    def test_rejected_commit_never_publishes_success_receipt(self):
        lab = Mock(); lab.ruleset.return_value = {}
        worker = collector.Collector(lab, self.allocation())
        with patch.object(collector.service, 'request', return_value={'ok': False}):
            with self.assertRaisesRegex(RuntimeError, 'not committed'):
                worker.collect()
        self.assertEqual(list(self.directory.glob('receipt-*.json')), [])

    def test_stop_finishes_current_cycle_and_idle_receipt_before_exit(self):
        allocation = self.allocation()
        worker = collector.Collector(Mock(), allocation)
        def collect_then_stop():
            worker.stop()
            return {'committed_sequence': 2, 'completed_at_utc': 'timestamp'}
        with patch.object(worker, 'collect', side_effect=collect_then_stop) as collect:
            worker.run()
        collect.assert_called_once()
        runtime = json.loads((self.directory / 'runtime.json').read_text())
        self.assertEqual(runtime['state'], 'idle')
        self.assertEqual(runtime['process_id'], os.getpid())


if __name__ == '__main__':
    unittest.main()
