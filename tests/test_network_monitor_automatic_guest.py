"""Portable safety and evidence-binding checks; actual services/packets run in QEMU."""
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import network_monitor_automatic_guest as guest

spec = importlib.util.spec_from_file_location('automatic_network_fixture', Path(__file__).with_name('test_network_monitoring_lab.py'))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


class AutomaticGuestTests(unittest.TestCase):
    def stages(self):
        critical = {'id': guest.reboot.CRITICAL + '#1', 'key': guest.reboot.CRITICAL, 'state': 'open'}
        status = {'process_id': 100, 'instance_id': 'a' * 32, 'committed_count': 5,
                  'current_evaluation': {'status': 'unknown', 'phase': 'collector_missing'},
                  'freshness': {'gap_recorded': True}, 'alerts': [critical]}
        return {key: {'status': copy.deepcopy(status)} for key in ('incident', 'silent', 'repaired_silent')}

    def silence(self):
        return {'collector_proc_state': 'T', 'monitor_rpc_requests_during_wait': 0, 'elapsed_seconds': 22,
                'gap_committed_at_utc': '2026-11-05T12:00:20+00:00',
                'first_inspected_at_utc': '2026-11-05T12:00:22+00:00'}

    def test_silence_requires_preinspection_gap_same_monitor_and_preserved_incident(self):
        incident = guest.reboot.CRITICAL + '#1'
        guest.validate_silence(self.stages(), self.silence(), incident)
        mutations = [('collector_proc_state', 'R'), ('monitor_rpc_requests_during_wait', 1),
                     ('elapsed_seconds', 2), ('gap_committed_at_utc', '2026-11-05T12:00:23+00:00')]
        for key, value in mutations:
            proof = self.silence(); proof[key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                guest.validate_silence(self.stages(), proof, incident)
        stages = self.stages(); stages['silent']['status']['process_id'] = 101
        with self.assertRaisesRegex(RuntimeError, 'monitor restarted'):
            guest.validate_silence(stages, self.silence(), incident)
        stages = self.stages(); stages['repaired_silent']['status']['committed_count'] = 6
        with self.assertRaisesRegex(RuntimeError, 'without new collection'):
            guest.validate_silence(stages, self.silence(), incident)
        stages = self.stages(); stages['silent']['status']['alerts'] = []
        with self.assertRaisesRegex(RuntimeError, 'incident'):
            guest.validate_silence(stages, self.silence(), incident)

    def test_harness_cannot_submit_observations(self):
        with patch.object(guest.service, 'request') as request:
            with self.assertRaisesRegex(RuntimeError, 'cannot submit'):
                guest.request('observe')
            request.assert_not_called()

    def inventory(self):
        records, rows = [], []
        for index, (instance, cycle, pid) in enumerate((('a' * 32, 1, 100), ('a' * 32, 2, 100), ('b' * 32, 1, 200), ('b' * 32, 2, 200)), 1):
            phase = f'automatic_{instance}_{cycle}'
            probes = [] if cycle == 1 else [dict(zip(('from', 'to', 'port'), path), source_port=42000 + index * 6 + n,
                                               destination_health=None) for n, path in enumerate(guest.monitoring.CANARIES)]
            observation = {'phase': phase, 'probes': probes}
            payload = {'command': 'observe', 'request_id': phase, 'observation': observation}
            evaluation = {'status': 'unknown' if cycle == 1 else 'healthy'}
            records.append({'instance_id': instance, 'cycle': cycle, 'process_id': pid, 'request': payload,
                            'committed_sequence': index, 'evaluation': evaluation, 'started_monotonic': index,
                            'completed_monotonic': index + 0.1})
            rows.append({'sequence': index, 'request_id': phase, 'sample': observation,
                         'request': {'observation': observation}, 'evaluation': evaluation})
        return {'rows': rows}, records

    def test_inventory_binds_each_automatic_receipt_and_port_to_journal(self):
        journal, records = self.inventory()
        self.assertEqual(len(guest.validate_inventory(journal, records)), 6)
        changed = copy.deepcopy(records); changed[0]['evaluation']['status'] = 'forged'
        with self.assertRaisesRegex(RuntimeError, 'differs from committed'):
            guest.validate_inventory(journal, changed)
        with self.assertRaisesRegex(RuntimeError, 'inventory differs'):
            guest.validate_inventory(journal, records[:-1])
        journal, records = self.inventory()
        # Share a repeated port in both receipt and journal; cross-record validation still catches it.
        records[-1]['request']['observation']['probes'][0]['source_port'] = records[1]['request']['observation']['probes'][0]['source_port']
        with self.assertRaisesRegex(RuntimeError, 'reused'):
            guest.validate_inventory(journal, records)

    def test_capture_sealing_matches_exact_file_and_rejects_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'capture.pcap'; path.write_bytes(b'synthetic test bytes')
            self.assertEqual(guest.seal_capture(path), hashlib.sha256(path.read_bytes()).hexdigest())
            linked = path.with_name('alias'); linked.symlink_to(path)
            with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
                guest.seal_capture(linked)
            linked.unlink(); os.link(path, linked)
            with self.assertRaisesRegex(RuntimeError, 'Unsafe'):
                guest.seal_capture(path)

    def test_exact_source_public_inventories_and_boot_configuration(self):
        self.assertEqual(len(guest.SOURCE_FILES), 14)
        self.assertEqual(len(set(guest.SOURCE_FILES)), 14)
        self.assertEqual(len(guest.PUBLIC_FILES), 10)
        monitor = guest.unit_text(guest.MONITOR_UNIT)
        collector = guest.unit_text(guest.COLLECTOR_UNIT)
        self.assertIn('--freshness-seconds 20', monitor)
        self.assertIn('Restart=on-failure', collector)
        self.assertIn('WantedBy=multi-user.target', collector)
        self.assertIn('network_monitor_collector.py serve', collector)
        self.assertNotIn('--token', collector)

    def test_collector_restart_recovers_original_incident_through_real_engine(self):
        class Fixture(fixtures.ScenarioFixture):
            def probe(self, *args):
                value = super().probe(*args)
                value['source_port'] = self.next_source_port
                self.next_source_port += 1
                return value
        with tempfile.TemporaryDirectory(prefix='auto-integration-') as directory:
            path = Path(directory).resolve(); path.chmod(0o700)
            private = path / 'collector'; private.mkdir(mode=0o700)
            lab = Fixture()
            guest.store.initialize(path / 'state', lab.ruleset())
            allocation = guest.collector.Allocation(private)
            journal = guest.store.Journal(path / 'state')
            try:
                service = guest.service.Service(journal, freshness_seconds=20)
                first = guest.collector.Collector(lab, allocation, state=path / 'state')
                first.process_id = 100  # Simulated PID boundary; real process proof is VM-only.
                with patch.object(guest.collector.service, 'request', side_effect=lambda _, payload, **kw: service.dispatch(payload)):
                    reference = first.collect()
                    baseline = first.collect()
                    self.assertEqual(baseline['evaluation']['status'], 'healthy')
                    lab.apply_policy('misconfigured')
                    incident = first.collect()
                    critical_id = guest.reboot.critical(service.status())['id']
                    # Advance only the monotonic measurement origin; no new source
                    # observation is submitted to create the missing-data record.
                    service.last_accepted['monotonic'] -= 22
                    service.started -= 22
                    service.tick()
                    missing = service.status()
                    self.assertEqual(missing['current_evaluation']['status'], 'unknown')
                    lab.apply_policy()
                    self.assertEqual(guest.reboot.critical(service.status())['id'], critical_id)
                    before_count = len(journal.rows)
                    second = guest.collector.Collector(lab, allocation, state=path / 'state')
                    second.process_id = 200
                    fresh_reference = second.collect()
                    self.assertEqual(guest.reboot.critical(service.status())['id'], critical_id)
                    self.assertNotEqual(fresh_reference['evaluation']['status'], 'healthy')
                    fresh_canaries = second.collect()
                    self.assertEqual(fresh_canaries['evaluation']['status'], 'healthy')
                    self.assertEqual(len(journal.rows), before_count + 2)
                    self.assertEqual(len(guest.validate_inventory(journal.export(),
                        [reference, baseline, incident, fresh_reference, fresh_canaries])), 11)
                    resolutions = [e for e in journal.export()['events'] if e['key'] == guest.reboot.CRITICAL and e['action'] == 'resolved']
                    self.assertEqual(len(resolutions), 1)
                    self.assertEqual(resolutions[0]['alert_id'], critical_id)
                    self.assertEqual(resolutions[0]['sequence'], fresh_canaries['committed_sequence'])
            finally:
                journal.close(); allocation.close()


if __name__ == '__main__':
    unittest.main()
