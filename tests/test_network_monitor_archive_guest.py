"""Portable contract checks for guarded archive VM exercise and receipt verification."""
import copy
import unittest
from unittest.mock import patch
from scripts import network_monitor_archive_guest as guest


class ArchiveGuestTests(unittest.TestCase):
    def test_ordinary_harness_cannot_submit_fabricated_observations(self):
        with patch.object(guest.service, 'request') as request:
            with self.assertRaisesRegex(RuntimeError, 'fabricate'):
                guest.request('observe')
        request.assert_not_called()

    def test_guarded_worker_and_collector_have_separate_exact_units(self):
        monitor = guest.unit_text(guest.MONITOR_UNIT)
        collector = guest.unit_text(guest.COLLECTOR_UNIT)
        self.assertIn('network_monitor_archive_guest.py worker', monitor)
        self.assertIn('network_monitor_archive_collector.py serve', collector)
        self.assertNotIn('--allow-test-crashes', monitor)
        self.assertIn('Restart=on-failure', monitor)
        self.assertNotIn('Requires=' + guest.MONITOR_UNIT, collector)
        self.assertIn('ReadWritePaths=' + str(guest.STATE) + ' ' + str(guest.RUNTIME), monitor)
        self.assertIn('RestrictAddressFamilies=AF_UNIX', monitor)
        with self.assertRaises(RuntimeError):
            guest.unit_text('unrelated.service')

    def test_public_inventory_is_fixed_and_source_hashes_include_archive_dependencies(self):
        self.assertEqual(len(guest.PUBLIC_FILES), 12)
        self.assertEqual(len(set(guest.PUBLIC_FILES)), 12)
        self.assertEqual(guest.ARCHIVE_FILES, ('archive-segment-000001.json', 'archive-segment-000002.json'))
        hashes = guest.source_hashes()
        self.assertEqual(set(hashes), set(guest.SOURCE_FILES))
        self.assertIn('scripts/network_monitor_archive.py', hashes)
        self.assertIn('scripts/network_monitor_archive_collector.py', hashes)

    def inventory(self):
        rows, records = [], []
        for cycle in range(1, 271):
            sequence = cycle + 1 + (cycle >= 128) + (cycle >= 255)
            name = 'archive_' + 'a' * 32 + '_' + str(cycle)
            probes = []
            if guest.collector.canary_cycle(cycle):
                for index, (source, target, port) in enumerate(guest.automatic.monitoring.CANARIES):
                    probes.append({'from': source, 'to': target, 'port': port, 'destination_health': None,
                                   'source_port': guest.collector.PORT_START + 6 * (cycle - 1) + index})
            observation = {'phase': name, 'ruleset': {'nftables': []}, 'collection_error': None, 'probes': probes}
            payload = {'command': 'observe', 'request_id': name, 'observation': observation}
            evaluation = {'status': 'critical' if probes else 'unknown'}
            records.append({'instance_id': 'a' * 32, 'process_id': 123, 'cycle': cycle, 'request': payload,
                            'committed_sequence': sequence, 'evaluation': evaluation,
                            'duplicate_acknowledgement': cycle in (127, 254),
                            'delivery_attempts': 2 if cycle in (127, 254) else 1,
                            'transport_failures': ['ConnectionResetError'] if cycle in (127, 254) else []})
            rows.append({'sequence': sequence, 'request_id': name, 'request': {'kind': 'observation', 'observation': observation},
                         'evaluation': evaluation})
        crashes = [{'boundary': {'request_id': records[c - 1]['request']['request_id'], 'request': records[c - 1]['request'],
                                'head_sequence': records[c - 1]['committed_sequence']}} for c in (127, 254)]
        return {'rows': rows}, records, crashes

    def test_inventory_binds_real_producer_receipts_canary_ports_and_both_retries(self):
        journal, records, crashes = self.inventory()
        probes = guest.validate_inventory(journal, records, crashes)
        self.assertEqual(len(probes), 51)
        broken = copy.deepcopy(records)
        broken[126]['duplicate_acknowledgement'] = False
        with self.assertRaisesRegex(RuntimeError, 'retried exactly'):
            guest.validate_inventory(journal, broken, crashes)
        broken = copy.deepcopy(journal)
        broken['rows'][0]['evaluation']['status'] = 'healthy'
        broken_records = copy.deepcopy(records)
        broken_records[0]['evaluation']['status'] = 'healthy'
        with self.assertRaisesRegex(RuntimeError, 'Rule-only'):
            guest.validate_inventory(broken, broken_records, crashes)
        broken = copy.deepcopy(records)
        broken[15]['request']['observation']['probes'][0]['source_port'] = 42006
        with self.assertRaises(RuntimeError):
            guest.validate_inventory(journal, broken, crashes)


if __name__ == '__main__':
    unittest.main()
