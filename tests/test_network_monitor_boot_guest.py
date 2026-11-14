"""Local contract checks for the boot-owned network and its failure gate."""
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

from scripts import network_monitor_boot_guest as guest


class BootGuestTests(unittest.TestCase):
    def test_monitor_is_independent_and_collector_waits_for_network_readiness(self):
        monitor, network, collector = (guest.unit_text(unit) for unit in guest.UNITS.values())
        for text in (monitor, network, collector):
            self.assertIn('WantedBy=multi-user.target', text)
        self.assertNotIn(guest.NETWORK_UNIT, monitor)
        self.assertNotIn(guest.COLLECTOR_UNIT, monitor)
        self.assertIn('Type=notify', network)
        self.assertIn('NotifyAccess=main', network)
        self.assertIn('KillMode=mixed', network)
        self.assertIn('KillMode=mixed', collector)
        self.assertIn(f'BindsTo={guest.NETWORK_UNIT}', collector)
        self.assertIn(f'Requires={guest.MONITOR_UNIT}', collector)
        self.assertIn(f'After={guest.NETWORK_UNIT} {guest.MONITOR_UNIT}', collector)
        for text in (network, collector):
            self.assertNotIn('ProtectSystem', text)
            self.assertNotIn('PrivateMounts', text)

    def test_firewall_failure_is_a_real_batch_scoped_to_owned_router(self):
        lab = Mock(tools={'nft': '/usr/sbin/nft'})
        lab.ruleset.return_value = {'nftables': [{'metainfo': {}}]}
        lab.run_in.return_value = subprocess.CompletedProcess([], 1, '', 'syntax error')
        approved = guest.automatic.monitoring.segmentation.policy_text()
        self.assertEqual(guest.firewall(lab, True).returncode, 1)
        lab.run_in.assert_called_once_with('router', ['/usr/sbin/nft', '-f', '-'],
                                          input=approved + guest.BAD_NFT_LINE, check=False)
        lab.ruleset.return_value = {'nftables': [{'table': {'name': 'unexpected'}}]}
        with self.assertRaisesRegex(RuntimeError, 'left rules'):
            guest.firewall(lab, True)

    def test_gap_must_persist_before_harness_reads_monitor_status(self):
        previous = {'rows': [{'sample': {'phase': 'monitor_restart'}}]}
        missing = {'rows': [{'sample': {'phase': 'collector_missing'}}],
                   'head_digest': 'head', 'head_sequence': 2}
        observed = {'ok': True, 'head_digest': 'head', 'committed_count': 2,
                    'current_evaluation': {'phase': 'collector_missing', 'status': 'unknown'}}
        allocation = {'cycles': 0, 'next_port': 42000}
        reads = Mock(side_effect=(previous, missing))
        def inspect():
            self.assertEqual(reads.call_count, 2)
            return observed
        with patch.object(guest.archived, 'readonly_history', reads), \
                patch.object(guest, 'status', side_effect=inspect) as read_status, \
                patch.object(guest, 'receipts_at_head', return_value=[]), \
                patch.object(guest, 'allocation_record', return_value=allocation), \
                patch.object(guest, 'PRIVATE', Path('/nonexistent/hevidence-test')), \
                patch.object(guest.time, 'sleep'):
            self.assertEqual(guest.coherent_snapshot('boot', failed=True),
                             (observed, missing, [], allocation))
            read_status.assert_called_once_with()

    def test_active_snapshot_uses_committed_receipts_while_next_cycle_is_allocated(self):
        history = {'rows': [{'request_id': 'archive_reboot_fixture_3', 'sequence': 4}],
                   'head_digest': 'head', 'head_sequence': 4}
        observed = {'ok': True, 'head_digest': 'head', 'committed_count': 4,
                    'current_evaluation': {'phase': 'fixture', 'status': 'healthy'}}
        receipts = [{'boot_id': 'boot', 'cycle': cycle} for cycle in (1, 2, 3)]
        port = guest.collector.PORT_START
        block = guest.collector.PORT_BLOCK
        with patch.object(guest.archived, 'readonly_history', return_value=history), \
                patch.object(guest, 'status', return_value=observed), \
                patch.object(guest, 'receipts_at_head', return_value=receipts) as read, \
                patch.object(guest, 'allocation_record', return_value={'cycles': 4, 'next_port': port + 4 * block}):
            result = guest.coherent_snapshot('boot', failed=False)
        self.assertEqual(result, (observed, history, receipts, {'cycles': 3, 'next_port': port + 3 * block}))
        read.assert_called_once_with(history['rows'])

    def powercut_receipt(self, **overrides):
        receipt = {
            'boot_id': '97c110dd-d2bc-45d0-b25e-912ed18dd022',
            'process_id': 42, 'instance_id': 'a' * 32, 'cycle': 3,
            'committed_sequence': 4, 'request': {'request_id': 'archive_reboot_fixture_3',
                                                 'observation': {'probes': [{}, {}, {}]}},
            'evaluation': {'status': 'healthy'},
        }
        receipt.update(delivery_boot_id=receipt['boot_id'], delivery_process_id=receipt['process_id'])
        receipt.update(overrides)
        return receipt

    def test_previous_boot_arm_does_not_trigger_current_boot(self):
        boot_id = self.powercut_receipt()['boot_id']
        with patch.object(guest.os.path, 'lexists', return_value=True), \
                patch.object(guest.store, 'read_private', return_value=(
                    b'{"boot_id":"ed27207d-4301-42f9-95d3-27c05cc67bc5"}')):
            self.assertFalse(guest.powercut_armed(boot_id))

    def test_armed_collector_publishes_post_commit_boundary_and_honors_stop(self):
        receipt = self.powercut_receipt()
        allocation = Mock(directory=Path('/nonexistent/hevidence-test'))
        allocation.read.return_value = {'cycles': receipt['cycle']}
        worker = guest.BootCollector(Mock(), allocation, boot_id=receipt['boot_id'], phase='before')
        receipt.update(process_id=worker.process_id, delivery_process_id=worker.process_id,
                       instance_id=worker.instance_id)
        with patch.object(guest.collector.Collector, 'collect', return_value=receipt) as collect, \
                patch.object(guest, 'powercut_armed', return_value=True), \
                patch.object(guest.ordinary_collector, 'replace_private') as publish, \
                patch.object(guest.time, 'sleep', side_effect=lambda duration: worker.stop()) as sleep:
            self.assertEqual(worker.collect(), receipt)
        collect.assert_called_once_with()
        publish.assert_called_once_with(guest.POWER_CUT_BOUNDARY, guest.cut_boundary(receipt))
        sleep.assert_called_once_with(0.1)

    def test_cut_snapshot_includes_autonomous_freshness_gap_after_held_receipt(self):
        receipt = self.powercut_receipt()
        receipts = [receipt, receipt, receipt]
        boundary = guest.cut_boundary(receipt)
        history = {'rows': [{'sample': {'phase': 'collector_missing'}}],
                   'head_digest': 'head', 'head_sequence': 5}
        observed = {'ok': True, 'head_digest': 'head', 'committed_count': 5,
                    'current_evaluation': {'phase': 'collector_missing', 'status': 'unknown'}}
        allocation = {'cycles': 3, 'next_port': guest.collector.PORT_START + guest.collector.PORT_BLOCK * 3}
        with patch.object(guest.archived, 'readonly_history', return_value=history), \
                patch.object(guest, 'status', return_value=observed), \
                patch.object(guest, 'receipts_at_head', return_value=receipts), \
                patch.object(guest, 'allocation_record', return_value=allocation), \
                patch.object(guest, 'PRIVATE', Path('/nonexistent/hevidence-test')):
            result = guest.coherent_snapshot(receipt['boot_id'], failed=False, powercut_boundary=boundary)
        self.assertEqual(result, (observed, history, receipts, allocation))

    def test_stage_binds_evidence_to_current_boot_after_snapshot(self):
        boot1 = {'boot_id': 'same', 'uptime_seconds': 0.5}
        boot2 = {'boot_id': 'same', 'uptime_seconds': 12}
        with patch.object(guest, 'guard', return_value='qemu'), \
                patch.object(guest.reboot, 'boot_info', side_effect=(boot1, boot2)), \
                patch.object(guest, 'snapshot', return_value={}) as snapshot:
            result = guest.stage('normal', 'token')
        self.assertEqual(result['boot'], boot2)
        snapshot.assert_called_once_with('same', failed=False)


if __name__ == '__main__':
    unittest.main()
