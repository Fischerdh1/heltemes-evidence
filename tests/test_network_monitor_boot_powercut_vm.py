"""Exercise the automatic cold-start evidence checks with replayable fixtures."""
import copy
import signal
import unittest

from scripts import network_monitor_boot_powercut_vm as host
from test_network_monitor_boot_vm import evidence_fixture


def recovery_fixture():
    snapshots, source, original = evidence_fixture()
    before, after = snapshots['baseline'], snapshots['normal']
    before['stage'] = 'inspect-powercut'
    after['stage'] = 'recovered'
    receipt = before['receipts'][-1]
    before['powercut_boundary'] = {
        **{field: receipt[field] for field in
           ('boot_id', 'process_id', 'instance_id', 'cycle', 'committed_sequence')},
        'request_id': receipt['request']['request_id'],
    }

    first = copy.deepcopy(original['initial_boot'])
    second = copy.deepcopy(original['reboots']['normal']['after'])
    old_process = copy.deepcopy(first)
    old_process['observed_elapsed_seconds'] = 5
    second['qemu_pid'] = first['qemu_pid'] + 1
    cache = {'device': 'he-monitor-disk', 'driver': 'qcow2', 'read_only': False,
             'requested_cache_mode': 'none',
             'cache': {'writeback': True, 'direct': True, 'no-flush': False}}
    cut = {'before': old_process, 'after': second, 'disk_cache_before_cut': cache,
           'signal': 'SIGKILL', 'qemu_wait_returncode': -signal.SIGKILL,
           'old_qemu_reaped': True, 'power_cut_elapsed_seconds': 6,
           'qemu_terminated_elapsed_seconds': 7, 'cold_launch_elapsed_seconds': 8,
           'ssh_unavailable_observed': True, 'new_qemu_process': True, 'same_disk': True,
           'guest_shutdown_requested': False, 'qemu_graceful_exit_requested': False}
    boots = [
        {'boot_number': number, 'snapshot': snapshot, 'launch_started_elapsed_seconds': start,
         'disk_cache': copy.deepcopy(cache), 'disk_cache_after_boot': copy.deepcopy(cache),
         'qmp_kvm': {'enabled': False}, 'cloud_init': {'status': 'done', 'extended_status': 'done'},
         'source_uploaded': number == 1}
        for number, snapshot, start in ((1, first, 0), (2, second, 8))
    ]
    return before, after, source, cut, boots


class BootPowerCutTests(unittest.TestCase):
    def test_verified_cut_and_recovery(self):
        before, after, source, cut, boots = recovery_fixture()
        host.validate_cut(cut, before, after, boots)
        host.validate_recovery(before, after, source)

    def test_recovery_rejects_changes_to_held_history_and_receipts(self):
        changes = (
            lambda before, after: before['history']['rows'][0].update(row_digest='d' * 64),
            lambda before, after: before['receipts'][0].update(delivery_process_id=101),
            lambda before, after: before['powercut_boundary'].update(cycle=999),
            lambda before, after: after['history']['identity'].update(database_id='a' * 32),
        )
        for change in changes:
            with self.subTest(change=change):
                before, after, source, _, _ = recovery_fixture()
                change(before, after)
                with self.assertRaises(RuntimeError):
                    host.validate_recovery(before, after, source)

    def test_recovery_requires_a_new_boot_scoped_canary(self):
        changes = (
            lambda after: after['receipts'][-1].update(delivery_boot_id='1' * 36),
            lambda after: after['history']['rows'][-3]['evaluation'].update(status='healthy'),
            lambda after: after['history']['rows'][-1]['sample'].update(probes=[]),
            lambda after: after['services']['network'].update(ActiveEnterTimestampMonotonic=20),
        )
        for change in changes:
            with self.subTest(change=change):
                before, after, source, _, _ = recovery_fixture()
                change(after)
                with self.assertRaises(RuntimeError):
                    host.validate_recovery(before, after, source)

    def test_cut_requires_abrupt_exit_replacement_process_and_retained_disk(self):
        changes = (
            lambda cut: cut.update(qemu_wait_returncode=0),
            lambda cut: cut.update(ssh_unavailable_observed=False),
            lambda cut: cut.update(guest_shutdown_requested=True),
            lambda cut: cut['after'].update(boot_id=cut['before']['boot_id']),
            lambda cut: cut['after'].update(qemu_pid=cut['before']['qemu_pid']),
            lambda cut: cut['after'].update(disk_identity={'device': 1, 'inode': 3}),
        )
        for change in changes:
            with self.subTest(change=change):
                before, after, _, cut, boots = recovery_fixture()
                change(cut)
                with self.assertRaises(RuntimeError):
                    host.validate_cut(cut, before, after, boots)

    def test_cold_launch_uses_same_cached_disk_and_installs_source_once(self):
        changes = (
            lambda boots: boots[0].update(source_uploaded=False),
            lambda boots: boots[1].update(source_uploaded=True),
            lambda boots: boots[1].update(launch_started_elapsed_seconds=4),
            lambda boots: boots[1]['disk_cache_after_boot']['cache'].update(direct=False),
            lambda boots: boots[0]['snapshot'].update(disk_identity={'device': 1, 'inode': 3}),
        )
        for change in changes:
            with self.subTest(change=change):
                before, after, _, cut, boots = recovery_fixture()
                change(boots)
                with self.assertRaises(RuntimeError):
                    host.validate_cut(cut, before, after, boots)


if __name__ == '__main__':
    unittest.main()
