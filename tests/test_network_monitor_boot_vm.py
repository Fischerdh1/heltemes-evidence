"""Host evidence checks using synthetic fixtures rather than running a VM."""
import copy
import unittest
from unittest.mock import patch

from scripts import network_monitor_boot_vm as host
from test_network_monitor import Fixture

BOOTS = tuple(f'{digit * 8}-{digit * 4}-4{digit * 3}-8{digit * 3}-{digit * 12}'
              for digit in '1234')


def evidence_fixture():
    samples = Fixture()
    engine = host.replay.archive.StreamingMonitor(samples.raw)
    approved = copy.deepcopy(samples.raw)
    fingerprint = host.monitor.policy_fingerprint(approved)
    source = {'source_sha256': {name: 'a' * 64 for name in host.GUEST_SOURCE_FILES}}
    identity = {'format': 'heltemes-monitor-archive-journal', 'version': 1,
                'database_id': 'f' * 32, 'approved_policy_sha256': fingerprint,
                'segment_rows': 128, 'max_rows': 1024}
    rows, receipts, stages = [], [], {}

    def append(sample, request_id, kind):
        payload = {'sequence': sample['sequence'], 'request_id': request_id,
                   'request': {'kind': kind, 'observation': {key: sample[key]
                               for key in host.store.OBSERVATION_KEYS}},
                   'sample': sample, 'evaluation': engine.observe(sample),
                   'events': copy.deepcopy(engine.events),
                   'previous_digest': rows[-1]['row_digest'] if rows else host.store.ZERO}
        row = {**payload, 'row_digest': host.store.digest(payload)}
        rows.append(row)
        return row

    def marker(phase, reason, request_id, kind):
        sample = samples.sample()
        sample.update(phase=phase, ruleset=None, probes=[], collection_error=reason)
        return append(sample, request_id, kind)

    def manager(pid, digit, start=1, *, state='active', result='success', status=0):
        return {'LoadState': 'loaded', 'UnitFileState': 'enabled', 'NRestarts': 0,
                'ActiveState': state, 'MainPID': pid, 'InvocationID': digit * 32,
                'ExecMainStatus': status, 'Result': result,
                'ExecMainStartTimestampMonotonic': start, 'ActiveEnterTimestampMonotonic': start + 1}

    for index, name in enumerate(host.STAGE_OUTPUTS):
        digit = str(index + 1); boot = BOOTS[index]
        failed = name == 'failed'
        marker('monitor_restart', 'monitor_restarted', '_restart_' + digit * 32, 'restart')
        monitor_pid, worker_pid = 40 + index, 50 + index
        fresh = None
        if failed:
            marker('collector_missing', 'freshness_deadline_exceeded',
                   'freshness-gap-' + digit * 32 + '-1', 'observation')
        else:
            for local_cycle in range(1, 4):
                cycle = len(receipts) + 1
                samples.port = host.collector.PORT_START + host.collector.PORT_BLOCK * (cycle - 1)
                sample = samples.sample(host.monitor.CANARIES if local_cycle == 3 else ())
                fresh = f'archive_reboot_{digit * 32}_{cycle}'
                for probe in sample['probes']:
                    probe['phase'] = fresh
                    if probe['destination_health']:
                        probe['destination_health']['phase'] = fresh
                        # Fixture normally shares the source port with the destination
                        # health probe. Real probes reserve a distinct port.
                        samples.port += 1
                        probe['destination_health']['source_port'] = samples.port
                sample['phase'] = fresh
                row = append(sample, fresh, 'observation')
                receipts.append({'boot_id': boot, 'delivery_boot_id': boot,
                    'instance_id': digit * 32, 'process_id': worker_pid, 'delivery_process_id': worker_pid,
                    'cycle': cycle, 'process_cycle': local_cycle, 'committed_sequence': row['sequence'],
                    'evaluation': row['evaluation'], 'request': {'command': 'observe', 'request_id': fresh,
                        'observation': row['request']['observation']}})
        namespaces = {role: f'he-fixture-{index}-{role}' for role in ('user', 'app', 'management', 'router')}
        head = rows[-1]
        stages[name] = copy.deepcopy({
            'ok': True, 'stage': name, 'boot': {'boot_id': boot, 'virtualization': 'qemu', 'uptime_seconds': 20},
            'source_sha256': source['source_sha256'],
            'storage': {'uuid': 'fixed', 'fstype': 'ext4', 'source': '/dev/vda1', 'options': 'rw'},
            'history': {'identity': identity, 'rows': rows, 'head_sequence': len(rows), 'head_digest': head['row_digest'],
                        'approved_policy': approved, 'archived_sequence': 0, 'archived_digest': host.store.ZERO,
                        'segments': []},
            'status': {'ok': True, 'process_id': monitor_pid, 'committed_count': len(rows),
                       'head_digest': head['row_digest'], 'current_evaluation': head['evaluation'],
                       'archives': {'persistence_error': None}, 'freshness': {'enabled': True,
                           'gap_recorded': failed, 'gap_sequence': len(rows) if failed else None,
                           'last_accepted_request_id': fresh}},
            'services': {'monitor': manager(monitor_pid, digit),
                         'network': manager(70, digit, 2) if not failed
                                    else manager(0, digit, 2, state='failed', result='exit-code', status=1),
                         'collector': manager(worker_pid, digit, 4) if not failed
                                      else manager(0, digit, 0, state='inactive')},
            'units': {'monitor': 'one', 'network': 'two', 'collector': 'three'},
            'network': {'state': 'firewall_failed' if failed else 'ready', 'boot_id': boot,
                        'namespaces': namespaces, 'policy_sha256': None if failed else fingerprint,
                        'nft_returncode': int(failed), 'cleanup': {'ok': True} if failed else None,
                        'failure': 'nftables_rejected' if failed else None},
            'fault_armed': failed, 'namespaces_present': [] if failed else list(namespaces.values()),
            'receipts': receipts, 'failed_boot_pending_absent': True if failed else None, 'allocation': {'cycles': len(receipts),
                'next_port': host.collector.PORT_START + host.collector.PORT_BLOCK * len(receipts)}})

    def boot_snapshot(boot_id, at):
        return {'boot_id': boot_id, 'qemu_pid': 99, 'disk_identity': {'device': 1, 'inode': 2},
                'observed_elapsed_seconds': at}
    host_boots = [boot_snapshot(boot, 10 * index) for index, boot in enumerate(BOOTS)]
    evidence = {'initial_boot': host_boots[0], 'reboots': {}}
    for name, before, after in zip(host.BOOT_CASES, host_boots, host_boots[1:]):
        at = before['observed_elapsed_seconds']
        evidence['reboots'][name] = {'before': before, 'after': after, 'ssh_unavailable_observed': True,
            'reboot_command': 'systemctl reboot', 'reboot_requested_elapsed_seconds': at + 1,
            'qmp_events': [{'event': 'RESET', 'data': {'guest': True}, 'observed_elapsed_seconds': at + 2}]}
    return stages, source, evidence


class HostBootTests(unittest.TestCase):
    def test_accepts_replayed_history_and_verified_boots(self):
        snapshots, source, evidence = evidence_fixture()
        host.validate_stages(snapshots, source)
        host.validate_reboots(snapshots, evidence)

    def test_rejects_failed_boot_that_started_collector_or_claimed_coverage(self):
        changes = (
            lambda stage: stage['services']['collector'].update(ExecMainStartTimestampMonotonic=10),
            lambda stage: stage['network'].update(nft_returncode=0),
            lambda stage: stage['namespaces_present'].append(stage['network']['namespaces']['router']),
            lambda stage: stage['status']['current_evaluation'].update(status='healthy'),
            lambda stage: stage['status']['freshness'].update(gap_recorded=False),
        )
        for change in changes:
            with self.subTest(change=change):
                snapshots, source, _ = evidence_fixture()
                change(snapshots['failed'])
                with self.assertRaises(RuntimeError):
                    host.validate_stages(snapshots, source)

    def test_rejects_unproven_readiness_changed_history_and_misattributed_receipt(self):
        changes = (
            lambda snapshots: snapshots['normal']['services']['network'].update(ActiveEnterTimestampMonotonic=10),
            lambda snapshots: snapshots['baseline']['history']['rows'][0].update(row_digest='d' * 64),
            lambda snapshots: snapshots['normal']['receipts'][-1].update(delivery_boot_id=BOOTS[0]),
        )
        for change in changes:
            with self.subTest(change=change):
                snapshots, source, _ = evidence_fixture()
                change(snapshots)
                with self.assertRaises(RuntimeError):
                    host.validate_stages(snapshots, source)

    def test_rejects_reboot_without_guest_reset_or_same_disk(self):
        for change in (
            lambda reboot: reboot.update(qmp_events=[]),
            lambda reboot: reboot['after'].update(disk_identity={'device': 1, 'inode': 3}),
        ):
            with self.subTest(change=change):
                snapshots, _, evidence = evidence_fixture()
                change(evidence['reboots']['normal'])
                with self.assertRaises(RuntimeError):
                    host.validate_reboots(snapshots, evidence)

    def test_failure_diagnostic_drops_key_material_and_local_paths(self):
        vm = host.DisposableVM({})
        diagnostic = host.safe_failure(vm, 'Boot failed ' + vm.token +
            ' /Users/example/private ssh-ed25519 AAAAFAKE=')
        self.assertNotIn(vm.token, diagnostic)
        self.assertNotIn('/Users/', diagnostic)
        self.assertNotIn('AAAAFAKE=', diagnostic)
        self.assertNotIn('secret', host.safe_failure(vm, '-----BEGIN OPENSSH PRIVATE KEY-----\nsecret'))

    def test_guest_cannot_submit_unrecognized_action(self):
        vm = host.DisposableVM({})
        with patch.object(vm, 'ssh') as ssh, self.assertRaises(RuntimeError):
            vm.guest('start-service')
        ssh.assert_not_called()


if __name__ == '__main__':
    unittest.main()
