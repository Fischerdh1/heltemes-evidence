"""Portable negative checks; synthetic fixtures are not Linux VM or packet evidence."""
import copy
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import network_monitor_archive_powercut_vm as host
from test_network_monitor import Fixture, ruleset

ROOT = Path(__file__).resolve().parents[1]
TOOLS = {name: '/tools/' + name for name in ('qemu-system-x86_64', 'qemu-img', 'cloud-localds', 'ssh', 'ssh-keygen', 'curl', 'git')}
BOOTS = tuple(str(n) * 8 + '-' + str(n) * 4 + '-4' + str(n) * 3 + '-8' + str(n) * 3 + '-' + str(n) * 12 for n in range(1, 5))


def fingerprint(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (host.canonical(value) + '\n').encode()


def archive_bytes(files, *, extra=None, link=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as bundle:
        for name, raw in files.items():
            entry = tarfile.TarInfo(name)
            if name == link:
                entry.type, entry.linkname = tarfile.SYMTYPE, '/outside'
                bundle.addfile(entry)
            else:
                entry.size = len(raw); bundle.addfile(entry, io.BytesIO(raw))
        if extra:
            bundle.addfile(tarfile.TarInfo(extra), io.BytesIO())
    return output.getvalue()


def fixture():
    """Replayable invented data used exclusively to challenge the artifact contract."""
    approved = ruleset(); engine = host.archive.StreamingMonitor(approved); samples = Fixture()
    identity = {'format': 'heltemes-monitor-archive-journal', 'version': 1, 'database_id': 'a' * 32,
        'segment_rows': 128, 'max_rows': 2048, 'max_segments': 16,
        'approved_policy_sha256': host.archive.monitor.policy_fingerprint(approved)}
    rows, events, previous, statuses = [], [], '0' * 64, {}
    snapshots = {127, 128, 129, 255, 256, 257, 383, 384, 385, 520}
    for number in range(1, 521):
        restart = number in (1, 129, 257, 385)
        cut_index = {128: 0, 256: 1, 384: 2}.get(number)
        canaries = host.archive.monitor.CANARIES if number in (3, 388, 520) else ()
        raw = samples.sample(canaries if number != 4 else (('user', 'app', 9090),), bad=number == 4)
        observation = {key: raw[key] for key in host.store.OBSERVATION_KEYS}
        if restart:
            observation.update(phase='monitor_restart', ruleset=None, probes=[], collection_error='monitor_restarted')
            request_id = '_restart_' + str((number - 1) // 128 + 1) * 32
        elif cut_index is not None:
            request_id = host.REQUEST_IDS[host.POINTS[cut_index]]
            observation.update(phase=request_id, ruleset=None, probes=[], collection_error='archive_powercut_boundary')
        else:
            request_id = 'synthetic-' + str(number)
        sample = {**copy.deepcopy(observation), 'sequence': number, 'elapsed_seconds': number * 2.}
        payload = {'sequence': number, 'request_id': request_id,
            'request': {'kind': 'restart' if restart else 'observation', 'observation': observation},
            'sample': sample, 'evaluation': engine.observe(sample), 'events': copy.deepcopy(engine.events),
            'previous_digest': previous}
        row = {**payload, 'row_digest': host.digest(payload)}; rows.append(row); events.extend(row['events'])
        previous = row['row_digest']
        if number in snapshots:
            index = sum(number >= boundary for boundary in (129, 257, 385)); segments = number // 128
            statuses[number] = {'process_id': 100 + index, 'instance_id': str(index + 1) * 32,
                'committed_count': number, 'head_digest': previous, 'current_evaluation': copy.deepcopy(row['evaluation']),
                'alerts': copy.deepcopy(engine.alerts), 'archives': {'sealed_segments': segments,
                    'archived_rows': segments * 128, 'active_rows': number % 128, 'capacity_remaining': 2048 - number,
                    'persistence_error': None, 'recovery_actions': []}}
    incident = host.CRITICAL + '#1'
    files = {name: b'synthetic test fixture, not captured packets' for name in host.CAPTURE_FILES}
    files.update({'APPROVED_POLICY.json': encoded(approved), 'monitor.service': b'synthetic service'})
    descriptors, proofs = [], []
    for index, name in enumerate(host.SEGMENT_FILES, 1):
        raw = host.segment_bytes(identity, rows, index); files[name] = raw
        descriptors.append(host.descriptor_for(identity, rows, index))
        proofs.append({'name': f'segment-{index:06d}.json', 'bytes': len(raw), 'sha256': fingerprint(raw),
                       'mode': 0o600, 'uid': 0, 'nlink': 1})
    source = {'source_sha256': {name: 'f' * 64 for name in host.SOURCE_FILES}}
    hashes = {name: source['source_sha256'][name] for name in host.GUEST_SOURCE_FILES}
    def history(count):
        return {'history_complete': True, 'identity': identity, 'approved_policy': approved,
            'rows': rows[:count], 'evaluations': [r['evaluation'] for r in rows[:count]],
            'events': [event for event in events if event['sequence'] <= count], 'archive_descriptors': descriptors[:count // 128]}
    def manager(index):
        return {'MainPID': 100 + index, 'NRestarts': 0, 'ActiveState': 'active', 'UnitFileState': 'enabled',
                'InvocationID': str(index + 1) * 32}
    cuts = []
    for index, point in enumerate(host.POINTS):
        count = (index + 1) * 128; staged = index == 0; committed = index == 2
        request = {'command': 'observe', 'request_id': host.REQUEST_IDS[point], 'observation': rows[count - 1]['request']['observation']}
        marker = {'format': 'heltemes-archive-powercut-boundary', 'version': 1, 'point': point,
            'request_id': request['request_id'], 'request': request, 'observation_sha256': host.digest(request['observation']),
            'process_id': 100 + index, 'instance_id': str(index + 1) * 32, 'boot_id': BOOTS[index], 'in_transaction': False,
            'synchronous': 3, 'journal_mode': 'delete', 'rows': rows[:count], 'identity': identity,
            'approved_policy': approved, 'head_sequence': count, 'head_digest': rows[count - 1]['row_digest'],
            'active_sql_rows': 0 if committed else 128,
            'archive_descriptors': descriptors[:index + int(committed)],
            'archive_files': proofs[:index + (not staged)],
            'pending_file': {**proofs[index], 'name': f'segment-{index + 1:06d}.json.pending'} if staged else None,
            'final_file': None if staged else proofs[index]}
        boundary = {'ok': True, 'boot_id': BOOTS[index], 'worker_state': 'T', 'worker_process_state': 'T',
            'worker_stopped_observed': True, 'response_received': False, 'ready_marker_filesystem': 'tmpfs',
            'boundary': marker, 'manager': manager(index)}
        before = {'boot_id': BOOTS[index], 'qemu_pid': 1000 + index, 'disk_identity': {'device': 1, 'inode': 2},
                  'observed_elapsed_seconds': index * 10.}
        after = {**copy.deepcopy(before), 'boot_id': BOOTS[index + 1], 'qemu_pid': 1001 + index, 'observed_elapsed_seconds': index * 10. + 5}
        cuts.append({'point': point, 'boundary': boundary, 'boundary_recheck': copy.deepcopy(boundary),
            'before': before, 'after': after, 'disk_cache_before_cut': {'device': 'he-monitor-disk', 'driver': 'qcow2',
                'read_only': False, 'requested_cache_mode': 'none', 'cache': dict(host.CACHE)},
            'signal': 'SIGKILL', 'qemu_wait_returncode': -9, 'old_qemu_reaped': True,
            'new_qemu_process': True, 'same_disk': True, 'ssh_unavailable_observed': True,
            'guest_shutdown_requested': False, 'qemu_graceful_exit_requested': False,
            'power_cut_elapsed_seconds': index * 10. + 1, 'qemu_terminated_elapsed_seconds': index * 10. + 2,
            'cold_launch_elapsed_seconds': index * 10. + 3})
    statuses[129]['archives']['recovery_actions'] = [{'action': 'rebuilt_verified_staging_prefix', 'segment_index': 1,
        'staged_bytes': len(files[host.SEGMENT_FILES[0]])}]
    statuses[257]['archives']['recovery_actions'] = [{'action': 'accepted_exact_uncommitted_segment', 'segment_index': 2}]
    for index, (stage, count) in enumerate(zip(host.STAGES, (127, 255, 383, 520))):
        h = history(count); name = stage.upper() + '-HISTORY.json'; files[name] = encoded(h)
        report = {'format': 'heltemes-monitor-archive-powercut-guest', 'version': 1, 'ok': True, 'stage': stage,
            'source_sha256': hashes, 'boot': {'boot_id': BOOTS[index]}, 'critical_incident_id': incident,
            'storage': {'target': '/', 'source': '/dev/vda1', 'fstype': 'ext4', 'uuid': 'original'},
            'unit_sha256': fingerprint(files['monitor.service']), 'manager': manager(index),
            'history_file': {'name': name, 'bytes': len(files[name]), 'sha256': fingerprint(files[name])},
            'final_status': statuses[count], 'archive_files': proofs[:count // 128],
            'journal_export_method': 'stopped_verified_journal' if index == 3 else 'readonly_committed_snapshot',
            'observations': [{'request': {'command': 'observe', 'request_id': row['request_id'],
                'observation': row['request']['observation']}, 'committed_sequence': row['sequence'],
                'evaluation': row['evaluation']} for row in rows[(1, 129, 257, 385)[index]:count]],
            'network_cleanup': {'ok': True}, 'capture_sha256': {n: fingerprint(files[n]) for n in host.CAPTURE_FILES if n.startswith(stage + '-')}}
        if index:
            startup_count = index * 128 + 1; status = statuses[startup_count]
            report.update(volatile_markers_absent=True, automatic_start={'status': status, 'manager': manager(index),
                'history': history(startup_count), 'no_manual_service_start': True})
            marker = cuts[index - 1]['boundary']['boundary']
            report['lost_ack_retry'] = {'request': marker['request'], 'before_status': status, 'after_status': status,
                'response': {'ok': True, 'duplicate': True, 'result_is_historical': True, 'committed_sequence': startup_count - 1,
                    'evaluation': rows[startup_count - 2]['evaluation'], 'current_status': status}}
        if index == 3:
            report['monitor_stopped_for_export'] = {'ActiveState': 'inactive', 'MainPID': 0}
        files[stage.upper() + '.json'] = encoded(report)
    references = {stage: {name: files[name] for name in host.reference_names(stage)} for stage in host.STAGES[:-1]}
    return references, files, source, cuts


class ArchivePowercutHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.artifacts = fixture()

    def test_genuine_replayable_synthetic_contract(self):
        reports, histories = host.validate_guest(*self.artifacts)
        self.assertEqual(len(histories[-1]['rows']), 520)
        self.assertEqual(len(histories[-1]['archive_descriptors']), 4)

    def test_staging_name_may_disappear_without_losing_committed_history(self):
        references, files, source, cuts = copy.deepcopy(self.artifacts)
        report = json.loads(files['AFTER-STAGING.json'])
        report['automatic_start']['status']['archives']['recovery_actions'] = []
        files['AFTER-STAGING.json'] = encoded(report)
        for held in references.values():
            if 'AFTER-STAGING.json' in held:
                held['AFTER-STAGING.json'] = files['AFTER-STAGING.json']
        host.validate_guest(references, files, source, cuts)

    def test_every_selected_boundary_has_exact_committed_rows_and_file_state(self):
        for cut in self.artifacts[3]:
            host.validate_boundary(cut['boundary'], cut['point'], cut['before']['boot_id'])
        mutations = [lambda x: x.update(worker_state='S'), lambda x: x.update(response_received=True),
            lambda x: x.update(ready_marker_filesystem='ext4'), lambda x: x['manager'].update(MainPID=900),
            lambda x: x['boundary'].update(in_transaction=True), lambda x: x['boundary'].update(active_sql_rows=0),
            lambda x: x['boundary'].update(synchronous=2), lambda x: x['boundary'].update(journal_mode='wal'),
            lambda x: x['boundary'].update(head_sequence=127), lambda x: x['boundary']['pending_file'].update(mode=0o644),
            lambda x: x['boundary']['pending_file'].update(sha256='a' * 64), lambda x: x['boundary'].update(pending_file=None),
            lambda x: x['boundary']['rows'][-1]['evaluation'].update(status='healthy')]
        good = self.artifacts[3][0]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(good['boundary']); mutate(value)
                with self.assertRaises((RuntimeError, ValueError, TypeError, KeyError)):
                    host.validate_boundary(value, good['point'], good['before']['boot_id'])

    def test_powercut_requires_new_vm_same_disk_sigkill_and_direct_io(self):
        mutations = [lambda x: x['after'].update(boot_id=x['before']['boot_id']),
            lambda x: x['after'].update(qemu_pid=x['before']['qemu_pid']),
            lambda x: x['after']['disk_identity'].update(inode=99), lambda x: x.update(signal='SIGTERM'),
            lambda x: x.update(qemu_wait_returncode=0), lambda x: x.update(guest_shutdown_requested=True),
            lambda x: x.update(qemu_graceful_exit_requested=True), lambda x: x.update(ssh_unavailable_observed=False),
            lambda x: x['disk_cache_before_cut']['cache'].update(direct=False),
            lambda x: x['disk_cache_before_cut']['cache'].update(**{'no-flush': True}),
            lambda x: x.update(cold_launch_elapsed_seconds=0)]
        for mutate in mutations:
            bad = copy.deepcopy(self.artifacts[3][0]); mutate(bad)
            with self.assertRaises(RuntimeError):
                host.validate_power_cut(bad)

    def test_changed_original_public_bytes_cannot_be_relegitimized_by_new_manifest(self):
        refs, files, source, cuts = copy.deepcopy(self.artifacts)
        files['before-user.pcap'] += b'altered'
        with self.assertRaisesRegex(RuntimeError, 'host-held'):
            host.validate_guest(refs, files, source, cuts)

    def test_exact_bytes_do_not_excuse_wrong_recovery_or_false_current_health(self):
        changes = [lambda r: r['automatic_start'].update(no_manual_service_start=False),
            lambda r: r['automatic_start']['manager'].update(UnitFileState='disabled'),
            lambda r: r['automatic_start']['status']['archives'].update(recovery_actions=[]),
            lambda r: r['lost_ack_retry']['response'].update(duplicate=False),
            lambda r: r['lost_ack_retry']['response'].update(committed_sequence=255),
            lambda r: r['lost_ack_retry']['after_status']['current_evaluation'].update(status='healthy'),
            lambda r: r.update(volatile_markers_absent=False)]
        for mutate in changes:
            refs, files, source, cuts = copy.deepcopy(self.artifacts)
            report = json.loads(files['AFTER-FILE.json']); mutate(report)
            files['AFTER-FILE.json'] = encoded(report)
            refs['after-file']['AFTER-FILE.json'] = files['AFTER-FILE.json']
            with self.assertRaises((RuntimeError, ValueError)):
                host.validate_guest(refs, files, source, cuts)

    def test_export_is_exact_fixed_inventory_and_rejects_links(self):
        files = {name: b'public' for name in host.GUEST_FILES}
        self.assertEqual(host.extract_guest_export(archive_bytes(files)), files)
        for raw in (archive_bytes(files, extra='../escape'), archive_bytes(files, link='BEFORE.json'),
                    archive_bytes({k: v for k, v in files.items() if k != 'BEFORE.json'})):
            with self.assertRaises(RuntimeError):
                host.extract_guest_export(raw)
        files['BEFORE.json'] = b'PRIVATE KEY'
        with self.assertRaises(RuntimeError):
            host.extract_guest_export(archive_bytes(files))

    def test_mac_guard_precedes_source_output_and_vm_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'not-created'
            with patch.object(host.sys, 'platform', 'darwin'), patch.object(host, 'source_identity') as source:
                with self.assertRaisesRegex(RuntimeError, 'does not run on macOS'):
                    host.run(output)
            source.assert_not_called(); self.assertFalse(output.exists())

    def test_abrupt_cut_kills_and_reaps_only_owned_vm_before_same_disk_cold_start(self):
        cut = copy.deepcopy(self.artifacts[3][0]); vm = host.DisposableVM(TOOLS)
        with tempfile.TemporaryDirectory() as directory:
            vm.directory = Path(directory); (vm.directory / 'disk.qcow2').write_bytes(b'owned temporary disk')
            process = Mock(); process.poll.return_value = None; process.wait.return_value = -9
            process.kill.side_effect = lambda: setattr(process.poll, 'return_value', -9)
            vm.process = process; vm.qmp = Mock(); vm.log = Mock()
            vm.qmp.command.return_value = [{'device': 'he-monitor-disk', 'inserted': {'drv': 'qcow2',
                'ro': False, 'cache': dict(host.CACHE)}}]
            qmp, log = vm.qmp, vm.log
            vm.boot_snapshot = Mock(return_value=cut['before'])
            vm.guest = Mock(return_value=cut['boundary_recheck'])
            vm.ssh = Mock(return_value=subprocess.CompletedProcess([], 255, b'', b''))
            def cold_start(previous):
                self.assertEqual(previous, cut['before'])
                self.assertIsNone(vm.process); self.assertIsNone(vm.qmp); self.assertIsNone(vm.log)
                self.assertEqual((vm.directory / 'disk.qcow2').read_bytes(), b'owned temporary disk')
                vm.last_launch_started = 3.
                return cut['after']
            vm.launch = Mock(side_effect=cold_start)
            with patch.object(host.time, 'monotonic', side_effect=[vm.started + 1., vm.started + 2.]):
                result = vm.power_cut(cut['point'], cut['boundary'])
            process.kill.assert_called_once_with(); process.wait.assert_called_once_with(timeout=15)
            process.terminate.assert_not_called(); qmp.close.assert_called_once(); log.close.assert_called_once()
            vm.guest.assert_called_once_with('inspect-staging'); vm.launch.assert_called_once()
            self.assertEqual(result['qemu_wait_returncode'], -9)

    def test_failure_cleans_owned_vm_and_never_publishes_partial_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory).resolve() / 'result'; vm = Mock()
            vm.prepare.side_effect = RuntimeError('deliberate preparation failure')
            vm.redact.side_effect = str; vm.cleanup.return_value = {'ok': True}
            with patch.object(host, 'preflight', return_value=TOOLS), patch.object(host, 'source_identity', return_value={'commit': 'a' * 40}), \
                    patch.object(host, 'DisposableVM', return_value=vm):
                with self.assertRaisesRegex(RuntimeError, 'deliberate preparation failure'):
                    host.run(output)
            vm.cleanup.assert_called_once_with(); vm.launch.assert_not_called()
            self.assertFalse((output / 'publish').exists())
            self.assertIs(json.loads((output / 'staging' / 'REPORT.json').read_text())['ok'], False)

    def test_source_upload_contains_only_allowlisted_guest_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in host.SOURCE_FILES:
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(name)
            (root / 'private-key').write_text('forbidden')
            with tarfile.open(fileobj=io.BytesIO(host.source_archive(root)), mode='r:gz') as bundle:
                self.assertEqual(bundle.getnames(), list(host.GUEST_SOURCE_FILES))
                self.assertTrue(all(e.isfile() and e.mode == 0o644 for e in bundle.getmembers()))
                self.assertNotIn('scripts/network_monitor_archive_powercut_vm.py', bundle.getnames())


if __name__ == '__main__':
    unittest.main()
