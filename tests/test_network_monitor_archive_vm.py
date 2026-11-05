"""Portable guard, artifact binding, and lifecycle checks for the VM runner."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import subprocess
import unittest
from unittest.mock import patch

from scripts import network_monitor_archive_vm as lab

BOOT = '11111111-1111-4111-8111-111111111111'


def boot_pair():
    before = {'boot_id': BOOT, 'qemu_pid': 123, 'disk_identity': {'device': 4, 'inode': 5},
              'observed_elapsed_seconds': 10.0}
    return before, {**copy.deepcopy(before), 'observed_elapsed_seconds': 90.0}


def archive_bytes(files, *, extra=None, changed_type=None):
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode='w:gz') as archive:
        for name, raw in files.items():
            entry = tarfile.TarInfo(name)
            if changed_type and name == changed_type[0]:
                entry.type, entry.linkname = changed_type[1], '/outside'
                archive.addfile(entry)
            else:
                entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))
        if extra is not None:
            archive.addfile(tarfile.TarInfo(extra), io.BytesIO())
    return content.getvalue()


def archive_fixture():
    rows, records, events, previous = [], [], [], '0' * 64
    critical, incident = 'forbidden_path_open:user->app:9090', 'forbidden_path_open:user->app:9090#1'
    for sequence in range(1, 292):
        restart = sequence in (1, 129, 257)
        cycle = len(records) + 1
        phase = 'monitor_restart' if restart else f'archive_{"a" * 32}_{cycle}'
        req_id = f'_restart_{sequence:032x}' if restart else phase
        probes = [] if restart or not (cycle == 2 or (cycle > 2 and cycle % 16 == 0)) else [1, 2, 3]
        observation = {'phase': phase, 'ruleset': None if restart else {'nftables': []},
                       'collection_error': 'monitor_restarted' if restart else None, 'probes': probes}
        evaluation = {'status': 'healthy' if probes and sequence in (3, 291) else 'unknown'}
        row_events = [{'key': critical, 'action': 'resolved', 'alert_id': incident, 'sequence': sequence}] if sequence == 291 else []
        payload = {'sequence': sequence, 'request_id': req_id,
                   'request': {'kind': 'restart' if restart else 'observation', 'observation': observation},
                   'sample': {**copy.deepcopy(observation), 'sequence': sequence}, 'evaluation': evaluation,
                   'events': row_events, 'previous_digest': previous}
        row = {**payload, 'row_digest': hashlib.sha256(lab.canonical(payload)).hexdigest()}
        rows.append(row); events.extend(row_events); previous = row['row_digest']
        if not restart:
            records.append({'instance_id': 'a' * 32, 'process_id': 500, 'delivery_process_id': 500, 'cycle': cycle,
                'request': {'command': 'observe', 'request_id': req_id, 'observation': copy.deepcopy(observation)},
                'committed_sequence': sequence, 'evaluation': copy.deepcopy(evaluation),
                'duplicate_acknowledgement': sequence in (128, 256), 'delivery_attempts': 2 if sequence in (128, 256) else 1,
                'transport_failures': ['ValueError'] if sequence in (128, 256) else []})
    identity = {'database_id': 'b' * 32, 'format': 'heltemes-monitor-archive-journal', 'version': 1,
                'segment_rows': 128, 'max_rows': 2048, 'max_segments': 16}
    files, descriptors, proofs = {}, [], []
    for index, name in enumerate(lab.SEGMENT_FILES, 1):
        prefix = rows[(index - 1) * 128:index * 128]
        segment = {'format': 'heltemes-monitor-archive-journal-segment', 'version': 1,
            'database_id': identity['database_id'], 'segment_index': index,
            'first_sequence': prefix[0]['sequence'], 'last_sequence': prefix[-1]['sequence'],
            'previous_digest': prefix[0]['previous_digest'], 'last_digest': prefix[-1]['row_digest'], 'rows': prefix}
        raw = lab.canonical(segment) + b'\n'; files[name] = raw
        descriptors.append({'segment_index': index, 'first_sequence': prefix[0]['sequence'],
            'last_sequence': prefix[-1]['sequence'], 'row_count': 128, 'byte_count': len(raw),
            'file_digest': hashlib.sha256(raw).hexdigest(), 'last_digest': prefix[-1]['row_digest']})
        proofs.append({'public_name': name, 'name': f'segment-{index:06d}.json', 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest(), 'mode': 0o600, 'uid': 0, 'nlink': 1})
    def stage(sequence, pid, restarts, elapsed, *, health=None, collector_stopped=False):
        archives = {'segment_rows': 128, 'sealed_segments': sequence // 128, 'archived_rows': sequence // 128 * 128,
            'active_rows': sequence % 128, 'capacity_remaining': 2048 - sequence,
            'archive_bytes': sum(d['byte_count'] for d in descriptors[:sequence // 128]), 'persistence_error': None}
        status = {'process_id': pid, 'committed_count': sequence, 'head_digest': rows[sequence - 1]['row_digest'],
            'current_evaluation': {'status': health or rows[sequence - 1]['evaluation']['status']},
            'alerts': [{'key': critical, 'id': incident, 'state': 'open'}] if 16 <= sequence < 291 else [],
            'freshness': {'enabled': True, 'threshold_seconds': 20, 'persistence_error': None,
                'last_accepted_request_id': rows[sequence - 1]['request_id']}, 'archives': archives}
        return {'status': status, 'observed_elapsed_seconds': elapsed,
            'monitor_manager': {'MainPID': pid, 'NRestarts': restarts, 'ActiveState': 'active', 'UnitFileState': 'enabled'},
            'collector_manager': {'MainPID': 0 if collector_stopped else 500, 'NRestarts': 0, 'UnitFileState': 'enabled'}}
    stages = {'initial': stage(1, 100, 0, 1), 'baseline': stage(3, 100, 0, 3),
        'incident': stage(17, 100, 0, 17), 'beyond_legacy_limit': stage(273, 102, 2, 273),
        'recovered': stage(291, 102, 2, 291, collector_stopped=True)}
    crashes = []
    for index, point in enumerate(('archive_file_durable', 'archive_metadata_committed'), 1):
        sequence = index * 128; record = next(r for r in records if r['committed_sequence'] == sequence)
        boundary = {'point': point, 'head_sequence': sequence, 'head_digest': rows[sequence - 1]['row_digest'],
            'request': copy.deepcopy(record['request']), 'request_id': record['request']['request_id'],
            'observation_sha256': hashlib.sha256(lab.canonical(record['request']['observation'])).hexdigest(),
            'process_id': 99 + index, 'in_transaction': False, 'synchronous': 3, 'journal_mode': 'delete',
            'active_sql_rows': 128 if index == 1 else 0, 'boot_id': BOOT,
            'archive_files': [{k: v for k, v in p.items() if k != 'public_name'} for p in proofs[:index]]}
        crashes.append({'before': stage(sequence - 1, 99 + index, index - 1, sequence - 1),
            'after': stage(sequence + 1, 100 + index, index, sequence + 1), 'boundary': boundary,
            'worker_stopped_observed': True, 'worker_process_state': 'T', 'response_received_before_crash': False})
    final = copy.deepcopy(stages['recovered']['status'])
    report = {'format': 'heltemes-monitor-archive-guest', 'version': 1, 'ok': True,
        'boot_enabled_configuration_only': True, 'services_stopped_after_exercise': True,
        'network_cleanup': {'ok': True}, 'boot': {'boot_id': BOOT}, 'journal_export_method': 'stopped_verified_journal',
        'monitor_stopped_for_export': {'ActiveState': 'inactive', 'MainPID': 0, 'UnitFileState': 'enabled'},
        'configuration': {'segment_rows': 128, 'max_rows': 2048, 'max_segments': 16, 'interval_seconds': 1.0,
                          'canary_every': 16, 'max_cycles': 320, 'finish_after_healthy_cycle': 270, 'freshness_seconds': 20},
        'stages': stages, 'critical_incident_id': incident, 'collector_receipts': records, 'crashes': crashes,
        'journal': {'history_complete': True, 'identity': identity, 'rows': rows, 'archive_descriptors': descriptors, 'events': events},
        'final_status': final, 'archive_files': proofs,
        'archived_duplicate': {'request': copy.deepcopy(records[0]['request']), 'before_status': copy.deepcopy(final),
            'after_status': copy.deepcopy(final), 'result': {'ok': True, 'duplicate': True,
                'committed_sequence': records[0]['committed_sequence'], 'evaluation': copy.deepcopy(records[0]['evaluation'])}},
        'refusal_checks': {'cases': [{'case': name, 'rejected': True} for name in ('missing_archive', 'modified_archive')],
            'original_state_sha256_before': {'db': 'x'}, 'original_state_sha256_after': {'db': 'x'},
            'original_reverified_count': len(rows)}}
    return report, files


class ArchiveHostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='archive-host-tests-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()

    def test_mac_guard_precedes_source_checks_and_output_creation(self):
        output = self.directory / 'not-created'
        with patch.object(lab.sys, 'platform', 'darwin'), patch.object(lab, 'source_identity') as source:
            with self.assertRaisesRegex(RuntimeError, 'does not run on macOS'):
                lab.run(output)
        source.assert_not_called()
        self.assertFalse(output.exists())

    def test_wrong_architecture_refuses_before_provisioning(self):
        with patch.object(lab.sys, 'platform', 'linux'), \
             patch.object(lab.reboot.platform, 'machine', return_value='aarch64'), \
             patch.object(lab.reboot, 'preflight') as provision:
            with self.assertRaisesRegex(RuntimeError, 'x86-64'):
                lab.preflight()
        provision.assert_not_called()

    def test_additional_source_upload_contains_only_five_allowlisted_scripts(self):
        for name in lab.SOURCE_FILES:
            path = self.directory / name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_text(name)
        (self.directory / 'private-key').write_text('not an upload input')
        raw = lab.extra_source_archive(self.directory)
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            self.assertEqual(archive.getnames(), list(lab.EXTRA_GUEST_FILES))
            self.assertEqual(len(archive.getmembers()), 5)
            self.assertTrue(all(member.isfile() and member.mode == 0o644 for member in archive.getmembers()))
            self.assertNotIn('scripts/network_monitor_archive_vm.py', archive.getnames())
            for member in archive.getmembers():
                self.assertEqual(archive.extractfile(member).read(), member.name.encode())
        self.assertEqual(len(lab.GUEST_SOURCE_FILES), 17)
        self.assertEqual(len(lab.SOURCE_FILES), 19)

    def test_export_is_exact_allowlist_and_preserves_bytes(self):
        files = {name: name.encode() for name in lab.GUEST_FILES}
        self.assertEqual(lab.extract_guest_export(archive_bytes(files)), files)
        self.assertEqual(len(lab.PUBLIC_FILES) + 1, 16)  # Public artifacts plus manifest.
        for extra in ('private-key', '../escape', 'GUEST.json'):
            with self.subTest(extra=extra), self.assertRaisesRegex(RuntimeError, 'allowlist'):
                lab.extract_guest_export(archive_bytes(files, extra=extra))
        missing = dict(files); missing.pop('collector.service')
        with self.assertRaisesRegex(RuntimeError, 'allowlist'):
            lab.extract_guest_export(archive_bytes(missing))

    def test_export_rejects_links_and_special_files(self):
        files = {name: b'public' for name in lab.GUEST_FILES}
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind), self.assertRaisesRegex(RuntimeError, 'Unsafe'):
                lab.extract_guest_export(archive_bytes(files, changed_type=('GUEST.json', kind)))

    def test_export_rejects_private_markers_and_compressed_size_overflow(self):
        for marker in (b'-----BEGIN PRIVATE KEY-----', b'/Users/private-path'):
            files = {name: b'public' for name in lab.GUEST_FILES}
            files['collector.service'] = marker
            with self.subTest(marker=marker), self.assertRaisesRegex(RuntimeError, 'private marker'):
                lab.extract_guest_export(archive_bytes(files))
        raw = archive_bytes({name: b'public' for name in lab.GUEST_FILES})
        with patch.object(lab, 'MAX_EXPORT', len(raw) - 1):
            with self.assertRaisesRegex(RuntimeError, 'size bound'):
                lab.extract_guest_export(raw)

    def test_same_guest_requires_boot_process_disk_and_forward_host_elapsed(self):
        before, after = boot_pair()
        lab.validate_same_guest(before, after)
        mutations = (lambda x: x.update(boot_id='22222222-2222-4222-8222-222222222222'),
                     lambda x: x.update(qemu_pid=456), lambda x: x['disk_identity'].update(inode=6),
                     lambda x: x.update(observed_elapsed_seconds=10.0),
                     lambda x: x.update(observed_elapsed_seconds=9.0))
        for change in mutations:
            bad = copy.deepcopy(after); change(bad)
            with self.assertRaises(RuntimeError):
                lab.validate_same_guest(before, bad)
        for pair in ((None, after), (before, None)):
            with self.assertRaisesRegex(RuntimeError, 'missing'):
                lab.validate_same_guest(*pair)


    def test_guest_validation_binds_source_boot_original_report_and_capture_bytes(self):
        report, segments = archive_fixture()
        files = {name: b'public synthetic test bytes' for name in lab.GUEST_FILES}
        files.update(segments)
        source = {'source_sha256': {name: 'c' * 64 for name in lab.SOURCE_FILES}}
        report['source_sha256'] = {name: source['source_sha256'][name] for name in lab.GUEST_SOURCE_FILES}
        report['capture_sha256'] = {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()
                                   if name.endswith(('.pcap', '-packets.txt'))}
        raw = lab.canonical(report); files['GUEST.json'] = raw
        summary = {'boot_id': BOOT, 'guest_report_sha256': hashlib.sha256(raw).hexdigest(),
                   'committed_count': len(report['journal']['rows']), 'current_status': 'healthy'}
        args = (raw, files, source, *boot_pair(), summary)
        lab.validate_guest(*args)
        changes = (
            lambda a: a[1].update({'GUEST.json': b'replaced report'}),
            lambda a: a[1].update({'user.pcap': b'replaced capture'}),
            lambda a: a[2]['source_sha256'].update({lab.GUEST_SOURCE_FILES[0]: 'd' * 64}),
            lambda a: a[5].update(boot_id='another boot'),
            lambda a: a[5].update(guest_report_sha256='0' * 64),
        )
        for index, change in enumerate(changes):
            bad = list(copy.deepcopy(args)); change(bad)
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                lab.validate_guest(*bad)

    def test_guest_failure_retains_bounded_diagnostics_and_redacts_private_transport(self):
        vm = lab.DisposableVM({})
        vm.directory = self.directory
        message = 'x' * 15000 + ' failed_checks:same_collector_process ' + vm.token + ' ' + str(self.directory)
        result = subprocess.CompletedProcess([], 1, stdout=b'', stderr=message.encode())
        with patch.object(vm, 'ssh', return_value=result) as ssh:
            with self.assertRaises(RuntimeError) as caught:
                vm.guest('exercise')
        self.assertIn('failed_checks:same_collector_process', str(caught.exception))
        self.assertNotIn(vm.token, str(caught.exception))
        self.assertNotIn(str(self.directory), str(caught.exception))
        self.assertLess(len(str(caught.exception)), 12500)
        self.assertFalse(ssh.call_args.kwargs['check'])

    def test_complete_archive_lifecycle_and_original_segments_are_accepted(self):
        report, files = archive_fixture()
        lab.validate_lifecycle(report)
        lab.validate_segments(report, files)

    def test_altered_history_segment_or_held_boundary_is_rejected(self):
        mutations = (
            lambda r, f: f.update({lab.SEGMENT_FILES[0]: f[lab.SEGMENT_FILES[0]] + b' '}),
            lambda r, f: r['journal']['rows'][2]['sample'].update(phase='changed'),
            lambda r, f: r['journal']['archive_descriptors'][0].update(first_sequence=2),
            lambda r, f: r['crashes'][0]['boundary']['archive_files'][0].update(sha256='0' * 64),
            lambda r, f: r['final_status']['archives'].update(active_rows=99),
            lambda r, f: r['archive_files'][0].update(mode=0o666),
        )
        for index, mutate in enumerate(mutations):
            report, files = archive_fixture(); mutate(report, files)
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                lab.validate_segments(report, files)

    def test_false_crash_retry_recovery_or_preservation_claims_are_rejected(self):
        mutations = (
            lambda r: r['crashes'][0]['boundary'].update(active_sql_rows=0),
            lambda r: r['crashes'][1]['boundary'].update(in_transaction=True),
            lambda r: r['crashes'][0]['after']['status'].update(process_id=100),
            lambda r: r['crashes'][0].update(response_received_before_crash=True),
            lambda r: r['journal']['rows'][128]['evaluation'].update(status='healthy'),
            lambda r: next(x for x in r['collector_receipts'] if x['committed_sequence'] == 128).update(duplicate_acknowledgement=False),
            lambda r: r['stages']['beyond_legacy_limit']['status']['alerts'].clear(),
            lambda r: r['journal']['events'][0].update(alert_id='replacement#1'),
            lambda r: r['archived_duplicate']['after_status'].update(head_digest='0' * 64),
            lambda r: r['archived_duplicate']['after_status']['freshness'].update(last_accepted_request_id='old'),
            lambda r: r['refusal_checks']['original_state_sha256_after'].update(db='changed'),
            lambda r: r['refusal_checks']['cases'][0].update(rejected=False),
            lambda r: r['monitor_stopped_for_export'].update(MainPID=100),
            lambda r: r['collector_receipts'][10].update(cycle=50),
        )
        for index, mutate in enumerate(mutations):
            report, _ = archive_fixture(); mutate(report)
            with self.subTest(index=index), self.assertRaises(RuntimeError):
                lab.validate_lifecycle(report)


if __name__ == "__main__":
    unittest.main()
