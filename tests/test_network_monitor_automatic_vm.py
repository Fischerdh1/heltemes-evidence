"""Portable guard, artifact binding, and lifecycle checks for the VM runner."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import network_monitor_automatic_vm as lab

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


def public_fixture():
    files = {name: b'synthetic public fixture' for name in lab.GUEST_FILES}
    source = {'source_sha256': {name: 'c' * 64 for name in lab.SOURCE_FILES}}
    report = {**lifecycle_fixture(), 'boot': {'boot_id': BOOT},
              'source_sha256': {name: source['source_sha256'][name] for name in lab.GUEST_SOURCE_FILES},
              'capture_sha256': {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()
                                 if name.endswith(('.pcap', '-packets.txt'))}}
    reference = json.dumps(report).encode()
    files['GUEST.json'] = reference
    summary = {'boot_id': BOOT, 'guest_report_sha256': hashlib.sha256(reference).hexdigest(),
               'committed_count': len(report['journal']['rows']), 'current_status': 'healthy'}
    return reference, files, source, *boot_pair(), summary


def lifecycle_fixture():
    critical, incident_id = 'forbidden_path_open:user->app:9090', 'critical#1'
    rows, receipts = [], []
    phases = ('monitor_restart', f'automatic_{"a" * 32}_1', f'automatic_{"a" * 32}_2', f'automatic_{"a" * 32}_3',
              'collector_missing', f'automatic_{"b" * 32}_1', f'automatic_{"b" * 32}_2')
    health = ('unknown', 'unknown', 'healthy', 'alerting', 'unknown', 'unknown', 'healthy')
    for sequence, (phase, status) in enumerate(zip(phases, health), 1):
        sample = {'phase': phase, 'probes': [1, 2, 3] if status == 'healthy' else []}
        evaluation = {'phase': phase, 'status': status}
        row = {'sequence': sequence, 'request_id': phase, 'request': {'observation': sample},
               'sample': sample, 'evaluation': evaluation}
        rows.append(row)
        if phase.startswith('automatic_'):
            replacement = phase.startswith('automatic_' + 'b' * 32 + '_')
            receipts.append({'committed_sequence': sequence, 'instance_id': ('b' if replacement else 'a') * 32,
                             'process_id': 300 if replacement else 200, 'evaluation': copy.deepcopy(evaluation),
                             'cycle': int(phase.rsplit('_', 1)[1]),
                             'request': {'command': 'observe', 'request_id': phase, 'observation': copy.deepcopy(sample)}})
    monitor_manager = {'MainPID': 100, 'NRestarts': 0, 'ActiveState': 'active', 'UnitFileState': 'enabled'}
    stages = {}
    for index, (name, sequence) in enumerate(zip(('initial', 'baseline', 'incident', 'silent', 'repaired_silent', 'recovered'),
                                               (1, 3, 4, 5, 5, 7)), 1):
        missing = name in ('silent', 'repaired_silent')
        recovered = name == 'recovered'
        status = {'process_id': 100, 'instance_id': 'c' * 32, 'committed_count': sequence,
                  'head_digest': str(sequence) * 64, 'current_evaluation': copy.deepcopy(rows[sequence - 1]['evaluation']),
                  'alerts': [{'key': critical, 'id': incident_id, 'state': 'resolved' if recovered else 'open'}]
                            if name in ('incident', 'silent', 'repaired_silent', 'recovered') else [],
                  'freshness': {'enabled': True, 'threshold_seconds': 20, 'persistence_error': None,
                                'gap_recorded': missing, 'expired': missing, 'gap_sequence': 5 if missing else None,
                                'gap_committed_at_utc': '2026-11-05T00:00:30+00:00' if missing else None}}
        stages[name] = {'status': status, 'monitor_manager': copy.deepcopy(monitor_manager),
                        'collector_manager': {'MainPID': 300 if recovered else 200, 'NRestarts': 1 if recovered else 0,
                                              'ActiveState': 'active', 'UnitFileState': 'enabled'},
                        'observed_elapsed_seconds': index * 5.0}
    return {'format': 'heltemes-monitor-automatic-guest', 'version': 1, 'ok': True,
            'boot_enabled_configuration_only': True, 'network_cleanup': {'ok': True}, 'stages': stages,
            'critical_incident_id': incident_id,
            'silence': {'collector_proc_state': 'T', 'monitor_rpc_requests_during_wait': 0, 'elapsed_seconds': 22,
                        'started_at_utc': '2026-11-05T00:00:10+00:00',
                        'gap_committed_at_utc': '2026-11-05T00:00:30+00:00',
                        'deadline_at_utc': '2026-11-05T00:00:30+00:00', 'deadline_lateness_seconds': 0.0,
                        'first_inspected_at_utc': '2026-11-05T00:00:32+00:00', 'gap_sequence': 5,
                        'collector_pid': 200, 'collector_idle_receipt': {'process_id': 200, 'state': 'idle'}},
            'journal': {'rows': rows, 'events': [{'key': critical, 'action': 'resolved',
                                                  'alert_id': incident_id, 'sequence': 7}]},
            'final_status': copy.deepcopy(stages['recovered']['status']), 'collector_receipts': receipts}


class AutomaticHostTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='automatic-host-tests-')
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

    def test_additional_source_upload_contains_only_two_allowlisted_scripts(self):
        for name in lab.SOURCE_FILES:
            path = self.directory / name
            path.parent.mkdir(exist_ok=True, parents=True)
            path.write_text(name)
        (self.directory / 'private-key').write_text('not an upload input')
        raw = lab.extra_source_archive(self.directory)
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
            self.assertEqual(archive.getnames(), list(lab.EXTRA_GUEST_FILES))
            self.assertEqual(len(archive.getmembers()), 2)
            self.assertTrue(all(member.isfile() and member.mode == 0o644 for member in archive.getmembers()))
            self.assertNotIn('scripts/network_monitor_automatic_vm.py', archive.getnames())
            for member in archive.getmembers():
                self.assertEqual(archive.extractfile(member).read(), member.name.encode())
        self.assertEqual(len(lab.GUEST_SOURCE_FILES), 14)
        self.assertEqual(len(lab.SOURCE_FILES), 16)

    def test_export_is_exact_allowlist_and_preserves_bytes(self):
        files = {name: name.encode() for name in lab.GUEST_FILES}
        self.assertEqual(lab.extract_guest_export(archive_bytes(files)), files)
        self.assertEqual(len(lab.PUBLIC_FILES) + 1, 14)  # Public artifacts plus manifest.
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
        with patch.object(lab.reboot, 'MAX_EXPORT', len(raw) - 1):
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

    def test_guest_export_binds_exact_source_report_boot_and_capture_bytes(self):
        args = public_fixture()
        result = lab.validate_guest(*args)
        self.assertEqual(result['boot']['boot_id'], BOOT)
        changes = (
            lambda a: a[1].update({'GUEST.json': b'changed'}),
            lambda a: a[1].update({'user.pcap': b'changed packet bytes'}),
            lambda a: a[2]['source_sha256'].update({lab.GUEST_SOURCE_FILES[0]: 'd' * 64}),
            lambda a: a[5].update(boot_id='another-boot'),
            lambda a: a[5].update(guest_report_sha256='e' * 64),
        )
        for change in changes:
            bad = list(copy.deepcopy(args)); change(bad)
            with self.assertRaises(RuntimeError):
                lab.validate_guest(*bad)

    def test_missing_or_additional_capture_fingerprints_are_rejected(self):
        for alter in ('missing', 'extra'):
            args = list(public_fixture())
            report = json.loads(args[0])
            if alter == 'missing':
                report['capture_sha256'].pop('user.pcap')
            else:
                report['capture_sha256']['private.pcap'] = '0' * 64
            args[0] = json.dumps(report).encode()
            args[1]['GUEST.json'] = args[0]
            args[5]['guest_report_sha256'] = hashlib.sha256(args[0]).hexdigest()
            with self.assertRaises(RuntimeError):
                lab.validate_guest(*args)

    def test_valid_bounded_lifecycle_is_accepted(self):
        lab.validate_lifecycle(lifecycle_fixture())

    def assert_lifecycle_rejected(self, mutations):
        for index, change in enumerate(mutations):
            bad = lifecycle_fixture(); change(bad)
            with self.subTest(mutation=index), self.assertRaises(RuntimeError):
                lab.validate_lifecycle(bad)

    def test_lifecycle_rejects_missing_stages_false_health_or_restarted_monitor(self):
        self.assert_lifecycle_rejected((
            lambda x: x.update(ok=False),
            lambda x: x['stages'].pop('baseline'),
            lambda x: x['stages']['silent']['status']['current_evaluation'].update(status='healthy'),
            lambda x: x['stages']['silent'].update(observed_elapsed_seconds=1),
            lambda x: x['stages']['recovered']['status'].update(process_id=101),
            lambda x: x['stages']['recovered']['status'].update(instance_id='d' * 32),
            lambda x: x['stages']['silent']['monitor_manager'].update(NRestarts=1),
            lambda x: x['stages']['silent']['monitor_manager'].update(UnitFileState='disabled'),
            lambda x: x['stages']['silent']['status']['freshness'].update(persistence_error='disk_full'),
            lambda x: x['stages']['silent']['status']['freshness'].update(threshold_seconds=30),
        ))

    def test_lifecycle_rejects_rpc_triggered_gap_late_gap_or_unpaused_collector(self):
        self.assert_lifecycle_rejected((
            lambda x: x['silence'].update(monitor_rpc_requests_during_wait=1),
            lambda x: x['silence'].update(collector_proc_state='S'),
            lambda x: x['silence'].update(elapsed_seconds=19),
            lambda x: x['silence'].update(elapsed_seconds=31),
            lambda x: x['silence'].update(gap_committed_at_utc='2026-11-05T00:00:32+00:00'),
            lambda x: x['silence'].update(gap_committed_at_utc='2026-11-05T00:00:09+00:00'),
            lambda x: x['silence'].update(deadline_at_utc='2026-11-05T00:00:24+00:00', deadline_lateness_seconds=6.0),
            lambda x: x['silence'].update(deadline_lateness_seconds=1.0),
            lambda x: x['stages']['silent']['status']['freshness'].update(gap_recorded=False),
            lambda x: x['stages']['silent']['status']['freshness'].update(gap_sequence=4),
        ))

    def test_lifecycle_requires_incident_preservation_and_unchanged_silent_repair(self):
        self.assert_lifecycle_rejected((
            lambda x: x['stages']['silent']['status']['alerts'].clear(),
            lambda x: x['stages']['repaired_silent']['status']['alerts'][0].update(id='another-incident'),
            lambda x: x['stages']['repaired_silent']['status']['alerts'][0].update(state='resolved'),
            lambda x: x['stages']['repaired_silent']['status'].update(committed_count=6),
            lambda x: x['stages']['repaired_silent']['status'].update(head_digest='f' * 64),
        ))

    def test_lifecycle_requires_supervisor_replacement_of_same_idle_collector(self):
        self.assert_lifecycle_rejected((
            lambda x: x['silence']['collector_idle_receipt'].update(process_id=999),
            lambda x: x['silence']['collector_idle_receipt'].update(state='collecting'),
            lambda x: x['stages']['recovered']['collector_manager'].update(MainPID=200),
            lambda x: x['stages']['recovered']['collector_manager'].update(NRestarts=0),
            lambda x: x['stages']['recovered']['collector_manager'].update(ActiveState='failed'),
        ))

    def test_lifecycle_requires_unique_gap_fresh_canaries_and_matching_receipts(self):
        self.assert_lifecycle_rejected((
            lambda x: x['final_status'].update(committed_count=6),
            lambda x: x['final_status']['current_evaluation'].update(status='unknown'),
            lambda x: x['journal']['rows'][1]['sample'].update(phase='collector_missing'),
            lambda x: x['journal']['events'][0].update(alert_id='another-incident'),
            lambda x: x['journal']['events'][0].update(sequence=4),
            lambda x: x['journal']['rows'][-1]['sample'].update(probes=[]),
            lambda x: x['collector_receipts'].pop(),
            lambda x: x['collector_receipts'][0]['request'].update(request_id='another-request'),
            lambda x: x['collector_receipts'][0]['request']['observation'].update(phase='fabricated-phase'),
            lambda x: x['collector_receipts'][0].update(cycle=True),
            lambda x: x['collector_receipts'][0]['evaluation'].update(status='fabricated'),
            lambda x: x['collector_receipts'][-1].update(instance_id='a' * 32),
        ))


if __name__ == '__main__':
    unittest.main()
