"""Verify bounded monitoring history archiving and crash recovery in a disposable VM."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor_reboot_vm as reboot

require, timestamp = reboot.require, reboot.timestamp
EXTRA_GUEST_FILES = ('scripts/network_monitor_collector.py', 'scripts/network_monitor_automatic_guest.py',
                     'scripts/network_monitor_archive.py', 'scripts/network_monitor_archive_collector.py',
                     'scripts/network_monitor_archive_guest.py')
GUEST_SOURCE_FILES = (*reboot.SOURCE_FILES[:-1], *EXTRA_GUEST_FILES)
SOURCE_FILES = (*GUEST_SOURCE_FILES, 'scripts/network_monitor_reboot_vm.py', 'scripts/network_monitor_archive_vm.py')
GUEST_ROOT = reboot.GUEST_ROOT
GUEST_SCRIPT = GUEST_ROOT + '/scripts/network_monitor_archive_guest.py'
GUEST_REPORT = '/var/lib/heltemes-archive-lab/report/publish'
GUEST_FILES = ('GUEST.json', 'APPROVED_POLICY.json', 'monitor.service', 'collector.service',
               *(name for zone in ('user', 'app', 'management') for name in (zone + '.pcap', zone + '-packets.txt')))
SEGMENT_FILES = ('archive-segment-000001.json', 'archive-segment-000002.json')
GUEST_FILES = (*GUEST_FILES, *SEGMENT_FILES)
MAX_EXPORT = 64 * 1024 * 1024
PUBLIC_FILES = ('REPORT.json', 'VM.json', 'SUMMARY.md', *GUEST_FILES)


def progress(message):
    print('Archive monitor VM: ' + message, file=sys.stderr, flush=True)


def preflight():
    require(sys.platform == 'linux' and reboot.platform.machine() in {'x86_64', 'amd64'},
            'Archive monitoring requires a disposable x86-64 Linux host; it does not run on macOS.')
    return reboot.preflight()


def source_identity(root=ROOT, environment=None):
    root = Path(root).resolve()
    identity = reboot.source_identity(root, environment)
    for name in (*EXTRA_GUEST_FILES, 'scripts/network_monitor_archive_vm.py'):
        content = (root / name).read_bytes()
        result = subprocess.run(['git', '-c', f'safe.directory={root}', '-C', str(root),
                                 'show', f"{identity['commit']}:{name}"], capture_output=True, timeout=30)
        require(result.returncode == 0 and result.stdout == content,
                'Archive monitor source differs from its committed version.')
        identity['source_sha256'][name] = hashlib.sha256(content).hexdigest()
    require(set(identity['source_sha256']) == set(SOURCE_FILES), 'The source inventory is incomplete.')
    return identity


def extra_source_archive(root=ROOT):
    content = io.BytesIO()
    with tarfile.open(fileobj=content, mode='w:gz') as archive:
        for name in EXTRA_GUEST_FILES:
            raw = (Path(root) / name).read_bytes()
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.uid, entry.gid, entry.mtime = len(raw), 0o644, 0, 0, 0
            archive.addfile(entry, io.BytesIO(raw))
    return content.getvalue()


class DisposableVM(reboot.DisposableVM):
    """Reuse the verified pinned image, private SSH transport, and owned cleanup."""
    def launch(self):
        super().launch()  # Installs exactly the existing twelve guest source files.
        progress('installing the five additional allowlisted archive and collector sources')
        self.ssh('sudo -n tar -xz --no-same-owner -f - -C ' + GUEST_ROOT,
                 input=extra_source_archive(), timeout=60)

    def guest(self, stage):
        require(stage in {'exercise', 'cleanup'}, 'Unknown archive guest stage.')
        result = self.ssh('sudo -n python3 -I -S -B ' + GUEST_SCRIPT + ' ' + stage + ' --token ' + self.token,
                          timeout=600 if stage == 'exercise' else 60, check=False)
        if result.returncode:
            error = (result.stderr or result.stdout).decode(errors='replace')[-12 * 1024:]
            raise RuntimeError('A disposable archive guest operation failed: ' + self.redact(error).strip())
        require(len(result.stdout) <= 1024 * 1024, 'Guest stage metadata exceeds its bound.')
        value = json.loads(result.stdout)
        require(isinstance(value, dict) and value.get('ok') is True, 'The archive guest stage failed.')
        return value

    def reference(self):
        content = self.ssh('sudo -n cat ' + GUEST_REPORT + '/GUEST.json', timeout=15).stdout
        require(0 < len(content) <= 16 * 1024 * 1024, 'Guest report exceeds its size bound.')
        return content

    def export_guest(self):
        result = self.ssh('sudo -n tar -cz -C ' + GUEST_REPORT + ' -- ' + ' '.join(GUEST_FILES), timeout=60)
        return extract_guest_export(result.stdout)


def extract_guest_export(content):
    require(len(content) <= MAX_EXPORT, 'Guest export exceeds its size bound.')
    with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as archive:
        entries = archive.getmembers()
        require(len(entries) == len(GUEST_FILES) and {entry.name for entry in entries} == set(GUEST_FILES),
                'Guest export differs from the fixed public allowlist.')
        require(all(entry.isfile() and entry.size <= 16 * 1024 * 1024 for entry in entries)
                and sum(entry.size for entry in entries) <= MAX_EXPORT, 'Unsafe guest export entry.')
        files = {entry.name: archive.extractfile(entry).read() for entry in entries}
    require(not any(b'PRIVATE KEY' in raw or b'/Users/' in raw for raw in files.values()),
            'A private marker appeared in the public export.')
    return files


def validate_same_guest(before, after):
    require(before is not None and after is not None, 'The guest boot observation is missing.')
    require(before['boot_id'] == after['boot_id'] and before['qemu_pid'] == after['qemu_pid']
            and before['disk_identity'] == after['disk_identity']
            and before['observed_elapsed_seconds'] < after['observed_elapsed_seconds'],
            'The bounded archive exercise unexpectedly replaced or rebooted its guest.')


def validate_lifecycle(report):
    require(report['format'] == 'heltemes-monitor-archive-guest' and report['version'] == 1
            and report['ok'] is True and report['boot_enabled_configuration_only'] is True
            and report['services_stopped_after_exercise'] is True and report['network_cleanup']['ok'] is True
            and report['journal_export_method'] == 'stopped_verified_journal',
            'Guest completion or scope differs.')
    stopped = report['monitor_stopped_for_export']
    require(stopped['ActiveState'] == 'inactive' and stopped['MainPID'] == 0
            and stopped['UnitFileState'] == 'enabled', 'Offline history export did not stop the writer.')
    require(report['configuration'] == {'segment_rows': 128, 'max_rows': 2048, 'max_segments': 16,
            'interval_seconds': 1.0, 'canary_every': 16, 'max_cycles': 320, 'finish_after_healthy_cycle': 270, 'freshness_seconds': 20},
            'Archive exercise configuration differs.')
    stages, journal = report['stages'], report['journal']
    names = ('initial', 'baseline', 'incident', 'beyond_legacy_limit', 'recovered')
    require(set(stages) == set(names), 'Archive stage inventory differs.')
    times = [stages[name]['observed_elapsed_seconds'] for name in names]
    require(all(a < b for a, b in zip(times, times[1:])), 'Stage chronology does not advance.')
    critical, incident = 'forbidden_path_open:user->app:9090', report['critical_incident_id']

    def check_status(stage):
        status, manager = stage['status'], stage['monitor_manager']
        require(manager['ActiveState'] == 'active' and manager['UnitFileState'] == 'enabled'
                and manager['MainPID'] == status['process_id']
                and status['freshness']['enabled'] is True and status['freshness']['threshold_seconds'] == 20
                and status['freshness']['persistence_error'] is None
                and status['archives']['persistence_error'] is None, 'Service identity, freshness, or persistence failed.')
        return status

    def check_incident(status):
        incidents = [a for a in status['alerts'] if a['key'] == critical and a['state'] == 'open']
        require(len(incidents) == 1 and incidents[0]['id'] == incident, 'Rollover or restart lost the unresolved incident.')

    for name in names:
        check_status(stages[name])
    require(stages['initial']['status']['current_evaluation']['status'] == 'unknown'
            and stages['baseline']['status']['current_evaluation']['status'] == 'healthy'
            and stages['recovered']['status']['current_evaluation']['status'] == 'healthy'
            and report['final_status']['current_evaluation']['status'] == 'healthy', 'Initial or final coverage differs.')
    for name in ('incident', 'beyond_legacy_limit'):
        check_incident(stages[name]['status'])
    require(stages['beyond_legacy_limit']['status']['committed_count'] > 256, 'The old history bound was not crossed.')
    rows, records, crashes = journal['rows'], report['collector_receipts'], report['crashes']
    require(270 <= len(records) <= 320 and len(rows) == len(records) + 3 and len(crashes) == 2,
            'Real observation or startup boundary counts differ.')
    require([r['cycle'] for r in records] == list(range(1, len(records) + 1))
            and len({r['instance_id'] for r in records}) == len({r['process_id'] for r in records}) == 1,
            'Autonomous collector identity or cycle continuity differs.')
    by_id = {row['request_id']: row for row in rows}
    for record in records:
        payload, cycle = record['request'], record['cycle']
        row = by_id[payload['request_id']]
        expected_probes = 3 if cycle == 2 or (cycle > 2 and cycle % 16 == 0) else 0
        require(payload['command'] == 'observe' and payload['request_id'] == f"archive_{record['instance_id']}_{cycle}"
                and row['request']['kind'] == 'observation' and row['request']['observation'] == payload['observation']
                and row['sequence'] == record['committed_sequence'] and row['evaluation'] == record['evaluation']
                and payload['observation']['ruleset'] is not None and payload['observation']['collection_error'] is None
                and len(payload['observation']['probes']) == expected_probes
                and record['delivery_process_id'] == record['process_id'], 'Autonomous receipt differs from committed evidence.')
        require(expected_probes or row['evaluation']['status'] != 'healthy', 'Rules alone asserted complete healthy coverage.')
    collector_pid = records[0]['process_id']
    for name in names[1:]:
        manager = stages[name]['collector_manager']
        require(manager['MainPID'] == collector_pid or (name == 'recovered' and manager['MainPID'] == 0),
                'Collector service identity differs from its receipts.')
        require(manager['NRestarts'] == 0 and manager['UnitFileState'] == 'enabled', 'Collector unexpectedly restarted.')
    expected_points = ('archive_file_durable', 'archive_metadata_committed')
    monitor_ids = [stages['initial']['status']['process_id']]
    for index, (crash, point) in enumerate(zip(crashes, expected_points), 1):
        before, boundary, after = crash['before'], crash['boundary'], crash['after']
        old, new = check_status(before), check_status(after)
        check_incident(old); check_incident(new)
        sequence = 128 * index
        row = rows[sequence - 1]
        receipt = next(r for r in records if r['committed_sequence'] == sequence)
        require(crash['worker_stopped_observed'] is True and crash['worker_process_state'] == 'T'
                and crash['response_received_before_crash'] is False and boundary['point'] == point
                and boundary['head_sequence'] == sequence and boundary['head_digest'] == row['row_digest']
                and boundary['process_id'] == old['process_id'] == monitor_ids[-1]
                and new['process_id'] != old['process_id'] and new['committed_count'] > sequence
                and boundary['in_transaction'] is False and boundary['synchronous'] == 3
                and boundary['journal_mode'] == 'delete' and boundary['active_sql_rows'] == (128 if index == 1 else 0)
                and boundary['boot_id'] == report['boot']['boot_id'], 'Archive process crash boundary differs.')
        require(after['monitor_manager']['NRestarts'] == before['monitor_manager']['NRestarts'] + 1
                and before['collector_manager']['MainPID'] == after['collector_manager']['MainPID'] == collector_pid,
                'Supervisor restart or independent collector identity differs.')
        require(boundary['request'] == receipt['request'] and boundary['request_id'] == row['request_id']
                and boundary['observation_sha256'] == hashlib.sha256(canonical(row['request']['observation'])).hexdigest()
                and receipt['duplicate_acknowledgement'] is True and receipt['delivery_attempts'] > 1
                and receipt['transport_failures'], 'Lost acknowledgement did not produce an exact historical retry.')
        restart = rows[sequence]
        require(restart['sample']['phase'] == 'monitor_restart' and restart['evaluation']['status'] == 'unknown',
                'Restart did not record unknown coverage after the archive boundary.')
        monitor_ids.append(new['process_id'])
    require(len(set(monitor_ids)) == 3 and stages['recovered']['status']['process_id'] == monitor_ids[-1]
            and stages['recovered']['monitor_manager']['NRestarts'] == 2, 'Expected exactly two monitor process restarts.')
    resolved = [event for event in journal['events'] if event['key'] == critical and event['action'] == 'resolved']
    require(len(resolved) == 1 and resolved[0]['alert_id'] == incident and resolved[0]['sequence'] > 256,
            'The original incident did not resolve exactly once after both handoffs.')
    resolution = rows[resolved[0]['sequence'] - 1]
    require(resolution['evaluation']['status'] == 'healthy' and len(resolution['sample']['probes']) == 3,
            'Incident resolution lacked fresh complete canaries.')
    duplicate = report['archived_duplicate']
    first, old, new, result = records[0], duplicate['before_status'], duplicate['after_status'], duplicate['result']
    require(duplicate['request'] == first['request'] and result['ok'] is True and result['duplicate'] is True
            and result['committed_sequence'] == first['committed_sequence'] <= 128
            and result['evaluation'] == first['evaluation'] and old['committed_count'] == new['committed_count']
            and old['head_digest'] == new['head_digest']
            and old['freshness']['last_accepted_request_id'] == new['freshness']['last_accepted_request_id'],
            'Archived retry changed history or refreshed current coverage.')
    refused = report['refusal_checks']
    require({item['case'] for item in refused['cases']} == {'missing_archive', 'modified_archive'}
            and len(refused['cases']) == 2 and all(item['rejected'] is True for item in refused['cases'])
            and refused['original_state_sha256_before'] == refused['original_state_sha256_after']
            and refused['original_reverified_count'] == len(rows), 'Disposable negative controls or original preservation failed.')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def validate_segments(report, files):
    journal = report['journal']
    rows, descriptors, identity = journal['rows'], journal['archive_descriptors'], journal['identity']
    require(journal['history_complete'] is True and 270 <= len(rows) <= 325
            and identity['format'] == 'heltemes-monitor-archive-journal'
            and identity['version'] == 1 and identity['segment_rows'] == 128
            and identity['max_rows'] == 2048 and identity['max_segments'] == 16,
            'Archive identity, complete history, or exercise row budget differs.')
    require(len(descriptors) == len(SEGMENT_FILES) == 2, 'Expected exactly two completed archive segments.')
    previous, requests = '0' * 64, set()
    for sequence, row in enumerate(rows, 1):
        require(row['sequence'] == sequence and row['sample']['sequence'] == sequence
                and row['previous_digest'] == previous and row['request_id'] not in requests,
                'Global history sequence, chain, or request uniqueness differs.')
        payload = {key: value for key, value in row.items() if key != 'row_digest'}
        require(hashlib.sha256(canonical(payload)).hexdigest() == row['row_digest'], 'A committed row fingerprint differs.')
        previous = row['row_digest']; requests.add(row['request_id'])
    for index, (name, descriptor) in enumerate(zip(SEGMENT_FILES, descriptors), 1):
        raw = files[name]
        prefix = rows[(index - 1) * 128:index * 128]
        segment = {'format': 'heltemes-monitor-archive-journal-segment', 'version': 1,
                   'database_id': identity['database_id'], 'segment_index': index,
                   'first_sequence': prefix[0]['sequence'], 'last_sequence': prefix[-1]['sequence'],
                   'previous_digest': prefix[0]['previous_digest'], 'last_digest': prefix[-1]['row_digest'], 'rows': prefix}
        require(raw == canonical(segment) + b'\n', 'Original archive bytes differ from the global history prefix.')
        expected = {'segment_index': index, 'first_sequence': prefix[0]['sequence'],
                    'last_sequence': prefix[-1]['sequence'], 'row_count': 128, 'byte_count': len(raw),
                    'file_digest': hashlib.sha256(raw).hexdigest(), 'last_digest': prefix[-1]['row_digest']}
        require(descriptor == expected, 'Archive descriptor differs from its original file.')
    require(len(report['archive_files']) == 2, 'Original archive inventory differs.')
    for index, proof in enumerate(report['archive_files'], 1):
        name = SEGMENT_FILES[index - 1]
        require(proof['public_name'] == name and proof['name'] == f'segment-{index:06d}.json'
                and proof['bytes'] == len(files[name]) and proof['sha256'] == hashlib.sha256(files[name]).hexdigest()
                and proof['mode'] == 0o600 and proof['uid'] == 0 and proof['nlink'] == 1,
                'Exported segment differs from its protected guest file.')
    for index, crash in enumerate(report['crashes'], 1):
        proofs = crash['boundary']['archive_files']
        require(len(proofs) == index, 'Crash archive inventory differs.')
        for position, proof in enumerate(proofs, 1):
            expected = {k: v for k, v in report['archive_files'][position - 1].items() if k != 'public_name'}
            require(proof == expected, 'Archive bytes changed after the held crash boundary.')
    final = report['final_status']
    archives = final['archives']
    require(final['committed_count'] == len(rows) and final['head_digest'] == previous
            and archives['segment_rows'] == 128 and archives['sealed_segments'] == 2
            and archives['archived_rows'] == 256 and archives['active_rows'] == len(rows) - 256
            and archives['capacity_remaining'] == 2048 - len(rows)
            and archives['archive_bytes'] == sum(len(files[name]) for name in SEGMENT_FILES)
            and archives['persistence_error'] is None, 'Final active/archive accounting differs.')


def validate_guest(reference, files, source, before, after, summary):
    validate_same_guest(before, after)
    require(files['GUEST.json'] == reference, 'The guest report changed before export.')
    report = json.loads(reference)
    require(report['source_sha256'] == {name: source['source_sha256'][name] for name in GUEST_SOURCE_FILES},
            'Guest source bytes differ from the exact committed source.')
    require(report['boot']['boot_id'] == before['boot_id'] == summary['boot_id'], 'Guest and host boot identities differ.')
    require(summary['guest_report_sha256'] == hashlib.sha256(reference).hexdigest(), 'Completed guest report fingerprint differs.')
    names = {name for name in GUEST_FILES if name.endswith(('.pcap', '-packets.txt'))}
    hashes = report.get('capture_sha256')
    require(isinstance(hashes, dict) and set(hashes) == names
            and all(hashlib.sha256(files[name]).hexdigest() == checksum for name, checksum in hashes.items()),
            'Exported capture bytes differ from their completed-stage fingerprints.')
    require(summary['committed_count'] == len(report['journal']['rows']) and summary['current_status'] == 'healthy',
            'Guest summary differs from its completed journal.')
    validate_segments(report, files)
    validate_lifecycle(report)
    return report


def run(output):
    tools = preflight()
    source = source_identity()
    destination = reboot.monitoring.base.new_output(output)
    staging = destination / 'staging'; staging.mkdir(mode=0o700)
    vm = DisposableVM(tools)
    report = {'format': 'heltemes-network-monitor-archive-lab', 'version': 1, 'ok': False,
              'started_at_utc': timestamp(), 'source': source,
              'scope': {'synthetic_only': True, 'aws_deployed': False, 'real_evidence_inputs': False,
                        'bounded_unattended_collection': True, 'collector_silence_detection_tested': False,
                        'vm_reboot_tested': False, 'physical_power_loss_tested': False,
                        'continuous_production_operation': False, 'dedicated_account_isolation_tested': False,
                        'external_notification_delivery': False, 'history_rotation_tested': True,
                        'archive_handoff_process_crashes_tested': True, 'administrator_resistant_history': False}}
    evidence, files = {}, {}
    step = 'preparing pinned VM image and private boot media'
    progress(step)
    try:
        evidence['image'] = {'url': reboot.IMAGE_URL, 'sha256': reboot.IMAGE_SHA256}
        evidence['virtualization'] = vm.prepare()
        step = 'booting and provisioning disposable guest'; progress(step); vm.launch()
        evidence['virtualization']['qmp_kvm'] = vm.kvm_status
        evidence['cloud_init'] = vm.cloud_init
        before = vm.boot_snapshot()
        step = 'running automatic collection beyond 256 rows, archive handoff crashes, and fresh recovery'; progress(step)
        summary = vm.guest('exercise')
        reference = vm.reference()
        after = vm.boot_snapshot()
        step = 'exporting and checking source, history, timing, and packet evidence'; progress(step)
        files = vm.export_guest()
        validate_guest(reference, files, source, before, after, summary)
        evidence.update({'boot_before': before, 'boot_after': after, 'guest_summary': summary,
                         'guest_reference_sha256': hashlib.sha256(reference).hexdigest(),
                         'guest_reference_held_outside_guest': True})
        step = 'removing guest services and synthetic state'; progress(step)
        evidence['guest_cleanup'] = vm.guest('cleanup')
        require(source_identity() == source, 'Archive monitoring source changed during the run.')
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        report['error'] = step + ': ' + vm.redact(error).replace(str(destination), '<report>')
    finally:
        try:
            progress('stopping the owned VM and deleting private credentials and disk')
            evidence['cleanup'] = vm.cleanup()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            evidence['cleanup'] = {'ok': False, 'error': vm.redact(error)}
        report['completed_at_utc'] = timestamp()
    report['ok'] = 'error' not in report and evidence['cleanup']['ok']
    report['cleanup'] = evidence['cleanup']
    reboot.write_json(staging / 'REPORT.json', report)
    if not report['ok']:
        raise RuntimeError('Archive monitoring exercise failed: ' + report.get('error', 'Private VM cleanup failed.'))
    for name, content in files.items():
        (staging / name).write_bytes(content)
    reboot.write_json(staging / 'VM.json', evidence)
    (staging / 'SUMMARY.md').write_text(f'''# HELTEMES Evidence monitoring history archive exercise

Source commit `{source['commit']}`. Completed {report['completed_at_utc']}.

The collector accepted more than 256 real firewall observations in a disposable Linux guest. Older rows moved into two replay-verified archive segments while the active database stayed bounded. One incident retained its identity across rollover and monitor process crashes, then required fresh network checks before resolution.

Both interruptions happened after an observation committed: once after its archive file became durable, and once after the database recorded the archive and pruned its active prefix. Saved exact-request retries returned the original observation without duplicate commits. Missing and altered archive segments were rejected on disposable state copies.

Inspect GUEST.json, the two original archive files, and the packet captures. VM.json binds this one-boot exercise to the pinned image, source, guest identity, and cleanup. MANIFEST.json covers every public file.

This is finite retention with explicit row, byte, segment, and probe budgets. It does not demonstrate unlimited runtime, physical power loss during archiving, an archive-aware full-VM reboot, separate-account isolation, external notifications, or administrator-resistant history. AWS and real Evidence keys/history are outside its scope.

The guest services and synthetic network were cleaned up. The owned VM, private access credentials, seed, and disk were removed before publication.
''')
    reboot.write_json(staging / 'MANIFEST.json', {name: reboot.sha256_file(staging / name) for name in PUBLIC_FILES})
    publish = destination / 'publish'; publish.mkdir(mode=0o755)
    for name in (*PUBLIC_FILES, 'MANIFEST.json'):
        (staging / name).rename(publish / name); (publish / name).chmod(0o644)
    destination.chmod(0o755)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='New report directory with an existing parent')
    args = parser.parse_args()
    try:
        result = run(args.output)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, 'Archive monitor VM stopped: ' + str(error) + '\n')
    print(json.dumps({'ok': result['ok'], 'source_commit': result['source']['commit'], 'cleanup': result['cleanup']}, indent=2))


if __name__ == '__main__':
    main()
