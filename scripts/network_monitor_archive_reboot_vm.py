"""Verify archived monitoring history across a full disposable Linux guest reboot."""
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
    'scripts/network_monitor_archive_reboot_collector.py', 'scripts/network_monitor_archive_reboot_guest.py')
GUEST_SOURCE_FILES = (*reboot.SOURCE_FILES[:-1], *EXTRA_GUEST_FILES)
SOURCE_FILES = (*GUEST_SOURCE_FILES, 'scripts/network_monitor_reboot_vm.py', 'scripts/network_monitor_archive_reboot_vm.py')
GUEST_ROOT = reboot.GUEST_ROOT
GUEST_SCRIPT = GUEST_ROOT + '/scripts/network_monitor_archive_reboot_guest.py'
GUEST_REPORT = '/var/lib/heltemes-archive-reboot-lab/report/publish'
SEGMENT_FILES = tuple(f'archive-segment-{i:06d}.json' for i in range(1, 4))
CAPTURE_FILES = tuple(phase + '-' + zone + suffix for phase in ('before', 'after')
                      for zone in ('user', 'app', 'management') for suffix in ('.pcap', '-packets.txt'))
COMMON_FILES = ('APPROVED_POLICY.json', 'monitor.service', 'collector.service')
PREBOOT_FILES = ('BEFORE.json', 'BEFORE-HISTORY.json', *COMMON_FILES,
                 *CAPTURE_FILES[:6], *SEGMENT_FILES[:2])
GUEST_FILES = (*PREBOOT_FILES, 'AFTER.json', 'AFTER-HISTORY.json', *CAPTURE_FILES[6:], SEGMENT_FILES[2])
PUBLIC_FILES = ('REPORT.json', 'VM.json', 'SUMMARY.md', *GUEST_FILES)
MAX_FILE, MAX_EXPORT = 16 * 1024 * 1024, 64 * 1024 * 1024
CRITICAL = 'forbidden_path_open:user->app:9090'


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def progress(message):
    print('Archive reboot VM: ' + message, file=sys.stderr, flush=True)


def preflight():
    require(sys.platform == 'linux' and reboot.platform.machine() in {'x86_64', 'amd64'},
            'Archive reboot monitoring requires a disposable x86-64 Linux host; it does not run on macOS.')
    return reboot.preflight()


def source_identity(root=ROOT, environment=None):
    root = Path(root).resolve()
    identity = reboot.source_identity(root, environment)
    for name in (*EXTRA_GUEST_FILES, 'scripts/network_monitor_archive_reboot_vm.py'):
        raw = (root / name).read_bytes()
        result = subprocess.run(['git', '-c', f'safe.directory={root}', '-C', str(root),
            'show', f"{identity['commit']}:{name}"], capture_output=True, timeout=30)
        require(result.returncode == 0 and result.stdout == raw, 'Archive reboot source differs from its committed version.')
        identity['source_sha256'][name] = hashlib.sha256(raw).hexdigest()
    require(set(identity['source_sha256']) == set(SOURCE_FILES), 'Archive reboot source inventory differs.')
    return identity


def extra_source_archive(root=ROOT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name in EXTRA_GUEST_FILES:
            raw = (Path(root) / name).read_bytes()
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.uid, entry.gid, entry.mtime = len(raw), 0o644, 0, 0, 0
            archive.addfile(entry, io.BytesIO(raw))
    return output.getvalue()


def extract_guest_export(content, names=GUEST_FILES):
    require(len(content) <= MAX_EXPORT, 'Guest export exceeds its size bound.')
    with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as archive:
        entries = archive.getmembers()
        require(len(entries) == len(names) and {e.name for e in entries} == set(names),
                'Guest export differs from the fixed public allowlist.')
        require(all(e.isfile() and 0 <= e.size <= MAX_FILE for e in entries)
                and sum(e.size for e in entries) <= MAX_EXPORT, 'Unsafe guest export entry.')
        files = {e.name: archive.extractfile(e).read() for e in entries}
    require(not any(b'PRIVATE KEY' in raw or b'/Users/' in raw for raw in files.values()),
            'A private marker appeared in the public export.')
    return files


class DisposableVM(reboot.DisposableVM):
    def launch(self):
        super().launch()
        self.ssh('sudo -n tar -xz --no-same-owner -f - -C ' + GUEST_ROOT,
                 input=extra_source_archive(), timeout=60)

    def guest(self, stage):
        require(stage in {'before', 'after', 'cleanup'}, 'Unknown archive reboot guest stage.')
        result = self.ssh('sudo -n python3 -I -S -B ' + GUEST_SCRIPT + ' ' + stage + ' --token ' + self.token,
                          timeout=600 if stage == 'before' else 360 if stage == 'after' else 60, check=False)
        if result.returncode:
            error = (result.stderr or result.stdout).decode(errors='replace')[-12 * 1024:]
            raise RuntimeError('A disposable archive reboot guest operation failed: ' + self.redact(error).strip())
        require(len(result.stdout) <= 1024 * 1024, 'Guest stage metadata exceeds its bound.')
        result = json.loads(result.stdout)
        require(isinstance(result, dict) and result.get('ok') is True, 'Archive reboot guest stage failed.')
        return result

    def export_guest(self, *, preboot=False):
        names = PREBOOT_FILES if preboot else GUEST_FILES
        result = self.ssh('sudo -n tar -cz -C ' + GUEST_REPORT + ' -- ' + ' '.join(names), timeout=60)
        return extract_guest_export(result.stdout, names)


def validate_history(history, files, segments):
    require(history['history_complete'] is True, 'Incomplete journal export.')
    rows, identity = history['rows'], history['identity']
    require(identity['format'] == 'heltemes-monitor-archive-journal' and identity['version'] == 1
            and identity['segment_rows'] == 128 and identity['max_rows'] == 2048
            and identity['max_segments'] == 16, 'Archive identity or limits differ.')
    require(len(history['archive_descriptors']) == segments and len(rows) // 128 == segments,
            'Archive segment count differs from global history.')
    previous, seen = '0' * 64, set()
    for sequence, row in enumerate(rows, 1):
        require(row['sequence'] == row['sample']['sequence'] == sequence
                and row['previous_digest'] == previous and row['request_id'] not in seen,
                'Global sequence, fingerprint chain, or request identity differs.')
        payload = {key: value for key, value in row.items() if key != 'row_digest'}
        require(hashlib.sha256(canonical(payload)).hexdigest() == row['row_digest'], 'Journal row fingerprint differs.')
        previous = row['row_digest']; seen.add(row['request_id'])
    for index, descriptor in enumerate(history['archive_descriptors'], 1):
        prefix, raw = rows[(index - 1) * 128:index * 128], files[SEGMENT_FILES[index - 1]]
        expected = {'format': 'heltemes-monitor-archive-journal-segment', 'version': 1,
            'database_id': identity['database_id'], 'segment_index': index,
            'first_sequence': prefix[0]['sequence'], 'last_sequence': prefix[-1]['sequence'],
            'previous_digest': prefix[0]['previous_digest'], 'last_digest': prefix[-1]['row_digest'], 'rows': prefix}
        require(raw == canonical(expected) + b'\n', 'Archive bytes differ from the global history prefix.')
        require(descriptor == {'segment_index': index, 'first_sequence': prefix[0]['sequence'],
            'last_sequence': prefix[-1]['sequence'], 'row_count': 128, 'byte_count': len(raw),
            'file_digest': hashlib.sha256(raw).hexdigest(), 'last_digest': prefix[-1]['row_digest']},
            'Archive descriptor differs from original bytes.')
    return rows


def check_incident(status, identity, state='open'):
    incidents = [a for a in status['alerts'] if a['key'] == CRITICAL and a['state'] == state]
    require(len(incidents) == 1 and incidents[0]['id'] == identity, 'Original incident identity or state differs.')


def validate_receipts(before, after, rows):
    receipts = before['collector_receipts'] + after['collector_receipts']
    require(len(before['collector_receipts']) == 270 and len(after['collector_receipts']) == 130
            and [r['cycle'] for r in receipts] == list(range(1, 401)), 'Durable collector cycle continuity differs.')
    by_id = {r['request_id']: r for r in rows}
    ports, instances = set(), set()
    for stage, records in ((before, receipts[:270]), (after, receipts[270:])):
        require(len({r['instance_id'] for r in records}) == 1, 'Collector changed instance within one boot.')
        instances.add(records[0]['instance_id'])
        for local_cycle, receipt in enumerate(records, 1):
            request, cycle = receipt['request'], receipt['cycle']
            observation = request['observation']; row = by_id[request['request_id']]
            require(receipt['boot_id'] == receipt['delivery_boot_id'] == stage['boot']['boot_id']
                    and receipt['process_cycle'] == local_cycle and request['command'] == 'observe'
                    and row['request']['kind'] == 'observation' and row['request']['observation'] == observation
                    and row['sequence'] == receipt['committed_sequence'] and row['evaluation'] == receipt['evaluation']
                    and observation['ruleset'] is not None and observation['collection_error'] is None,
                    'Collector receipt differs from the committed, current-boot observation.')
            expected = local_cycle == 3 or (local_cycle > 2 and cycle % 16 == 0)
            require(len(observation['probes']) == (3 if expected else 0), 'Canary schedule differs.')
            if not expected:
                require(row['evaluation']['status'] != 'healthy', 'Rules alone asserted healthy coverage.')
            for probe in observation['probes']:
                for item in (probe, probe.get('destination_health')):
                    if item is None:
                        continue
                    port = item['source_port']
                    require(port not in ports and 42000 + 6 * (cycle - 1) <= port < 42000 + 6 * cycle,
                            'A probe port was reused or escaped its durable cycle allocation.')
                    ports.add(port)
    require(len(instances) == 2, 'Collector instance identity did not change across boot.')
    return receipts


def validate_guest(held, files, source, reboot_evidence):
    require(set(held) == set(PREBOOT_FILES) and all(files[name] == raw for name, raw in held.items()),
            'A host-held preboot reference changed during reboot.')
    before, after = json.loads(files['BEFORE.json']), json.loads(files['AFTER.json'])
    old, new = json.loads(files['BEFORE-HISTORY.json']), json.loads(files['AFTER-HISTORY.json'])
    expected_sources = {name: source['source_sha256'][name] for name in GUEST_SOURCE_FILES}
    for stage, label, history, number in ((before, 'before', old, 2), (after, 'after', new, 3)):
        require(stage['format'] == 'heltemes-monitor-archive-reboot-guest' and stage['version'] == 1
                and stage['ok'] is True and stage['stage'] == label and stage['source_sha256'] == expected_sources,
                'Guest stage identity or source differs.')
        require(stage['boot']['boot_id'] == reboot_evidence[label]['boot_id'], 'Host and guest boot records disagree.')
        name = label.upper() + '-HISTORY.json'; proof = stage['history_file']
        require(proof['name'] == name and proof['bytes'] == len(files[name])
                and proof['sha256'] == hashlib.sha256(files[name]).hexdigest(), 'History file binding differs.')
        require(stage['journal_export_method'] == 'stopped_verified_journal'
                and stage['monitor_stopped_for_export']['ActiveState'] == 'inactive'
                and stage['monitor_stopped_for_export']['MainPID'] == 0
                and stage['monitor_stopped_for_export']['UnitFileState'] == 'enabled', 'Offline export writer was not stopped.')
        rows = validate_history(history, files, number)
        status = stage['final_status']; archives = status['archives']
        require(status['committed_count'] == len(rows) and status['head_digest'] == rows[-1]['row_digest']
                and archives['sealed_segments'] == number and archives['archived_rows'] == number * 128
                and archives['active_rows'] == len(rows) - number * 128
                and archives['capacity_remaining'] == 2048 - len(rows)
                and archives['persistence_error'] is None, 'Captured status does not match the offline export.')
        captures = {n for n in CAPTURE_FILES if n.startswith(label + '-')}
        require(set(stage['capture_sha256']) == captures and all(hashlib.sha256(files[n]).hexdigest() == digest
                for n, digest in stage['capture_sha256'].items()), 'Capture bytes differ from completed-stage fingerprints.')
        require(len(stage['archive_files']) == number, 'Protected archive inventory differs.')
        for index, archive in enumerate(stage['archive_files']):
            raw = files[SEGMENT_FILES[index]]
            require(archive['sha256'] == hashlib.sha256(raw).hexdigest() and archive['bytes'] == len(raw)
                    and archive['mode'] == 0o600 and archive['uid'] == 0 and archive['nlink'] == 1,
                    'Exported archive differs from its protected guest file.')
    require(old['identity'] == new['identity'] and old['approved_policy'] == new['approved_policy']
            and new['rows'][:len(old['rows'])] == old['rows'] and len(old['rows']) == 271
            and 402 <= len(new['rows']) <= 403,
            'Reboot replaced or rolled back the original archive identity or history.')
    incident = before['critical_incident_id']
    require(after['critical_incident_id'] == incident and before['no_pending_before_reboot'] is True,
            'Pending request or incident identity differs at reboot.')
    startup = after['automatic_start']; status, manager = startup['status'], startup['manager']
    require(startup['no_manual_service_start'] is True and status['current_evaluation']['status'] == 'unknown'
            and 272 <= status['committed_count'] <= 273
            and status['head_digest'] == new['rows'][status['committed_count'] - 1]['row_digest']
            and new['rows'][271]['sample']['phase'] == 'monitor_restart'
            and manager['ActiveState'] == 'active' and manager['UnitFileState'] == 'enabled'
            and manager['MainPID'] == status['process_id']
            and manager['InvocationID'] != before['manager']['InvocationID'],
            'Enabled monitor did not automatically reopen to an unknown startup boundary.')
    require(after['network_missing_before_rebuild'] is True and after['preboot_prefix_preserved'] is True,
            'Volatile network or preserved-prefix recovery evidence differs.')
    for current in (before['final_status'], status):
        check_incident(current, incident)
    boundaries = [r for r in new['rows'] if r['request']['kind'] == 'restart' or r['sample']['phase'] == 'collector_missing']
    require([r['sample']['phase'] for r in boundaries] in
            (['monitor_restart', 'monitor_restart'], ['monitor_restart', 'monitor_restart', 'collector_missing'])
            and all(r['evaluation']['status'] == 'unknown' for r in boundaries),
            'Unexpected startup or missing-data boundary.')
    snapshot = startup['readonly_history']
    require(snapshot['identity'] == old['identity'] and snapshot['approved_policy'] == old['approved_policy']
            and snapshot['segments'] == old['archive_descriptors'] and snapshot['archived_sequence'] == 256
            and snapshot['archived_digest'] == old['rows'][255]['row_digest']
            and snapshot['head_sequence'] == status['committed_count'] and snapshot['head_digest'] == status['head_digest']
            and snapshot['rows'] == new['rows'][256:status['committed_count']],
            'Read-only automatic startup snapshot differs from the preserved original history.')
    receipts = validate_receipts(before, after, new['rows'])
    receipt_ids = {r['request']['request_id'] for r in receipts}
    require([r for r in new['rows'] if r['request_id'] not in receipt_ids] == boundaries,
            'Journal contains an unexplained row outside real receipts and explicit startup gaps.')
    if len(boundaries) == 3:
        gap = boundaries[2]
        require(gap['request']['kind'] == 'observation' and gap['request_id'].startswith('freshness-gap-')
                and gap['sample']['collection_error'] == 'freshness_deadline_exceeded'
                and gap['sample']['ruleset'] is None and gap['sample']['probes'] == []
                and boundaries[1]['sequence'] < gap['sequence'] < receipts[270]['committed_sequence'],
                'Optional missing-data row is not the explicit pre-collection startup gap.')
    require(after['first_rule_only_receipts'] == receipts[270:272], 'Postboot baseline receipt binding differs.')
    for receipt in receipts[270:272]:
        require(receipt['evaluation']['status'] != 'healthy' and CRITICAL in receipt['evaluation']['active_alert_keys'],
                'Postboot baseline claimed healthy coverage or cleared the original incident.')
    duplicate = after['archived_duplicate']; old_status, new_status = duplicate['before_status'], duplicate['after_status']
    require(duplicate['request'] == receipts[0]['request'] and duplicate['result']['ok'] is True
            and duplicate['result']['duplicate'] is True
            and duplicate['result']['committed_sequence'] == receipts[0]['committed_sequence']
            and duplicate['result']['evaluation'] == receipts[0]['evaluation']
            and old_status['committed_count'] == new_status['committed_count']
            and status['committed_count'] <= old_status['committed_count'] <= 273
            and old_status['head_digest'] == new_status['head_digest'] == new['rows'][old_status['committed_count'] - 1]['row_digest']
            and old_status['freshness']['last_accepted_request_id'] == new_status['freshness']['last_accepted_request_id']
            and new_status['current_evaluation']['status'] == 'unknown', 'Historical retry renewed coverage or changed history.')
    resolutions = [e for e in new['events'] if e['key'] == CRITICAL and e['action'] == 'resolved']
    require(len(resolutions) == 1 and resolutions[0]['alert_id'] == incident and resolutions[0]['sequence'] == receipts[272]['committed_sequence'],
            'Original incident did not resolve exactly once after fresh postboot checks.')
    resolution = new['rows'][resolutions[0]['sequence'] - 1]
    require(resolution['evaluation']['status'] == 'healthy' and len(resolution['sample']['probes']) == 3
            and after['final_status']['current_evaluation']['status'] == 'healthy'
            and after['network_cleanup']['ok'] is True, 'Fresh recovery or network cleanup failed.')
    return before, after


def run(output):
    tools = preflight(); source = source_identity()
    destination = reboot.monitoring.base.new_output(output)
    staging = destination / 'staging'; staging.mkdir(mode=0o700)
    vm = DisposableVM(tools)
    report = {'format': 'heltemes-network-monitor-archive-reboot-lab', 'version': 1, 'ok': False,
        'started_at_utc': timestamp(), 'source': source,
        'scope': {'synthetic_only': True, 'aws_deployed': False, 'real_evidence_inputs': False,
            'full_guest_os_reboot_tested': True, 'history_rotation_tested': True,
            'automatic_monitor_startup_tested': True, 'network_reconstruction_by_harness': True,
            'automatic_collector_startup_tested': False, 'physical_power_loss_tested': False,
            'continuous_production_operation': False, 'administrator_resistant_history': False,
            'dedicated_account_isolation_tested': False, 'external_notification_delivery': False}}
    evidence, files = {}, {}
    step = 'preparing pinned VM image and private boot media'; progress(step)
    try:
        evidence['image'] = {'url': reboot.IMAGE_URL, 'sha256': reboot.IMAGE_SHA256}
        evidence['virtualization'] = vm.prepare()
        step = 'booting and provisioning disposable guest'; progress(step); vm.launch()
        evidence['virtualization']['qmp_kvm'] = vm.kvm_status; evidence['cloud_init'] = vm.cloud_init
        step = 'collecting 270 observations and holding two archives outside the guest'; progress(step)
        before = vm.guest('before'); held = vm.export_guest(preboot=True)
        evidence['preboot_reference_sha256'] = {n: hashlib.sha256(raw).hexdigest() for n, raw in held.items()}
        step = 'performing and verifying full Linux guest reboot'; progress(step)
        evidence['reboot'] = vm.reboot()
        require(before['boot_id'] == evidence['reboot']['before']['boot_id'], 'Preboot stage boot identity differs.')
        step = 'verifying automatic unknown startup, fresh network recovery, and third rollover'; progress(step)
        after = vm.guest('after')
        require(after['boot_id'] == evidence['reboot']['after']['boot_id'], 'Postboot stage boot identity differs.')
        step = 'checking original bytes, full history, receipts, incidents, and captures'; progress(step)
        files = vm.export_guest(); validate_guest(held, files, source, evidence['reboot'])
        evidence.update({'guest_stages': {'before': before, 'after': after}, 'preboot_reference_held_outside_guest': True})
        step = 'removing guest services and synthetic state'; progress(step)
        evidence['guest_cleanup'] = vm.guest('cleanup')
        require(evidence['guest_cleanup']['ok'] is True and source_identity() == source, 'Cleanup or exact source revalidation failed.')
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        report['error'] = step + ': ' + vm.redact(error).replace(str(destination), '<report>')
    finally:
        try:
            progress('stopping owned VM and deleting private credentials and disk')
            evidence['cleanup'] = vm.cleanup()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            evidence['cleanup'] = {'ok': False, 'error': vm.redact(error)}
        report['completed_at_utc'] = timestamp()
    report['ok'] = 'error' not in report and evidence['cleanup']['ok']; report['cleanup'] = evidence['cleanup']
    reboot.write_json(staging / 'REPORT.json', report)
    if not report['ok']:
        raise RuntimeError('Archive reboot exercise failed: ' + report.get('error', 'Private VM cleanup failed.'))
    for name, raw in files.items():
        (staging / name).write_bytes(raw)
    reboot.write_json(staging / 'VM.json', evidence)
    (staging / 'SUMMARY.md').write_text(f'''# Archived monitoring history through a full Linux VM reboot

Source commit `{source['commit']}`. Completed {report['completed_at_utc']}.

The collector saved 270 actual firewall observations and two 128-row archive segments before a graceful Linux guest reboot. The host held the original public bytes before requesting reboot. QEMU reported a guest reset, SSH became unavailable, and the kernel boot ID changed on the same VM process and disk.

The enabled monitor started automatically and replayed the preserved history. Coverage was unknown and the original incident remained open. An archived request retry returned its original result without renewing freshness. The harness explicitly rebuilt the volatile synthetic network and started the collector. Two fresh rule-only samples established the new baseline; complete fresh canaries were required for recovery. Collection continued through cycle 400 and sealed a third segment, preserving the complete journal and unique probe allocation. An independently detected missing-data gap may add one row while the network is being reconstructed.

BEFORE/AFTER reports contain lifecycle and receipt evidence. The two HISTORY files preserve the full preboot and final history; three original segment files and twelve capture files are independently comparable. VM.json records host-held hashes, boot observations, and cleanup. Every public file is covered by MANIFEST.json.

This is a bounded graceful-reboot test with explicit network reconstruction. It does not establish unattended network provisioning, collector boot startup, indefinite operation, physical power-loss durability during archiving, or administrator-resistant history. AWS and real Evidence keys and trusted history were outside the exercise. Owned guest services, synthetic networks, VM, private access credentials, seed, and disk were removed before publication.
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
    arguments = parser.parse_args()
    try:
        report = run(arguments.output)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, 'Archive reboot VM stopped: ' + str(error) + '\n')
    print(json.dumps({'ok': report['ok'], 'source_commit': report['source']['commit'], 'cleanup': report['cleanup']}, indent=2))


if __name__ == '__main__':
    main()
