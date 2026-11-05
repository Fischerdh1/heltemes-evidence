"""Verify automatic collection and independent missing-data detection in a disposable VM."""
from __future__ import annotations

import argparse
from datetime import datetime
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
EXTRA_GUEST_FILES = ('scripts/network_monitor_collector.py', 'scripts/network_monitor_automatic_guest.py')
GUEST_SOURCE_FILES = (*reboot.SOURCE_FILES[:-1], *EXTRA_GUEST_FILES)
SOURCE_FILES = (*GUEST_SOURCE_FILES, 'scripts/network_monitor_reboot_vm.py', 'scripts/network_monitor_automatic_vm.py')
GUEST_ROOT = reboot.GUEST_ROOT
GUEST_SCRIPT = GUEST_ROOT + '/scripts/network_monitor_automatic_guest.py'
GUEST_REPORT = '/var/lib/heltemes-automatic-lab/report/publish'
GUEST_FILES = ('GUEST.json', 'APPROVED_POLICY.json', 'monitor.service', 'collector.service',
               *(name for zone in ('user', 'app', 'management') for name in (zone + '.pcap', zone + '-packets.txt')))
PUBLIC_FILES = ('REPORT.json', 'VM.json', 'SUMMARY.md', *GUEST_FILES)


def progress(message):
    print('Automatic monitor VM: ' + message, file=sys.stderr, flush=True)


def preflight():
    require(sys.platform == 'linux' and reboot.platform.machine() in {'x86_64', 'amd64'},
            'Automatic monitoring requires a disposable x86-64 Linux host; it does not run on macOS.')
    return reboot.preflight()


def source_identity(root=ROOT, environment=None):
    root = Path(root).resolve()
    identity = reboot.source_identity(root, environment)
    for name in (*EXTRA_GUEST_FILES, 'scripts/network_monitor_automatic_vm.py'):
        content = (root / name).read_bytes()
        result = subprocess.run(['git', '-c', f'safe.directory={root}', '-C', str(root),
                                 'show', f"{identity['commit']}:{name}"], capture_output=True, timeout=30)
        require(result.returncode == 0 and result.stdout == content,
                'Automatic monitor source differs from its committed version.')
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
        progress('installing the two additional allowlisted collector and guest sources')
        self.ssh('sudo -n tar -xz --no-same-owner -f - -C ' + GUEST_ROOT,
                 input=extra_source_archive(), timeout=60)

    def guest(self, stage):
        require(stage in {'exercise', 'cleanup'}, 'Unknown automatic guest stage.')
        result = self.ssh('sudo -n python3 -I -S -B ' + GUEST_SCRIPT + ' ' + stage + ' --token ' + self.token,
                          timeout=360 if stage == 'exercise' else 60)
        require(len(result.stdout) <= 1024 * 1024, 'Guest stage metadata exceeds its bound.')
        value = json.loads(result.stdout)
        require(isinstance(value, dict) and value.get('ok') is True, 'The automatic guest stage failed.')
        return value

    def reference(self):
        content = self.ssh('sudo -n cat ' + GUEST_REPORT + '/GUEST.json', timeout=15).stdout
        require(0 < len(content) <= 8 * 1024 * 1024, 'Guest report exceeds its size bound.')
        return content

    def export_guest(self):
        result = self.ssh('sudo -n tar -cz -C ' + GUEST_REPORT + ' -- ' + ' '.join(GUEST_FILES), timeout=60)
        return extract_guest_export(result.stdout)


def extract_guest_export(content):
    require(len(content) <= reboot.MAX_EXPORT, 'Guest export exceeds its size bound.')
    with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as archive:
        entries = archive.getmembers()
        require(len(entries) == len(GUEST_FILES) and {entry.name for entry in entries} == set(GUEST_FILES),
                'Guest export differs from the fixed public allowlist.')
        require(all(entry.isfile() and entry.size <= 8 * 1024 * 1024 for entry in entries)
                and sum(entry.size for entry in entries) <= reboot.MAX_EXPORT, 'Unsafe guest export entry.')
        files = {entry.name: archive.extractfile(entry).read() for entry in entries}
    require(not any(b'PRIVATE KEY' in raw or b'/Users/' in raw for raw in files.values()),
            'A private marker appeared in the public export.')
    return files


def validate_same_guest(before, after):
    require(before is not None and after is not None, 'The guest boot observation is missing.')
    require(before['boot_id'] == after['boot_id'] and before['qemu_pid'] == after['qemu_pid']
            and before['disk_identity'] == after['disk_identity']
            and before['observed_elapsed_seconds'] < after['observed_elapsed_seconds'],
            'The bounded automatic exercise unexpectedly replaced or rebooted its guest.')


def validate_lifecycle(report):
    require(report['format'] == 'heltemes-monitor-automatic-guest' and report['version'] == 1
            and report['ok'] is True and report['boot_enabled_configuration_only'] is True
            and report['network_cleanup']['ok'] is True, 'Guest completion or scope is invalid.')
    stages = report['stages']
    names = ('initial', 'baseline', 'incident', 'silent', 'repaired_silent', 'recovered')
    require(set(stages) == set(names), 'Automatic stage inventory differs.')
    statuses = [stages[name]['status'] for name in names]
    require([s['current_evaluation']['status'] for s in statuses]
            == ['unknown', 'healthy', 'alerting', 'unknown', 'unknown', 'healthy'],
            'Automatic collection and recovery statuses differ.')
    times = [stages[name]['observed_elapsed_seconds'] for name in names]
    require(all(a < b for a, b in zip(times, times[1:])), 'Stage chronology does not advance.')
    require(len({s['process_id'] for s in statuses}) == len({s['instance_id'] for s in statuses}) == 1,
            'The independent monitor restarted during the exercise.')
    for name, status in zip(names, statuses):
        manager = stages[name]['monitor_manager']
        require(manager['ActiveState'] == 'active' and manager['UnitFileState'] == 'enabled'
                and manager['MainPID'] == status['process_id'] and manager['NRestarts'] == 0,
                'The independent enabled monitor process was not continuously observed.')
        require(status['freshness']['enabled'] is True and status['freshness']['threshold_seconds'] == 20
                and status['freshness']['persistence_error'] is None, 'Freshness configuration or storage failed.')
    critical = 'forbidden_path_open:user->app:9090'
    incident_id = report['critical_incident_id']
    for name in ('incident', 'silent', 'repaired_silent'):
        alerts = [a for a in stages[name]['status']['alerts'] if a['key'] == critical and a['state'] == 'open']
        require(len(alerts) == 1 and alerts[0]['id'] == incident_id, 'Silence or repair lost the unresolved incident.')
    silence = report['silence']
    missing = statuses[3]
    require(silence['collector_proc_state'] == 'T' and silence['monitor_rpc_requests_during_wait'] == 0
            and 20 <= silence['elapsed_seconds'] <= 30, 'Silence was not independently observed at the deadline.')
    gap_at = datetime.fromisoformat(silence['gap_committed_at_utc'])
    inspected = datetime.fromisoformat(silence['first_inspected_at_utc'])
    require(datetime.fromisoformat(silence['started_at_utc']) < gap_at < inspected,
            'The missing-data gap was not committed before the first inspection request.')
    lateness = (gap_at - datetime.fromisoformat(silence['deadline_at_utc'])).total_seconds()
    require(0 <= lateness <= 5 and abs(lateness - silence['deadline_lateness_seconds']) < 0.000001,
            'Independent missing-data detection exceeded the bounded deadline tolerance.')
    require(missing['freshness']['gap_recorded'] and missing['freshness']['expired']
            and missing['freshness']['gap_sequence'] == silence['gap_sequence']
            and missing['freshness']['gap_committed_at_utc'] == silence['gap_committed_at_utc']
            and missing['current_evaluation']['phase'] == 'collector_missing', 'Durable missing-data evidence differs.')
    repaired = statuses[4]
    require(missing['committed_count'] == repaired['committed_count'] and missing['head_digest'] == repaired['head_digest'],
            'Repair without collection changed committed history.')
    old, new = (stages[name]['collector_manager'] for name in ('silent', 'recovered'))
    require(old['MainPID'] == silence['collector_pid'] == silence['collector_idle_receipt']['process_id']
            and silence['collector_idle_receipt']['state'] == 'idle'
            and old['MainPID'] != new['MainPID'] and new['NRestarts'] == old['NRestarts'] + 1
            and new['ActiveState'] == 'active' and old['UnitFileState'] == new['UnitFileState'] == 'enabled',
            'The collector was not independently restarted by its supervisor.')
    journal = report['journal']
    rows = journal['rows']
    require(6 <= len(rows) < 256 and report['final_status']['committed_count'] == len(rows)
            and report['final_status']['current_evaluation']['status'] == 'healthy', 'Bounded final journal failed.')
    gaps = [r for r in rows if r['sample']['phase'] == 'collector_missing']
    require(len(gaps) == 1 and gaps[0]['sequence'] == silence['gap_sequence'], 'Missing-data gap was absent or repeated.')
    resolutions = [e for e in journal['events'] if e['key'] == critical and e['action'] == 'resolved']
    require(len(resolutions) == 1 and resolutions[0]['alert_id'] == incident_id
            and resolutions[0]['sequence'] > silence['gap_sequence'], 'Recovery resolved the wrong incident or time.')
    recovered_row = next(r for r in rows if r['sequence'] == resolutions[0]['sequence'])
    require(recovered_row['evaluation']['status'] == 'healthy' and len(recovered_row['sample']['probes']) == 3,
            'Recovery lacked fresh complete canaries.')
    receipts = report['collector_receipts']
    automatic = [r for r in rows if r['sample']['phase'].startswith('automatic_')]
    require(len(receipts) == len(automatic) and len({r['committed_sequence'] for r in receipts}) == len(receipts),
            'Autonomous receipt coverage differs from accepted observations.')
    by_sequence = {r['sequence']: r for r in rows}
    producers = {}
    for receipt in receipts:
        row = by_sequence[receipt['committed_sequence']]
        instance, cycle, pid = receipt['instance_id'], receipt['cycle'], receipt['process_id']
        require(type(cycle) is int and cycle > 0 and producers.setdefault(instance, pid) == pid,
                'Collector instance identity changed between receipts.')
        phase = f'automatic_{instance}_{cycle}'
        require(receipt['request']['request_id'] == receipt['request']['observation']['phase'] == phase,
                'Collector request does not identify its producing instance and cycle.')
        require(row['request_id'] == receipt['request']['request_id']
                and row['request']['observation'] == receipt['request']['observation']
                and row['evaluation'] == receipt['evaluation'], 'Collector receipt and journal differ.')
    require(len({r['instance_id'] for r in receipts}) == len({r['process_id'] for r in receipts}) == 2,
            'Expected two distinct automatic collector instances.')
    require({r['process_id'] for r in receipts} == {old['MainPID'], new['MainPID']},
            'Producer receipts do not belong to the observed collector processes.')


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
    validate_lifecycle(report)
    return report


def run(output):
    tools = preflight()
    source = source_identity()
    destination = reboot.monitoring.base.new_output(output)
    staging = destination / 'staging'; staging.mkdir(mode=0o700)
    vm = DisposableVM(tools)
    report = {'format': 'heltemes-network-monitor-automatic-lab', 'version': 1, 'ok': False,
              'started_at_utc': timestamp(), 'source': source,
              'scope': {'synthetic_only': True, 'aws_deployed': False, 'real_evidence_inputs': False,
                        'bounded_unattended_collection': True, 'collector_silence_detection_tested': True,
                        'vm_reboot_tested': False, 'physical_power_loss_tested': False,
                        'continuous_production_operation': False, 'dedicated_account_isolation_tested': False,
                        'external_notification_delivery': False, 'history_rotation_tested': False}}
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
        step = 'running automatic collection, collector silence, and fresh recovery'; progress(step)
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
        require(source_identity() == source, 'Automatic monitoring source changed during the run.')
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
        raise RuntimeError('Automatic monitoring exercise failed: ' + report.get('error', 'Private VM cleanup failed.'))
    for name, content in files.items():
        (staging / name).write_bytes(content)
    reboot.write_json(staging / 'VM.json', evidence)
    (staging / 'SUMMARY.md').write_text(f'''# HELTEMES Evidence automatic monitoring exercise

Source commit `{source['commit']}`. Completed {report['completed_at_utc']}.

Separate Linux services collected real firewall rules, counters, and connection checks and evaluated their freshness. The monitor detected a silent collector independently while preserving the existing incident. Repaired rules alone did not restore healthy coverage; fresh autonomous observations were required.

Inspect GUEST.json for the measured collector cadence, deadline, service identities, incident history, and recovery observations. Packet captures and their completed-stage fingerprints substantiate the actual synthetic traffic. VM.json binds this one-boot exercise to the pinned image, source, guest identity, and cleanup.

This is a bounded unattended exercise within the existing 256-row journal limit. The units are enabled for boot, but this exercise does not reboot the VM or establish persistent networking across a reboot. It does not test long-running retention, separate-account isolation, external notifications, or physical power loss. AWS and real Evidence keys/history are outside its scope.

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
        parser.exit(1, 'Automatic monitor VM stopped: ' + str(error) + '\n')
    print(json.dumps({'ok': result['ok'], 'source_commit': result['source']['commit'], 'cleanup': result['cleanup']}, indent=2))


if __name__ == '__main__':
    main()
