"""Autonomous collection, silent-input detection, and supervised recovery in one disposable VM."""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor_reboot_guest as reboot
from scripts import network_monitor_collector as collector
from scripts import network_monitoring_lab as monitoring
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store

DATA, STATE, PRIVATE, CONFIG = collector.DATA, collector.STATE, collector.PRIVATE, collector.CONFIG
REPORT = DATA / 'report'
PUBLISH = REPORT / 'publish'
INSTALL = reboot.INSTALL
MONITOR_UNIT = 'heltemes-automatic-monitor.service'
COLLECTOR_UNIT = 'heltemes-automatic-collector.service'
FRESHNESS = 20
SOURCE_FILES = (*reboot.SOURCE_FILES, 'scripts/network_monitor_collector.py', 'scripts/network_monitor_automatic_guest.py')
CAPTURE_FILES = reboot.CAPTURE_FILES
PUBLIC_FILES = ('GUEST.json', 'APPROVED_POLICY.json', 'monitor.service', 'collector.service', *CAPTURE_FILES)
require, command, write_new = reboot.require, reboot.command, reboot.write_new


def unit_path(unit):
    require(unit in (MONITOR_UNIT, COLLECTOR_UNIT), 'Unknown owned service.')
    return Path('/etc/systemd/system') / unit


def unit_text(unit):
    monitor = unit == MONITOR_UNIT
    unit_path(unit)
    start = (f'{INSTALL}/scripts/network_monitor_service.py serve --state {STATE} --freshness-seconds {FRESHNESS}'
             if monitor else f'{INSTALL}/scripts/network_monitor_collector.py serve')
    dependency = '' if monitor else f'After={MONITOR_UNIT}\nRequires={MONITOR_UNIT}\n'
    protection = f'ProtectSystem=strict\nReadWritePaths={STATE}\nRestrictAddressFamilies=AF_UNIX\n' if monitor else ''
    return f'''[Unit]
Description=HELTEMES disposable automatic {'monitor' if monitor else 'collector'}
After=local-fs.target
{dependency}RequiresMountsFor={DATA}
StartLimitIntervalSec=30
StartLimitBurst=3

[Service]
Type=exec
ExecStart=/usr/bin/python3 -I -S -B {start}
Restart=on-failure
RestartSec=1
TimeoutStopSec=25
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
{protection}
[Install]
WantedBy=multi-user.target
'''


def guard(token):
    virtualization = reboot.guard(token)
    for path in (DATA, STATE, PRIVATE, CONFIG, REPORT, PUBLISH, unit_path(MONITOR_UNIT), unit_path(COLLECTOR_UNIT)):
        require(not any(p.is_symlink() for p in (path, *path.parents)), 'Automatic guest paths cannot traverse links.')
    return virtualization


def source_hashes():
    result = {}
    for name in SOURCE_FILES:
        path = ROOT / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size < 1024 * 1024, 'Unsafe automatic source input.')
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def manager(unit):
    path = unit_path(unit)
    reboot.ordinary(path, mode=0o644)
    require(path.read_text() == unit_text(unit), 'Installed service differs from the owned unit.')
    response = command(['systemctl', 'show', '--no-pager', '--property=' + ','.join(reboot.MANAGER_FIELDS), unit])
    values = dict(line.split('=', 1) for line in response.stdout.splitlines() if '=' in line)
    require(set(values) == set(reboot.MANAGER_FIELDS), 'Service manager proof is incomplete.')
    require(values['LoadState'] == 'loaded' and values['UnitFileState'] == 'enabled'
            and values['FragmentPath'] == str(path), 'Automatic service must be enabled from its exact unit.')
    for key in ('MainPID', 'NRestarts', 'ExecMainStartTimestampMonotonic'):
        require(values[key].isdecimal(), 'Invalid service numeric proof.')
        values[key] = int(values[key])
    return values


def request(command_name):
    require(command_name in ('status', 'export'), 'The exercise harness cannot submit observations.')
    return service.request(STATE, {'command': command_name}, timeout=10)


def install(approved, namespaces):
    require(not STATE.exists() and not any(unit_path(u).exists() for u in (MONITOR_UNIT, COLLECTOR_UNIT)), 'Never replace existing service state.')
    store.initialize(STATE, approved)
    PRIVATE.mkdir(mode=0o700)
    write_new(CONFIG, {'version': 1, 'interval_seconds': collector.INTERVAL, 'namespaces': namespaces})
    for unit in (MONITOR_UNIT, COLLECTOR_UNIT):
        write_new(unit_path(unit), unit_text(unit)); unit_path(unit).chmod(0o644)
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', MONITOR_UNIT, COLLECTOR_UNIT])
    command(['systemctl', 'start', MONITOR_UNIT])
    wait_status(lambda s: s['current_evaluation']['status'] == 'unknown')


def wait_status(predicate, timeout=45):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = request('status')
            if last.get('ok') is True and predicate(last):
                return last
        except (OSError, ValueError):
            pass
        time.sleep(0.2)
    raise RuntimeError('Autonomous monitor condition timed out: ' + (reboot.evaluation_diagnostic(last) if last else 'unavailable'))


def snapshot(started):
    status = request('status')
    require(status.get('ok') is True, 'Monitor status failed.')
    monitor = manager(MONITOR_UNIT)
    require(monitor['ActiveState'] == 'active' and monitor['MainPID'] == status['process_id'], 'Monitor process proof differs.')
    return {'status': status, 'monitor_manager': monitor, 'collector_manager': manager(COLLECTOR_UNIT),
            'observed_elapsed_seconds': time.monotonic() - started, 'observed_at_utc': reboot.timestamp()}


def runtime():
    path = PRIVATE / 'runtime.json'
    reboot.ordinary(path)
    require(path.stat().st_size < 4096, 'Oversized collector runtime receipt.')
    return store.parse(path.read_bytes())


def pause_idle_collector():
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        properties = manager(COLLECTOR_UNIT)
        if (PRIVATE / 'runtime.json').exists():
            current = runtime()
            if (current['state'] == 'idle' and current['process_id'] == properties['MainPID']
                    and current['next_due_monotonic'] - time.monotonic() > 1.0):
                os.kill(properties['MainPID'], signal.SIGSTOP)
                for _ in range(40):
                    state = Path(f"/proc/{properties['MainPID']}/status").read_text()
                    match = re.search(r'^State:\s+(\S)', state, re.MULTILINE)
                    if match and match.group(1) == 'T':
                        require(runtime() == current, 'Collector changed its idle receipt while being paused.')
                        return current, properties, match.group(1)
                    time.sleep(0.05)
                raise RuntimeError('Collector did not enter the stopped process state.')
        time.sleep(0.1)
    raise RuntimeError('No quiescent collector sampling boundary was available.')


def receipts():
    result = []
    for path in sorted(PRIVATE.glob('receipt-*.json')):
        reboot.ordinary(path)
        require(re.fullmatch(r'receipt-[0-9]{4}\.json', path.name) and path.stat().st_size < 1024 * 1024,
                'Unsafe collector receipt.')
        result.append(store.parse(path.read_bytes()))
    require(2 <= len(result) <= collector.MAX_CYCLES, 'Autonomous receipt count is invalid.')
    return result


def validate_inventory(journal, records):
    by_sequence = {row['sequence']: row for row in journal['rows']}
    observed = [row for row in journal['rows'] if row['sample']['phase'].startswith('automatic_')]
    require(len(observed) == len(records) and len({r['committed_sequence'] for r in records}) == len(records), 'Collector journal/receipt inventory differs.')
    probes, ids, instances = [], set(), {}
    for record in records:
        payload, seq = record['request'], record['committed_sequence']
        row = by_sequence[seq]
        instance, cycle = record['instance_id'], record['cycle']
        require(re.fullmatch(r'[0-9a-f]{32}', instance) and type(cycle) is int and cycle > 0, 'Invalid collector identity.')
        phase = f'automatic_{instance}_{cycle}'
        require(payload['command'] == 'observe' and payload['request_id'] == phase and phase not in ids
                and payload['observation']['phase'] == phase, 'Collector request identity differs.')
        ids.add(phase)
        require(row['request_id'] == phase and row['request']['observation'] == payload['observation']
                and row['evaluation'] == record['evaluation'], 'Collector receipt differs from committed observation.')
        previous = instances.setdefault(instance, {'pid': record['process_id'], 'cycles': []})
        require(previous['pid'] == record['process_id'] and record['completed_monotonic'] >= record['started_monotonic'], 'Collector process/timing identity differs.')
        previous['cycles'].append(cycle)
        sampled = payload['observation']['probes']
        require([(p['from'], p['to'], p['port']) for p in sampled] == ([] if cycle == 1 else list(monitoring.CANARIES)), 'Autonomous canary coverage differs.')
        for probe in sampled:
            probes.append(probe)
            if probe.get('destination_health'):
                probes.append(probe['destination_health'])
    require(len(instances) == 2 and len({v['pid'] for v in instances.values()}) == 2, 'Expected exactly two independent collector processes.')
    require(all(v['cycles'] == list(range(1, len(v['cycles']) + 1)) for v in instances.values()), 'Collector cycles were lost or repeated.')
    require(len({p['source_port'] for p in probes}) == len(probes), 'Probe ports were reused across collector restart.')
    return probes


def validate_silence(stages, silence, incident_id):
    first, silent, repaired = (stages[name] for name in ('incident', 'silent', 'repaired_silent'))
    for stage in (silent, repaired):
        status = stage['status']
        require(status['process_id'] == first['status']['process_id'] and status['instance_id'] == first['status']['instance_id'], 'The monitor restarted during silence.')
        require(status['current_evaluation']['status'] == 'unknown' and status['freshness']['gap_recorded']
                and status['current_evaluation']['phase'] == 'collector_missing', 'Silence did not produce durable unknown coverage.')
        require(reboot.critical(status)['id'] == incident_id, 'Silence or rule repair lost the original incident.')
    require(silent['status']['committed_count'] == repaired['status']['committed_count'], 'Rule repair without new collection changed accepted observations.')
    require(silence['collector_proc_state'] == 'T' and silence['monitor_rpc_requests_during_wait'] == 0
            and FRESHNESS <= silence['elapsed_seconds'] <= FRESHNESS + 10, 'Idle detection timing proof differs.')
    gap = datetime.fromisoformat(silence['gap_committed_at_utc'])
    inspected = datetime.fromisoformat(silence['first_inspected_at_utc'])
    require(gap < inspected, 'Missing data was not committed before the first inspection request.')
    freshness = silent['status']['freshness']
    if 'deadline_at_utc' in freshness:
        deadline = datetime.fromisoformat(freshness['deadline_at_utc'])
        require(0 <= (gap - deadline).total_seconds() <= 5,
                'Missing-data commit exceeded its measured deadline tolerance.')


def run_exercise(lab):
    started = time.monotonic()
    lab.setup(); lab.start_services(); lab.apply_policy()
    approved = lab.ruleset()
    # Prepare capture processes before the monitor's freshness clock starts.
    lab.start_captures()
    install(approved, lab.names)
    stages = {'initial': snapshot(started)}
    command(['systemctl', 'start', COLLECTOR_UNIT])
    wait_status(lambda s: s['current_evaluation']['status'] == 'healthy')
    stages['baseline'] = snapshot(started)
    lab.apply_policy('misconfigured')
    wait_status(lambda s: any(a['key'] == reboot.CRITICAL and a['state'] == 'open' for a in s['alerts']))
    stages['incident'] = snapshot(started)
    incident_id = reboot.critical(stages['incident']['status'])['id']
    idle, paused, process_state = pause_idle_collector()
    silence = {'started_at_utc': reboot.timestamp(), 'collector_pid': paused['MainPID'],
               'collector_proc_state': process_state, 'collector_idle_receipt': idle,
               'monitor_rpc_requests_during_wait': 0}
    silent_start = time.monotonic()
    # Deliberately no status/export/observe requests here. The monitor's idle loop
    # must create the durable gap even though nobody is asking for its status.
    time.sleep(FRESHNESS + 2)
    silence['elapsed_seconds'] = time.monotonic() - silent_start
    silence['first_inspected_at_utc'] = reboot.timestamp()
    stages['silent'] = snapshot(started)
    freshness = stages['silent']['status']['freshness']
    silence.update({key: freshness[key] for key in ('gap_sequence', 'gap_committed_at_utc')})
    silence['deadline_at_utc'] = freshness['deadline_at_utc']
    silence['deadline_lateness_seconds'] = (datetime.fromisoformat(freshness['gap_committed_at_utc'])
                                           - datetime.fromisoformat(freshness['deadline_at_utc'])).total_seconds()
    lab.apply_policy()
    stages['repaired_silent'] = snapshot(started)
    validate_silence(stages, silence, incident_id)
    # SIGKILL works even on a stopped process. systemd, rather than this harness,
    # starts its replacement via the configured Restart=on-failure policy.
    command(['systemctl', 'kill', '--kill-who=main', '--signal=KILL', COLLECTOR_UNIT])
    wait_status(lambda s: s['current_evaluation']['status'] == 'healthy')
    stages['recovered'] = snapshot(started)
    recovered_manager = stages['recovered']['collector_manager']
    require(recovered_manager['MainPID'] != paused['MainPID'] and recovered_manager['NRestarts'] == paused['NRestarts'] + 1,
            'The collector was not automatically restarted by its supervisor.')
    require(stages['recovered']['status']['instance_id'] == stages['incident']['status']['instance_id'], 'Recovery restarted the monitor.')
    command(['systemctl', 'stop', COLLECTOR_UNIT], timeout=30)
    journal = request('export')
    records = receipts()
    lab.probes = validate_inventory(journal, records)
    require({r['process_id'] for r in records} == {paused['MainPID'], recovered_manager['MainPID']}
            and records[0]['instance_id'] == idle['instance_id']
            and records[0]['process_id'] == paused['MainPID']
            and records[-1]['process_id'] == recovered_manager['MainPID'],
            'Autonomous receipt producers differ from the observed service processes.')
    resolutions = [e for e in journal['events'] if e['key'] == reboot.CRITICAL and e['action'] == 'resolved']
    require(len(resolutions) == 1 and resolutions[0]['alert_id'] == incident_id
            and resolutions[0]['sequence'] > silence['gap_sequence'], 'Incident recovery was not uniquely recorded after the gap.')
    resolution_row = next(r for r in journal['rows'] if r['sequence'] == resolutions[0]['sequence'])
    require(resolution_row['evaluation']['status'] == 'healthy' and len(resolution_row['sample']['probes']) == 3,
            'Incident recovery did not require a complete fresh canary cycle.')
    captured = lab.stop_captures()
    require(captured['routed_flows_verified'] == len([p for p in lab.probes if p['from'] != p['to']]), 'Capture/collector coverage differs.')
    final = request('status')
    require(final['current_evaluation']['status'] == 'healthy', 'Final collection failed to remain fresh during artifact sealing.')
    return {'approved_policy': approved, 'stages': stages, 'silence': silence, 'collector_receipts': records,
            'journal': journal, 'final_status': final, 'critical_incident_id': incident_id, 'capture': captured,
            'boot_enabled_configuration_only': True, 'collector_stopped_after_exercise': True}


def seal_capture(path):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid() and before.st_nlink == 1
            and 0 < before.st_size <= 8 * 1024 * 1024, 'Unsafe completed capture.')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'Capture changed while opening.')
        os.fsync(fd)
        value = hashlib.sha256()
        total = 0
        while chunk := os.read(fd, 65536):
            total += len(chunk)
            require(total <= 8 * 1024 * 1024, 'Capture grew beyond its bound.')
            value.update(chunk)
        after = os.fstat(fd)
        require(total == before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns and after.st_nlink == 1,
                'Capture changed while sealing.')
        return value.hexdigest()
    finally:
        os.close(fd)


def storage_info():
    with_target = command(['findmnt', '--json', '--target', str(STATE), '--output', 'TARGET,SOURCE,FSTYPE,OPTIONS,UUID'])
    data = json.loads(with_target.stdout)
    require(set(data) == {'filesystems'} and len(data['filesystems']) == 1, 'Ambiguous state mount.')
    record = data['filesystems'][0]
    require(record['fstype'] in {'ext4', 'xfs', 'btrfs'} and record['source'].startswith('/dev/')
            and record['uuid'] and 'rw' in record['options'].split(','), 'Automatic state needs a persistent writable disk.')
    return record


def exercise(token):
    virtualization = guard(token)
    require(not DATA.exists() and not any(unit_path(u).exists() for u in (MONITOR_UNIT, COLLECTOR_UNIT)), 'Existing automatic installation cannot be reset.')
    DATA.mkdir(mode=0o700); REPORT.mkdir(mode=0o700); PUBLISH.mkdir(mode=0o700)
    staging = REPORT / 'capture'; staging.mkdir(mode=0o700)
    store.sync_directory(DATA.parent)
    boot, hashes = reboot.boot_info(virtualization), source_hashes()
    lab = monitoring.MonitoringLab(reboot.base.preflight(), staging)
    try:
        outcome = run_exercise(lab)
    finally:
        if unit_path(COLLECTOR_UNIT).exists():
            command(['systemctl', 'kill', '--kill-who=main', '--signal=CONT', COLLECTOR_UNIT], check=False)
            command(['systemctl', 'stop', COLLECTOR_UNIT], check=False, timeout=30)
        cleaned = lab.cleanup()
        require(cleaned['ok'], 'Owned network cleanup failed.')
    capture_hashes = {}
    for name in CAPTURE_FILES:
        capture_hashes[name] = seal_capture(staging / name)
        require(not (PUBLISH / name).exists(), 'Published capture already exists.')
        (staging / name).rename(PUBLISH / name)
    store.sync_directory(staging); store.sync_directory(PUBLISH)
    require({name: seal_capture(PUBLISH / name) for name in CAPTURE_FILES} == capture_hashes, 'Published capture hash changed.')
    require(source_hashes() == hashes, 'Automatic guest source changed.')
    report = {'format': 'heltemes-monitor-automatic-guest', 'version': 1, 'ok': True, 'boot': boot,
              'source_sha256': hashes, 'storage': storage_info(), 'network_cleanup': cleaned,
              'capture_sha256': capture_hashes, 'completed_at_utc': reboot.timestamp(), **outcome}
    write_new(PUBLISH / 'APPROVED_POLICY.json', outcome['approved_policy'])
    write_new(PUBLISH / 'monitor.service', unit_text(MONITOR_UNIT))
    write_new(PUBLISH / 'collector.service', unit_text(COLLECTOR_UNIT))
    write_new(PUBLISH / 'GUEST.json', report)
    require({p.name for p in PUBLISH.iterdir()} == set(PUBLIC_FILES), 'Public automatic artifact inventory differs.')
    return {'ok': True, 'stage': 'exercise', 'boot_id': boot['boot_id'], 'committed_count': len(outcome['journal']['rows']),
            'current_status': outcome['final_status']['current_evaluation']['status'], 'network_cleanup': cleaned,
            'guest_report_sha256': hashlib.sha256((PUBLISH / 'GUEST.json').read_bytes()).hexdigest()}


def cleanup(token):
    guard(token)
    for unit in (COLLECTOR_UNIT, MONITOR_UNIT):
        path = unit_path(unit)
        if path.exists():
            reboot.ordinary(path, mode=0o644)
            require(path.read_text() == unit_text(unit), 'An unexpected unit cannot be removed.')
            command(['systemctl', 'kill', '--kill-who=main', '--signal=CONT', unit], check=False)
            command(['systemctl', 'disable', '--now', unit], timeout=30)
            active = command(['systemctl', 'is-active', unit], check=False).stdout.strip()
            require(active not in {'active', 'activating', 'deactivating'}, 'Owned service did not stop.')
            path.unlink()
    command(['systemctl', 'daemon-reload'])
    for path in (STATE, PRIVATE):
        if path.exists():
            store.state_path(path); shutil.rmtree(path)
    if CONFIG.exists():
        reboot.ordinary(CONFIG); CONFIG.unlink()
    require(not any(p.exists() for p in (STATE, PRIVATE, CONFIG, unit_path(MONITOR_UNIT), unit_path(COLLECTOR_UNIT))), 'Owned service cleanup incomplete.')
    return {'ok': True, 'services_disabled_removed': True, 'state_removed': True, 'collector_config_removed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('exercise', 'cleanup'))
    parser.add_argument('--token', required=True)
    args = parser.parse_args()
    try:
        result = cleanup(args.token) if args.stage == 'cleanup' else exercise(args.token)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Disposable automatic guest stopped: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
