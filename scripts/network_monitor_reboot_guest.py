"""Persistent monitor and live observations inside an explicitly marked disposable VM.

The host controller performs the OS reboot. This module never reinitializes state
on boot or in the after stage, and it never starts the unit in the after stage.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_lab as base
from scripts import network_monitoring_lab as monitoring
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store
from scripts import network_segmentation_lab as segmentation

INSTALL = Path('/opt/heltemes-reboot-lab')
MARKER = Path('/etc/heltemes-reboot-lab.json')
DATA = Path('/var/lib/heltemes-reboot-lab')
STATE = DATA / 'state'
REPORT = DATA / 'report'
PUBLISH = REPORT / 'publish'
VOLATILE = Path('/run/heltemes-reboot-lab-marker')
UNIT = 'heltemes-reboot-monitor.service'
UNIT_FILE = Path('/etc/systemd/system') / UNIT
DESCRIPTION = 'HELTEMES disposable VM reboot monitor'
SOURCE_FILES = (*monitoring.SOURCE_FILES, 'scripts/network_monitor_store.py',
                'scripts/network_monitor_service.py', 'scripts/network_monitor_reboot_guest.py')
CAPTURE_FILES = tuple(name for zone in segmentation.ZONES for name in (zone + '.pcap', zone + '-packets.txt'))
PUBLIC_FILES = ('BEFORE.json', 'AFTER.json', 'APPROVED_POLICY.json', 'monitor.service',
                *(stage + '-' + name for stage in ('before', 'after') for name in CAPTURE_FILES))
MANAGER_FIELDS = ('LoadState', 'ActiveState', 'SubState', 'MainPID', 'NRestarts',
                  'ExecMainStartTimestampMonotonic', 'InvocationID', 'UnitFileState', 'FragmentPath')
CRITICAL = 'forbidden_path_open:user->app:9090'
require, timestamp = base.require, base.timestamp


def command(arguments, *, check=True, timeout=15):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout)
    if check:
        require(result.returncode == 0, 'A disposable guest operation failed: ' + Path(arguments[0]).name)
    return result


def ordinary(path, *, mode=0o600):
    require(not path.is_symlink(), 'A guest-owned path cannot be a symlink.')
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and stat.S_IMODE(info.st_mode) == mode, 'A guest-owned file has an unexpected identity or mode.')
    return info


def guard(token):
    require(sys.platform == 'linux' and os.geteuid() == 0, 'This operation requires the disposable Linux guest.')
    require(ROOT == INSTALL, 'Guest source must be installed at the dedicated lab path.')
    require(isinstance(token, str) and re.fullmatch(r'[0-9a-f]{32}', token), 'Invalid disposable guest token.')
    ordinary(MARKER)
    require(MARKER.stat().st_size <= 4096, 'Guest marker is oversized.')
    marker = store.parse(MARKER.read_bytes())
    require(marker == {'format': 'heltemes-disposable-reboot-vm', 'version': 1, 'token': token},
            'This VM was not explicitly marked for this invocation.')
    virtualization = command(['systemd-detect-virt', '--vm']).stdout.strip()
    require(virtualization in {'qemu', 'kvm'}, 'A QEMU disposable guest is required.')
    for path in (INSTALL, DATA, STATE, REPORT, PUBLISH, UNIT_FILE, VOLATILE):
        require(not any(p.is_symlink() for p in (path, *path.parents)), 'Guest paths must not traverse symbolic links.')
    return virtualization


def source_hashes():
    result = {}
    for name in SOURCE_FILES:
        path = ROOT / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size < 1024 * 1024,
                'A source input is missing or unsafe.')
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def boot_info(virtualization):
    identity = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', identity), 'Invalid kernel boot identity.')
    uptime = float(Path('/proc/uptime').read_text().split()[0])
    require(0 < uptime < 86400, 'Unexpected guest boot uptime.')
    return {'boot_id': identity, 'uptime_seconds': uptime,
            'kernel_release': os.uname().release, 'virtualization': virtualization,
            'observed_at_utc': timestamp()}


def storage_info():
    data = json.loads(command(['findmnt', '--json', '--target', str(STATE),
                              '--output', 'TARGET,SOURCE,FSTYPE,OPTIONS,UUID']).stdout)
    require(set(data) == {'filesystems'} and len(data['filesystems']) == 1, 'State mount is ambiguous.')
    record = data['filesystems'][0]
    require(set(record) == {'target', 'source', 'fstype', 'options', 'uuid'}
            and record['fstype'] in {'ext4', 'xfs', 'btrfs'}
            and record['source'].startswith('/dev/') and record['uuid']
            and 'rw' in record['options'].split(','), 'Monitor state is not on a writable persistent disk filesystem.')
    return record


def unit_text():
    return f'''[Unit]
Description={DESCRIPTION}
After=local-fs.target
RequiresMountsFor={STATE}
StartLimitIntervalSec=30
StartLimitBurst=3

[Service]
Type=exec
ExecStart=/usr/bin/python3 -I -S -B {INSTALL}/scripts/network_monitor_service.py serve --state {STATE}
Restart=on-failure
RestartSec=1
UMask=0077
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths={STATE}
RestrictAddressFamilies=AF_UNIX

[Install]
WantedBy=multi-user.target
'''


def write_new(path, value):
    data = value.encode() if isinstance(value, str) else (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    store.write_new(path, data)
    store.sync_directory(path.parent)


def manager():
    ordinary(UNIT_FILE, mode=0o644)
    require(UNIT_FILE.read_text() == unit_text(), 'Installed boot unit differs from the expected unit.')
    response = command(['systemctl', 'show', '--no-pager', '--property=' + ','.join(MANAGER_FIELDS), UNIT])
    values = dict(line.split('=', 1) for line in response.stdout.splitlines() if '=' in line)
    require(set(values) == set(MANAGER_FIELDS), 'Service manager evidence is incomplete.')
    require(values['LoadState'] == 'loaded' and values['FragmentPath'] == str(UNIT_FILE)
            and values['UnitFileState'] == 'enabled', 'Persistent boot service is not enabled from its expected unit.')
    for key in ('MainPID', 'NRestarts', 'ExecMainStartTimestampMonotonic'):
        require(values[key].isdecimal(), 'Invalid service numeric evidence.')
        values[key] = int(values[key])
    require(re.fullmatch(r'[0-9a-f]{32}', values['InvocationID']), 'Invalid service invocation identity.')
    return values


def request(payload):
    return service.request(STATE, payload, timeout=10)


def process_boot_timing(properties, uptime):
    started = properties['ExecMainStartTimestampMonotonic']
    require(isinstance(started, int) and not isinstance(started, bool)
            and 0 < started <= uptime * 1_000_000 and 0 < uptime < 86400,
            'The service start timestamp does not belong to the observed running boot.')
    return {**properties, 'inspected_uptime_seconds': uptime}


def ready(timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        properties = manager()
        if properties['ActiveState'] == 'active' and properties['MainPID'] > 0:
            try:
                status = request({'command': 'status'})
                if status.get('ok') is True and status['process_id'] == properties['MainPID']:
                    require(properties['NRestarts'] == 0, 'The boot service unexpectedly restarted inside this boot.')
                    uptime = float(Path('/proc/uptime').read_text().split()[0])
                    return status, process_boot_timing(properties, uptime)
            except (OSError, ValueError):
                pass
        time.sleep(0.1)
    raise RuntimeError('The enabled monitor did not become independently ready.')


def critical(status):
    matches = [a for a in status['alerts'] if a['key'] == CRITICAL and a['state'] == 'open']
    require(len(matches) == 1, 'The original critical incident is missing or duplicated.')
    return matches[0]


def unknown(status):
    evaluation = status['current_evaluation']
    require(evaluation['status'] == 'unknown' and evaluation['phase'] == 'monitor_restart'
            and 'telemetry_gap:collector' in evaluation['active_alert_keys'],
            'Startup must record unknown monitoring coverage before accepting observations.')


def install(approved):
    require(not STATE.exists() and not UNIT_FILE.exists(), 'Existing monitor state or boot unit must never be replaced.')
    store.initialize(STATE, approved)
    write_new(UNIT_FILE, unit_text())
    UNIT_FILE.chmod(0o644)
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', '--now', UNIT])
    status, properties = ready()
    unknown(status)
    require(status['committed_count'] == 1, 'New state must contain only the initial startup boundary.')
    return status, properties


def observe(lab, observations, phase, rows=()):
    lab.phase = phase
    probes = []
    for source, target, port in rows:
        probe = lab.probe(source, target, port)
        probe['destination_health'] = lab.probe(target, target, port) if probe['outcome'] == 'connect_timeout' else None
        probes.append(probe)
    observation = {'phase': phase, 'observed_at_utc': timestamp(), 'ruleset': lab.ruleset(),
                   'collection_error': None, 'probes': probes}
    payload = {'command': 'observe', 'request_id': phase, 'observation': observation}
    result = request(payload)
    require(result.get('ok') is True and result.get('duplicate') is False, 'Fresh observation was not committed exactly once.')
    observations.append({'request': copy.deepcopy(payload), 'committed_sequence': result['committed_sequence'],
                         'evaluation': result['evaluation']})
    return result['current_status']


def inventory(lab, observations, stage):
    expected = {'before': [('before_reference', ()), ('before_baseline', monitoring.CANARIES),
                           ('before_rule_drift', ()), ('before_forbidden', (segmentation.EXCEPTION,))],
                'after': [('after_reference', ()), ('after_canaries', monitoring.CANARIES)]}[stage]
    require([r['request']['observation']['phase'] for r in observations] == [name for name, _ in expected],
            'Guest observation phases differ.')
    routed = [p for p in lab.probes if p['from'] != p['to']]
    controls = [p for p in lab.probes if p['from'] == p['to']]
    require(len(routed) == (4 if stage == 'before' else 3) and len(controls) == 1
            and len({p['source_port'] for p in lab.probes}) == len(lab.probes), 'Guest probe inventory is incomplete.')
    for record, (phase, paths) in zip(observations, expected):
        probes = record['request']['observation']['probes']
        require([(p['from'], p['to'], p['port']) for p in probes] == list(paths), 'Guest canary coverage differs.')
        require(probes == [p for p in routed if p['phase'] == phase], 'An actual probe was omitted from its observation.')
        for probe in probes:
            expected_outcome = 'connect_timeout' if (probe['from'], probe['to'], probe['port']) == segmentation.EXCEPTION and phase != 'before_forbidden' else 'response'
            require(probe['outcome'] == expected_outcome, 'Unexpected guest canary outcome.')
            if probe['outcome'] == 'response':
                segmentation.require_response(probe, probe['to'], probe['port'])
            else:
                health = probe['destination_health']
                require(health in controls and health['from'] == health['to'] == probe['to'], 'Denial lacks its healthy destination.')
                segmentation.require_response(health, probe['to'], probe['port'])


def run_before(lab):
    lab.setup(); lab.start_services(); lab.apply_policy()
    approved = lab.ruleset()
    initial, initial_manager = install(approved)
    lab.start_captures()
    observations = []
    observe(lab, observations, 'before_reference')
    baseline = observe(lab, observations, 'before_baseline', monitoring.CANARIES)
    require(baseline['current_evaluation']['status'] == 'healthy', 'Fresh baseline was not healthy.')
    lab.apply_policy('misconfigured')
    drift = observe(lab, observations, 'before_rule_drift')
    require('rule_drift:ruleset' in drift['current_evaluation']['active_alert_keys'], 'Incorrect rule was not detected.')
    final = observe(lab, observations, 'before_forbidden', (segmentation.EXCEPTION,))
    incident = critical(final)
    journal = request({'command': 'export'})
    require(journal.get('ok') is True and len(journal['rows']) == 5, 'Preboot journal size differs.')
    inventory(lab, observations, 'before')
    captured = lab.stop_captures()
    require(captured['routed_flows_verified'] == 4, 'Preboot capture coverage is incomplete.')
    return {'approved_policy': approved, 'initial_status': initial, 'initial_manager': initial_manager,
            'final_status': final, 'manager': manager(), 'journal': journal, 'observations': observations,
            'critical_incident_id': incident['id'], 'capture': captured}


def verify_reboot(before, boot, status, properties, journal, storage, hashes):
    require(boot['boot_id'] != before['boot']['boot_id'], 'A full Linux boot change was not observed.')
    require(not VOLATILE.exists() and not VOLATILE.is_symlink(), 'The volatile preboot marker survived; reboot proof is incomplete.')
    require(hashes == before['source_sha256'], 'Guest source changed across reboot.')
    require(all(storage[key] == before['storage'][key] for key in ('target', 'source', 'fstype', 'uuid')),
            'Persistent monitor state is not on the original filesystem.')
    require(properties['InvocationID'] != before['manager']['InvocationID']
            and status['instance_id'] != before['final_status']['instance_id'], 'The monitor did not start a new boot instance.')
    unknown(status)
    require(critical(status)['id'] == before['critical_incident_id'], 'The accepted incident identity changed during reboot.')
    require(journal.get('ok') is True and journal['identity'] == before['journal']['identity']
            and journal['approved_policy'] == before['journal']['approved_policy'], 'The accepted journal identity or policy changed.')
    old_rows, rows = before['journal']['rows'], journal['rows']
    require(store.encoded(rows[:-1]) == store.encoded(old_rows) and len(rows) == len(old_rows) + 1 == 6
            and status['committed_count'] == 6, 'Preboot committed history was lost, changed, repeated, or reinitialized.')
    require(rows[-1]['request']['kind'] == 'restart' and rows[-1]['evaluation']['status'] == 'unknown',
            'The only appended boot record must describe unknown coverage.')


def run_after(lab, before, boot, hashes, storage):
    # No systemctl start/restart, initialization, or observation occurs here.
    startup, properties = ready()
    accepted = request({'command': 'export'})
    verify_reboot(before, boot, startup, properties, accepted, storage, hashes)
    auto = {'status': startup, 'manager': properties, 'journal': accepted,
            'inspected_before_collection_at_utc': timestamp(), 'no_manual_service_start': True}
    # Preserve the engine's no-reused-probe-port invariant across fresh kernels.
    lab.next_source_port = 45000
    lab.setup(); lab.start_services(); lab.apply_policy()
    require(monitoring.monitor.policy_fingerprint(lab.ruleset()) == before['journal']['identity']['approved_policy_sha256'],
            'Newly created network rules differ from the original approved reference.')
    lab.start_captures()
    observations = []
    reference = observe(lab, observations, 'after_reference')
    require(critical(reference)['id'] == before['critical_incident_id'], 'Rules alone incorrectly cleared the old incident.')
    final = observe(lab, observations, 'after_canaries', monitoring.CANARIES)
    require(final['current_evaluation']['status'] == 'healthy'
            and all(a['severity'] == 'info' for a in final['alerts'] if a['state'] == 'open'),
            'Fresh committed checks did not establish recovered monitoring.')
    journal = request({'command': 'export'})
    require(journal.get('ok') is True and len(journal['rows']) == 8
            and store.encoded(journal['rows'][:5]) == store.encoded(before['journal']['rows']), 'Final history lost the preboot prefix.')
    resolutions = [e for e in journal['events'] if e['key'] == CRITICAL and e['action'] == 'resolved']
    require(len(resolutions) == 1 and resolutions[0]['phase'] == 'after_canaries'
            and resolutions[0]['sequence'] == 8, 'The original incident resolved before fresh committed recovery.')
    inventory(lab, observations, 'after')
    captured = lab.stop_captures()
    require(captured['routed_flows_verified'] == 3, 'Postboot capture coverage is incomplete.')
    return {'automatic_start': auto, 'final_status': final, 'manager': manager(), 'journal': journal,
            'observations': observations, 'critical_incident_id': before['critical_incident_id'],
            'capture': captured, 'preboot_prefix_preserved': True, 'volatile_marker_absent': True}


def stage(name, token):
    virtualization = guard(token)
    tools = base.preflight()
    boot = boot_info(virtualization)
    hashes = source_hashes()
    require(name in {'before', 'after'}, 'Unknown guest stage.')
    if name == 'before':
        require(not DATA.exists() and not UNIT_FILE.exists() and not VOLATILE.exists(), 'Disposable state already exists; never reset it.')
        DATA.mkdir(mode=0o700); REPORT.mkdir(mode=0o700); PUBLISH.mkdir(mode=0o700)
        store.sync_directory(DATA.parent)
        write_new(VOLATILE, 'HELTEMES disposable runtime marker\n')
    else:
        store.state_path(DATA); store.state_path(STATE); store.state_path(REPORT); store.state_path(PUBLISH)
        ordinary(PUBLISH / 'BEFORE.json')
        require(not (PUBLISH / 'AFTER.json').exists(), 'Completed after stage must not be repeated.')
    staging = REPORT / name
    staging.mkdir(mode=0o700)
    lab = monitoring.MonitoringLab(tools, staging)
    outcome = None
    try:
        if name == 'before':
            outcome = run_before(lab)
        else:
            before = store.parse((PUBLISH / 'BEFORE.json').read_bytes())
            outcome = run_after(lab, before, boot, hashes, storage_info())
    finally:
        cleanup = lab.cleanup()
        require(cleanup['ok'], 'Guest-owned network cleanup failed.')
    result = {'format': 'heltemes-monitor-reboot-guest', 'version': 1, 'ok': True, 'stage': name,
              'boot': boot, 'source_sha256': hashes, 'storage': storage_info(), 'unit_sha256': hashlib.sha256(unit_text().encode()).hexdigest(),
              'network_cleanup': cleanup, 'completed_at_utc': timestamp(), **outcome}
    require(source_hashes() == hashes, 'Guest source changed during collection.')
    for filename in CAPTURE_FILES:
        source = staging / filename
        require(source.is_file() and not source.is_symlink(), 'A completed capture is missing.')
        source.rename(PUBLISH / (name + '-' + filename))
    write_new(PUBLISH / (name.upper() + '.json'), result)
    if name == 'before':
        write_new(PUBLISH / 'APPROVED_POLICY.json', outcome['approved_policy'])
        write_new(PUBLISH / 'monitor.service', unit_text())
    else:
        require({p.name for p in PUBLISH.iterdir()} == set(PUBLIC_FILES), 'Guest public output inventory differs.')
    return {'ok': True, 'stage': name, 'boot_id': boot['boot_id'], 'committed_count': len(outcome['journal']['rows']),
            'current_status': outcome['final_status']['current_evaluation']['status'],
            'critical_incident_id': outcome['critical_incident_id'], 'network_cleanup': cleanup}


def cleanup(token):
    guard(token)
    if UNIT_FILE.exists():
        ordinary(UNIT_FILE, mode=0o644)
        require(UNIT_FILE.read_text() == unit_text(), 'An unexpected unit cannot be removed.')
        command(['systemctl', 'disable', '--now', UNIT])
        status = command(['systemctl', 'is-active', UNIT], check=False).stdout.strip()
        require(status not in {'active', 'activating', 'deactivating'}, 'The guest monitor has not stopped.')
        UNIT_FILE.unlink(); command(['systemctl', 'daemon-reload'])
    require(not UNIT_FILE.exists(), 'The owned unit remains installed.')
    if STATE.exists():
        store.state_path(DATA); store.state_path(STATE)
        shutil.rmtree(STATE)
    if VOLATILE.exists():
        ordinary(VOLATILE); VOLATILE.unlink()
    require(not STATE.exists() and not VOLATILE.exists(), 'Disposable state cleanup did not complete.')
    return {'ok': True, 'service_disabled_removed': True, 'state_removed': True, 'volatile_marker_removed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('before', 'after', 'cleanup'))
    parser.add_argument('--token', required=True)
    args = parser.parse_args()
    try:
        result = cleanup(args.token) if args.stage == 'cleanup' else stage(args.stage, args.token)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Disposable reboot guest stopped: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
