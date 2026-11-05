"""Guarded guest exercise for abrupt VM power cuts at transaction boundaries.

Only this explicitly marked disposable worker enables the pause callback. The
host kills QEMU after observing a stopped worker; this module never reboots it.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor_reboot_guest as reboot
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store

base, monitoring, segmentation = reboot.base, reboot.monitoring, reboot.segmentation
require, timestamp = reboot.require, reboot.timestamp
ordinary, command, write_new = reboot.ordinary, reboot.command, reboot.write_new
INSTALL = reboot.INSTALL
DATA = Path('/var/lib/heltemes-powercut-lab')
STATE, REPORT = DATA / 'state', DATA / 'report'
PUBLISH = REPORT / 'publish'
RUNTIME = Path('/run/heltemes-powercut-lab')
BOUNDARY = RUNTIME / 'boundary.json'
VOLATILE = RUNTIME / 'precut-marker'
UNIT = 'heltemes-powercut-monitor.service'
UNIT_FILE = Path('/etc/systemd/system') / UNIT
SOURCE_FILES = (*reboot.SOURCE_FILES, 'scripts/network_monitor_powercut_guest.py')
CAPTURE_FILES = reboot.CAPTURE_FILES
PUBLIC_FILES = ('BEFORE.json', 'AFTER_BEFORE.json', 'AFTER.json', 'APPROVED_POLICY.json', 'monitor.service',
                *(stage + '-' + name for stage in ('before', 'after') for name in CAPTURE_FILES))
POINTS = {'arm-before': 'before_commit', 'arm-after': 'after_commit_before_ack'}
REQUEST_IDS = {'before_commit': 'powercut-uncommitted', 'after_commit_before_ack': 'powercut-committed'}
CRITICAL = reboot.CRITICAL


def guard(token):
    virtualization = reboot.guard(token)
    for path in (DATA, STATE, REPORT, PUBLISH, RUNTIME, BOUNDARY, UNIT_FILE, VOLATILE):
        require(not any(p.is_symlink() for p in (path, *path.parents)), 'Power-cut guest paths cannot traverse symlinks.')
    return virtualization


def source_hashes():
    result = reboot.source_hashes()
    path = ROOT / 'scripts/network_monitor_powercut_guest.py'
    require(path.is_file() and not path.is_symlink() and path.stat().st_size < 1024 * 1024, 'Power-cut source is missing or unsafe.')
    result['scripts/network_monitor_powercut_guest.py'] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def storage_info():
    data = json.loads(command(['findmnt', '--json', '--target', str(STATE), '--output', 'TARGET,SOURCE,FSTYPE,OPTIONS,UUID']).stdout)
    require(set(data) == {'filesystems'} and len(data['filesystems']) == 1, 'State mount is ambiguous.')
    record = data['filesystems'][0]
    require(set(record) == {'target', 'source', 'fstype', 'options', 'uuid'}
            and record['fstype'] in {'ext4', 'xfs', 'btrfs'} and record['source'].startswith('/dev/')
            and record['uuid'] and 'rw' in record['options'].split(','), 'State must use a writable persistent disk filesystem.')
    return record


def unit_text(token):
    require(reboot.re.fullmatch(r'[0-9a-f]{32}', token), 'Invalid worker token.')
    # The public unit omits the private token by using the root-only seed marker.
    return f'''[Unit]
Description=HELTEMES disposable VM power-cut monitor
After=local-fs.target
RequiresMountsFor={STATE}
StartLimitIntervalSec=30
StartLimitBurst=3

[Service]
Type=exec
ExecStart=/usr/bin/python3 -I -S -B {INSTALL}/scripts/network_monitor_powercut_guest.py worker
Restart=on-failure
RestartSec=1
UMask=0077
RuntimeDirectory=heltemes-powercut-lab
RuntimeDirectoryMode=0700
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths={STATE} {RUNTIME}
RestrictAddressFamilies=AF_UNIX

[Install]
WantedBy=multi-user.target
'''


def manager(token):
    ordinary(UNIT_FILE, mode=0o644)
    require(UNIT_FILE.read_text() == unit_text(token), 'Installed power-cut unit differs.')
    response = command(['systemctl', 'show', '--no-pager', '--property=' + ','.join(reboot.MANAGER_FIELDS), UNIT])
    values = dict(line.split('=', 1) for line in response.stdout.splitlines() if '=' in line)
    require(set(values) == set(reboot.MANAGER_FIELDS), 'Service manager evidence is incomplete.')
    require(values['LoadState'] == 'loaded' and values['FragmentPath'] == str(UNIT_FILE)
            and values['UnitFileState'] == 'enabled', 'The exact persistent boot service is not enabled.')
    for key in ('MainPID', 'NRestarts', 'ExecMainStartTimestampMonotonic'):
        require(values[key].isdecimal(), 'Invalid service manager numeric evidence.')
        values[key] = int(values[key])
    require(reboot.re.fullmatch(r'[0-9a-f]{32}', values['InvocationID']), 'Invalid service invocation identity.')
    return values


def request(payload):
    return service.request(STATE, payload, timeout=10)


def ready(token, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        properties = manager(token)
        if properties['ActiveState'] == 'active' and properties['MainPID'] > 0:
            try:
                status = request({'command': 'status'})
                if status.get('ok') is True and status['process_id'] == properties['MainPID']:
                    require(properties['NRestarts'] == 0, 'Worker unexpectedly restarted within the same boot.')
                    uptime = float(Path('/proc/uptime').read_text().split()[0])
                    return status, reboot.process_boot_timing(properties, uptime)
            except (OSError, ValueError):
                pass
        time.sleep(0.1)
    raise RuntimeError('The enabled worker did not become independently ready.')


def install(approved, token):
    require(not STATE.exists() and not UNIT_FILE.exists(), 'Existing state or unit must never be replaced.')
    store.initialize(STATE, approved)
    write_new(UNIT_FILE, unit_text(token)); UNIT_FILE.chmod(0o644)
    command(['systemctl', 'daemon-reload']); command(['systemctl', 'enable', '--now', UNIT])
    status, properties = ready(token)
    reboot.unknown(status)
    require(status['committed_count'] == 1, 'Initial journal must contain only its startup boundary.')
    return status, properties


def observe(lab, observations, phase, rows=()):
    lab.phase = phase
    probes = []
    for source, target, port in rows:
        probe = lab.probe(source, target, port)
        probe['destination_health'] = lab.probe(target, target, port) if probe['outcome'] == 'connect_timeout' else None
        probes.append(probe)
    observation = {'phase': phase, 'observed_at_utc': timestamp(), 'ruleset': lab.ruleset(), 'collection_error': None, 'probes': probes}
    payload = {'command': 'observe', 'request_id': phase, 'observation': observation}
    result = request(payload)
    require(result.get('ok') is True and result.get('duplicate') is False, 'Fresh observation was not accepted exactly once.')
    observations.append({'request': copy.deepcopy(payload), 'committed_sequence': result['committed_sequence'], 'evaluation': result['evaluation']})
    return result['current_status']


def run_before(lab, token):
    lab.setup(); lab.start_services(); lab.apply_policy()
    approved = lab.ruleset()
    initial, initial_manager = install(approved, token)
    lab.start_captures(); observations = []
    observe(lab, observations, 'before_reference')
    baseline = observe(lab, observations, 'before_baseline', monitoring.CANARIES)
    require(baseline['current_evaluation']['status'] == 'healthy', 'Fresh baseline was not healthy: ' + reboot.evaluation_diagnostic(baseline))
    lab.apply_policy('misconfigured')
    drift = observe(lab, observations, 'before_rule_drift')
    require('rule_drift:ruleset' in drift['current_evaluation']['active_alert_keys'], 'Incorrect rule was not detected.')
    final = observe(lab, observations, 'before_forbidden', (segmentation.EXCEPTION,))
    incident = reboot.critical(final)
    journal = request({'command': 'export'})
    require(journal.get('ok') is True and len(journal['rows']) == 5, 'Pre-cut journal size differs.')
    reboot.inventory(lab, observations, 'before')
    captured = lab.stop_captures()
    require(captured['routed_flows_verified'] == 4, 'Pre-cut packet coverage is incomplete.')
    return {'approved_policy': approved, 'initial_status': initial, 'initial_manager': initial_manager,
            'final_status': final, 'manager': manager(token), 'journal': journal, 'observations': observations,
            'critical_incident_id': incident['id'], 'capture': captured}


def cut_payload(point):
    require(point in REQUEST_IDS, 'Unknown transaction boundary.')
    return {'command': 'observe', 'request_id': REQUEST_IDS[point], 'test_pause': point,
            'observation': {'phase': REQUEST_IDS[point], 'observed_at_utc': timestamp(), 'ruleset': None,
                            'collection_error': 'powercut_test_boundary', 'probes': []}}


def sql_rows(connection):
    rows = connection.execute('SELECT sequence,request_id,request,sample,evaluation,events,previous_digest,row_digest FROM observations ORDER BY sequence').fetchall()
    require(len(rows) <= store.MAX_ROWS, 'Boundary journal exceeds its bound.')
    return [{'sequence': row[0], 'request_id': row[1], 'request': store.parse(row[2]), 'sample': store.parse(row[3]),
             'evaluation': store.parse(row[4]), 'events': store.parse(row[5]), 'previous_digest': row[6], 'row_digest': row[7]} for row in rows]


def pause_worker(worker, point, payload):
    """Report a reached boundary on tmpfs, then stop until host kills this VM."""
    require(point in REQUEST_IDS and payload['request_id'] == REQUEST_IDS[point], 'Invalid pause request identity.')
    store.state_path(RUNTIME)
    require(command(['findmnt', '-n', '-o', 'FSTYPE', '--target', str(RUNTIME)]).stdout.strip() == 'tmpfs',
            'The boundary marker must use volatile tmpfs storage.')
    require(not BOUNDARY.exists() and not BOUNDARY.is_symlink(), 'A stale boundary marker must not be reused.')
    connection = worker.journal.connection
    require(connection.in_transaction is (point == 'before_commit'), 'Transaction state differs from requested boundary.')
    rows = sql_rows(connection)
    require(rows[-1]['request_id'] == payload['request_id'], 'The boundary did not reach its candidate row.')
    journal_path = STATE / 'monitor.sqlite3-journal'
    journal_info = {'exists': journal_path.exists(), 'bytes': journal_path.stat().st_size if journal_path.exists() else 0}
    value = {'format': 'heltemes-powercut-boundary', 'version': 1, 'point': point,
             'request_id': payload['request_id'], 'request': {key: value for key, value in payload.items() if key != 'test_pause'},
             'observation_sha256': store.digest(payload['observation']), 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
             'process_id': os.getpid(), 'instance_id': worker.instance_id, 'in_transaction': connection.in_transaction,
             'database_view_rows': rows, 'accepted_in_memory_count': len(worker.journal.rows),
             'rollback_journal_observation': journal_info, 'observed_at_utc': timestamp(),
             'synchronous': connection.execute('PRAGMA synchronous').fetchone()[0],
             'journal_mode': connection.execute('PRAGMA journal_mode').fetchone()[0]}
    # This marker is on tmpfs. It must not force a persistent-disk sync before the cut.
    store.write_new(BOUNDARY, (store.encoded(value) + '\n').encode())
    os.kill(os.getpid(), signal.SIGSTOP)
    os._exit(74)  # An unexpected SIGCONT cannot resume or acknowledge the test transaction.


def process_stopped(pid):
    require(type(pid) is int and pid > 0, 'Invalid worker PID.')
    lines = Path('/proc') / str(pid) / 'status'
    state = next((line.split()[1] for line in lines.read_text().splitlines() if line.startswith('State:')), None)
    require(state in {'R', 'S', 'D', 'T', 't', 'Z', 'X', 'I'}, 'Unknown worker process state.')
    return state == 'T'


def arm(name, token):
    virtualization = guard(token)
    point = POINTS[name]
    previous_name = 'BEFORE.json' if name == 'arm-before' else 'AFTER_BEFORE.json'
    previous = read_report(previous_name)
    status, properties = ready(token)
    require(status['committed_count'] == (5 if name == 'arm-before' else 6), 'Wrong journal count for transaction cut.')
    require(status['instance_id'] == previous['final_status']['instance_id'], 'The expected worker instance changed before arming.')
    require(not BOUNDARY.exists() and not BOUNDARY.is_symlink(), 'A stale pause marker exists.')
    require(not VOLATILE.exists() and not VOLATILE.is_symlink(), 'A stale volatile marker exists.')
    write_new(VOLATILE, 'Current disposable boot before abrupt VM loss\n')
    payload = cut_payload(point)
    sock = service.socket_path(STATE)
    info = sock.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'Unsafe worker socket.')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3); connection.connect(str(sock)); connection.sendall((store.encoded(payload) + '\n').encode())
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if BOUNDARY.exists():
                ordinary(BOUNDARY)
                require(BOUNDARY.stat().st_size <= service.MAX_RESPONSE, 'Boundary evidence exceeds its bound.')
                try:
                    marker = store.parse(BOUNDARY.read_bytes())
                except (ValueError, UnicodeError):
                    time.sleep(0.05); continue  # A writer may still be finishing its tmpfs marker.
                if process_stopped(marker['process_id']):
                    validate_boundary(marker, point, payload, status, previous)
                    return {'ok': True, 'stage': name, 'boot_id': marker['boot_id'], 'boundary': marker,
                            'worker_stopped_observed': True, 'worker_process_state': 'T', 'worker_state': 'T', 'manager': properties,
                            'response_received': False, 'ready_marker_filesystem': 'tmpfs'}
            time.sleep(0.05)
    raise RuntimeError('The exact transaction boundary was not observed with its worker stopped.')


def inspect_boundary(name, token):
    guard(token)
    point = 'before_commit' if name == 'inspect-before' else 'after_commit_before_ack'
    previous = read_report('BEFORE.json' if name == 'inspect-before' else 'AFTER_BEFORE.json')
    ordinary(BOUNDARY)
    require(BOUNDARY.stat().st_size <= service.MAX_RESPONSE, 'Boundary evidence exceeds its bound.')
    marker = store.parse(BOUNDARY.read_bytes())
    properties = manager(token)
    require(properties['ActiveState'] == 'active' and properties['NRestarts'] == 0
            and properties['MainPID'] == marker['process_id']
            and properties['InvocationID'] == previous['manager']['InvocationID'] and process_stopped(marker['process_id']),
            'The boundary worker is no longer stopped in the expected boot service.')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == marker['boot_id'], 'The boundary marker belongs to another boot.')
    validate_boundary(marker, point, {**marker['request'], 'test_pause': point}, previous['final_status'], previous)
    return {'ok': True, 'stage': name, 'boot_id': marker['boot_id'], 'boundary': marker,
            'worker_stopped_observed': True, 'worker_process_state': 'T', 'worker_state': 'T',
            'manager': properties, 'response_received': False, 'ready_marker_filesystem': 'tmpfs'}


def validate_boundary(marker, point, payload, status, previous):
    require(marker['synchronous'] == 3 and marker['journal_mode'] == 'delete',
            'Boundary must use DELETE journaling and EXTRA synchronization.')
    require(marker['point'] == point and marker['request_id'] == payload['request_id']
            and marker['request'] == {k: v for k, v in payload.items() if k != 'test_pause'}
            and marker['observation_sha256'] == store.digest(payload['observation']), 'Boundary request identity differs.')
    require(marker['process_id'] == status['process_id'] and marker['instance_id'] == status['instance_id']
            and marker['boot_id'] == previous['boot']['boot_id'], 'Boundary worker or boot identity differs.')
    rows = marker['database_view_rows']; old = previous['journal']['rows']
    require(marker['in_transaction'] is (point == 'before_commit') and marker['accepted_in_memory_count'] == len(old),
            'Boundary transaction or accepted in-memory state differs.')
    require(len(rows) == len(old) + 1 and store.encoded(rows[:-1]) == store.encoded(old)
            and rows[-1]['request_id'] == payload['request_id'], 'Boundary candidate prefix differs.')


def verify_start(previous, boot, status, properties, journal, storage, hashes, point):
    require(boot['boot_id'] != previous['boot']['boot_id'], 'A new Linux boot was not observed.')
    require(not VOLATILE.exists() and not VOLATILE.is_symlink() and not BOUNDARY.exists() and not BOUNDARY.is_symlink(),
            'Old volatile markers survived the VM cut.')
    require(hashes == previous['source_sha256'], 'Guest source changed across the VM cut.')
    require(all(storage[key] == previous['storage'][key] for key in ('target', 'source', 'fstype', 'uuid')), 'Persistent filesystem changed.')
    require(properties['InvocationID'] != previous['manager']['InvocationID']
            and status['instance_id'] != previous['final_status']['instance_id'], 'Worker did not automatically start a new boot instance.')
    reboot.unknown(status)
    require(reboot.critical(status)['id'] == previous['critical_incident_id'], 'Original unresolved incident identity changed.')
    require(journal.get('ok') is True and journal['identity'] == previous['journal']['identity']
            and journal['approved_policy'] == previous['journal']['approved_policy'], 'Journal identity or approved policy changed.')
    old, rows = previous['journal']['rows'], journal['rows']
    extra = 1 if point == 'before_commit' else 2
    require(len(rows) == len(old) + extra and status['committed_count'] == len(rows)
            and store.encoded(rows[:len(old)]) == store.encoded(old), 'Committed prefix was lost, changed, repeated, or reinitialized.')
    require(all(row['request_id'] != REQUEST_IDS['before_commit'] for row in rows), 'An uncommitted request was incorrectly accepted.')
    if point == 'after_commit_before_ack':
        require(rows[-2]['request_id'] == REQUEST_IDS[point], 'The completed unacknowledged transaction was lost.')
    require(rows[-1]['request']['kind'] == 'restart' and rows[-1]['evaluation']['status'] == 'unknown', 'Startup must record a new unknown-coverage boundary.')


def after_first(before, boot, hashes, storage, token):
    status, properties = ready(token)
    journal = request({'command': 'export'})
    verify_start(before, boot, status, properties, journal, storage, hashes, 'before_commit')
    return {'automatic_start': {'status': status, 'manager': properties, 'journal': journal,
                               'inspected_before_collection_at_utc': timestamp(), 'no_manual_service_start': True},
            'final_status': status, 'manager': properties, 'journal': journal,
            'critical_incident_id': before['critical_incident_id'], 'uncommitted_request_absent': True,
            'precut_prefix_preserved': True, 'volatile_markers_absent': True}


def run_after(lab, previous, boot, hashes, storage, token):
    startup, properties = ready(token)
    accepted = request({'command': 'export'})
    verify_start(previous, boot, startup, properties, accepted, storage, hashes, 'after_commit_before_ack')
    auto = {'status': startup, 'manager': properties, 'journal': accepted,
            'inspected_before_collection_at_utc': timestamp(), 'no_manual_service_start': True}
    committed = accepted['rows'][-2]
    # Reconstruct the exact accepted request, dropping its internal kind field.
    payload = {'command': 'observe', 'request_id': committed['request_id'], 'observation': committed['request']['observation']}
    retried = request(payload)
    require(retried.get('ok') is True and retried['duplicate'] is True and retried['result_is_historical'] is True
            and retried['committed_sequence'] == committed['sequence'] and retried['evaluation'] == committed['evaluation'],
            'The lost acknowledgement retry was not recognized as the original accepted transaction.')
    require(store.encoded(request({'command': 'export'})['rows']) == store.encoded(accepted['rows'])
            and retried['current_status']['committed_count'] == len(accepted['rows']), 'Retry appended a duplicate transaction.')
    reboot.unknown(retried['current_status'])
    require(reboot.critical(retried['current_status'])['id'] == previous['critical_incident_id'], 'Historical retry cleared the current incident.')
    lab.next_source_port = 45000
    lab.setup(); lab.start_services(); lab.apply_policy()
    require(monitoring.monitor.policy_fingerprint(lab.ruleset()) == previous['journal']['identity']['approved_policy_sha256'], 'Restored rules differ from approved policy.')
    lab.start_captures(); observations = []
    reference = observe(lab, observations, 'after_reference')
    require(reboot.critical(reference)['id'] == previous['critical_incident_id'], 'Rules alone cleared the old incident.')
    interval = observe(lab, observations, 'after_interval')
    require(interval['current_evaluation']['telemetry_valid'] and interval['current_evaluation']['policy_matches']
            and reboot.critical(interval)['id'] == previous['critical_incident_id'], 'Fresh rule baseline was not valid.')
    final = observe(lab, observations, 'after_canaries', monitoring.CANARIES)
    require(final['current_evaluation']['status'] == 'healthy'
            and all(a['severity'] == 'info' for a in final['alerts'] if a['state'] == 'open'),
            'Fresh checks did not establish recovery: ' + reboot.evaluation_diagnostic(final))
    journal = request({'command': 'export'})
    require(len(journal['rows']) == 11 and store.encoded(journal['rows'][:6]) == store.encoded(previous['journal']['rows']), 'Final history lost its original prefix.')
    resolutions = [e for e in journal['events'] if e['key'] == CRITICAL and e['action'] == 'resolved']
    require(len(resolutions) == 1 and resolutions[0]['phase'] == 'after_canaries' and resolutions[0]['sequence'] == 11, 'Incident resolved before fresh recovery.')
    reboot.inventory(lab, observations, 'after')
    captured = lab.stop_captures()
    require(captured['routed_flows_verified'] == 3, 'Post-cut packet coverage is incomplete.')
    return {'automatic_start': auto, 'lost_ack_retry': {'request': payload, 'response': retried, 'history_unchanged': True},
            'final_status': final, 'manager': manager(token), 'journal': journal, 'observations': observations,
            'critical_incident_id': previous['critical_incident_id'], 'capture': captured,
            'precut_prefix_preserved': True, 'volatile_markers_absent': True}


def read_report(name):
    path = PUBLISH / name; ordinary(path)
    require(path.stat().st_size <= service.MAX_RESPONSE, 'Saved report exceeds its bound.')
    return store.parse(path.read_bytes())


def capture_fingerprint(path, *, synchronize=False):
    """Read one completed, bounded capture through its checked file descriptor."""
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_uid == os.geteuid()
            and before.st_nlink == 1 and 0 < before.st_size <= 8 * 1024 * 1024,
            'Completed capture must be a bounded, owned, singly linked regular file.')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'Capture identity changed while opening.')
        # Completed captures are prepared before arming a transaction cut. This
        # sync is never called from the paused transaction boundary callback.
        if synchronize:
            os.fsync(descriptor)
        digest, size = hashlib.sha256(), 0
        while True:
            block = os.read(descriptor, 65536)
            if not block:
                break
            size += len(block)
            require(size <= 8 * 1024 * 1024, 'Completed capture exceeds its byte bound.')
            digest.update(block)
        after = os.fstat(descriptor)
        require(size == before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns
                and after.st_nlink == 1, 'Completed capture changed while reading.')
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def seal_captures(staging, stage_name):
    """Persist completed evidence and bind its exact bytes before a VM cut."""
    require(stage_name in {'before', 'after'}, 'Unknown capture stage.')
    store.state_path(staging); store.state_path(PUBLISH)
    checksums = {}
    for filename in CAPTURE_FILES:
        source = staging / filename
        public_name = stage_name + '-' + filename
        destination = PUBLISH / public_name
        require(not destination.exists() and not destination.is_symlink(), 'Completed capture must not replace existing evidence.')
        checksums[public_name] = capture_fingerprint(source, synchronize=True)
        source.rename(destination)
    store.sync_directory(staging)
    store.sync_directory(PUBLISH)
    verify_captures({'capture_sha256': checksums}, stage_name)
    return checksums


def verify_captures(report, stage_name):
    require(stage_name in {'before', 'after'}, 'Unknown capture stage.')
    store.state_path(PUBLISH)
    checksums = report.get('capture_sha256')
    expected = {stage_name + '-' + filename for filename in CAPTURE_FILES}
    require(isinstance(checksums, dict) and set(checksums) == expected
            and all(isinstance(value, str) and reboot.re.fullmatch(r'[0-9a-f]{64}', value) for value in checksums.values()),
            'Saved capture fingerprints do not cover the exact six public files.')
    for name, expected_digest in checksums.items():
        require(capture_fingerprint(PUBLISH / name) == expected_digest, 'Completed capture bytes changed across the VM cut: ' + name)
    return copy.deepcopy(checksums)


def stage(name, token):
    virtualization = guard(token)
    boot, hashes = reboot.boot_info(virtualization), source_hashes()
    require(name in {'before', 'after-before', 'after-after'}, 'Unknown power-cut guest stage.')
    if name == 'before':
        require(not DATA.exists() and not UNIT_FILE.exists() and not RUNTIME.exists(), 'Disposable state exists; never reset it.')
        DATA.mkdir(mode=0o700); REPORT.mkdir(mode=0o700); PUBLISH.mkdir(mode=0o700)
        for directory in (REPORT, DATA, DATA.parent):
            store.sync_directory(directory)
    else:
        for path in (DATA, STATE, REPORT, PUBLISH, RUNTIME):
            store.state_path(path)
        preserved_captures = verify_captures(read_report('BEFORE.json'), 'before')
    output = {'before': 'BEFORE.json', 'after-before': 'AFTER_BEFORE.json', 'after-after': 'AFTER.json'}[name]
    require(not (PUBLISH / output).exists(), 'Completed stage must not be repeated.')
    if name == 'after-before':
        outcome = after_first(read_report('BEFORE.json'), boot, hashes, storage_info(), token)
        cleanup = {'ok': True, 'no_network_created': True}
    else:
        tools = base.preflight(); stage_name = 'before' if name == 'before' else 'after'
        staging = REPORT / stage_name; staging.mkdir(mode=0o700)
        lab = monitoring.MonitoringLab(tools, staging)
        try:
            outcome = run_before(lab, token) if name == 'before' else run_after(lab, read_report('AFTER_BEFORE.json'), boot, hashes, storage_info(), token)
        finally:
            cleanup = lab.cleanup(); require(cleanup['ok'], 'Guest network cleanup failed.')
        outcome['capture_sha256'] = seal_captures(staging, stage_name)
    result = {'format': 'heltemes-monitor-powercut-guest', 'version': 1, 'ok': True, 'stage': name,
              'boot': boot, 'source_sha256': hashes, 'storage': storage_info(),
              'unit_sha256': hashlib.sha256(unit_text(token).encode()).hexdigest(),
              'network_cleanup': cleanup, 'completed_at_utc': timestamp(), **outcome}
    if name != 'before':
        result['before_capture_bytes_verified'] = True
        result['preserved_before_capture_sha256'] = preserved_captures
    require(source_hashes() == hashes, 'Guest source changed during collection.')
    write_new(PUBLISH / output, result)
    if name == 'before':
        write_new(PUBLISH / 'APPROVED_POLICY.json', outcome['approved_policy']); write_new(PUBLISH / 'monitor.service', unit_text(token))
    if name == 'after-after':
        require({p.name for p in PUBLISH.iterdir()} == set(PUBLIC_FILES), 'Guest public inventory differs.')
    return {'ok': True, 'stage': name, 'boot_id': boot['boot_id'], 'committed_count': len(outcome['journal']['rows']),
            'current_status': outcome['final_status']['current_evaluation']['status'],
            'critical_incident_id': outcome['critical_incident_id'], 'network_cleanup': cleanup}


def cleanup(token):
    guard(token)
    if UNIT_FILE.exists():
        ordinary(UNIT_FILE, mode=0o644); require(UNIT_FILE.read_text() == unit_text(token), 'Unexpected unit cannot be removed.')
        command(['systemctl', 'disable', '--now', UNIT])
        status = command(['systemctl', 'is-active', UNIT], check=False).stdout.strip()
        require(status not in {'active', 'activating', 'deactivating'}, 'The guest worker has not stopped.')
        UNIT_FILE.unlink(); command(['systemctl', 'daemon-reload'])
    require(not UNIT_FILE.exists() and not RUNTIME.exists(), 'Guest unit or runtime remains.')
    if STATE.exists():
        store.state_path(DATA); store.state_path(STATE); reboot.shutil.rmtree(STATE)
    require(not STATE.exists(), 'Disposable state cleanup failed.')
    return {'ok': True, 'service_disabled_removed': True, 'state_removed': True, 'volatile_runtime_removed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('before', 'arm-before', 'inspect-before', 'after-before', 'arm-after', 'inspect-after', 'after-after', 'cleanup', 'worker'))
    parser.add_argument('--token')
    args = parser.parse_args()
    try:
        if args.stage == 'worker':
            require(args.token is None, 'Worker token is read only from its root-owned seed marker.')
            require(sys.platform == 'linux' and os.geteuid() == 0, 'Disposable Linux guest required.')
            require(ROOT == INSTALL, 'Worker source must use the dedicated disposable installation.')
            ordinary(reboot.MARKER)
            require(reboot.MARKER.stat().st_size <= 4096, 'Guest seed marker exceeds its bound.')
            marker = store.parse(reboot.MARKER.read_bytes()); token = marker['token']
            guard(token); store.state_path(STATE); store.state_path(RUNTIME)
            service.serve(STATE, test_pause=pause_worker)
            return
        require(args.token is not None, 'A disposable token is required.')
        if args.stage == 'cleanup':
            result = cleanup(args.token)
        elif args.stage in POINTS:
            result = arm(args.stage, args.token)
        elif args.stage in {'inspect-before', 'inspect-after'}:
            result = inspect_boundary(args.stage, args.token)
        else:
            result = stage(args.stage, args.token)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Disposable power-cut guest stopped: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
