"""Guarded archive handoff power-cut exercise in an explicitly disposable VM.

The host kills QEMU; these callbacks only stop the worker at three observed
archive boundaries. Test controls never run in an ordinary monitor entrypoint.
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
import sqlite3
import stat
import subprocess
import sys
import time
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor_archive as archive
from scripts import network_monitor_powercut_guest as powercut
from scripts import network_monitor_reboot_guest as reboot
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store

require, command, write_new = reboot.require, reboot.command, reboot.write_new
DATA = Path('/var/lib/heltemes-archive-powercut-lab')
STATE, REPORT = DATA / 'state', DATA / 'report'
PUBLISH = REPORT / 'publish'
RUNTIME = Path('/run/heltemes-archive-powercut-lab')
ARM, BOUNDARY, VOLATILE = (RUNTIME / n for n in ('arm.json', 'boundary.json', 'precut-marker'))
BOUNDARY_WRITING = RUNTIME / 'boundary.json.writing'
PROGRESS = RUNTIME / 'boundary-progress.json'
PROGRESS_WRITING = RUNTIME / 'boundary-progress.json.writing'
PROGRESS_PHASES = ('hook_entered', 'snapshot_captured', 'marker_encoded', 'marker_published')
UNIT = 'heltemes-archive-powercut-monitor.service'
UNIT_FILE = Path('/etc/systemd/system') / UNIT
SOURCE_FILES = (*reboot.SOURCE_FILES, 'scripts/network_monitor_archive.py',
                'scripts/network_monitor_powercut_guest.py', 'scripts/network_monitor_archive_powercut_guest.py')
CAPTURE_FILES = reboot.CAPTURE_FILES
STAGES = ('before', 'after-staging', 'after-file', 'after')
STEMS = ('BEFORE', 'AFTER-STAGING', 'AFTER-FILE', 'AFTER')
POINTS = {'staging': 'archive_staging_durable', 'file': 'archive_file_durable', 'metadata': 'archive_metadata_committed'}
HEADS = {'staging': 128, 'file': 256, 'metadata': 384}
REQUEST_IDS = {key: 'archive-powercut-' + key for key in POINTS}
SEGMENT_ROWS, MAX_ROWS, MAX_PUBLIC = 128, 2048, 32 * 1024 * 1024
SEGMENT_FILES = tuple(f'archive-segment-{i:06d}.json' for i in range(1, 5))
PUBLIC_FILES = (*[stem + suffix for stem in STEMS for suffix in ('.json', '-HISTORY.json')],
                'APPROVED_POLICY.json', 'monitor.service', *SEGMENT_FILES,
                *(stage + '-' + name for stage in ('before', 'after') for name in CAPTURE_FILES))
DESCRIPTOR_KEYS = ('segment_index', 'first_sequence', 'last_sequence', 'row_count', 'byte_count', 'file_digest', 'last_digest')


def guard(token):
    virtualization = reboot.guard(token)
    for path in (DATA, STATE, REPORT, PUBLISH, RUNTIME, ARM, BOUNDARY, VOLATILE, BOUNDARY_WRITING,
                 PROGRESS, PROGRESS_WRITING, UNIT_FILE):
        require(not any(p.is_symlink() for p in (path, *path.parents)), 'Archive power-cut paths cannot traverse links.')
    return virtualization


def source_hashes():
    result = {}
    for name in SOURCE_FILES:
        path = ROOT / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size < 1024 * 1024, 'Unsafe guest source.')
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def unit_text():
    return f'''[Unit]
Description=HELTEMES disposable archive power-cut monitor
After=local-fs.target
RequiresMountsFor={STATE}
StartLimitIntervalSec=30
StartLimitBurst=3

[Service]
Type=exec
ExecStart=/usr/bin/python3 -I -S -B {reboot.INSTALL}/scripts/network_monitor_archive_powercut_guest.py worker
Restart=on-failure
RestartSec=1
TimeoutStopSec=25
UMask=0077
RuntimeDirectory=heltemes-archive-powercut-lab
RuntimeDirectoryMode=0700
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths={STATE} {RUNTIME}
RestrictAddressFamilies=AF_UNIX

[Install]
WantedBy=multi-user.target
'''


def manager():
    reboot.ordinary(UNIT_FILE, mode=0o644)
    require(UNIT_FILE.read_text() == unit_text(), 'Installed archive unit differs.')
    response = command(['systemctl', 'show', '--no-pager', '--property=' + ','.join(reboot.MANAGER_FIELDS), UNIT])
    values = dict(line.split('=', 1) for line in response.stdout.splitlines() if '=' in line)
    require(set(values) == set(reboot.MANAGER_FIELDS) and values['LoadState'] == 'loaded'
            and values['FragmentPath'] == str(UNIT_FILE) and values['UnitFileState'] == 'enabled', 'Boot service is not enabled.')
    for key in ('MainPID', 'NRestarts', 'ExecMainStartTimestampMonotonic'):
        require(values[key].isdecimal(), 'Invalid service numeric evidence.'); values[key] = int(values[key])
    require(reboot.re.fullmatch(r'[0-9a-f]{32}', values['InvocationID']) is not None
            or (values['InvocationID'] == '' and values['ActiveState'] in ('inactive', 'activating') and values['MainPID'] == 0),
            'Invalid service invocation identity.')
    return values


def request(payload):
    return service.request(STATE, payload, timeout=20)


def ready(timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        properties = manager()
        if properties['ActiveState'] == 'active' and properties['MainPID'] > 0:
            try:
                status = request({'command': 'status'})
                if status.get('ok') is True and status['process_id'] == properties['MainPID']:
                    require(properties['NRestarts'] == 0, 'Unexpected monitor restart within one boot.')
                    return status, reboot.process_boot_timing(properties, float(Path('/proc/uptime').read_text().split()[0]))
            except (OSError, ValueError):
                pass
        time.sleep(0.1)
    raise RuntimeError('The enabled archive monitor did not become ready.')


def file_proof(path):
    info = reboot.ordinary(path)
    require(info.st_size <= MAX_PUBLIC, 'Public file exceeds its bound.')
    return {'name': path.name, 'bytes': info.st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'nlink': info.st_nlink}


def read_public(name):
    require(name in PUBLIC_FILES, 'Unexpected public file.')
    path = PUBLISH / name; file_proof(path)
    return store.parse(path.read_bytes())


def committed_snapshot_from_connection(connection):
    """Capture exact committed bytes; the host replays boundary snapshots before cutting power.

This reads and checks protected files, canonical encoding, SQL descriptors, and
the complete row chain. It deliberately does not repeat the monitor's semantic
evaluation inside the short pause callback. Ordinary snapshots use the full
replay wrapper below, and cold starts retain ArchiveJournal's normal validation.
"""
    config = connection.execute('SELECT identity,approved,head_sequence,head_digest,archived_sequence,archived_digest FROM config WHERE id=1').fetchone()
    require(config is not None, 'Missing archive configuration.')
    identity, approved = store.parse(config[0]), store.parse(config[1])
    descriptors = connection.execute('SELECT * FROM segments ORDER BY segment_index').fetchall()
    rows = []
    for index, descriptor in enumerate(descriptors, 1):
        raw = store.read_private(STATE / 'archives' / f'segment-{descriptor[0]:06d}.json')
        require(len(raw) == descriptor[4] and hashlib.sha256(raw).hexdigest() == descriptor[5], 'Committed archive bytes differ.')
        segment = store.parse(raw)
        require(raw == (store.encoded(segment) + '\n').encode() and segment['database_id'] == identity['database_id'],
                'Archive encoding or identity differs.')
        segment_rows = segment['rows']
        require(descriptor == (index, len(rows) + 1, len(rows) + len(segment_rows), len(segment_rows), len(raw),
                hashlib.sha256(raw).hexdigest(), segment_rows[-1]['row_digest']) and len(segment_rows) == SEGMENT_ROWS
                and segment['segment_index'] == index and segment['first_sequence'] == descriptor[1]
                and segment['last_sequence'] == descriptor[2] and segment['last_digest'] == descriptor[6]
                and segment['previous_digest'] == (rows[-1]['row_digest'] if rows else store.ZERO),
                'Committed archive descriptor or prefix differs.')
        rows.extend(segment['rows'])
    require(config[4] == len(rows) and config[5] == (rows[-1]['row_digest'] if rows else store.ZERO),
            'Committed archive SQL head differs.')
    rows.extend(powercut.sql_rows(connection))
    require(len(rows) == config[2] <= MAX_ROWS and rows[-1]['row_digest'] == config[3], 'Snapshot head differs.')
    previous, seen = store.ZERO, set()
    for sequence, row in enumerate(rows, 1):
        require(row['sequence'] == row['sample']['sequence'] == sequence and row['previous_digest'] == previous
                and row['request_id'] not in seen and store.digest({k: v for k, v in row.items() if k != 'row_digest'}) == row['row_digest'],
                'Snapshot sequence or digest chain differs.')
        previous = row['row_digest']; seen.add(row['request_id'])
    return {'identity': identity, 'approved_policy': approved, 'rows': rows,
            'archive_descriptors': [dict(zip(DESCRIPTOR_KEYS, item)) for item in descriptors]}


def history_from_connection(connection):
    """Fully replay an already committed snapshot without writing or flushing disk."""
    captured = committed_snapshot_from_connection(connection)
    identity, approved, rows = captured['identity'], captured['approved_policy'], captured['rows']
    engine = archive.StreamingMonitor(approved)
    for row in rows:
        require(engine.observe(row['sample']) == row['evaluation'] and engine.events == row['events'], 'Snapshot deterministic replay differs.')
    descriptors = [tuple(item[key] for key in DESCRIPTOR_KEYS) for item in captured['archive_descriptors']]
    # The exporter only consumes these immutable snapshot values; no journal is opened for writing.
    view = SimpleNamespace(identity=identity, approved=approved, segments=descriptors, iter_rows=lambda: iter(rows))
    return archive.ArchiveJournal.export(view)


def readonly_history():
    reboot.ordinary(STATE / 'monitor.sqlite3')
    connection = sqlite3.connect((STATE / 'monitor.sqlite3').as_uri() + '?mode=ro', uri=True, isolation_level=None, timeout=10)
    try:
        connection.execute('PRAGMA trusted_schema=OFF'); connection.execute('PRAGMA query_only=ON'); connection.execute('BEGIN')
        return history_from_connection(connection)
    finally:
        connection.close()


def snapshot():
    before = request({'command': 'status'}); history = readonly_history(); after = request({'command': 'status'})
    require(before['committed_count'] == after['committed_count'] == len(history['rows'])
            and before['head_digest'] == after['head_digest'] == history['rows'][-1]['row_digest'], 'Snapshot moved unexpectedly.')
    return after, history


def storage_info():
    data = json.loads(command(['findmnt', '--json', '--target', str(STATE), '--output', 'TARGET,SOURCE,FSTYPE,OPTIONS,UUID']).stdout)
    require(set(data) == {'filesystems'} and len(data['filesystems']) == 1, 'State mount is ambiguous.')
    record = data['filesystems'][0]
    require(set(record) == {'target', 'source', 'fstype', 'options', 'uuid'} and record['fstype'] in {'ext4', 'xfs', 'btrfs'}
            and record['source'].startswith('/dev/') and record['uuid'] and 'rw' in record['options'].split(','), 'Persistent disk required.')
    return record


def publish_segments(number):
    values = []
    require(len(list((STATE / 'archives').glob('segment-*.json'))) == number, 'Archive inventory differs.')
    for index, name in enumerate(SEGMENT_FILES[:number], 1):
        path = STATE / 'archives' / f'segment-{index:06d}.json'; proof = file_proof(path); raw = path.read_bytes()
        target = PUBLISH / name
        if target.exists():
            require(target.read_bytes() == raw, 'Previously published archive changed.')
        else:
            store.write_new(target, raw)
        values.append({'public_name': name, **proof})
    store.sync_directory(PUBLISH)
    return values


def seal_captures(staging, stage):
    values = {}
    for name in CAPTURE_FILES:
        path = staging / name; target = PUBLISH / (stage + '-' + name)
        require(not target.exists() and not target.is_symlink(), 'Capture already exists.')
        values[target.name] = powercut.capture_fingerprint(path, synchronize=True)
        path.rename(target)
    store.sync_directory(staging); store.sync_directory(PUBLISH)
    return values


def verify_captures(report):
    expected = {'before-' + name for name in CAPTURE_FILES}
    require(set(report['capture_sha256']) == expected, 'Pre-cut capture reference inventory differs.')
    for name, digest in report['capture_sha256'].items():
        require(powercut.capture_fingerprint(PUBLISH / name) == digest, 'Pre-cut capture changed.')


def observe(lab, observations, phase, probes=()):
    lab.phase = phase; actual = []
    for source, target, port in probes:
        value = lab.probe(source, target, port)
        value['destination_health'] = lab.probe(target, target, port) if value['outcome'] == 'connect_timeout' else None
        actual.append(value)
    payload = {'command': 'observe', 'request_id': phase, 'observation': {'phase': phase, 'observed_at_utc': reboot.timestamp(),
               'ruleset': lab.ruleset(), 'collection_error': None, 'probes': actual}}
    result = request(payload)
    require(result.get('ok') is True and result['duplicate'] is False, 'Fresh observation was not accepted once.')
    observations.append({'request': payload, 'committed_sequence': result['committed_sequence'], 'evaluation': result['evaluation']})
    return result['current_status']


def fill(lab, observations, target, prefix):
    status = request({'command': 'status'})
    require(status['committed_count'] < target <= 519, 'Unexpected fill target.')
    for sequence in range(status['committed_count'] + 1, target + 1):
        status = observe(lab, observations, f'{prefix}_{sequence:04d}')
        require(status['committed_count'] == sequence, 'Fill sequence differs.')
    return status


def install(approved):
    require(not STATE.exists() and not UNIT_FILE.exists(), 'Existing state must never be reset.')
    archive.initialize(STATE, approved, segment_rows=SEGMENT_ROWS, max_rows=MAX_ROWS)
    write_new(UNIT_FILE, unit_text()); UNIT_FILE.chmod(0o644)
    command(['systemctl', 'daemon-reload']); command(['systemctl', 'enable', '--now', UNIT])
    status, properties = ready(); reboot.unknown(status)
    require(status['committed_count'] == 1, 'Initial startup head differs.')
    return status, properties


def boundary_payload(key):
    require(key in POINTS, 'Unknown archive boundary.')
    return {'command': 'observe', 'request_id': REQUEST_IDS[key], 'observation': {'phase': REQUEST_IDS[key],
            'observed_at_utc': reboot.timestamp(), 'ruleset': None, 'collection_error': 'archive_powercut_test_boundary', 'probes': []}}


def progress_record(key, phase, started, *, marker_bytes=0):
    """Publish only bounded control-plane progress on the already verified tmpfs."""
    require(key in POINTS and phase in PROGRESS_PHASES and type(marker_bytes) is int
            and 0 <= marker_bytes <= store.MAX_BYTES, 'Invalid boundary progress.')
    value = {'point': POINTS[key], 'phase': phase, 'process_id': os.getpid(), 'expected_head': HEADS[key],
             'elapsed_ms': max(0, int((time.monotonic() - started) * 1000)), 'marker_bytes': marker_bytes}
    require(not PROGRESS_WRITING.exists() and not PROGRESS_WRITING.is_symlink(), 'Stale progress staging file.')
    if PROGRESS.exists() or PROGRESS.is_symlink():
        store.ordinary(PROGRESS, limit=1024)
    store.write_new(PROGRESS_WRITING, (store.encoded(value) + '\n').encode())
    os.replace(PROGRESS_WRITING, PROGRESS)


def publish_boundary(raw):
    require(isinstance(raw, bytes) and len(raw) <= store.MAX_BYTES, 'Boundary marker exceeds its bound.')
    require(not any(p.exists() or p.is_symlink() for p in (BOUNDARY, BOUNDARY_WRITING)), 'Stale boundary publication exists.')
    store.write_new(BOUNDARY_WRITING, raw)
    # Atomic tmpfs publication prevents the reader repeatedly parsing a partially
    # written multi-megabyte marker while the single writer is still finishing it.
    os.rename(BOUNDARY_WRITING, BOUNDARY)


def boundary_diagnostic(pid):
    """Retain bounded state on failure without logs, observations, or private paths."""
    result = {'expected_process_id': pid if type(pid) is int and pid > 0 else None,
              'process_state': 'unavailable', 'files': {}}
    for label, path in (('progress', PROGRESS), ('marker', BOUNDARY), ('marker_writing', BOUNDARY_WRITING)):
        try:
            info = path.lstat()
            result['files'][label] = {'exists': True, 'bytes': info.st_size, 'regular': stat.S_ISREG(info.st_mode),
                                      'mode': stat.S_IMODE(info.st_mode), 'links': info.st_nlink}
            if label == 'progress':
                value = store.parse(store.read_private(path, limit=1024))
                require(set(value) == {'point', 'phase', 'process_id', 'expected_head', 'elapsed_ms', 'marker_bytes'}
                        and value['point'] in POINTS.values() and value['phase'] in PROGRESS_PHASES
                        and all(type(value[k]) is int and 0 <= value[k] <= 2 ** 63 - 1
                                for k in ('process_id', 'expected_head', 'elapsed_ms', 'marker_bytes')),
                        'Invalid bounded progress diagnostic.')
                result['progress'] = value
        except FileNotFoundError:
            result['files'][label] = {'exists': False}
        except (OSError, ValueError, RuntimeError, TypeError, KeyError) as error:
            result['files'][label] = {'inspection_error': type(error).__name__}
    try:
        if type(pid) is int and pid > 0:
            raw = (Path('/proc') / str(pid) / 'status').read_text()
            require(len(raw) <= 65536, 'Process status exceeds diagnostic bound.')
            state = next(line.split()[1] for line in raw.splitlines() if line.startswith('State:'))
            require(state in {'R', 'S', 'D', 'T', 't', 'Z', 'X', 'I'}, 'Unknown process state.')
            result['process_state'] = state
    except (OSError, ValueError, RuntimeError, StopIteration):
        pass
    try:
        fields = ('ActiveState', 'SubState', 'MainPID', 'NRestarts', 'Result', 'ExecMainCode', 'ExecMainStatus')
        response = command(['systemctl', 'show', '--no-pager', '--property=' + ','.join(fields), UNIT], timeout=3, check=False)
        values = dict(line.split('=', 1) for line in response.stdout.splitlines() if '=' in line)
        managed = {}
        for key in ('MainPID', 'NRestarts', 'ExecMainCode', 'ExecMainStatus'):
            value = values.get(key, '')
            if len(value) <= 16 and value.lstrip('-').isdecimal():
                managed[key] = int(value)
        allowed = {'ActiveState': {'active', 'inactive', 'failed', 'activating', 'deactivating', 'reloading'},
                   'SubState': {'running', 'dead', 'failed', 'start', 'start-pre', 'start-post', 'auto-restart', 'stop-sigterm', 'stop-sigkill'},
                   'Result': {'success', 'exit-code', 'signal', 'core-dump', 'timeout', 'watchdog', 'start-limit-hit', 'resources', 'oom-kill'}}
        for key, choices in allowed.items():
            managed[key] = values[key] if values.get(key) in choices else 'unavailable'
        result['manager'] = managed
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        result['manager'] = {'inspection_error': 'unavailable'}
    return result


class ExerciseJournal(archive.ArchiveJournal):
    def append(self, request_id, observation, elapsed_seconds, *, restart=False, fault=None):
        def boundary(point):
            if fault:
                fault(point)
            if restart or point not in POINTS.values() or not ARM.exists():
                return
            armed = store.parse(store.read_private(ARM, limit=4096))
            require(set(armed) == {'key', 'request', 'instance_id'} and armed['key'] in POINTS, 'Invalid archive arm.')
            key = armed['key']
            if point != POINTS[key]:
                return
            require(request_id == REQUEST_IDS[key] and armed['request']['request_id'] == request_id
                    and armed['request']['observation'] == observation, 'Archive arm request differs.')
            require(command(['findmnt', '-n', '-o', 'FSTYPE', '--target', str(RUNTIME)]).stdout.strip() == 'tmpfs', 'Boundary storage must be tmpfs.')
            require(not any(p.exists() or p.is_symlink() for p in (BOUNDARY, BOUNDARY_WRITING, PROGRESS, PROGRESS_WRITING))
                    and not self.connection.in_transaction, 'Invalid boundary state.')
            started = time.monotonic(); progress_record(key, 'hook_entered', started)
            history = committed_snapshot_from_connection(self.connection)
            progress_record(key, 'snapshot_captured', started)
            require(len(history['rows']) == HEADS[key], 'Archive hook head differs.')
            final = STATE / 'archives' / f'segment-{HEADS[key] // SEGMENT_ROWS:06d}.json'
            pending = final.with_name(final.name + '.pending')
            marker = {'format': 'heltemes-archive-powercut-boundary', 'version': 1, 'point': point,
                'request_id': request_id, 'request': armed['request'], 'instance_id': armed['instance_id'],
                'observation_sha256': store.digest(observation), 'process_id': os.getpid(),
                'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'in_transaction': False,
                'head_sequence': len(history['rows']), 'head_digest': history['rows'][-1]['row_digest'],
                'rows': history['rows'], 'identity': history['identity'], 'approved_policy': history['approved_policy'],
                'archive_descriptors': history['archive_descriptors'],
                'active_sql_rows': self.connection.execute('SELECT count(*) FROM observations').fetchone()[0],
                'archive_files': [file_proof(p) for p in sorted((STATE / 'archives').glob('segment-*.json'))],
                'pending_file': file_proof(pending) if pending.exists() else None,
                'final_file': file_proof(final) if final.exists() else None,
                'synchronous': self.connection.execute('PRAGMA synchronous').fetchone()[0],
                'journal_mode': self.connection.execute('PRAGMA journal_mode').fetchone()[0], 'observed_at_utc': reboot.timestamp()}
            # Only tmpfs is written here: no persistent-disk flush is added after arming.
            raw = (store.encoded(marker) + '\n').encode()
            progress_record(key, 'marker_encoded', started, marker_bytes=len(raw))
            publish_boundary(raw)
            progress_record(key, 'marker_published', started, marker_bytes=len(raw))
            os.kill(os.getpid(), signal.SIGSTOP)
            os._exit(74)
        return super().append(request_id, observation, elapsed_seconds, restart=restart, fault=boundary)


def validate_boundary(marker, key, previous, history):
    require(key in POINTS and marker['point'] == POINTS[key] and marker['request_id'] == REQUEST_IDS[key], 'Boundary identity differs.')
    require(marker['head_sequence'] == HEADS[key] and len(marker['rows']) == HEADS[key]
            and marker['rows'][:-1] == history['rows'] and marker['identity'] == history['identity']
            and marker['approved_policy'] == history['approved_policy'], 'Boundary committed prefix differs.')
    row = marker['rows'][-1]
    require(row['request_id'] == marker['request_id'] and row['request']['observation'] == marker['request']['observation']
            and marker['request']['command'] == 'observe' and marker['request']['request_id'] == marker['request_id']
            and marker['head_digest'] == row['row_digest'] and marker['observation_sha256'] == store.digest(row['request']['observation']),
            'Boundary request or head binding differs.')
    require(marker['process_id'] == previous['final_status']['process_id'] and marker['instance_id'] == previous['final_status']['instance_id']
            and marker['boot_id'] == previous['boot']['boot_id'] and marker['in_transaction'] is False
            and marker['synchronous'] == 3 and marker['journal_mode'] == 'delete', 'Boundary process or commit mode differs.')
    index = HEADS[key] // SEGMENT_ROWS
    require(len(marker['archive_descriptors']) == (index if key == 'metadata' else index - 1)
            and marker['active_sql_rows'] == (0 if key == 'metadata' else SEGMENT_ROWS), 'Archive handoff SQL state differs.')
    require((marker['pending_file'] is not None) is (key == 'staging')
            and (marker['final_file'] is not None) is (key != 'staging'), 'Archive handoff file state differs.')


def arm(name, token):
    guard(token); key = name.removeprefix('arm-'); require(key in POINTS, 'Unknown arm stage.')
    stem = STEMS[tuple(POINTS).index(key)]; previous = read_public(stem + '.json'); history = read_public(stem + '-HISTORY.json')
    status, properties = ready()
    require(status['committed_count'] == HEADS[key] - 1 and status['head_digest'] == previous['final_status']['head_digest']
            and status['instance_id'] == previous['final_status']['instance_id'], 'Archive head changed before arming.')
    require(not any(p.exists() or p.is_symlink() for p in (ARM, BOUNDARY, VOLATILE, BOUNDARY_WRITING,
                                                        PROGRESS, PROGRESS_WRITING)), 'Stale volatile boundary exists.')
    require(command(['findmnt', '-n', '-o', 'FSTYPE', '--target', str(RUNTIME)]).stdout.strip() == 'tmpfs', 'Arm storage must be tmpfs.')
    payload = boundary_payload(key)
    store.write_new(ARM, (store.encoded({'key': key, 'request': payload, 'instance_id': status['instance_id']}) + '\n').encode())
    store.write_new(VOLATILE, b'Current disposable pre-cut boot\n')
    path = service.socket_path(STATE); info = path.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600, 'Unsafe monitor socket.')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(3); connection.connect(str(path)); connection.sendall((store.encoded(payload) + '\n').encode())
        return wait_for_boundary(name, key, previous, history, properties)


def wait_for_boundary(name, key, previous, history, properties):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if BOUNDARY.exists():
            marker = store.parse(store.read_private(BOUNDARY))
            if powercut.process_stopped(marker['process_id']):
                validate_boundary(marker, key, previous, history)
                return boundary_response(name, marker, properties)
        time.sleep(0.05)
    raise RuntimeError('Exact stopped archive boundary was not observed: ' + store.encoded(boundary_diagnostic(properties['MainPID'])))


def boundary_response(name, marker, properties):
    return {'ok': True, 'stage': name, 'boot_id': marker['boot_id'], 'boundary': marker,
            'worker_stopped_observed': True, 'worker_process_state': 'T', 'worker_state': 'T', 'manager': properties,
            'response_received': False, 'ready_marker_filesystem': 'tmpfs'}


def inspect_boundary(name, token):
    guard(token); key = name.removeprefix('inspect-'); require(key in POINTS, 'Unknown inspect stage.')
    stem = STEMS[tuple(POINTS).index(key)]; previous = read_public(stem + '.json')
    marker = store.parse(store.read_private(BOUNDARY)); properties = manager()
    require(properties['ActiveState'] == 'active' and properties['NRestarts'] == 0
            and properties['MainPID'] == marker['process_id'] and properties['InvocationID'] == previous['manager']['InvocationID']
            and powercut.process_stopped(marker['process_id'])
            and Path('/proc/sys/kernel/random/boot_id').read_text().strip() == marker['boot_id'], 'Stopped worker identity changed.')
    validate_boundary(marker, key, previous, read_public(stem + '-HISTORY.json'))
    return boundary_response(name, marker, properties)


def verify_start(previous, old, boot, status, properties, history, storage, hashes, key):
    require(boot['boot_id'] != previous['boot']['boot_id'] and hashes == previous['source_sha256'], 'Boot or source identity differs.')
    require(not any(p.exists() or p.is_symlink() for p in (ARM, BOUNDARY, VOLATILE, BOUNDARY_WRITING,
                                                        PROGRESS, PROGRESS_WRITING)), 'Old volatile boundary survived.')
    require(all(storage[k] == previous['storage'][k] for k in ('target', 'source', 'fstype', 'uuid')), 'Persistent filesystem changed.')
    require(properties['InvocationID'] != previous['manager']['InvocationID']
            and status['instance_id'] != previous['final_status']['instance_id'], 'Monitor did not start a new boot instance.')
    reboot.unknown(status)
    require(reboot.critical(status)['id'] == previous['critical_incident_id'], 'Original incident changed.')
    rows = history['rows']
    require(history['identity'] == old['identity'] and history['approved_policy'] == old['approved_policy']
            and rows[:len(old['rows'])] == old['rows'] and len(rows) == HEADS[key] + 1
            and status['committed_count'] == len(rows), 'Recovered history prefix differs.')
    require(rows[-2]['request_id'] == REQUEST_IDS[key] and rows[-1]['request']['kind'] == 'restart'
            and rows[-1]['evaluation']['status'] == 'unknown', 'Recovery did not retain committed boundary then append startup.')
    actions = status['archives']['recovery_actions']; index = HEADS[key] // SEGMENT_ROWS
    if key == 'staging':
        require(actions == [] or (len(actions) == 1 and actions[0] == {'action': 'rebuilt_verified_staging_prefix',
                'segment_index': index, 'staged_bytes': (STATE / 'archives' / f'segment-{index:06d}.json').stat().st_size}),
                'Unexpected staging recovery action.')
    elif key == 'file':
        require(actions == [{'action': 'accepted_exact_uncommitted_segment', 'segment_index': index}], 'Uncommitted segment not recovered exactly.')
    else:
        require(actions == [], 'Committed archive metadata was unexpectedly repeated.')
    require(status['archives']['sealed_segments'] == index and status['archives']['active_rows'] == 1
            and status['archives']['persistence_error'] is None, 'Recovered archive partition differs.')


def retry_boundary(history):
    row = history['rows'][-2]
    payload = {'command': 'observe', 'request_id': row['request_id'], 'observation': row['request']['observation']}
    before = request({'command': 'status'}); result = request(payload); after = request({'command': 'status'})
    require(result.get('ok') is True and result['duplicate'] is True and result['result_is_historical'] is True
            and result['committed_sequence'] == row['sequence'] and result['evaluation'] == row['evaluation'], 'Retry differs from committed boundary.')
    require(before == after and {k: v for k, v in before.items() if k != 'ok'} == result['current_status'],
            'Historical retry changed current monitoring state.')
    reboot.unknown(after)
    return {'request': payload, 'response': result, 'before_status': before, 'after_status': after, 'history_unchanged': True}


def stage(name, token):
    virtualization = guard(token); require(name in STAGES, 'Unknown guest stage.'); position = STAGES.index(name)
    if position == 0:
        require(not DATA.exists() and not UNIT_FILE.exists() and not RUNTIME.exists(), 'Existing installation cannot be reset.')
        DATA.mkdir(mode=0o700); REPORT.mkdir(mode=0o700); PUBLISH.mkdir(mode=0o700)
        for directory in (PUBLISH, REPORT, DATA, DATA.parent):
            store.sync_directory(directory)
    else:
        for path in (DATA, STATE, REPORT, PUBLISH, RUNTIME):
            store.state_path(path)
        verify_captures(read_public('BEFORE.json'))
    require(not (PUBLISH / (STEMS[position] + '.json')).exists(), 'Completed stage cannot be repeated.')
    boot, hashes = reboot.boot_info(virtualization), source_hashes(); outcome = {}; observations = []
    if position:
        previous, old = read_public(STEMS[position - 1] + '.json'), read_public(STEMS[position - 1] + '-HISTORY.json')
        _, properties = ready(); startup, accepted = snapshot(); key = tuple(POINTS)[position - 1]
        verify_start(previous, old, boot, startup, properties, accepted, storage_info(), hashes, key)
        outcome.update(automatic_start={'status': startup, 'manager': properties, 'history': accepted,
            'inspected_before_collection_at_utc': reboot.timestamp(), 'no_manual_service_start': True},
            lost_ack_retry=retry_boundary(accepted), volatile_markers_absent=True, precut_prefix_preserved=True,
            before_capture_bytes_verified=True, preserved_before_capture_sha256=read_public('BEFORE.json')['capture_sha256'])
        names = {line.split()[0] for line in command(['ip', 'netns', 'list']).stdout.splitlines() if line.strip()}
        require(not names.intersection(previous['network_names'].values()), 'Old network namespaces survived power loss.')
        outcome['network_missing_before_rebuild'] = True
    staging = REPORT / name; staging.mkdir(mode=0o700)
    lab = reboot.monitoring.MonitoringLab(reboot.base.preflight(), staging)
    lab.next_source_port = 42000 + position * 1000
    completed = False
    try:
        lab.setup(); lab.start_services(); lab.apply_policy()
        approved = lab.ruleset()
        if position:
            require(reboot.monitoring.monitor.policy_fingerprint(approved) == old['identity']['approved_policy_sha256'], 'Reconstructed policy differs.')
            outcome['network_rebuilt_by_harness'] = True
        if position == 0:
            initial, initial_manager = install(approved); lab.start_captures()
            observe(lab, observations, 'before_reference')
            baseline = observe(lab, observations, 'before_baseline', reboot.monitoring.CANARIES)
            require(baseline['current_evaluation']['status'] == 'healthy',
                    'Initial canaries did not establish healthy coverage: ' + reboot.evaluation_diagnostic(baseline))
            lab.apply_policy('misconfigured'); observe(lab, observations, 'before_rule_drift')
            detected = observe(lab, observations, 'before_forbidden', (reboot.segmentation.EXCEPTION,))
            incident = reboot.critical(detected)['id']; reboot.inventory(lab, observations, 'before')
            captured = lab.stop_captures(); require(captured['routed_flows_verified'] == 4, 'Pre-cut packet coverage differs.')
            outcome.update(initial_status=initial, initial_manager=initial_manager, baseline_status=baseline,
                           incident_status=detected, capture=captured, approved_policy=approved)
            fill(lab, observations, 127, 'before_fill')
        elif position < 3:
            incident = previous['critical_incident_id']; lab.apply_policy('misconfigured')
            fill(lab, observations, (255 if position == 1 else 383), name.replace('-', '_') + '_fill')
        else:
            incident = previous['critical_incident_id']; lab.start_captures()
            reference = observe(lab, observations, 'after_reference')
            require(reboot.critical(reference)['id'] == incident, 'Rules alone cleared old incident.')
            interval = observe(lab, observations, 'after_interval')
            require(interval['current_evaluation']['telemetry_valid'] and interval['current_evaluation']['policy_matches']
                    and reboot.critical(interval)['id'] == incident, 'Fresh counter baseline failed.')
            recovered = observe(lab, observations, 'after_canaries', reboot.monitoring.CANARIES)
            require(recovered['current_evaluation']['status'] == 'healthy',
                    'Fresh canaries did not establish recovery: ' + reboot.evaluation_diagnostic(recovered))
            reboot.inventory(lab, observations, 'after')
            fill(lab, observations, 519, 'after_fill')
            final_canaries = observe(lab, observations, 'after_final_canaries', reboot.monitoring.CANARIES)
            require(final_canaries['committed_count'] == 520 and final_canaries['current_evaluation']['status'] == 'healthy',
                    'Final normal rollover not healthy: ' + reboot.evaluation_diagnostic(final_canaries))
            captured = lab.stop_captures(); require(captured['routed_flows_verified'] == 6, 'Post-cut packet coverage differs.')
            outcome.update(reference_status=reference, interval_status=interval, recovery_status=recovered,
                           normal_rollover_status=final_canaries, capture=captured)
        final, history = snapshot(); properties = manager()
        if position < 3:
            require(reboot.critical(final)['id'] == incident, 'Original incident lost before next cut.')
        else:
            resolutions = [e for e in history['events'] if e['key'] == reboot.CRITICAL and e['action'] == 'resolved']
            require(len(resolutions) == 1 and resolutions[0]['sequence'] == 388 and resolutions[0]['alert_id'] == incident,
                    'Original incident resolved before fresh canaries.')
            command(['systemctl', 'stop', UNIT], timeout=30); stopped = manager()
            require(stopped['ActiveState'] == 'inactive' and stopped['MainPID'] == 0, 'Final writer did not stop.')
            with archive.ArchiveJournal(STATE) as journal:
                exported = journal.export()
            require(exported == history, 'Final offline export differs from committed snapshot.')
            outcome['monitor_stopped_for_export'] = stopped
        outcome.update(final_status=final, manager=properties, observations=observations, critical_incident_id=incident,
                       archive_files=publish_segments((0, 1, 2, 4)[position]))
        completed = True
    finally:
        if position == 3 or not completed:
            cleaned = lab.cleanup(); require(cleaned['ok'], 'Owned network cleanup failed.')
        else:
            cleaned = {'ok': True, 'deferred_to_vm_power_cut': True, 'namespaces': list(lab.names.values())}
    if position in (0, 3):
        outcome['capture_sha256'] = seal_captures(staging, 'before' if position == 0 else 'after')
    path = PUBLISH / (STEMS[position] + '-HISTORY.json')
    store.write_new(path, (store.encoded(history) + '\n').encode())
    result = {'format': 'heltemes-monitor-archive-powercut-guest', 'version': 1, 'ok': True, 'stage': name,
              'boot': boot, 'source_sha256': hashes, 'storage': storage_info(), 'unit_sha256': hashlib.sha256(unit_text().encode()).hexdigest(),
              'network_names': lab.names, 'network_cleanup': cleaned, 'history_file': file_proof(path),
              'journal_export_method': 'stopped_verified_journal' if position == 3 else 'readonly_committed_snapshot',
              'completed_at_utc': reboot.timestamp(), **outcome}
    require(source_hashes() == hashes, 'Guest source changed during exercise.')
    if position == 0:
        write_new(PUBLISH / 'APPROVED_POLICY.json', approved); write_new(PUBLISH / 'monitor.service', unit_text())
    store.write_new(PUBLISH / (STEMS[position] + '.json'), (store.encoded(result) + '\n').encode()); store.sync_directory(PUBLISH)
    if position == 3:
        require({p.name for p in PUBLISH.iterdir()} == set(PUBLIC_FILES), 'Final public inventory differs.')
    return {'ok': True, 'stage': name, 'boot_id': boot['boot_id'], 'committed_count': len(history['rows']),
            'archive_segments': len(outcome['archive_files']), 'current_status': final['current_evaluation']['status'],
            'critical_incident_id': incident, 'network_cleanup': cleaned}


def worker():
    reboot.ordinary(reboot.MARKER)
    require(reboot.MARKER.stat().st_size <= 4096, 'Oversized disposable marker.')
    guard(store.parse(reboot.MARKER.read_bytes())['token'])
    service.serve(STATE, archive_history=True, journal_factory=ExerciseJournal)


def cleanup(token):
    guard(token)
    if UNIT_FILE.exists():
        reboot.ordinary(UNIT_FILE, mode=0o644); require(UNIT_FILE.read_text() == unit_text(), 'Unexpected unit cannot be removed.')
        command(['systemctl', 'disable', '--now', UNIT], timeout=30)
        require(command(['systemctl', 'is-active', UNIT], check=False).stdout.strip() not in ('active', 'activating', 'deactivating'), 'Owned worker remains active.')
        UNIT_FILE.unlink(); command(['systemctl', 'daemon-reload'])
    require(not UNIT_FILE.exists() and not RUNTIME.exists(), 'Owned unit or runtime remains.')
    if STATE.exists():
        store.state_path(DATA); store.state_path(STATE); reboot.shutil.rmtree(STATE)
    require(not STATE.exists(), 'Owned archive state remains.')
    return {'ok': True, 'service_disabled_removed': True, 'state_removed': True, 'volatile_runtime_removed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=(*STAGES, *('arm-' + k for k in POINTS), *('inspect-' + k for k in POINTS), 'cleanup', 'worker'))
    parser.add_argument('--token'); args = parser.parse_args()
    try:
        if args.stage == 'worker':
            require(args.token is None, 'Worker reads only its root-owned seed marker.'); worker(); return
        require(args.token is not None, 'Disposable token required.')
        if args.stage == 'cleanup':
            result = cleanup(args.token)
        elif args.stage.startswith('arm-'):
            result = arm(args.stage, args.token)
        elif args.stage.startswith('inspect-'):
            result = inspect_boundary(args.stage, args.token)
        else:
            result = stage(args.stage, args.token)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, sqlite3.Error, subprocess.SubprocessError) as error:
        parser.exit(1, 'Disposable archive power-cut stopped: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
