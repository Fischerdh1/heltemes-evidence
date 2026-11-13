"""Real autonomous observations, archive handoff crashes, and verified recovery in a disposable VM."""
from __future__ import annotations

import argparse
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
from scripts import network_monitor_archive as archive
from scripts import network_monitor_archive_collector as collector
from scripts import network_monitor_automatic_guest as automatic
from scripts import network_monitor_reboot_guest as reboot
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store

DATA, STATE, PRIVATE, CONFIG = collector.DATA, collector.STATE, collector.PRIVATE, collector.CONFIG
REPORT, RUNTIME = DATA / 'report', Path('/run/heltemes-archive-lab')
PUBLISH = REPORT / 'publish'
ARM, BOUNDARY = RUNTIME / 'arm.json', RUNTIME / 'boundary.json'
MONITOR_UNIT, COLLECTOR_UNIT = 'heltemes-archive-monitor.service', 'heltemes-archive-collector.service'
FRESHNESS, SEGMENT_ROWS, MAX_ROWS, MIN_OBSERVATIONS = 20, 128, 2048, 270
POINTS = ('archive_file_durable', 'archive_metadata_committed')
SOURCE_FILES = (*reboot.SOURCE_FILES, 'scripts/network_monitor_collector.py', 'scripts/network_monitor_automatic_guest.py',
                'scripts/network_monitor_archive.py', 'scripts/network_monitor_archive_collector.py', 'scripts/network_monitor_archive_guest.py')
CAPTURE_FILES = reboot.CAPTURE_FILES
ARCHIVE_FILES = ('archive-segment-000001.json', 'archive-segment-000002.json')
PUBLIC_FILES = ('GUEST.json', 'APPROVED_POLICY.json', 'monitor.service', 'collector.service', *CAPTURE_FILES, *ARCHIVE_FILES)
require, command, write_new = reboot.require, reboot.command, reboot.write_new
COLLECTOR_RESTART = 'The autonomous collector unexpectedly restarted.'
RESTART_DIAGNOSTIC_PREFIX = 'Archive collector restart diagnostics: '
MAX_RESTART_DIAGNOSTIC = 8192
IDENTITY_FIELDS = ('MainPID', 'NRestarts', 'ExecMainStartTimestampMonotonic', 'InvocationID')
MONITOR_REJECTIONS = service.RETRYABLE_REJECTIONS | {
    'source_timestamp_stale', 'source_timestamp_not_advancing', 'source_timestamp_before_boundary',
    'journal_error', 'receive_rejected', 'dispatch_rejected', 'response_rejected',
}


class CollectorRestartError(RuntimeError):
    def __init__(self, stage, *, current=None, first=None, differing=None):
        super().__init__('Archive stage ' + stage + ' failed: ' + COLLECTOR_RESTART)
        self.stage, self.current, self.first, self.differing = stage, current, first, differing
        self.reported = False


def unit_path(unit):
    require(unit in (MONITOR_UNIT, COLLECTOR_UNIT), 'Unknown archive service.')
    return Path('/etc/systemd/system') / unit


def unit_text(unit):
    monitor = unit == MONITOR_UNIT
    unit_path(unit)
    start = (f'{reboot.INSTALL}/scripts/network_monitor_archive_guest.py worker'
             if monitor else f'{reboot.INSTALL}/scripts/network_monitor_archive_collector.py serve')
    dependency = '' if monitor else f'After={MONITOR_UNIT}\n'
    protection = (f'ProtectSystem=strict\nReadWritePaths={STATE} {RUNTIME}\nRestrictAddressFamilies=AF_UNIX\n' if monitor else '')
    return f'''[Unit]
Description=HELTEMES disposable archive {'monitor' if monitor else 'collector'}
After=local-fs.target
{dependency}RequiresMountsFor={DATA}
StartLimitIntervalSec=30
StartLimitBurst=5

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
    for path in (DATA, STATE, PRIVATE, CONFIG, REPORT, PUBLISH, RUNTIME, ARM, BOUNDARY,
                 unit_path(MONITOR_UNIT), unit_path(COLLECTOR_UNIT)):
        require(not any(p.is_symlink() for p in (path, *path.parents)), 'Archive paths cannot traverse symbolic links.')
    return virtualization


def source_hashes():
    result = {}
    for name in SOURCE_FILES:
        path = ROOT / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size < 1024 * 1024, 'Unsafe archive source input.')
        result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def manager(unit):
    path = unit_path(unit)
    reboot.ordinary(path, mode=0o644)
    require(path.read_text() == unit_text(unit), 'Installed archive unit differs.')
    output = command(['systemctl', 'show', '--no-pager', '--property=' + ','.join(reboot.MANAGER_FIELDS), unit]).stdout
    values = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
    require(set(values) == set(reboot.MANAGER_FIELDS) and values['LoadState'] == 'loaded'
            and values['UnitFileState'] == 'enabled' and values['FragmentPath'] == str(path), 'Archive service proof differs.')
    for key in ('MainPID', 'NRestarts', 'ExecMainStartTimestampMonotonic'):
        require(values[key].isdecimal(), 'Invalid service numeric proof.')
        values[key] = int(values[key])
    return values


def request(name):
    require(name in ('status', 'export'), 'Harness cannot fabricate observations.')
    return service.request(STATE, {'command': name}, timeout=10)


def diagnostic_log(unit, text):
    """Keep fixed manager events and lab error categories, with no arbitrary log text."""
    patterns = (
        r'Main process exited, code=(?:exited|killed|dumped), status=[0-9]{1,3}(?:/[A-Z0-9_]{1,32})?\.?',
        r"Failed with result '(?:exit-code|signal|core-dump|timeout|watchdog|oom-kill|resources|protocol|start-limit-hit)'\.?",
        r'Scheduled restart job, restart counter is at [0-9]{1,6}\.',
        r'(?:Start request repeated too quickly|A process of this unit has been killed by the OOM killer)\.',
    )
    result = []
    for line in text[-16384:].splitlines()[-24:]:
        if line.startswith(unit + ': '):
            message = line.removeprefix(unit + ': ')
            if any(re.fullmatch(pattern, message) for pattern in patterns):
                result.append(message)
        elif unit == MONITOR_UNIT and line.startswith('Monitor request rejected: '):
            if line.removeprefix('Monitor request rejected: ') in MONITOR_REJECTIONS:
                result.append(line)
        elif unit == COLLECTOR_UNIT and line.startswith('Disposable archive collector stopped: '):
            message = line.removeprefix('Disposable archive collector stopped: ')
            if message in {'Archive observation was rejected; pending evidence is retained.',
                           'Archive acknowledgement is incomplete.', 'Archive collector allocation is invalid or exhausted.',
                           'Unsafe archive allocation.', 'Unsafe pending archive observation.', 'Pending archive identity differs.',
                           'Unsafe existing collector receipt.', 'Existing receipt differs from the committed observation.'}:
                result.append(message)
            else:
                retry = re.fullmatch(r'Archive service retry deadline exceeded; pending evidence is retained: '
                                     r'\{"attempts":([0-9]{1,4}),"cycle":([0-9]{1,4}),"errno":(-?[0-9]{1,6}|null),'
                                     r'"error_type":"[A-Za-z0-9_]{1,64}","reason":"([a-z_]{1,32})"\}', message)
                if retry and retry[4] in {'timeout', 'incomplete_response', 'multiple_frames', 'response_size_limit',
                                          'socket_path_limit', 'socket_identity', 'request_size_limit', 'duplicate_json_key',
                                          'nonfinite_json', 'os_error', 'invalid_response'}:
                    result.append(f'Archive service retry deadline exceeded (cycle={retry[2]}, attempts={retry[1]}, '
                                  f'errno={retry[3]}, reason={retry[4]}).')
                else:
                    result.append('Collector stopped with an unclassified error.')
    return '\n'.join(result[-12:])


def diagnostics():
    """Read bounded service properties and current-boot logs for the two owned units."""
    values = {}
    numeric_fields = ('MainPID', 'NRestarts', 'ExecMainCode', 'ExecMainStatus')
    state_values = {
        'ActiveState': {'active', 'reloading', 'inactive', 'failed', 'activating', 'deactivating', 'maintenance', 'refreshing'},
        'SubState': {'running', 'dead', 'failed', 'auto-restart', 'auto-restart-queued', 'start', 'stop', 'stop-sigterm', 'stop-sigkill', 'exited'},
        'Result': {'success', 'exit-code', 'signal', 'core-dump', 'timeout', 'watchdog', 'oom-kill', 'resources', 'protocol', 'start-limit-hit'},
    }
    fields = (*numeric_fields, *state_values)
    for unit in (MONITOR_UNIT, COLLECTOR_UNIT):
        record = {'service': {}, 'recent_log': ''}
        try:
            properties = command(['systemctl', 'show', '--no-pager', '--property=' + ','.join(fields), unit],
                                 check=False, timeout=5)
            require(properties.returncode == 0, 'Service properties unavailable.')
            for line in properties.stdout[:4096].splitlines():
                key, _, value = line.partition('=')
                if ((key in numeric_fields and re.fullmatch(r'[0-9]{1,20}', value))
                        or value in state_values.get(key, ())):
                    record['service'][key] = value
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            record['diagnostic_unavailable'] = True
        try:
            logs = command(['journalctl', '--boot', '--no-pager', '--output=cat', '--lines=24', '--unit=' + unit],
                           check=False, timeout=5)
            require(logs.returncode == 0, 'Service journal unavailable.')
            record['recent_log'] = diagnostic_log(unit, logs.stdout)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            record['diagnostic_unavailable'] = True
        values[unit] = record
    return values


def collector_diagnostic(request_id):
    """Describe three fixed disposable files without exposing observations or identifiers."""
    result = {}
    specifications = (('runtime.json', 4096), ('allocation.json', 1024), ('pending.json', store.MAX_REQUEST))
    for name, limit in specifications:
        path = PRIVATE / name
        record = {'exists': path.exists() or path.is_symlink()}
        if record['exists']:
            try:
                store.state_path(PRIVATE)
                info = reboot.ordinary(path)
                require(info.st_size < limit, 'Oversized collector diagnostic file.')
                value = store.parse(path.read_bytes())
                require(isinstance(value, dict), 'Invalid collector diagnostic file.')
                record['bytes'] = info.st_size
                for key in ('process_id', 'cycle', 'cycles', 'next_port', 'committed_sequence'):
                    if key in value:
                        record[key] = bounded_int(value[key])
                if name in ('runtime.json', 'pending.json'):
                    record['instance_id_sha256'] = instance_digest(value.get('instance_id'))
                if name == 'runtime.json':
                    record['state'] = value.get('state') if value.get('state') in ('collecting', 'idle') else 'unrecognized'
                if name == 'pending.json':
                    payload = value.get('request')
                    identity = payload.get('request_id') if isinstance(payload, dict) else None
                    require(isinstance(identity, str) and len(identity) <= 128, 'Invalid pending identity.')
                    record['request_id_sha256'] = hashlib.sha256(identity.encode()).hexdigest()
                    record['matches_boundary_request'] = identity == request_id
            except (OSError, ValueError, RuntimeError, TypeError):
                record['diagnostic_unavailable'] = True
        result[name] = record
    return result


def bounded_int(value):
    return value if type(value) is int and 0 <= value < 2**64 else None


def is_invocation_id(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{32}', value) is not None


def instance_digest(value):
    if is_invocation_id(value):
        return hashlib.sha256(value.encode()).hexdigest()
    return None


def manager_identity(managed):
    if not managed:
        return None
    invocation = managed.get('InvocationID')
    return {**{key: bounded_int(managed.get(key)) for key in IDENTITY_FIELDS[:-1]},
            'InvocationID': invocation if is_invocation_id(invocation) else ''}


def receipt_identity(receipt):
    return {**{key: bounded_int(receipt.get(key)) for key in ('cycle', 'committed_sequence', 'process_id', 'delivery_process_id')},
            'instance_id_sha256': instance_digest(receipt.get('instance_id'))}


class CollectorContinuity:
    def __init__(self, *, inject):
        self.initial = None
        self.first = None
        self.progress = None
        self.inject = inject
        self.injected = False
        self.next_check = 0

    def observe(self, status):
        self.progress = {key: bounded_int(status.get(key)) for key in ('committed_count', 'process_id')}

    def check(self, current=None, *, force=False):
        if current is None:
            if not force and time.monotonic() < self.next_check:
                return
            current = manager(COLLECTOR_UNIT)
        self.next_check = time.monotonic() + 5
        if self.initial is None:
            self.initial = current
            require(current['MainPID'] > 0 and current['ActiveState'] == 'active'
                    and current['ExecMainStartTimestampMonotonic'] > 0
                    and is_invocation_id(current['InvocationID']) and current['InvocationID'] != '0' * 32,
                    'Initial archive collector identity is unavailable.')
        # At the final healthy canary the original collector may exit successfully on its own.
        # Explicit stop can clear NRestarts, so receipts also prove continuity after that stop.
        changed = (current['NRestarts'] != 0 or current['ActiveState'] == 'failed'
                   or current['SubState'] in {'auto-restart', 'auto-restart-queued'}
                   or (current['MainPID'] > 0 and any(current[key] != self.initial[key] for key in IDENTITY_FIELDS)))
        if changed:
            raise CollectorRestartError('collector_identity_verification', current=current)

    def report(self, error):
        # Evidence collection cannot replace the specific failure or prevent teardown.
        def available(action):
            try:
                return action()
            except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError):
                return None

        first = self.first or error.first or available(lambda: receipt_identity(read_receipt(PRIVATE / 'receipt-0002.json')))
        current = error.current or available(lambda: manager(COLLECTOR_UNIT))
        value = {
            'format': 'heltemes-archive-collector-restart-diagnostic', 'version': 1,
            'stage': error.stage, 'error': COLLECTOR_RESTART, 'injected': self.injected,
            'initial': manager_identity(self.initial), 'current': manager_identity(current),
            'first_receipt': first, 'differing_receipt': error.differing,
            'last_monitor_status': self.progress,
            'collector_state': available(lambda: collector_diagnostic('')),
            'bounded_unit_diagnostics': available(diagnostics),
        }
        line = RESTART_DIAGNOSTIC_PREFIX + store.encoded(value)
        require(len(line.encode('ascii')) <= MAX_RESTART_DIAGNOSTIC, 'Restart diagnostics exceed their bound.')
        print(line, file=sys.stderr, flush=True)

    def reproduce(self):
        """Kill the exact disposable unit after the original collector finishes its first commit."""
        require(self.inject, 'Collector restart injection requires the explicit exercise flag.')
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            self.check()
            runtime = collector_diagnostic('')['runtime.json']
            if runtime.get('state') == 'idle' and (runtime.get('cycle') or 0) >= 1:
                self.first = receipt_identity(read_receipt(PRIVATE / 'receipt-0002.json'))
                break
            time.sleep(0.1)
        require(self.first and self.first['cycle'] == 1 and self.first['committed_sequence'] == 2
                and self.first['process_id'] == self.first['delivery_process_id'] == self.initial['MainPID']
                and self.first['instance_id_sha256'], 'First committed receipt did not come from the original collector.')
        status = request('status')
        self.observe(status)
        require(status.get('ok') is True and status['committed_count'] >= 2,
                'Monitor did not confirm the first committed observation.')
        self.check(force=True)
        command(['systemctl', 'kill', '--kill-who=main', '--signal=KILL', COLLECTOR_UNIT])
        self.injected = True
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            current = manager(COLLECTOR_UNIT)
            if current['ActiveState'] == 'active' and current['MainPID'] > 0 and current['MainPID'] != self.initial['MainPID']:
                # Exercise the same rejection used for ordinary collector continuity.
                self.check(current)
            time.sleep(0.1)
        self.check(force=True)
        raise RuntimeError('Injected archive collector replacement was not observed.')


def validate_recovery(before, marker, managed, recovered, after, incident, recovery_elapsed_seconds=None):
    """Keep every recovery invariant strict and report which exact observation failed."""
    def critical_ids(status):
        return [item['id'] for item in status['alerts'] if item['key'] == reboot.CRITICAL and item['state'] == 'open']
    checks = {
        'exactly_one_monitor_restart': after['monitor_manager']['NRestarts'] == managed['NRestarts'] + 1,
        'same_collector_process': after['collector_manager']['MainPID'] == before['collector_manager']['MainPID'],
        'wait_result_preserves_incident': critical_ids(recovered) == [incident],
        'snapshot_preserves_incident': critical_ids(after['status']) == [incident],
        'wait_and_snapshot_same_monitor': recovered['process_id'] == after['status']['process_id'],
    }
    if all(checks.values()):
        return
    evidence = {
        'failed_checks': [name for name, passed in checks.items() if not passed],
        'boundary_sequence': marker['head_sequence'],
        'recovery_elapsed_seconds': recovery_elapsed_seconds,
        'collector_state': collector_diagnostic(marker['request_id']),
        'monitor_restart_counts': {'before_snapshot': before['monitor_manager']['NRestarts'],
                                  'at_boundary': managed['NRestarts'], 'after_snapshot': after['monitor_manager']['NRestarts']},
        'monitor_pids': {'before_snapshot': before['status']['process_id'], 'boundary': marker['process_id'],
                         'wait_result': recovered['process_id'], 'after_snapshot': after['status']['process_id']},
        'collector_pids': {'before_snapshot': before['collector_manager']['MainPID'],
                          'after_snapshot': after['collector_manager']['MainPID']},
        'collector_restart_counts': {'before_snapshot': before['collector_manager']['NRestarts'],
                                    'after_snapshot': after['collector_manager']['NRestarts']},
        'committed_counts': {'wait_result': recovered['committed_count'], 'after_snapshot': after['status']['committed_count']},
        'critical_ids': {'expected': [incident], 'wait_result': critical_ids(recovered),
                         'after_snapshot': critical_ids(after['status'])},
        'bounded_unit_diagnostics': diagnostics(),
    }
    raise RuntimeError('Supervisor recovery or incident continuity differs: ' + json.dumps(evidence, sort_keys=True))


def wait_status(predicate, timeout=45, *, continuity=None):
    deadline, last = time.monotonic() + timeout, None
    while time.monotonic() < deadline:
        if continuity is not None:
            continuity.check()
        try:
            last = request('status')
            if last.get('ok') is True:
                if continuity is not None:
                    continuity.observe(last)
                if predicate(last):
                    return last
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    raise RuntimeError('Archive condition timed out: ' + (reboot.evaluation_diagnostic(last) if last else 'unavailable')
                       + '; bounded diagnostics: ' + json.dumps(diagnostics(), sort_keys=True))


def snapshot(started):
    status, managed = request('status'), manager(MONITOR_UNIT)
    require(status.get('ok') is True and status['process_id'] == managed['MainPID'], 'Archive monitor identity differs.')
    return {'status': status, 'monitor_manager': managed, 'collector_manager': manager(COLLECTOR_UNIT),
            'observed_elapsed_seconds': time.monotonic() - started, 'observed_at_utc': reboot.timestamp()}


def file_proof(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_uid == 0 and info.st_nlink == 1
            and info.st_size <= 16 * 1024 * 1024, 'Unsafe archive evidence file.')
    return {'name': path.name, 'bytes': info.st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'nlink': info.st_nlink}


class ExerciseJournal(archive.ArchiveJournal):
    """Only the guarded worker installs hooks; ordinary archive serving never pauses."""
    def append(self, request_id, observation, elapsed_seconds, *, restart=False, fault=None):
        def boundary(point):
            if fault:
                fault(point)
            if point not in POINTS or restart or not request_id.startswith('archive_') or not ARM.exists():
                return
            reboot.ordinary(ARM)
            require(ARM.stat().st_size < 4096, 'Oversized archive crash arm.')
            armed = store.parse(ARM.read_bytes())
            require(set(armed) == {'point', 'head_sequence'} and armed['point'] in POINTS
                    and armed['head_sequence'] in (128, 256), 'Unexpected archive crash arm.')
            if point != armed['point']:
                return
            head = self.connection.execute('SELECT head_sequence,head_digest FROM config WHERE id=1').fetchone()
            require(head[0] == armed['head_sequence'] and not self.connection.in_transaction,
                    'Archive hook must follow the observation commit outside a transaction.')
            require(not BOUNDARY.exists(), 'A prior boundary cannot be replaced.')
            files = [file_proof(p) for p in sorted((STATE / 'archives').glob('segment-*.json'))]
            marker = {'format': 'heltemes-archive-boundary', 'version': 1, 'point': point,
                      'head_sequence': head[0], 'head_digest': head[1], 'request_id': request_id,
                      'request': {'command': 'observe', 'request_id': request_id, 'observation': observation},
                      'observation_sha256': store.digest(observation), 'process_id': os.getpid(),
                      'in_transaction': self.connection.in_transaction,
                      'active_sql_rows': self.connection.execute('SELECT count(*) FROM observations').fetchone()[0],
                      'archive_files': files, 'observed_at_utc': reboot.timestamp(),
                      'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                      'synchronous': self.connection.execute('PRAGMA synchronous').fetchone()[0],
                      'journal_mode': self.connection.execute('PRAGMA journal_mode').fetchone()[0]}
            write_new(BOUNDARY, marker)
            os.kill(os.getpid(), signal.SIGSTOP)
            os._exit(74)
        return super().append(request_id, observation, elapsed_seconds, restart=restart, fault=boundary)


def worker():
    reboot.ordinary(reboot.MARKER)
    require(reboot.MARKER.stat().st_size < 4096, 'Oversized marker.')
    guard(store.parse(reboot.MARKER.read_bytes())['token'])
    # Injection is confined to this explicit disposable guest entry point.
    service.serve(STATE, freshness_seconds=FRESHNESS, archive_history=True, journal_factory=ExerciseJournal,
                  diagnose_rejections=True)


def install(approved, names):
    require(not STATE.exists() and not any(unit_path(u).exists() for u in (MONITOR_UNIT, COLLECTOR_UNIT)),
            'Existing archive installation must not be replaced.')
    archive.initialize(STATE, approved, segment_rows=SEGMENT_ROWS, max_rows=MAX_ROWS)
    PRIVATE.mkdir(mode=0o700); RUNTIME.mkdir(mode=0o700)
    write_new(CONFIG, {'version': 1, 'interval_seconds': collector.INTERVAL, 'canary_every': collector.CANARY_EVERY,
                       'max_cycles': collector.MAX_CYCLES, 'namespaces': names})
    for unit in (MONITOR_UNIT, COLLECTOR_UNIT):
        write_new(unit_path(unit), unit_text(unit)); unit_path(unit).chmod(0o644)
    command(['systemctl', 'daemon-reload']); command(['systemctl', 'enable', MONITOR_UNIT, COLLECTOR_UNIT])
    command(['systemctl', 'start', MONITOR_UNIT])
    wait_status(lambda s: s['current_evaluation']['status'] == 'unknown')


def stopped(pid):
    return next((line.split()[1] for line in (Path('/proc') / str(pid) / 'status').read_text().splitlines()
                 if line.startswith('State:')), None) == 'T'


def crash_rollover(point, number, started, incident, continuity):
    before = snapshot(started)
    continuity.check(before['collector_manager'])
    require(reboot.critical(before['status'])['id'] == incident, 'Critical incident changed before archiving.')
    write_new(ARM, {'point': point, 'head_sequence': SEGMENT_ROWS * number})
    deadline, marker = time.monotonic() + 160, None
    while time.monotonic() < deadline:
        continuity.check()
        if BOUNDARY.exists():
            reboot.ordinary(BOUNDARY)
            require(BOUNDARY.stat().st_size < 1024 * 1024, 'Oversized boundary record.')
            try:
                candidate = store.parse(BOUNDARY.read_bytes())
                if stopped(candidate['process_id']):
                    marker = candidate; break
            except (ValueError, OSError):
                pass
        time.sleep(0.1)
    if marker is None:
        raise RuntimeError('Archive handoff boundary was not reached: ' + json.dumps({
            'services': diagnostics(), 'collector_state': collector_diagnostic('')}, sort_keys=True))
    managed = manager(MONITOR_UNIT)
    require(marker['point'] == point and marker['head_sequence'] == SEGMENT_ROWS * number
            and managed['MainPID'] == marker['process_id'] == before['status']['process_id']
            and marker['synchronous'] == 3 and marker['journal_mode'] == 'delete'
            and marker['in_transaction'] is False and len(marker['archive_files']) == number,
            'Archive crash marker does not match the intended durable boundary.')
    require(marker['active_sql_rows'] == (SEGMENT_ROWS if point == POINTS[0] else 0), 'Archive pruning boundary differs.')
    ARM.unlink(); store.sync_directory(RUNTIME)
    recovery_started = time.monotonic()
    command(['systemctl', 'kill', '--kill-who=main', '--signal=KILL', MONITOR_UNIT])
    recovered = wait_status(lambda s: s['process_id'] != marker['process_id'] and s['committed_count'] > marker['head_sequence'],
                            continuity=continuity)
    after = snapshot(started)
    continuity.check(after['collector_manager'])
    recovery_elapsed = time.monotonic() - recovery_started
    validate_recovery(before, marker, managed, recovered, after, incident, recovery_elapsed)
    BOUNDARY.unlink(); store.sync_directory(RUNTIME)
    return {'before': before, 'boundary': marker, 'worker_stopped_observed': True, 'worker_process_state': 'T',
            'after': after, 'response_received_before_crash': False, 'recovery_elapsed_seconds': recovery_elapsed}


def read_receipt(path):
    reboot.ordinary(path)
    require(path.stat().st_size < store.MAX_REQUEST, 'Oversized archive receipt.')
    return store.parse(path.read_bytes())


def receipts():
    result = []
    for path in sorted(PRIVATE.glob('receipt-[0-9][0-9][0-9][0-9].json')):
        result.append(read_receipt(path))
    require(MIN_OBSERVATIONS <= len(result) <= collector.MAX_CYCLES, 'Archive observation inventory differs.')
    return result


def validate_inventory(journal, records, crashes):
    rows = {r['request_id']: r for r in journal['rows'] if r['request']['kind'] == 'observation'}
    require(len(rows) == len(records), 'Every committed observation must have one autonomous receipt.')
    if not records:
        raise CollectorRestartError('receipt_history_verification')
    first = records[0]
    for record in records:
        if (record['instance_id'] != first['instance_id'] or record['process_id'] != first['process_id']
                or record.get('delivery_process_id', record['process_id']) != first['process_id']):
            raise CollectorRestartError('receipt_history_verification', first=receipt_identity(first),
                                        differing=receipt_identity(record))
    require([r['cycle'] for r in records] == list(range(1, len(records) + 1)), 'Collector cycle sequence has gaps.')
    probes, ports = [], set()
    for record in records:
        payload = record['request']; row = rows.get(payload['request_id'])
        require(row and row['sequence'] == record['committed_sequence'] and row['request']['observation'] == payload['observation']
                and row['evaluation'] == record['evaluation'], 'Collector receipt differs from committed history.')
        sample = payload['observation']; cycle = record['cycle']
        require(sample['ruleset'] is not None and sample['collection_error'] is None
                and payload['request_id'] == f"archive_{record['instance_id']}_{cycle}", 'Receipt was not a real ruleset sample.')
        expected = set(automatic.monitoring.CANARIES) if collector.canary_cycle(cycle) else set()
        require({(p['from'], p['to'], p['port']) for p in sample['probes']} == expected, 'Canary schedule differs.')
        if not expected:
            require(row['evaluation']['status'] != 'healthy', 'Rule-only sample must not assert complete healthy coverage.')
        for probe in sample['probes']:
            for item in (probe, probe.get('destination_health')):
                if item is None:
                    continue
                port = item['source_port']
                require(port not in ports and collector.PORT_START + collector.PORT_BLOCK * (cycle - 1)
                        <= port < collector.PORT_START + collector.PORT_BLOCK * cycle, 'Probe port was reused or outside reservation.')
                ports.add(port); probes.append(item)
    for crash in crashes:
        marker = crash['boundary']
        record = next(r for r in records if r['request']['request_id'] == marker['request_id'])
        require(record['request'] == marker['request'] and record['duplicate_acknowledgement'] is True
                and record['delivery_attempts'] > 1 and record['transport_failures']
                and record['committed_sequence'] == marker['head_sequence'], 'Crash request was not retried exactly and acknowledged historically.')
    return probes


def state_fingerprints():
    result = {}
    for path in sorted(STATE.rglob('*')):
        if path.is_file():
            result[str(path.relative_to(STATE))] = file_proof(path)['sha256']
    return result


def refusal_checks():
    before = state_fingerprints()
    results = []
    for label in ('missing_archive', 'modified_archive'):
        target = DATA / ('verification-' + label)
        require(not target.exists(), 'Disposable verification copy already exists.')
        shutil.copytree(STATE, target)
        segment = target / 'archives' / 'segment-000001.json'
        original = file_proof(segment)
        if label == 'missing_archive':
            segment.unlink()
        else:
            raw = segment.read_bytes()
            segment.chmod(0o600)
            segment.write_bytes(raw.replace(b'archive_', b'ARCHIVE_', 1))
            require(segment.read_bytes() != raw, 'Disposable archive mutation made no change.')
        rejected, reason = False, None
        try:
            with archive.ArchiveJournal(target):
                pass
        except (OSError, ValueError, RuntimeError, store.sqlite3.Error) as error:
            rejected, reason = True, str(error)
        require(rejected, 'Invalid disposable archive was accepted.')
        results.append({'case': label, 'rejected': rejected, 'reason': reason, 'original_segment': original})
        shutil.rmtree(target)
    require(state_fingerprints() == before, 'Original disposable state changed during refusal checks.')
    with archive.ArchiveJournal(STATE) as verified:
        total = verified.total_count
    return {'cases': results, 'original_state_sha256_before': before, 'original_state_sha256_after': state_fingerprints(),
            'original_reverified_count': total}


def stage_call(name, action):
    require(name in ('live_retry_status', 'live_archived_retry', 'stop_monitor_for_export', 'offline_verified_export',
                     'collector_receipt_inventory', 'receipt_history_verification', 'capture_validation', 'archive_refusal_checks'),
            'Unknown archive completion stage.')
    try:
        return action()
    except CollectorRestartError:
        raise
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise RuntimeError('Archive stage ' + name + ' failed: ' + str(error)) from error


def offline_export(final, stopped_manager):
    require(stopped_manager['ActiveState'] == 'inactive' and stopped_manager['MainPID'] == 0,
            'Complete history export requires the monitor to be stopped.')
    with archive.ArchiveJournal(STATE) as verified:
        require(verified.total_count == final['committed_count'] and verified.head_digest == final['head_digest'],
                'Offline verified head differs from the last live monitor status.')
        exported = verified.export()
    require(len(exported['rows']) == final['committed_count']
            and exported['rows'][-1]['row_digest'] == final['head_digest'], 'Offline export changed the accepted head.')
    return {'ok': True, **exported, 'current_status': final}


def retry_and_stop(first):
    """Complete the live retry and freshness checks before any expensive full-history export."""
    before_retry = stage_call('live_retry_status', lambda: request('status'))
    # Exact retry of an actual producer request; the harness creates no observation.
    retry = stage_call('live_archived_retry', lambda: service.request(STATE, first['request']))
    after_retry = stage_call('live_retry_status', lambda: request('status'))
    require(retry.get('ok') is True and retry['duplicate'] is True and retry['committed_sequence'] == first['committed_sequence']
            and retry['evaluation'] == first['evaluation'] and before_retry['committed_count'] == after_retry['committed_count'],
            'An archived retry changed history or its original result.')
    final = stage_call('live_retry_status', lambda: request('status'))
    require(final['current_evaluation']['status'] == 'healthy', 'Final live canary coverage is no longer fresh.')
    stage_call('stop_monitor_for_export', lambda: command(['systemctl', 'stop', MONITOR_UNIT], timeout=30))
    stopped_manager = manager(MONITOR_UNIT)
    journal = stage_call('offline_verified_export', lambda: offline_export(final, stopped_manager))
    duplicate = {'request': first['request'], 'before_status': before_retry, 'result': retry, 'after_status': after_retry}
    return journal, final, duplicate, stopped_manager


def run_exercise(lab, continuity):
    started = time.monotonic()
    lab.setup(); lab.start_services(); lab.apply_policy()
    approved = lab.ruleset()
    lab.start_captures(); install(approved, lab.names)
    stages = {'initial': snapshot(started)}
    command(['systemctl', 'start', COLLECTOR_UNIT])
    continuity.check(force=True)
    if continuity.inject:
        continuity.reproduce()
    wait_status(lambda s: s['current_evaluation']['status'] == 'healthy', continuity=continuity)
    stages['baseline'] = snapshot(started)
    continuity.check(stages['baseline']['collector_manager'])
    lab.apply_policy('misconfigured')
    detected = wait_status(lambda s: any(a['key'] == reboot.CRITICAL and a['state'] == 'open' for a in s['alerts']),
                           timeout=40, continuity=continuity)
    incident = reboot.critical(detected)['id']
    stages['incident'] = snapshot(started)
    continuity.check(stages['incident']['collector_manager'])
    crashes = [crash_rollover(point, index, started, incident, continuity) for index, point in enumerate(POINTS, 1)]
    wait_status(lambda s: s['committed_count'] >= MIN_OBSERVATIONS + 3, timeout=50, continuity=continuity)
    stages['beyond_legacy_limit'] = snapshot(started)
    continuity.check(stages['beyond_legacy_limit']['collector_manager'])
    require(reboot.critical(stages['beyond_legacy_limit']['status'])['id'] == incident, 'Archiving cleared the unresolved incident.')
    lab.apply_policy()
    wait_status(lambda s: s['current_evaluation']['status'] == 'healthy', timeout=40, continuity=continuity)
    continuity.check(force=True)
    command(['systemctl', 'stop', COLLECTOR_UNIT], timeout=30)
    stages['recovered'] = snapshot(started)
    require(stages['recovered']['status']['current_evaluation']['status'] == 'healthy', 'Fresh canary recovery was not preserved at stop.')
    first = read_receipt(PRIVATE / 'receipt-0002.json')
    require(first['cycle'] == 1 and first['committed_sequence'] == 2, 'First autonomous receipt differs.')
    journal, final, duplicate, stopped_manager = retry_and_stop(first)
    records = stage_call('collector_receipt_inventory', receipts)
    lab.probes = stage_call('receipt_history_verification', lambda: validate_inventory(journal, records, crashes))
    require(len(journal['rows']) == len(records) + 3, 'Journal must contain exactly three monitor startup boundaries.')
    resolutions = [e for e in journal['events'] if e['key'] == reboot.CRITICAL and e['action'] == 'resolved']
    require(len(resolutions) == 1 and resolutions[0]['alert_id'] == incident and resolutions[0]['sequence'] > 256,
            'Critical incident recovery was not uniquely recorded after both archive handoffs.')
    resolution = journal['rows'][resolutions[0]['sequence'] - 1]
    require(len(resolution['sample']['probes']) == 3 and resolution['evaluation']['status'] == 'healthy', 'Recovery lacked fresh full canaries.')
    captured = stage_call('capture_validation', lab.stop_captures)
    require(captured['routed_flows_verified'] == len([p for p in lab.probes if p['from'] != p['to']]), 'Packet coverage differs.')
    checks = stage_call('archive_refusal_checks', refusal_checks)
    segments = []
    for index, name in enumerate(ARCHIVE_FILES, 1):
        source = STATE / 'archives' / f'segment-{index:06d}.json'
        proof = file_proof(source)
        store.write_new(PUBLISH / name, source.read_bytes())
        segments.append({'public_name': name, **proof})
    require(len(list((STATE / 'archives').glob('segment-*.json'))) == 2, 'Exactly two archived segments were expected.')
    return {'approved_policy': approved, 'stages': stages, 'crashes': crashes, 'collector_receipts': records,
            'journal': journal, 'final_status': final, 'critical_incident_id': incident, 'capture': captured,
            'archived_duplicate': duplicate, 'journal_export_method': 'stopped_verified_journal',
            'monitor_stopped_for_export': stopped_manager,
            'refusal_checks': checks, 'archive_files': segments,
            'configuration': {'segment_rows': SEGMENT_ROWS, 'max_rows': MAX_ROWS, 'max_segments': 16,
                              'interval_seconds': collector.INTERVAL, 'canary_every': collector.CANARY_EVERY,
                              'max_cycles': collector.MAX_CYCLES, 'freshness_seconds': FRESHNESS,
                              'finish_after_healthy_cycle': collector.FINISH_AFTER_HEALTHY_CYCLE},
            'boot_enabled_configuration_only': True, 'services_stopped_after_exercise': True}


def storage_info():
    value = json.loads(command(['findmnt', '--json', '--target', str(STATE), '--output', 'TARGET,SOURCE,FSTYPE,OPTIONS,UUID']).stdout)
    require(set(value) == {'filesystems'} and len(value['filesystems']) == 1, 'Ambiguous archive state mount.')
    record = value['filesystems'][0]
    require(record['fstype'] in {'ext4', 'xfs', 'btrfs'} and record['source'].startswith('/dev/')
            and record['uuid'] and 'rw' in record['options'].split(','), 'Archive state requires a persistent writable disk.')
    return record


def exercise(token, *, inject_collector_restart=False):
    virtualization = guard(token)
    require(not DATA.exists() and not RUNTIME.exists() and not any(unit_path(u).exists() for u in (MONITOR_UNIT, COLLECTOR_UNIT)),
            'Existing archive installation cannot be reset.')
    DATA.mkdir(mode=0o700); REPORT.mkdir(mode=0o700); PUBLISH.mkdir(mode=0o700)
    staging = REPORT / 'capture'; staging.mkdir(mode=0o700)
    store.sync_directory(DATA.parent)
    boot, hashes = reboot.boot_info(virtualization), source_hashes()
    lab = automatic.monitoring.MonitoringLab(reboot.base.preflight(), staging)
    continuity = CollectorContinuity(inject=inject_collector_restart)
    failed = False
    try:
        outcome = run_exercise(lab, continuity)
    except BaseException as error:
        failed = True
        if isinstance(error, CollectorRestartError):
            try:
                print('Disposable archive guest stopped: ' + str(error), file=sys.stderr, flush=True)
                error.reported = True
                continuity.report(error)
            except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError):
                pass
        raise
    finally:
        try:
            try:
                for unit in (COLLECTOR_UNIT, MONITOR_UNIT):
                    if unit_path(unit).exists():
                        command(['systemctl', 'kill', '--kill-who=main', '--signal=CONT', unit], check=False)
                        command(['systemctl', 'stop', unit], check=False, timeout=30)
            finally:
                cleaned = lab.cleanup()
                require(cleaned['ok'], 'Owned network cleanup failed.')
        except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError):
            if not failed:
                raise
    capture_hashes = {}
    for name in CAPTURE_FILES:
        capture_hashes[name] = automatic.seal_capture(staging / name)
        (staging / name).rename(PUBLISH / name)
    store.sync_directory(staging); store.sync_directory(PUBLISH)
    require({name: automatic.seal_capture(PUBLISH / name) for name in CAPTURE_FILES} == capture_hashes, 'Published capture changed.')
    require(source_hashes() == hashes, 'Archive guest source changed during exercise.')
    report = {'format': 'heltemes-monitor-archive-guest', 'version': 1, 'ok': True, 'boot': boot,
              'source_sha256': hashes, 'storage': storage_info(), 'network_cleanup': cleaned,
              'capture_sha256': capture_hashes, 'completed_at_utc': reboot.timestamp(), **outcome}
    write_new(PUBLISH / 'APPROVED_POLICY.json', outcome['approved_policy'])
    write_new(PUBLISH / 'monitor.service', unit_text(MONITOR_UNIT)); write_new(PUBLISH / 'collector.service', unit_text(COLLECTOR_UNIT))
    store.write_new(PUBLISH / 'GUEST.json', (store.encoded(report) + '\n').encode())
    store.sync_directory(PUBLISH)
    require({p.name for p in PUBLISH.iterdir()} == set(PUBLIC_FILES), 'Public archive inventory differs.')
    return {'ok': True, 'stage': 'exercise', 'boot_id': boot['boot_id'], 'committed_count': len(outcome['journal']['rows']),
            'archive_segments': 2, 'autonomous_observations': len(outcome['collector_receipts']),
            'current_status': outcome['final_status']['current_evaluation']['status'], 'network_cleanup': cleaned,
            'guest_report_sha256': hashlib.sha256((PUBLISH / 'GUEST.json').read_bytes()).hexdigest()}


def cleanup(token):
    guard(token)
    for unit in (COLLECTOR_UNIT, MONITOR_UNIT):
        path = unit_path(unit)
        if path.exists():
            reboot.ordinary(path, mode=0o644)
            require(path.read_text() == unit_text(unit), 'An unexpected archive unit cannot be removed.')
            command(['systemctl', 'kill', '--kill-who=main', '--signal=CONT', unit], check=False)
            command(['systemctl', 'disable', '--now', unit], timeout=30)
            require(command(['systemctl', 'is-active', unit], check=False).stdout.strip() not in {'active', 'activating', 'deactivating'},
                    'Owned archive service did not stop.')
            path.unlink()
    command(['systemctl', 'daemon-reload'])
    for path in (STATE, PRIVATE, RUNTIME):
        if path.exists():
            store.state_path(path); shutil.rmtree(path)
    if CONFIG.exists():
        reboot.ordinary(CONFIG); CONFIG.unlink()
    require(not any(p.exists() for p in (STATE, PRIVATE, RUNTIME, CONFIG, unit_path(MONITOR_UNIT), unit_path(COLLECTOR_UNIT))),
            'Archive service cleanup incomplete.')
    return {'ok': True, 'services_disabled_removed': True, 'state_removed': True, 'collector_config_removed': True, 'runtime_removed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('worker', 'exercise', 'cleanup'))
    parser.add_argument('--token')
    parser.add_argument('--inject-collector-restart', action='store_true', help='Inject one restart in the guarded exercise.')
    args = parser.parse_args()
    if args.inject_collector_restart and args.stage != 'exercise':
        parser.error('Collector restart injection is only available in the disposable exercise.')
    try:
        if args.stage == 'worker':
            require(args.token is None, 'Worker reads only its root-owned marker.')
            worker(); return
        result = (cleanup(args.token) if args.stage == 'cleanup'
                  else exercise(args.token, inject_collector_restart=args.inject_collector_restart))
    except CollectorRestartError as error:
        parser.exit(1, None if error.reported else 'Disposable archive guest stopped: ' + str(error) + '\n')
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Disposable archive guest stopped: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
