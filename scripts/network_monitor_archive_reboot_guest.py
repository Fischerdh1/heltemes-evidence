"""Archived monitoring through a real reboot of an explicitly marked disposable VM.

The host reboots Linux. Only the monitor starts automatically; the harness
recreates volatile namespaces before explicitly starting the bounded collector.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor_archive as archive
from scripts import network_monitor_archive_reboot_collector as collector
from scripts import network_monitor_automatic_guest as automatic
from scripts import network_monitor_collector as ordinary_collector
from scripts import network_monitor_reboot_guest as reboot
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store

DATA, STATE, PRIVATE, CONFIG = collector.DATA, collector.STATE, collector.PRIVATE, collector.CONFIG
REPORT, PUBLISH = DATA / 'report', DATA / 'report' / 'publish'
RUNTIME = Path('/run/heltemes-archive-reboot-lab')
VOLATILE = Path('/run/heltemes-archive-reboot-marker')
MONITOR_UNIT = 'heltemes-archive-reboot-monitor.service'
COLLECTOR_UNIT = 'heltemes-archive-reboot-collector.service'
FRESHNESS, SEGMENT_ROWS, MAX_ROWS = 20, 128, 2048
SOURCE_FILES = (*reboot.SOURCE_FILES, 'scripts/network_monitor_collector.py',
                'scripts/network_monitor_automatic_guest.py', 'scripts/network_monitor_archive.py',
                'scripts/network_monitor_archive_collector.py',
                'scripts/network_monitor_archive_reboot_collector.py',
                'scripts/network_monitor_archive_reboot_guest.py')
CAPTURE_FILES = reboot.CAPTURE_FILES
ARCHIVE_FILES = tuple(f'archive-segment-{number:06d}.json' for number in range(1, 4))
BEFORE_FILES = ('BEFORE.json', 'BEFORE-HISTORY.json', 'APPROVED_POLICY.json', 'monitor.service', 'collector.service',
                *('before-' + name for name in CAPTURE_FILES), *ARCHIVE_FILES[:2])
PUBLIC_FILES = (*BEFORE_FILES, 'AFTER.json', 'AFTER-HISTORY.json',
                *('after-' + name for name in CAPTURE_FILES), ARCHIVE_FILES[2])
require, command, write_new = reboot.require, reboot.command, reboot.write_new


def unit_path(unit):
    require(unit in (MONITOR_UNIT, COLLECTOR_UNIT), 'Unknown archive reboot service.')
    return Path('/etc/systemd/system') / unit


def unit_text(unit):
    monitor = unit == MONITOR_UNIT
    unit_path(unit)
    entry = 'network_monitor_archive_reboot_guest.py worker' if monitor else 'network_monitor_archive_reboot_collector.py serve'
    dependency = '' if monitor else f'After={MONITOR_UNIT}\n'
    protection = (f'RuntimeDirectory=heltemes-archive-reboot-lab\nRuntimeDirectoryMode=0700\n'
                  f'ProtectSystem=strict\nReadWritePaths={STATE} {RUNTIME}\nRestrictAddressFamilies=AF_UNIX\n' if monitor else '')
    return f'''[Unit]
Description=HELTEMES disposable archived history reboot {'monitor' if monitor else 'collector'}
After=local-fs.target
{dependency}RequiresMountsFor={DATA}
StartLimitIntervalSec=30
StartLimitBurst=3

[Service]
Type=exec
ExecStart=/usr/bin/python3 -I -S -B {reboot.INSTALL}/scripts/{entry}
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
    for path in (DATA, STATE, PRIVATE, CONFIG, REPORT, PUBLISH, RUNTIME, VOLATILE,
                 unit_path(MONITOR_UNIT), unit_path(COLLECTOR_UNIT)):
        require(not any(p.is_symlink() for p in (path, *path.parents)), 'Archive reboot paths cannot traverse links.')
    return virtualization


def source_hashes():
    values = {}
    for name in SOURCE_FILES:
        path = ROOT / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size < 1024 * 1024, 'Unsafe guest source input.')
        values[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return values


def file_proof(path):
    info = reboot.ordinary(path)
    require(info.st_size <= 16 * 1024 * 1024, 'Public evidence file exceeds its bounded size.')
    return {'name': path.name, 'bytes': info.st_size, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'nlink': info.st_nlink}


def read_private(path, limit=store.MAX_REQUEST):
    info = reboot.ordinary(path)
    require(info.st_size <= limit, 'Oversized private exercise record.')
    return store.parse(path.read_bytes())


def manager(unit):
    path = unit_path(unit)
    reboot.ordinary(path, mode=0o644)
    require(path.read_text() == unit_text(unit), 'Installed archive reboot unit differs.')
    output = command(['systemctl', 'show', '--no-pager', '--property=' + ','.join(reboot.MANAGER_FIELDS), unit]).stdout
    values = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
    expected_state = 'enabled' if unit == MONITOR_UNIT else 'disabled'
    require(set(values) == set(reboot.MANAGER_FIELDS) and values['LoadState'] == 'loaded'
            and values['UnitFileState'] == expected_state and values['FragmentPath'] == str(path), 'Service ownership or boot configuration differs.')
    for key in ('MainPID', 'NRestarts', 'ExecMainStartTimestampMonotonic'):
        require(values[key].isdecimal(), 'Invalid service numeric evidence.')
        values[key] = int(values[key])
    return values


def request(name):
    require(name == 'status', 'Harness cannot fabricate observations or export a live archive.')
    return service.request(STATE, {'command': name}, timeout=10)


def diagnostics():
    """Bounded read-only failure facts, never observation payloads or credentials."""
    result = {}
    fields = ('LoadState', 'ActiveState', 'SubState', 'MainPID', 'NRestarts', 'ExecMainCode',
              'ExecMainStatus', 'Result', 'FragmentPath', 'MemoryCurrent', 'CPUUsageNSec')
    for unit in (MONITOR_UNIT, COLLECTOR_UNIT):
        record = {}
        try:
            output = command(['systemctl', 'show', '--no-pager', '--property=' + ','.join(fields), unit], check=False, timeout=5).stdout
            properties = {key: automatic.sanitize_diagnostic(value) for line in output.splitlines() if '=' in line
                          for key, value in [line.split('=', 1)] if key in fields}
            record['service'] = properties
            raw = dict(line.split('=', 1) for line in output.splitlines() if '=' in line)
            pid = raw.get('MainPID', '')
            if pid.isdecimal() and 1 < int(pid) < 4194304 and raw.get('FragmentPath') == str(unit_path(unit)):
                record['process'] = process_diagnostic(int(pid))
            record['recent_log'] = automatic.sanitize_diagnostic(command(
                ['journalctl', '--no-pager', '--output=cat', '--lines=12', '--unit=' + unit], check=False, timeout=5).stdout)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            record['unavailable'] = True
        result[unit] = record
    result['collector_state'] = collector_diagnostic()
    result['archive_state'] = archive_diagnostic()
    return result


def process_diagnostic(pid):
    require(type(pid) is int and 1 < pid < 4194304, 'Invalid owned process identity.')
    result = {'process_id': pid}
    try:
        process = Path('/proc') / str(pid)
        with (process / 'status').open() as stream:
            raw = stream.read(16385)
        require(len(raw) <= 16384, 'Oversized process status.')
        fields = ('State', 'PPid', 'Threads', 'VmRSS')
        result['status'] = {key: value.strip()[:80] for line in raw.splitlines() if ':' in line
                            for key, value in [line.split(':', 1)] if key in fields}
        with (process / 'wchan').open() as stream:
            wait = stream.read(129).strip()
        result['wait_channel'] = wait if len(wait) <= 128 and re.fullmatch(r'[A-Za-z0-9_]+', wait) else 'unavailable'
    except (OSError, ValueError, RuntimeError):
        result['unavailable'] = True
    return result


def collector_diagnostic():
    result = {}
    specifications = (('runtime.json', 4096), ('allocation.json', 1024),
                      ('pending.json', store.MAX_REQUEST), ('transport.json', 4096))
    integers = ('process_id', 'delivery_process_id', 'process_cycle', 'cycle', 'cycles', 'next_port',
                'committed_sequence', 'attempts', 'errno', 'stop_after_cycle')
    for name, limit in specifications:
        path = PRIVATE / name
        record = {'exists': path.exists() or path.is_symlink()}
        if record['exists']:
            try:
                value = read_private(path, limit)
                require(isinstance(value, dict), 'Invalid collector diagnostic object.')
                record['bytes'] = path.stat().st_size
                record['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                record.update({key: value[key] for key in integers if type(value.get(key)) is int})
                if type(value.get('deadline_exceeded')) is bool:
                    record['deadline_exceeded'] = value['deadline_exceeded']
                for key in ('state', 'phase', 'error_type', 'reason'):
                    text = value.get(key)
                    if isinstance(text, str) and re.fullmatch(r'[A-Za-z0-9_]{1,64}', text):
                        record[key] = text
                payload = value.get('request')
                if isinstance(payload, dict):
                    identity = payload.get('request_id')
                    if isinstance(identity, str) and len(identity) <= 128:
                        record['request_id_sha256'] = hashlib.sha256(identity.encode()).hexdigest()
            except (OSError, ValueError, RuntimeError, KeyError, TypeError):
                record['unavailable'] = True
        result[name] = record
    return result


def archive_diagnostic():
    """Read small database metadata with a one-second lock deadline; no replay."""
    result, connection = {}, None
    try:
        database = STATE / 'monitor.sqlite3'
        info = reboot.ordinary(database)
        require(info.st_size <= store.MAX_BYTES, 'Oversized diagnostic database.')
        result['database_bytes'] = info.st_size
        connection = sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=1)
        connection.execute('BEGIN')
        config = connection.execute('SELECT head_sequence,head_digest,archived_sequence,archived_digest FROM config WHERE id=1').fetchone()
        require(config is not None, 'Missing diagnostic journal head.')
        result.update(dict(zip(('head_sequence', 'head_digest', 'archived_sequence', 'archived_digest'), config)))
        active = connection.execute('SELECT COUNT(*),MIN(sequence),MAX(sequence) FROM observations').fetchone()
        result['active_rows'], result['first_active_sequence'], result['last_active_sequence'] = active
        segments = connection.execute('SELECT COUNT(*),MAX(last_sequence),SUM(byte_count) FROM segments').fetchone()
        result['sealed_segments'], result['last_archived_sequence'], result['archive_bytes'] = segments
        connection.close(); connection = None
        names = []
        for index, path in enumerate((STATE / 'archives').iterdir()):
            require(index < archive.MAX_SEGMENTS + 1, 'Archive diagnostic inventory exceeds bound.')
            require(re.fullmatch(r'segment-[0-9]{6}\.json(?:\.pending)?', path.name), 'Unexpected diagnostic archive filename.')
            item = reboot.ordinary(path)
            names.append({'name': path.name, 'bytes': item.st_size})
        result['archive_files'] = sorted(names, key=lambda item: item['name'])
    except (OSError, ValueError, RuntimeError, sqlite3.Error):
        result['unavailable'] = True
    finally:
        if connection is not None:
            connection.close()
    return result


def stage_call(label, action):
    require(label in ('before_install', 'before_baseline', 'before_incident', 'before_collection', 'before_export',
                      'before_inventory', 'before_capture', 'after_startup', 'after_collection', 'after_export',
                      'after_inventory', 'after_capture'), 'Unknown archive reboot operation.')
    try:
        return action()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise RuntimeError('Archive reboot operation ' + label + ' failed: ' + str(error)) from error


def wait_status(predicate, timeout=45):
    deadline, last = time.monotonic() + timeout, None
    while time.monotonic() < deadline:
        try:
            last = request('status')
            if last.get('ok') is True and predicate(last):
                return last
        except (OSError, ValueError):
            pass
        time.sleep(0.1)
    raise RuntimeError('Archive reboot condition timed out: ' + (reboot.evaluation_diagnostic(last) if last else 'unavailable')
                       + '; bounded unit diagnostics: ' + json.dumps(diagnostics(), sort_keys=True))


def ready():
    status = wait_status(lambda s: s['process_id'] == manager(MONITOR_UNIT)['MainPID'])
    properties = manager(MONITOR_UNIT)
    require(properties['ActiveState'] == 'active' and properties['NRestarts'] == 0,
            'Enabled monitor failed or restarted within this boot.')
    require(re.fullmatch(r'[0-9a-f]{32}', properties['InvocationID']), 'Invalid monitor invocation identity.')
    return status, reboot.process_boot_timing(properties, float(Path('/proc/uptime').read_text().split()[0]))


def unknown(status):
    evaluation = status['current_evaluation']
    require(evaluation['status'] == 'unknown' and evaluation['phase'] in ('monitor_restart', 'collector_missing')
            and 'telemetry_gap:collector' in evaluation['active_alert_keys']
            and status['freshness']['last_accepted_request_id'] is None,
            'Restart without new network observations must remain unknown.')


def configuration():
    return {'segment_rows': SEGMENT_ROWS, 'max_rows': MAX_ROWS, 'max_segments': archive.MAX_SEGMENTS,
            'interval_seconds': collector.INTERVAL, 'canary_every': collector.CANARY_EVERY,
            'max_cycles': collector.MAX_CYCLES, 'before_stop_cycle': collector.BEFORE_STOP_CYCLE,
            'after_stop_cycle': collector.AFTER_STOP_CYCLE, 'freshness_seconds': FRESHNESS}


def configure_collector(names, boot_id, phase):
    value = {'version': 1, 'interval_seconds': collector.INTERVAL, 'canary_every': collector.CANARY_EVERY,
             'max_cycles': collector.MAX_CYCLES, 'namespaces': names, 'boot_id': boot_id, 'phase': phase,
             'stop_after_cycle': collector.BEFORE_STOP_CYCLE if phase == 'before' else collector.AFTER_STOP_CYCLE}
    collector.validate_config(value, boot_id=boot_id)
    ordinary_collector.replace_private(CONFIG, value)


def install(approved, names, boot_id):
    require(not STATE.exists() and not any(unit_path(u).exists() for u in (MONITOR_UNIT, COLLECTOR_UNIT)),
            'Existing archive state or units cannot be replaced.')
    archive.initialize(STATE, approved, segment_rows=SEGMENT_ROWS, max_rows=MAX_ROWS)
    PRIVATE.mkdir(mode=0o700)
    configure_collector(names, boot_id, 'before')
    for unit in (MONITOR_UNIT, COLLECTOR_UNIT):
        write_new(unit_path(unit), unit_text(unit)); unit_path(unit).chmod(0o644)
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', MONITOR_UNIT])
    command(['systemctl', 'start', MONITOR_UNIT])
    status, _ = ready()
    unknown(status)
    require(status['committed_count'] == 1, 'New archive must contain only its initial startup boundary.')
    return status


def wait_collector_complete(phase):
    target = collector.BEFORE_STOP_CYCLE if phase == 'before' else collector.AFTER_STOP_CYCLE
    deadline = time.monotonic() + (target if phase == 'before' else target - collector.BEFORE_STOP_CYCLE) * 1.6 + 45
    next_manager_check = time.monotonic()
    while time.monotonic() < deadline:
        path = PRIVATE / 'runtime.json'
        if path.exists():
            runtime = read_private(path, 4096)
            if runtime.get('state') == 'complete' and runtime.get('phase') == phase:
                require(runtime['cycle'] == target, 'Collector completed at an unexpected global cycle.')
                command(['systemctl', 'stop', COLLECTOR_UNIT], timeout=30)
                require(not (PRIVATE / 'pending.json').exists() and not (PRIVATE / 'pending.json').is_symlink(),
                        'Unacknowledged pending observation must not cross the planned reboot.')
                allocation = read_private(PRIVATE / 'allocation.json', 1024)
                require(allocation == {'cycles': target, 'next_port': collector.PORT_START + collector.PORT_BLOCK * target},
                        'Durable source port allocation differs from completed cycles.')
                return runtime, allocation
        if time.monotonic() >= next_manager_check:
            managed = {unit: manager(unit) for unit in (MONITOR_UNIT, COLLECTOR_UNIT)}
            invalid = [unit for unit, value in managed.items() if value['NRestarts'] != 0 or value['ActiveState'] == 'failed'
                       or (unit == MONITOR_UNIT and value['ActiveState'] != 'active')]
            if invalid:
                raise RuntimeError('A supervised service failed or restarted during the required single-instance phase: '
                                   + json.dumps(diagnostics(), sort_keys=True))
            next_manager_check = time.monotonic() + 5
        time.sleep(0.1)
    raise RuntimeError('Autonomous collector completion timed out: ' + json.dumps(diagnostics(), sort_keys=True))


def all_receipts():
    return [read_private(path) for path in sorted(PRIVATE.glob('receipt-[0-9][0-9][0-9][0-9].json'))]


def validate_inventory(journal, records, boots):
    expected_count = collector.BEFORE_STOP_CYCLE if len(boots) == 1 else collector.AFTER_STOP_CYCLE
    require(len(records) == expected_count and [r['cycle'] for r in records] == list(range(1, expected_count + 1)),
            'Autonomous receipt cycles are missing or duplicated.')
    rows = {r['request_id']: r for r in journal['rows'] if r['request_id'].startswith('archive_')}
    require(len(rows) == expected_count, 'Committed autonomous observation inventory differs.')
    probes, ports, instances = [], set(), {}
    for record in records:
        phase = 'before' if record['cycle'] <= collector.BEFORE_STOP_CYCLE else 'after'
        local = record['cycle'] if phase == 'before' else record['cycle'] - collector.BEFORE_STOP_CYCLE
        require(record['boot_id'] == record['delivery_boot_id'] == boots[phase] and record['process_cycle'] == local,
                'Receipt was produced or delivered in an unexpected boot.')
        instances.setdefault(phase, set()).add(record['instance_id'])
        payload, cycle = record['request'], record['cycle']
        row = rows.get(payload['request_id'])
        require(row and row['sequence'] == record['committed_sequence'] and row['request']['observation'] == payload['observation']
                and row['evaluation'] == record['evaluation'], 'Receipt differs from committed archive history.')
        sample = payload['observation']
        require(sample['ruleset'] is not None and sample['collection_error'] is None
                and payload['request_id'] == f"archive_reboot_{record['instance_id']}_{cycle}", 'Receipt does not contain real ruleset collection.')
        expected = set(automatic.monitoring.CANARIES) if local >= 3 and (local == 3 or cycle % collector.CANARY_EVERY == 0) else set()
        require({(p['from'], p['to'], p['port']) for p in sample['probes']} == expected, 'Actual canary schedule differs.')
        if not expected:
            require(row['evaluation']['status'] != 'healthy', 'Rules alone cannot assert healthy coverage.')
        for probe in sample['probes']:
            for item in (probe, probe.get('destination_health')):
                if item is None:
                    continue
                port = item['source_port']
                require(port not in ports and collector.PORT_START + collector.PORT_BLOCK * (cycle - 1)
                        <= port < collector.PORT_START + collector.PORT_BLOCK * cycle, 'Probe port was reused or escaped its durable reservation.')
                ports.add(port); probes.append(item)
    require(all(len(values) == 1 for values in instances.values())
            and len(set.union(*instances.values())) == len(instances), 'Collector identity must be stable per boot and new after reboot.')
    return probes


def stop_export():
    final, properties = request('status'), manager(MONITOR_UNIT)
    command(['systemctl', 'stop', MONITOR_UNIT], timeout=30)
    stopped = manager(MONITOR_UNIT)
    require(stopped['ActiveState'] == 'inactive' and stopped['MainPID'] == 0, 'Offline export requires a stopped monitor.')
    with archive.ArchiveJournal(STATE) as verified:
        require(verified.total_count == final['committed_count'] and verified.head_digest == final['head_digest'],
                'Accepted live head differs from stopped verified history.')
        exported = verified.export()
    return final, properties, stopped, exported


def storage_info():
    value = json.loads(command(['findmnt', '--json', '--target', str(STATE),
                               '--output', 'TARGET,SOURCE,FSTYPE,OPTIONS,UUID']).stdout)
    require(set(value) == {'filesystems'} and len(value['filesystems']) == 1, 'Ambiguous persistent state mount.')
    record = value['filesystems'][0]
    require(record['fstype'] in {'ext4', 'xfs', 'btrfs'} and record['source'].startswith('/dev/') and record['uuid']
            and 'rw' in record['options'].split(','), 'Archive state requires a persistent writable disk filesystem.')
    return record


def readonly_history():
    """Small read-only SQLite snapshot while the live monitor owns its writer lock."""
    reboot.ordinary(STATE / 'monitor.sqlite3')
    connection = sqlite3.connect((STATE / 'monitor.sqlite3').as_uri() + '?mode=ro', uri=True)
    try:
        connection.execute('BEGIN')
        config = connection.execute('SELECT identity,approved,head_sequence,head_digest,archived_sequence,archived_digest FROM config WHERE id=1').fetchone()
        raw = connection.execute('SELECT sequence,request_id,request,sample,evaluation,events,previous_digest,row_digest FROM observations ORDER BY sequence').fetchall()
        require(len(raw) <= SEGMENT_ROWS, 'Active snapshot exceeds archive segment bound.')
        keys = ('sequence', 'request_id', 'request', 'sample', 'evaluation', 'events', 'previous_digest', 'row_digest')
        rows = [dict(zip(keys, (*item[:2], *(store.parse(v) for v in item[2:6]), *item[6:]))) for item in raw]
        names = ('segment_index', 'first_sequence', 'last_sequence', 'row_count', 'byte_count', 'file_digest', 'last_digest')
        segments = [dict(zip(names, row)) for row in connection.execute('SELECT * FROM segments ORDER BY segment_index')]
        return {'identity': store.parse(config[0]), 'approved_policy': store.parse(config[1]), 'head_sequence': config[2],
                'head_digest': config[3], 'archived_sequence': config[4], 'archived_digest': config[5], 'rows': rows, 'segments': segments}
    finally:
        connection.close()


def startup_snapshot():
    # The independent freshness timer may append its single missing-data row
    # between reads. Retry that race; never mix different committed heads.
    for unused in range(3):
        before = request('status')
        snapshot = readonly_history()
        after = request('status')
        if (before['committed_count'] == snapshot['head_sequence'] == after['committed_count']
                and before['head_digest'] == snapshot['head_digest'] == after['head_digest']):
            unknown(after)
            return after, snapshot
    raise RuntimeError('Could not capture a coherent, read-only startup head.')


def verify_reboot(before, before_history, boot, status, properties, snapshot, storage, hashes):
    require(boot['boot_id'] != before['boot']['boot_id'], 'A full Linux boot change was not observed.')
    require(not VOLATILE.exists() and not VOLATILE.is_symlink(), 'Preboot volatile marker survived.')
    require(hashes == before['source_sha256'], 'Guest source changed across reboot.')
    require(all(storage[key] == before['storage'][key] for key in ('target', 'source', 'fstype', 'uuid')), 'Persistent filesystem changed.')
    require(properties['InvocationID'] != before['manager']['InvocationID']
            and status['instance_id'] != before['final_status']['instance_id'], 'Monitor did not start a new boot instance.')
    unknown(status)
    require(reboot.critical(status)['id'] == before['critical_incident_id'], 'Reboot changed the original critical incident.')
    require(snapshot['identity'] == before_history['identity'] and snapshot['approved_policy'] == before_history['approved_policy']
            and snapshot['segments'] == before_history['archive_descriptors'], 'Archive identity, approved policy, or descriptors changed.')
    archived = snapshot['archived_sequence']
    require(archived == 256 and snapshot['archived_digest'] == before_history['rows'][archived - 1]['row_digest'], 'Archived prefix head changed.')
    old = before_history['rows'][archived:]
    require(snapshot['rows'][:len(old)] == old, 'Preboot active history prefix changed.')
    suffix = snapshot['rows'][len(old):]
    require(1 <= len(suffix) <= 2 and suffix[0]['request']['kind'] == 'restart'
            and suffix[0]['previous_digest'] == before['final_status']['head_digest'], 'Reboot did not append one startup boundary to the accepted head.')
    if len(suffix) == 2:
        require(suffix[1]['sample']['phase'] == 'collector_missing' and suffix[1]['sample']['collection_error'] == 'freshness_deadline_exceeded',
                'Unexpected pre-collection startup observation.')
    require(all(r['evaluation']['status'] == 'unknown' and r['sample']['ruleset'] is None and not r['sample']['probes'] for r in suffix),
            'Startup without networking fabricated healthy evidence.')
    require(snapshot['head_sequence'] == status['committed_count'] == len(before_history['rows']) + len(suffix)
            and snapshot['head_digest'] == status['head_digest'] == suffix[-1]['row_digest'], 'Startup snapshot and live head differ.')
    for index, proof in enumerate(before['archive_files'], 1):
        require(file_proof(STATE / 'archives' / f'segment-{index:06d}.json') == {k: v for k, v in proof.items() if k != 'public_name'},
                'A preboot archive segment changed across reboot.')


def archived_retry(first):
    raced = []
    for attempt in range(2):
        before = request('status')
        result = service.request(STATE, first['request'], timeout=10)
        after = request('status')
        require(result.get('ok') is True and result['duplicate'] is True and result['committed_sequence'] == first['committed_sequence']
                and result['evaluation'] == first['evaluation'], 'Archived request did not return its original historical acknowledgement.')
        unknown(before); unknown(after)
        require(before['freshness']['last_accepted_request_id'] == after['freshness']['last_accepted_request_id'] is None,
                'Historical retry renewed live freshness.')
        if before['committed_count'] == after['committed_count'] and before['head_digest'] == after['head_digest']:
            return {'request': first['request'], 'before_status': before, 'result': result, 'after_status': after,
                    'independent_gap_during_prior_attempt': raced}
        snapshot = readonly_history()
        last = snapshot['rows'][-1]
        require(attempt == 0 and after['committed_count'] == before['committed_count'] + 1
                and snapshot['head_sequence'] == last['sequence'] == after['committed_count']
                and snapshot['head_digest'] == last['row_digest'] == after['head_digest']
                and last['previous_digest'] == before['head_digest'] and last['sample']['phase'] == 'collector_missing'
                and last['sample']['collection_error'] == 'freshness_deadline_exceeded' and last['sample']['ruleset'] is None
                and last['sample']['probes'] == [] and last['evaluation']['status'] == 'unknown',
                'Historical retry unexpectedly changed committed history.')
        raced.append({'before_status': before, 'result': result, 'after_status': after, 'independent_gap_row': last})
    raise RuntimeError('Historical retry failed to stabilize.')


def publish_segments(number):
    result = []
    require(len(list((STATE / 'archives').glob('segment-*.json'))) == number, 'Archive segment inventory differs.')
    for index, name in enumerate(ARCHIVE_FILES[:number], 1):
        source = STATE / 'archives' / f'segment-{index:06d}.json'
        proof = file_proof(source)
        target = PUBLISH / name
        if target.exists():
            require(target.read_bytes() == source.read_bytes(), 'Previously published archive segment changed.')
        else:
            store.write_new(target, source.read_bytes())
        result.append({'public_name': name, **proof})
    store.sync_directory(PUBLISH)
    return result


def run_before(lab, boot):
    lab.setup(); lab.start_services(); lab.apply_policy()
    approved = lab.ruleset()
    lab.start_captures()
    initial = stage_call('before_install', lambda: install(approved, lab.names, boot['boot_id']))
    command(['systemctl', 'start', COLLECTOR_UNIT])
    baseline = stage_call('before_baseline', lambda: wait_status(lambda s: s['current_evaluation']['status'] == 'healthy'))
    lab.apply_policy('misconfigured')
    detected = stage_call('before_incident', lambda: wait_status(lambda s: any(a['key'] == reboot.CRITICAL and a['state'] == 'open' for a in s['alerts'])))
    incident = reboot.critical(detected)['id']
    runtime, allocation = stage_call('before_collection', lambda: wait_collector_complete('before'))
    final, properties, stopped, journal = stage_call('before_export', stop_export)
    require(reboot.critical(final)['id'] == incident and len(journal['rows']) == collector.BEFORE_STOP_CYCLE + 1,
            'Preboot history or unresolved incident differs.')
    records = all_receipts()
    lab.probes = stage_call('before_inventory', lambda: validate_inventory(journal, records, {'before': boot['boot_id']}))
    captured = stage_call('before_capture', lab.stop_captures)
    return journal, {'approved_policy': approved, 'initial_status': initial, 'baseline_status': baseline,
            'incident_status': detected, 'final_status': final, 'manager': properties, 'monitor_stopped_for_export': stopped,
            'collector_manager': manager(COLLECTOR_UNIT), 'collector_runtime': runtime, 'allocation': allocation,
            'collector_receipts': records, 'critical_incident_id': incident, 'capture': captured,
            'archive_files': publish_segments(2), 'no_pending_before_reboot': True}


def run_after(lab, before, before_history, boot, hashes):
    # Neither starting/restarting the monitor nor initializing archive state is allowed in this stage.
    _, properties = stage_call('after_startup', ready)
    startup, snapshot = startup_snapshot()
    verify_reboot(before, before_history, boot, startup, properties, snapshot, storage_info(), hashes)
    duplicate = archived_retry(before['collector_receipts'][0])
    if duplicate['before_status']['head_digest'] != startup['head_digest']:
        startup, snapshot = startup_snapshot()
        verify_reboot(before, before_history, boot, startup, properties, snapshot, storage_info(), hashes)
    automatic_start = {'status': startup, 'manager': properties, 'readonly_history': snapshot,
                       'inspected_before_collection_at_utc': reboot.timestamp(), 'no_manual_service_start': True}
    names = {line.split()[0] for line in command(['ip', 'netns', 'list']).stdout.splitlines() if line.strip()}
    require(not names.intersection(before['network_names'].values()), 'Old network namespaces unexpectedly survived OS reboot.')
    require(manager(COLLECTOR_UNIT)['ActiveState'] == 'inactive', 'Collector ran before explicit network reconstruction.')
    require(read_private(PRIVATE / 'allocation.json', 1024) == before['allocation']
            and not (PRIVATE / 'pending.json').exists() and not (PRIVATE / 'pending.json').is_symlink(),
            'Durable allocation or quiescent pending state changed across reboot.')
    lab.setup(); lab.start_services(); lab.apply_policy()
    require(automatic.monitoring.monitor.policy_fingerprint(lab.ruleset()) == before_history['identity']['approved_policy_sha256'],
            'Recreated approved rules differ from the original reference.')
    lab.start_captures()
    configure_collector(lab.names, boot['boot_id'], 'after')
    command(['systemctl', 'start', COLLECTOR_UNIT])
    runtime, allocation = stage_call('after_collection', lambda: wait_collector_complete('after'))
    final, managed, stopped, journal = stage_call('after_export', stop_export)
    require(final['current_evaluation']['status'] == 'healthy', 'Final postboot full canaries did not establish healthy coverage.')
    require(journal['identity'] == before_history['identity'] and journal['approved_policy'] == before_history['approved_policy']
            and journal['rows'][:len(before_history['rows'])] == before_history['rows'], 'Final archive lost the exact preboot identity or history prefix.')
    records = all_receipts()
    all_probes = stage_call('after_inventory', lambda: validate_inventory(journal, records, {'before': before['boot']['boot_id'], 'after': boot['boot_id']}))
    following = records[collector.BEFORE_STOP_CYCLE:]
    post_phases = {r['request']['request_id'] for r in following}
    lab.probes = [p for p in all_probes if p['phase'] in post_phases]
    for record in following[:2]:
        require(not record['request']['observation']['probes'] and reboot.CRITICAL in record['evaluation']['active_alert_keys'],
                'A rule-only postboot baseline incorrectly resolved the old incident.')
    require(following[1]['evaluation']['telemetry_valid'] and following[1]['evaluation']['policy_matches'],
            'Fresh postboot rule baseline did not become valid.')
    require(all(value is None for value in following[0]['evaluation']['counter_deltas'].values()),
            'Postboot counters must not be compared with the previous kernel baseline.')
    resolutions = [e for e in journal['events'] if e['key'] == reboot.CRITICAL and e['action'] == 'resolved']
    require(len(resolutions) == 1 and resolutions[0]['alert_id'] == before['critical_incident_id']
            and resolutions[0]['sequence'] == following[2]['committed_sequence']
            and following[2]['evaluation']['status'] == 'healthy', 'Original incident did not resolve exactly on fresh postboot canaries.')
    require(sum(r['request']['kind'] == 'restart' for r in journal['rows']) == 2, 'Unexpected monitor restart in full archived history.')
    captured = stage_call('after_capture', lab.stop_captures)
    return journal, {'automatic_start': automatic_start, 'archived_duplicate': duplicate, 'final_status': final,
            'manager': managed, 'monitor_stopped_for_export': stopped, 'collector_manager': manager(COLLECTOR_UNIT),
            'collector_runtime': runtime, 'allocation': allocation, 'collector_receipts': following,
            'critical_incident_id': before['critical_incident_id'], 'capture': captured, 'archive_files': publish_segments(3),
            'first_rule_only_receipts': following[:2], 'preboot_prefix_preserved': True, 'network_missing_before_rebuild': True,
            'network_rebuilt_by_harness': True, 'collector_started_after_network_rebuild': True}


def stage(name, token):
    virtualization = guard(token)
    require(name in ('before', 'after'), 'Unknown archive reboot stage.')
    if name == 'before':
        require(not DATA.exists() and not VOLATILE.exists() and not any(unit_path(u).exists() for u in (MONITOR_UNIT, COLLECTOR_UNIT)),
                'Existing archive reboot installation cannot be reset.')
        DATA.mkdir(mode=0o700); REPORT.mkdir(mode=0o700); PUBLISH.mkdir(mode=0o700)
        write_new(VOLATILE, 'HELTEMES disposable archived history preboot marker\n')
        store.sync_directory(DATA.parent)
    else:
        for path in (DATA, STATE, PRIVATE, REPORT, PUBLISH):
            store.state_path(path)
        require(not (PUBLISH / 'AFTER.json').exists(), 'Completed reboot recovery cannot be repeated.')
    staging = REPORT / name; staging.mkdir(mode=0o700)
    boot, hashes = reboot.boot_info(virtualization), source_hashes()
    lab = automatic.monitoring.MonitoringLab(reboot.base.preflight(), staging)
    completed = False
    try:
        if name == 'before':
            journal, outcome = run_before(lab, boot)
        else:
            before = read_private(PUBLISH / 'BEFORE.json', 16 * 1024 * 1024)
            before_history = read_private(PUBLISH / 'BEFORE-HISTORY.json', 16 * 1024 * 1024)
            require(file_proof(PUBLISH / 'BEFORE-HISTORY.json') == before['history_file'], 'Preboot history file changed.')
            journal, outcome = run_after(lab, before, before_history, boot, hashes)
        completed = True
    finally:
        if name == 'after' or not completed:
            for unit in (COLLECTOR_UNIT, MONITOR_UNIT):
                if unit_path(unit).exists():
                    command(['systemctl', 'stop', unit], check=False, timeout=30)
            cleaned = lab.cleanup()
            require(cleaned['ok'], 'Owned disposable network cleanup failed.')
        else:
            cleaned = {'ok': True, 'deferred_to_vm_reboot': True, 'namespaces': list(lab.names.values())}
    capture_hashes = {}
    for name_part in CAPTURE_FILES:
        path = staging / name_part
        capture_hashes[name + '-' + name_part] = automatic.seal_capture(path)
        path.rename(PUBLISH / (name + '-' + name_part))
    store.sync_directory(staging); store.sync_directory(PUBLISH)
    history_path = PUBLISH / (name.upper() + '-HISTORY.json')
    store.write_new(history_path, (store.encoded(journal) + '\n').encode())
    result = {'format': 'heltemes-monitor-archive-reboot-guest', 'version': 1, 'ok': True, 'stage': name,
              'boot': boot, 'source_sha256': hashes, 'storage': storage_info(), 'configuration': configuration(),
              'network_cleanup': cleaned, 'network_names': lab.names, 'capture_sha256': capture_hashes,
              'history_file': file_proof(history_path), 'journal_export_method': 'stopped_verified_journal',
              'completed_at_utc': reboot.timestamp(), **outcome}
    require(source_hashes() == hashes, 'Guest source changed during exercise.')
    if name == 'before':
        write_new(PUBLISH / 'APPROVED_POLICY.json', outcome['approved_policy'])
        write_new(PUBLISH / 'monitor.service', unit_text(MONITOR_UNIT))
        write_new(PUBLISH / 'collector.service', unit_text(COLLECTOR_UNIT))
    store.write_new(PUBLISH / (name.upper() + '.json'), (store.encoded(result) + '\n').encode())
    file_proof(PUBLISH / (name.upper() + '.json'))
    store.sync_directory(PUBLISH)
    require({p.name for p in PUBLISH.iterdir()} == set(BEFORE_FILES if name == 'before' else PUBLIC_FILES), 'Public reboot inventory differs.')
    return {'ok': True, 'stage': name, 'boot_id': boot['boot_id'], 'committed_count': len(journal['rows']),
            'autonomous_observations': len(outcome['collector_receipts']), 'archive_segments': len(outcome['archive_files']),
            'current_status': outcome['final_status']['current_evaluation']['status'], 'network_cleanup': cleaned,
            'critical_incident_id': outcome['critical_incident_id']}


def worker():
    reboot.ordinary(reboot.MARKER)
    require(reboot.MARKER.stat().st_size < 4096, 'Oversized disposable marker.')
    guard(store.parse(reboot.MARKER.read_bytes())['token'])
    service.serve(STATE, freshness_seconds=FRESHNESS, archive_history=True)


def cleanup(token):
    guard(token)
    for unit in (COLLECTOR_UNIT, MONITOR_UNIT):
        path = unit_path(unit)
        if path.exists():
            reboot.ordinary(path, mode=0o644)
            require(path.read_text() == unit_text(unit), 'An unexpected unit cannot be removed.')
            command(['systemctl', 'disable', '--now', unit], timeout=30)
            require(command(['systemctl', 'is-active', unit], check=False).stdout.strip() not in ('active', 'activating', 'deactivating'),
                    'Owned service did not stop.')
            path.unlink()
    command(['systemctl', 'daemon-reload'])
    for path in (STATE, PRIVATE, RUNTIME):
        if path.exists():
            store.state_path(path); shutil.rmtree(path)
    for path in (CONFIG, VOLATILE):
        if path.exists():
            reboot.ordinary(path); path.unlink()
    require(not any(p.exists() for p in (STATE, PRIVATE, RUNTIME, CONFIG, VOLATILE, unit_path(MONITOR_UNIT), unit_path(COLLECTOR_UNIT))),
            'Owned archive reboot state cleanup did not finish.')
    return {'ok': True, 'services_disabled_removed': True, 'state_removed': True,
            'collector_config_removed': True, 'runtime_removed': True, 'volatile_marker_removed': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('before', 'after', 'cleanup', 'worker'))
    parser.add_argument('--token')
    args = parser.parse_args()
    try:
        if args.stage == 'worker':
            require(args.token is None, 'Worker only reads its root-owned marker.')
            worker(); return
        result = cleanup(args.token) if args.stage == 'cleanup' else stage(args.stage, args.token)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Disposable archive reboot stopped: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
