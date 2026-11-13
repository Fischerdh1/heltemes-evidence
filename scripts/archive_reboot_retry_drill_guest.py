"""Exercise real archived-collector retries in the marked disposable Linux guest."""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor_archive as archive
from scripts import network_monitor_archive_reboot_collector as collector
from scripts import network_monitor_archive_reboot_guest as reboot_guest
from scripts import network_monitor_reboot_guest as reboot
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store

CASES = ('request_deadline', 'source_timestamp_in_future')
FUTURE_LEAD_SECONDS = 2.0
require = reboot.require
MONITOR_PROGRAM = """
import sys
sys.path.insert(0, sys.argv[1])
from scripts.network_monitor_service import serve
serve(sys.argv[2], freshness_seconds=float(sys.argv[3]), archive_history=True, diagnose_rejections=True)
"""


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def frame(payload):
    return (store.encoded(payload) + '\n').encode()


def snapshot(status):
    require(status['ok'] is True and status['archives']['enabled'] is True
            and status['freshness']['threshold_seconds'] == reboot_guest.FRESHNESS
            and status['freshness']['gap_recorded'] is False
            and status['freshness']['persistence_error'] is None,
            'The drill monitor did not retain normal archive and freshness settings.')
    return {key: status[key] for key in ('committed_count', 'head_digest', 'process_id', 'instance_id')}


def wait_ready(process, state):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        require(process.poll() is None, 'The drill monitor exited before becoming ready.')
        try:
            status = service.request(state, {'command': 'status'}, timeout=0.5)
        except (OSError, ValueError):
            time.sleep(0.05)
            continue
        ready = snapshot(status)
        require(ready['process_id'] == process.pid and ready['committed_count'] == 1,
                'The monitor did not start with a single restart boundary.')
        return ready
    raise RuntimeError('The drill monitor did not become ready within eight seconds.')


def send_incomplete(state, data):
    path = service.socket_path(state)
    info = path.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o600, 'The drill socket has an unexpected identity.')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        # Keep the write side open so the real server reaches its receive deadline.
        connection.settimeout(service.IO_SECONDS + 3)
        connection.connect(str(path))
        connection.sendall(data[:-1])
        return service.receive(connection, service.MAX_RESPONSE)


def wait_until_source_time(source_timestamp):
    started = time.monotonic()
    while (remaining := source_timestamp + 0.05 - time.time()) > 0:
        require(time.monotonic() - started < 3, 'The future timestamp did not become eligible in time.')
        time.sleep(min(remaining, 0.05))
    return time.monotonic() - started


def run_case(worker, reason):
    request = service.request
    state = worker.state
    pending_path = worker.pending
    before = snapshot(request(state, {'command': 'status'}, timeout=3))
    require(not pending_path.exists(), 'A previous request is still pending.')
    if reason == 'source_timestamp_in_future':
        # The single original timestamp is synthesized before its durable write.
        # The monitor subprocess uses its unmodified guest wall clock.
        with patch.object(reboot, 'timestamp', side_effect=lambda: (
                datetime.now(timezone.utc) + timedelta(seconds=FUTURE_LEAD_SECONDS)).isoformat()):
            pending = worker.prepare()
    else:
        pending = worker.prepare()
    original = pending['request']
    observation = original['observation']
    observed_at = observation['observed_at_utc']
    source_timestamp = store.monitor.utc(observed_at)
    pending_bytes = store.read_private(pending_path, limit=store.MAX_REQUEST)
    original_frame = frame(original)
    require(store.parse(pending_bytes) == pending and not observation['probes'],
            'The collector did not persist its original rules-only observation.')

    evidence = {}
    attempts = 0

    def read_unchanged_pending(field):
        current = store.read_private(pending_path, limit=store.MAX_REQUEST)
        require(current == pending_bytes, 'The durable pending bytes changed during delivery.')
        evidence[field] = sha256(current)

    def transport(target, payload, *, timeout):
        nonlocal attempts
        attempts += 1
        data = frame(payload)
        require(target == state and timeout == 3 and data == original_frame and attempts <= 2,
                'Collector retry altered the original frame or delivery contract.')
        if attempts == 1:
            read_unchanged_pending('pending_sha256_before')
            started = time.monotonic()
            if reason == 'request_deadline':
                result = send_incomplete(target, data)
                evidence['initial_sent_bytes'] = len(data) - 1
                evidence['future_lead_at_first_send_seconds'] = None
            else:
                lead = source_timestamp - time.time()
                require(lead > 0, 'The initial source timestamp was no longer in the future.')
                result = request(target, payload, timeout=timeout)
                evidence['initial_sent_bytes'] = len(data)
                evidence['future_lead_at_first_send_seconds'] = lead
            elapsed = time.monotonic() - started
            evidence['first_attempt_elapsed_seconds'] = elapsed
            require(reason != 'request_deadline' or elapsed >= service.IO_SECONDS,
                    'The first request did not wait through the receive deadline.')
            require(result == {'ok': False, 'error': 'request_rejected', 'reason': reason},
                    'The real monitor did not return the expected retryable rejection.')
            evidence['initial_rejection'] = result
            read_unchanged_pending('pending_sha256_after_rejection')
            rejected = snapshot(request(state, {'command': 'status'}, timeout=3))
            require(rejected == before, 'The rejected request changed journal or monitor identity.')
            evidence['after_rejection'] = rejected
            return result

        evidence['retry_hold_seconds'] = (wait_until_source_time(source_timestamp)
                                          if reason == 'source_timestamp_in_future' else 0.0)
        read_unchanged_pending('pending_sha256_before_retry')
        evidence['retry_frame_sha256'] = sha256(data)
        return request(target, payload, timeout=timeout)

    with patch.object(service, 'request', new=transport):
        receipt = worker.collect()
    after_retry = snapshot(request(state, {'command': 'status'}, timeout=3))
    sequence = receipt['committed_sequence']
    require(attempts == receipt['delivery_attempts'] == 2 and receipt['transport_failures'] == [reason]
            and receipt['duplicate_acknowledgement'] is False and receipt['request'] == original
            and sequence == after_retry['committed_count'] == before['committed_count'] + 1
            and after_retry['head_digest'] != before['head_digest'],
            'The collector did not commit the original request exactly once after rejection.')
    require(all(after_retry[key] == before[key] for key in ('process_id', 'instance_id')),
            'The monitor restarted during retry delivery.')
    require(not pending_path.exists() and not pending_path.is_symlink()
            and worker.allocation.read()['cycles'] == pending['cycle'],
            'The collector did not retire the pending request after its single reservation.')
    receipt_bytes = store.read_private(worker.allocation.directory / f'receipt-{sequence:04d}.json',
                                       limit=store.MAX_REQUEST)
    require(store.parse(receipt_bytes) == receipt, 'The durable receipt differs from the collector result.')
    diagnostic = collector.private_json(worker.allocation.directory / 'transport.json')
    require(diagnostic == {'cycle': pending['cycle'], 'attempts': 1, 'deadline_exceeded': False,
                           'error_type': 'request_rejected', 'errno': None, 'reason': reason},
            'The collector did not record the retryable rejection in its durable diagnostic.')

    replay_frame = frame(original)
    require(replay_frame == original_frame, 'The duplicate replay changed the original request bytes.')
    response = request(state, original, timeout=3)
    replay = {key: response[key] for key in ('ok', 'committed_sequence', 'duplicate', 'result_is_historical')}
    after_replay = snapshot(request(state, {'command': 'status'}, timeout=3))
    require(replay == {'ok': True, 'committed_sequence': sequence, 'duplicate': True,
                       'result_is_historical': True}
            and response['evaluation'] == receipt['evaluation'] and after_replay == after_retry,
            'The duplicate replay did not return the original receipt without changing the journal.')
    identity = {'request_id': original['request_id'], 'observed_at_utc': observed_at,
                'observation_sha256': store.digest(observation)}
    return {**identity, **evidence, 'frame_sha256': sha256(original_frame),
            'replay_frame_sha256': sha256(replay_frame), 'frame_bytes': len(original_frame),
            'before': before, 'after_retry': after_retry, 'after_replay': after_replay,
            'transport_diagnostic': diagnostic, 'pending_removed': True, 'replay': replay,
            'receipt': {**identity, 'sha256': sha256(receipt_bytes), **{key: receipt[key] for key in
                        ('committed_sequence', 'delivery_attempts', 'transport_failures', 'duplicate_acknowledgement')}}}


def verify_offline(state, ready, cases):
    with archive.ArchiveJournal(state) as journal:
        rows = list(journal.iter_rows())
        final = cases[CASES[-1]]['after_replay']
        require(len(rows) == journal.total_count == final['committed_count'] == 3
                and journal.head_digest == final['head_digest']
                and rows[0]['request_id'] == '_restart_' + ready['instance_id']
                and rows[0]['row_digest'] == ready['head_digest'],
                'The offline journal did not verify one restart and exactly two observation rows.')
        observations = []
        for row, case in zip(rows[1:], cases.values()):
            observation = row['request']['observation']
            evidence = {'sequence': row['sequence'], 'request_id': row['request_id'],
                        'observed_at_utc': observation['observed_at_utc'],
                        'observation_sha256': store.digest(observation),
                        'previous_digest': row['previous_digest'], 'row_digest': row['row_digest']}
            require(evidence == {'sequence': case['receipt']['committed_sequence'],
                                 'request_id': case['request_id'], 'observed_at_utc': case['observed_at_utc'],
                                 'observation_sha256': case['observation_sha256'],
                                 'previous_digest': case['before']['head_digest'],
                                 'row_digest': case['after_retry']['head_digest']},
                    'An offline row differs from the original collector request or observed journal head.')
            observations.append(evidence)
        return {'committed_count': len(rows), 'head_digest': journal.head_digest, 'observation_rows': observations}


def exercise(boot_id, virtualization):
    from tests.test_network_monitor import ruleset

    with tempfile.TemporaryDirectory(prefix='he-retry-', dir=Path('/tmp').resolve()) as directory:
        temporary = Path(directory)
        state = temporary / 'state'
        private = temporary / 'collector'
        private.mkdir(mode=0o700)
        archive.initialize(state, ruleset(), segment_rows=reboot_guest.SEGMENT_ROWS, max_rows=reboot_guest.MAX_ROWS)
        allocation = collector.Allocation(private)
        try:
            worker = collector.Collector(SimpleNamespace(ruleset=ruleset), allocation, boot_id=boot_id,
                                         phase='before', state=state)
            arguments = (sys.executable, '-I', '-S', '-B', '-c', MONITOR_PROGRAM, str(ROOT),
                         str(state), str(reboot_guest.FRESHNESS))
            with subprocess.Popen(arguments, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE) as process:
                try:
                    ready = wait_ready(process, state)
                    cases = {reason: run_case(worker, reason) for reason in CASES}
                    require(cases[CASES[0]]['before'] == ready
                            and cases[CASES[1]]['before'] == cases[CASES[0]]['after_replay']
                            and process.poll() is None, 'The monitor or journal changed between cases.')
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        _, diagnostics = process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.communicate(timeout=5)
                        raise RuntimeError('The drill monitor did not stop within five seconds.') from None
            lines = diagnostics.decode().splitlines()
            socket_path = service.socket_path(state)
            require(process.returncode == 0 and not socket_path.exists() and not socket_path.is_symlink()
                    and lines == ['Monitor request rejected: ' + reason for reason in CASES],
                    'The monitor did not shut down cleanly or its diagnostic log differed.')
            offline = verify_offline(state, ready, cases)
        finally:
            allocation.close()
    require(not temporary.exists(), 'The drill temporary state was not removed.')
    return {'format': 'heltemes-archive-reboot-retry-drill-guest', 'version': 1, 'ok': True,
            'boot_id': boot_id, 'virtualization': virtualization, 'freshness_seconds': reboot_guest.FRESHNESS,
            'monitor': {'process_id': ready['process_id'], 'instance_id': ready['instance_id'],
                        'unchanged': True, 'diagnostics': lines, 'returncode': process.returncode,
                        'socket_removed': True},
            'cases': cases, 'offline_journal': offline, 'cleanup': {'temporary_state_removed': True}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--token', required=True)
    arguments = parser.parse_args()
    try:
        virtualization = reboot_guest.guard(arguments.token)
        report = exercise(collector.current_boot_id(), virtualization)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, ImportError,
            store.sqlite3.Error, subprocess.SubprocessError) as error:
        parser.exit(1, 'Disposable archive retry drill stopped: ' + str(error) + '\n')
    print(store.encoded(report))


if __name__ == '__main__':
    main()
