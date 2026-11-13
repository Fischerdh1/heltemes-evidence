"""Run the archive reboot collector's retry drill in an owned Linux VM."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor_archive_reboot_vm as archive_vm
from scripts import network_monitor_reboot_vm as reboot

require = reboot.require
GUEST_SCRIPT = 'scripts/archive_reboot_retry_drill_guest.py'
EXTRA_FILES = (GUEST_SCRIPT, 'tests/test_network_monitor.py')
HOST_SCRIPT = 'scripts/archive_reboot_retry_drill_vm.py'
REASONS = ('request_deadline', 'source_timestamp_in_future')
SHA256 = re.compile(r'[a-f0-9]{64}')
FILES = ('REPORT.json', 'DRILL.json', 'VM.json')


def source_identity():
    source = archive_vm.source_identity()
    for name in (*EXTRA_FILES, HOST_SCRIPT):
        raw = (ROOT / name).read_bytes()
        committed = subprocess.check_output(['git', 'show', f"{source['commit']}:{name}"],
                                            cwd=ROOT, timeout=30)
        require(raw == committed, 'Retry drill source differs from the tested commit.')
        source['source_sha256'][name] = hashlib.sha256(raw).hexdigest()
    return source


def drill_archive():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name in EXTRA_FILES:
            raw = (ROOT / name).read_bytes()
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(raw), 0o644
            archive.addfile(entry, io.BytesIO(raw))
    return output.getvalue()


def validate_drill(drill, boot_id, *, request_deadline_seconds, freshness_seconds):
    require(drill['format'] == 'heltemes-archive-reboot-retry-drill-guest'
            and drill['version'] == 1 and drill['ok'] is True
            and drill['boot_id'] == boot_id and drill['virtualization'] in {'qemu', 'kvm'}
            and drill['freshness_seconds'] == freshness_seconds, 'Guest identity or drill result differs.')
    monitor = drill['monitor']
    require(monitor['diagnostics'] == ['Monitor request rejected: ' + reason for reason in REASONS]
            and monitor['returncode'] == 0 and monitor['socket_removed'] is True
            and monitor['unchanged'] is True and drill['cleanup']['temporary_state_removed'] is True,
            'Monitor diagnostics, process continuity or guest cleanup differs.')
    require(set(drill['cases']) == set(REASONS), 'Both retry cases are required.')
    journal = drill['offline_journal']
    rows = journal['observation_rows']
    require(len(rows) == len(REASONS) and journal['committed_count'] == 3,
            'Offline journal must contain one startup and two observations.')
    previous_head = None
    for index, reason in enumerate(REASONS, 2):
        case = drill['cases'][reason]
        before, rejected = case['before'], case['after_rejection']
        accepted, replayed = case['after_retry'], case['after_replay']
        for snapshot in (before, rejected, accepted, replayed):
            require(snapshot['process_id'] == monitor['process_id']
                    and snapshot['instance_id'] == monitor['instance_id']
                    and SHA256.fullmatch(snapshot['head_digest']), 'Monitor restarted or journal digest is malformed.')
        require(before == rejected and accepted == replayed
                and before['committed_count'] == index - 1 and accepted['committed_count'] == index
                and before['head_digest'] != accepted['head_digest']
                and (previous_head is None or previous_head == before['head_digest']),
                'The rejected request, successful retry or duplicate changed the journal unexpectedly.')
        previous_head = accepted['head_digest']
        require(case['initial_rejection'] == {'ok': False, 'error': 'request_rejected', 'reason': reason}
                and case['transport_diagnostic']['reason'] == reason
                and case['transport_diagnostic']['attempts'] == 1,
                'The monitor did not reject the first delivery for the requested reason.')
        require(SHA256.fullmatch(case['pending_sha256_before'])
                and case['pending_sha256_before'] == case['pending_sha256_after_rejection']
                == case['pending_sha256_before_retry'] and case['pending_removed'] is True
                and SHA256.fullmatch(case['frame_sha256'])
                and case['frame_sha256'] == case['retry_frame_sha256'] == case['replay_frame_sha256'],
                'The durable observation or encoded request changed during retry.')
        if reason == 'request_deadline':
            require(0 < case['initial_sent_bytes'] < case['frame_bytes']
                    and case['first_attempt_elapsed_seconds'] >= request_deadline_seconds - 0.1,
                    'The deadline exercise did not leave the original request incomplete.')
        else:
            require(case['initial_sent_bytes'] == case['frame_bytes']
                    and case['future_lead_at_first_send_seconds'] > 0,
                    'The future timestamp exercise did not send the original complete request.')
        receipt = case['receipt']
        require(receipt['delivery_attempts'] == 2 and receipt['duplicate_acknowledgement'] is False
                and receipt['transport_failures'] == [reason] and receipt['committed_sequence'] == index
                and case['replay'] == {'ok': True, 'duplicate': True, 'result_is_historical': True,
                                       'committed_sequence': index},
                'The collector did not commit once and recognize the replay as historical.')
        row = rows[index - 2]
        require(row['sequence'] == index and row['previous_digest'] == before['head_digest']
                and row['row_digest'] == accepted['head_digest'] and SHA256.fullmatch(case['observation_sha256']),
                'Offline journal evidence differs from the live snapshots.')
        for field in ('request_id', 'observed_at_utc', 'observation_sha256'):
            require(case[field] == receipt[field] == row[field], 'Observation identity differs in the journal.')
    require(journal['head_digest'] == previous_head
            and len({row['request_id'] for row in rows}) == len(REASONS),
            'Offline journal head or request uniqueness differs.')


def run(output):
    from scripts import network_monitor_archive_reboot_guest as guest
    from scripts import network_monitor_service as service

    tools = archive_vm.preflight()
    source = source_identity()
    destination = reboot.monitoring.base.new_output(output)
    vm = archive_vm.DisposableVM(tools)
    report = {'format': 'heltemes-archive-reboot-retry-drill', 'version': 1,
              'source': source, 'started_at_utc': reboot.timestamp(), 'ok': False,
              'scope': {'synthetic_only': True, 'aws_deployed': False, 'real_evidence_inputs': False}}
    evidence = {'image': {'url': reboot.IMAGE_URL, 'sha256': reboot.IMAGE_SHA256}}
    try:
        evidence['virtualization'] = vm.prepare()
        vm.launch()
        evidence['cloud_init'] = vm.cloud_init
        evidence['virtualization']['qmp_kvm'] = vm.kvm_status
        snapshot = vm.boot_snapshot()
        require(snapshot is not None, 'Guest boot identity was unavailable.')
        evidence['boot'] = snapshot
        vm.ssh('sudo -n tar -xz --no-same-owner -f - -C ' + archive_vm.GUEST_ROOT,
               input=drill_archive(), timeout=30)
        command = 'sudo -n python3 -I -S -B ' + archive_vm.GUEST_ROOT + '/' + GUEST_SCRIPT
        result = vm.ssh(command + ' --token ' + vm.token, timeout=100)
        require(0 < len(result.stdout) <= 64 * 1024 and b'PRIVATE KEY' not in result.stdout
                and vm.token.encode() not in result.stdout, 'Guest report is oversized or contains private VM material.')
        drill = json.loads(result.stdout)
        validate_drill(drill, snapshot['boot_id'], request_deadline_seconds=service.IO_SECONDS,
                       freshness_seconds=guest.FRESHNESS)
        require(source_identity() == source, 'Tested source changed during the exercise.')
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise RuntimeError('Disposable retry drill failed: ' + vm.redact(error)) from None
    finally:
        evidence['cleanup'] = vm.cleanup()
    require(evidence['cleanup']['ok'] is True, 'Disposable VM cleanup failed.')
    report.update(ok=True, completed_at_utc=reboot.timestamp())
    publish = destination / 'publish'
    publish.mkdir(mode=0o700)
    for name, content in zip(FILES, (report, drill, evidence)):
        reboot.write_json(publish / name, content)
    reboot.write_json(publish / 'MANIFEST.json',
                      {name: reboot.sha256_file(publish / name) for name in FILES})
    for reason in REASONS:
        case = drill['cases'][reason]
        print('Monitor request rejected: ' + reason)
        print(f"  journal rows {case['before']['committed_count']} → {case['after_rejection']['committed_count']}"
              f" → {case['after_retry']['committed_count']} → {case['after_replay']['committed_count']};"
              f" exact request SHA-256 {case['frame_sha256']}")
    print('Both retries and duplicate replays verified; disposable VM removed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True)
    options = parser.parse_args()
    try:
        run(options.output)
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
