"""Verify durable, authenticated alert delivery in a disposable Linux VM."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import signal
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor as monitor
from scripts import network_monitor_alert_delivery as delivery
from scripts import network_monitor_boot_vm as boot
from scripts import network_monitor_reboot_vm as reboot
from scripts import network_monitor_store as store

require = reboot.require
GUEST_SCRIPT = 'scripts/network_monitor_alert_delivery_guest.py'
GUEST_FILES = ('scripts/network_monitor_alert_delivery.py', GUEST_SCRIPT)
GUEST_SOURCES = (*reboot.SOURCE_FILES[:-1], *GUEST_FILES)
PUBLIC_FILES = ('REPORT.json', 'DELIVERY.json')
MAX_REPORT = 4 * 1024 * 1024
PHASES = ('monitor_restart', 'delivery_reference', 'delivery_baseline', 'delivery_drift', 'delivery_forbidden',
          'delivery_repaired_reference', 'delivery_repaired_interval', 'delivery_repaired_canaries')
CRITICAL = 'forbidden_path_open:user->app:9090'


def source_identity(root=ROOT, environment=None):
    source = reboot.source_identity(root, environment)
    for name in (*GUEST_FILES, 'scripts/network_monitor_boot_vm.py',
                 'scripts/network_monitor_alert_delivery_vm.py'):
        raw = (root / name).read_bytes()
        committed = subprocess.check_output(
            ['git', '-C', str(root), 'show', f"{source['commit']}:{name}"], timeout=30)
        require(raw == committed, 'Alert delivery source differs from its committed version.')
        source['source_sha256'][name] = hashlib.sha256(raw).hexdigest()
    return source


def guest_source(root=ROOT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name in GUEST_FILES:
            raw = (root / name).read_bytes()
            entry = tarfile.TarInfo(name)
            entry.mode, entry.size = 0o644, len(raw)
            archive.addfile(entry, io.BytesIO(raw))
    return output.getvalue()


class DisposableVM(reboot.DisposableVM):
    def exercise(self):
        self.ssh('sudo -n tar -xz --no-same-owner -f - -C ' + reboot.GUEST_ROOT,
                 input=guest_source(), timeout=30)
        result = self.ssh('sudo -n python3 -I -S -B ' + reboot.GUEST_ROOT + '/' + GUEST_SCRIPT
                          + ' exercise --token ' + self.token, timeout=180, check=False)
        if result.returncode:
            message = (result.stderr or result.stdout)[-8000:].decode(errors='replace')
            raise RuntimeError('Guest drill stopped: ' + boot.safe_failure(self, message).strip())
        require(0 < len(result.stdout) <= MAX_REPORT
                and not any(marker in result.stdout for marker in
                            (self.token.encode(), b'PRIVATE KEY', b'/Users/', b'/home/', b'he-rb-')),
                'Guest evidence is oversized or contains private material.')
        return store.parse(result.stdout)


def validate_journal(journal, incident_id):
    identity, approved, rows = (journal[name] for name in ('identity', 'approved_policy', 'rows'))
    require(identity['format'] == store.FORMAT and identity['version'] == store.VERSION
            and reboot.TOKEN.fullmatch(identity['database_id'])
            and identity['engine_sha256'] == store.engine_hash()
            and journal['ok'] is True and monitor.policy_fingerprint(approved) == identity['approved_policy_sha256'],
            'Journal scope, approval or identity differs.')
    require(tuple(row['sample']['phase'] for row in rows) == PHASES,
            'Unexpected journal phases.')
    engine = monitor.Monitor(approved)
    previous = store.ZERO
    identifiers = set()
    committed_events = []
    for sequence, row in enumerate(rows, 1):
        request, sample = row['request'], row['sample']
        require(type(row['sequence']) is int and row['sequence'] == sample['sequence'] == sequence
                and row['previous_digest'] == previous and row['request_id'] not in identifiers
                and request['kind'] == ('restart' if sequence == 1 else 'observation')
                and all(sample[field] == request['observation'][field] for field in store.OBSERVATION_KEYS)
                and row['row_digest'] == store.digest({k: v for k, v in row.items() if k != 'row_digest'}),
                'Committed row linkage differs.')
        require(engine.observe(sample) == row['evaluation']
                and engine.events[len(committed_events):] == row['events'],
                'Saved firewall evaluation does not match deterministic replay.')
        committed_events.extend(row['events'])
        identifiers.add(row['request_id'])
        previous = row['row_digest']
    require(journal['events'] == committed_events == engine.events and journal['alerts'] == engine.alerts
            and journal['evaluations'] == engine.evaluations
            and journal['current_status']['head_digest'] == previous
            and journal['current_status']['committed_count'] == len(rows),
            'Journal export does not match committed history.')
    opened, resolved = [event for event in committed_events if event['key'] == CRITICAL and
                        event['action'] in {'opened', 'resolved'}]
    require(opened['alert_id'] == resolved['alert_id'] == incident_id
            and opened['action'] == 'opened' and opened['phase'] == 'delivery_forbidden'
            and resolved['action'] == 'resolved' and resolved['phase'] == 'delivery_repaired_canaries',
            'Expected one measured violation and its later resolution.')
    opened_probes = rows[opened['sequence'] - 1]['sample']['probes']
    repaired = rows[resolved['sequence'] - 1]
    require(len(opened_probes) == 1 and (opened_probes[0]['from'], opened_probes[0]['to'], opened_probes[0]['port']) ==
            ('user', 'app', 9090) and monitor.good_response(opened_probes[0], 'app', 9090)
            and repaired['evaluation']['status'] == 'healthy'
            and [(p['from'], p['to'], p['port'], p['outcome']) for p in repaired['sample']['probes']] ==
            [('user', 'app', 8080, 'response'), ('user', 'app', 9090, 'connect_timeout'),
             ('management', 'app', 9090, 'response')]
            and monitor.good_response(repaired['sample']['probes'][1]['destination_health'], 'app', 9090),
            'A real forbidden response or repaired traffic controls are absent.')
    return [delivery.project(identity['database_id'], event) for event in (opened, resolved)]


def validate_delivery(evidence, source, boot_id):
    require(evidence['ok'] is True and evidence['stage'] == 'exercise'
            and evidence['format'] == 'heltemes-monitor-alert-delivery-guest'
            and evidence['boot']['boot_id'] == boot_id
            and evidence['boot']['virtualization'] in {'qemu', 'kvm'}
            and evidence['source_sha256'] == {name: source['source_sha256'][name] for name in GUEST_SOURCES},
            'Guest boot or committed source provenance differs.')
    messages = validate_journal(evidence['journal'], evidence['incident_id'])
    stages = [evidence[name] for name in ('unavailable', 'lost_ack', 'retry', 'resolution')]
    for index, (stage, state, receiver_count, result) in enumerate(zip(
            stages, ('pending', 'pending', 'delivered', 'delivered'),
            (0, 1, 1, 2), ('transport_error', 'ack_missing', 'duplicate', 'accepted')), 1):
        sender, receiver, attempt = (stage[key] for key in ('sender', 'receiver', 'attempt'))
        require(sender['ok'] is receiver['ok'] is True and sender['role'] == 'sender'
                and receiver['role'] == 'receiver' and stage['sender_pid'] > 0
                and len(sender['attempts']) == index and sender['attempts'][-1] == attempt
                and attempt == {'number': index, 'id': messages[1 if index == 4 else 0]['id'], 'result': result}
                and len(sender['deliveries']) == (2 if index == 4 else 1)
                and len(receiver['deliveries']) == receiver_count,
                'Persisted attempt order, sender state, or receiver count differs.')
        if index > 1:
            require(sender['attempts'][:-1] == stages[index - 2]['sender']['attempts'],
                    'The sender lost a previously persisted attempt.')
        for item, message in zip(sender['deliveries'], messages):
            digest = delivery.payload_digest(delivery.canonical(message))
            expected_state = state
            expected_ack = ({'id': message['id'], 'payload_sha256': digest,
                             'duplicate': message['action'] == 'opened'} if state == 'delivered' else None)
            require(item['id'] == message['id'] and item['message'] == message
                    and item['payload_sha256'] == digest and item['state'] == expected_state
                    and item['acknowledgement'] == expected_ack,
                    'Sender did not retain the exact committed message and its bound receipt.')
        for item, message in zip(receiver['deliveries'], messages):
            opened = message['action'] == 'opened'
            require(item['id'] == message['id'] and item['message'] == message
                    and item['payload_sha256'] == delivery.payload_digest(delivery.canonical(message))
                    and item['duplicate_requests'] == (1 if index >= 3 and opened else 0)
                    and item['ack_dropped'] is opened, 'Receiver changed the event or created a duplicate record.')
    restart = evidence['sender_restart']
    require(restart['signal'] == 'SIGKILL' and restart['returncode'] == -signal.SIGKILL
            and restart['terminated_pid'] == stages[1]['sender_pid']
            and restart['restarted_pid'] == stages[2]['sender_pid']
            and restart['terminated_pid'] != restart['restarted_pid'],
            'Sender loss and new worker process were not observed.')
    require(evidence['invalid_requests'] == {'unsigned_status': 401, 'tampered_status': 401,
                'conflicting_status': 409, 'receiver_unchanged': True},
            'Unsigned, tampered, or conflicting input reached the receiver.')
    cleanup = evidence['cleanup']
    require(cleanup['ok'] is cleanup['network']['ok'] is cleanup['processes_stopped']
            is cleanup['private_state_removed'] is True, 'Guest-owned state or processes survived cleanup.')
    return {'journal_rows': len(evidence['journal']['rows']), 'receiver_events': 2,
            'attempts': [r['attempt']['result'] for r in stages], 'duplicate_requests': 1,
            'firewall_incident_id': evidence['incident_id'], 'sender_restarted': True}


def run(output):
    tools = reboot.preflight()
    source = source_identity()
    destination = reboot.monitoring.base.new_output(output)
    staging = destination / 'staging'
    staging.mkdir(mode=0o700)
    vm = DisposableVM(tools)
    report = {'format': 'heltemes-network-monitor-alert-delivery-vm', 'version': 1, 'ok': False,
              'source': source, 'started_at_utc': reboot.timestamp(),
              'scope': {'synthetic_only': True, 'aws_deployed': False, 'real_evidence_inputs': False,
                        'loopback_only': True, 'external_notifications': False}}
    step = 'preparing the pinned disposable VM'
    try:
        boot.progress(step)
        report['image'] = {'url': reboot.IMAGE_URL, 'sha256': reboot.IMAGE_SHA256}
        report['virtualization'] = vm.prepare()
        step = 'booting the Linux guest and transferring allowlisted source'
        boot.progress(step)
        vm.launch()
        report['virtualization']['qmp_kvm'] = vm.kvm_status
        report['cloud_init'] = vm.cloud_init
        report['boot'] = vm.boot_snapshot()
        require(report['boot'] is not None, 'Guest boot identity is unavailable.')
        step = 'exercising firewall alert delivery with offline and lost-ack cases'
        boot.progress(step)
        evidence = vm.exercise()
        step = 'replaying the committed incident and checking delivery'
        boot.progress(step)
        report['delivery'] = validate_delivery(evidence, source, report['boot']['boot_id'])
        require(source_identity() == source, 'Tested source changed during the drill.')
    except boot.RUN_ERRORS as error:
        report['error'] = step + ': ' + boot.safe_failure(vm, error).replace(str(destination), '<report>')
    finally:
        try:
            boot.progress('removing the disposable VM, disk and temporary SSH material')
            report['cleanup'] = vm.cleanup()
        except boot.RUN_ERRORS as error:
            report['cleanup'] = {'ok': False, 'error': boot.safe_failure(vm, error)}
        report['completed_at_utc'] = reboot.timestamp()
    report['ok'] = 'error' not in report and report['cleanup']['ok'] is True
    if not report['ok']:
        reboot.write_json(staging / 'FAILURE.json', report)
        raise RuntimeError(report.get('error', 'Disposable VM cleanup failed.'))
    publish = destination / 'publish'
    publish.mkdir(mode=0o700)
    for name, value in zip(PUBLIC_FILES, (report, evidence)):
        reboot.write_json(publish / name, value)
    reboot.write_json(publish / 'MANIFEST.json', {name: reboot.sha256_file(publish / name) for name in PUBLIC_FILES})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='New report directory with an existing parent')
    args = parser.parse_args()
    try:
        report = run(args.output)
    except boot.RUN_ERRORS as error:
        parser.exit(1, 'Alert delivery drill stopped: ' + str(error) + '\n')
    print(json.dumps({'ok': report['ok'], 'source_commit': report['source']['commit'],
                      'delivery': report['delivery'], 'cleanup': report['cleanup']}, indent=2))


if __name__ == '__main__':
    main()
