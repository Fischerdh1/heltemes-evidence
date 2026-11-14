"""Exercise durable delivery of a real synthetic firewall incident in a guarded VM."""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from datetime import datetime, timedelta
import hashlib
import http.client
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor_alert_delivery as delivery
from scripts import network_monitor_reboot_guest as reboot

SOURCE_FILES = (*reboot.SOURCE_FILES, 'scripts/network_monitor_alert_delivery.py',
                'scripts/network_monitor_alert_delivery_guest.py')
DATA = reboot.DATA
SENDER, RECEIVER = DATA / 'outbox', DATA / 'inbox'
SECRET, DROP_ACK = DATA / 'disposable-http.key', DATA / 'drop-ack'
require = reboot.require


def journal():
    result = reboot.request({'command': 'export'})
    require(result['ok'] is True, 'Could not read the monitor journal.')
    return result


def start_incident(lab):
    lab.setup()
    lab.start_services()
    lab.apply_policy()
    approved = lab.ruleset()
    reboot.install(approved)
    samples = []
    reboot.observe(lab, samples, 'delivery_reference')
    baseline = reboot.observe(lab, samples, 'delivery_baseline', reboot.monitoring.CANARIES)
    require(baseline['current_evaluation']['status'] == 'healthy', 'Initial policy did not verify.')
    lab.apply_policy('misconfigured')
    drift = reboot.observe(lab, samples, 'delivery_drift')
    require('rule_drift:ruleset' in drift['current_evaluation']['active_alert_keys'],
            'The deliberately permissive rule did not trigger policy drift.')
    opened = reboot.observe(lab, samples, 'delivery_forbidden', (reboot.segmentation.EXCEPTION,))
    reboot.segmentation.require_response(samples[-1]['request']['observation']['probes'][0], 'app', 9090)
    incident = reboot.critical(opened)
    return incident['id']


def resolve_incident(lab, incident):
    lab.apply_policy()
    samples = []
    reference = reboot.observe(lab, samples, 'delivery_repaired_reference')
    require(reboot.critical(reference)['id'] == incident, 'Firewall repair alone cleared the incident.')
    reboot.observe(lab, samples, 'delivery_repaired_interval')
    result = reboot.observe(lab, samples, 'delivery_repaired_canaries', reboot.monitoring.CANARIES)
    require(result['current_evaluation']['status'] == 'healthy', 'Fresh probes did not verify the repair.')
    matches = [item for item in result['alerts'] if item['key'] == reboot.CRITICAL]
    require(len(matches) == 1 and matches[0]['id'] == incident and matches[0]['state'] == 'resolved',
            'Recovery did not resolve the same incident.')
    complete = journal()
    events = [event for event in complete['events'] if event['key'] == reboot.CRITICAL]
    require([event['action'] for event in events if event['action'] != 'updated'] == ['opened', 'resolved']
            and all(event['alert_id'] == incident for event in events), 'Incident lifecycle differs.')
    return complete


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    require(process.poll() is not None, 'Owned delivery process did not stop.')


def spawn(children, token, mode, *, hold=False):
    arguments = [sys.executable, '-I', '-S', '-B', str(Path(__file__)), mode, '--token', token]
    if hold:
        arguments.append('--hold')
    child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, cwd=ROOT)
    children.callback(stop_process, child)
    return child


def sender_snapshot():
    return delivery.status(SENDER, 'sender')


def receiver_snapshot():
    return delivery.status(RECEIVER, 'receiver')


def wait_for_receiver(process):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        require(process.poll() is None, 'The synthetic HTTP receiver exited during startup.')
        try:
            with socket.create_connection((delivery.HOST, delivery.PORT), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError('The synthetic HTTP receiver did not become ready.')


def attempt(children, token, number, expected, *, hold=False):
    worker = spawn(children, token, 'sender-worker', hold=hold)
    if hold:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            require(worker.poll() is None, 'The sender exited before the controlled process loss.')
            prior = sender_snapshot()['attempts']
            if len(prior) == number and prior[-1]['result'] != 'started':
                break
            time.sleep(0.1)
        else:
            raise RuntimeError('The live sender did not finish its bounded delivery attempt.')
    else:
        require(worker.wait(timeout=20) == 0, 'The sender exited unsuccessfully.')
    sent = sender_snapshot()
    require(len(sent['attempts']) == number, 'Sender attempt count differed.')
    entry = sent['attempts'][-1]
    require(entry['number'] == number and entry['result'] == expected,
            f"Delivery attempt {number} returned {entry['result']}; expected {expected}.")
    return worker, {'attempt': entry, 'sender': sent, 'receiver': receiver_snapshot(),
                    'sender_pid': worker.pid}


def probe_request(message, signature=None):
    data = delivery.canonical(message)
    headers = {'Content-Type': 'application/json'}
    if signature is not None:
        headers[delivery.AUTH_HEADER] = signature
    connection = http.client.HTTPConnection(delivery.HOST, delivery.PORT, timeout=3)
    try:
        connection.request('POST', delivery.ENDPOINT, body=data, headers=headers)
        response = connection.getresponse()
        response.read(8193)
        return response.status
    finally:
        connection.close()


def invalid_requests(secret, message):
    held = receiver_snapshot()
    signed = delivery.signature(secret, 'request', delivery.canonical(message))
    changed = {**message, 'observed_at_utc': (
        datetime.fromisoformat(message['observed_at_utc']) + timedelta(seconds=1)).isoformat()}
    unsigned = probe_request(message)
    tampered = probe_request(changed, signed)
    conflicting = probe_request(changed, delivery.signature(secret, 'request', delivery.canonical(changed)))
    require((unsigned, tampered, conflicting) == (401, 401, 409) and receiver_snapshot() == held,
            'An unsigned, tampered, or conflicting request changed receipt state.')
    return {'unsigned_status': unsigned, 'tampered_status': tampered,
            'conflicting_status': conflicting, 'receiver_unchanged': True}


def run_delivery(children, lab, token):
    incident_id = start_incident(lab)
    delivery.initialize(SENDER, 'sender')
    delivery.initialize(RECEIVER, 'receiver')
    secret = secrets.token_bytes(32)
    reboot.store.write_new(SECRET, secret)
    reboot.store.write_new(DROP_ACK, delivery.FAULT_MARKER)
    reboot.store.sync_directory(DATA)

    _, unavailable = attempt(children, token, 1, 'transport_error')
    first = unavailable['attempt']['id']
    require(not unavailable['receiver']['deliveries'] and len(unavailable['sender']['deliveries']) == 1
            and unavailable['sender']['deliveries'][0]['state'] == 'pending',
            'Unavailable receiver lost or acknowledged the queued alert.')

    receiver = spawn(children, token, 'receiver-worker')
    wait_for_receiver(receiver)
    original_sender, lost_ack = attempt(children, token, 2, 'ack_missing', hold=True)
    accepted = lost_ack['receiver']['deliveries']
    require(lost_ack['attempt']['id'] == first and len(accepted) == 1 and accepted[0]['id'] == first
            and accepted[0]['ack_dropped'] is True and accepted[0]['duplicate_requests'] == 0
            and lost_ack['sender']['deliveries'][0]['state'] == 'pending',
            'The receiver did not commit once while leaving its sender without an acknowledgement.')
    require(original_sender.poll() is None, 'The sender was not live when interrupted.')
    original_sender.kill()
    returncode = original_sender.wait(timeout=10)
    require(returncode == -signal.SIGKILL, 'The owned sender did not exit by SIGKILL.')

    replacement, retry = attempt(children, token, 3, 'duplicate')
    require(replacement.pid != original_sender.pid, 'Sender replacement process identity did not change.')
    require(retry['attempt']['id'] == first and len(retry['receiver']['deliveries']) == 1
            and retry['receiver']['deliveries'][0] == {**accepted[0], 'duplicate_requests': 1}
            and retry['sender']['deliveries'][0]['state'] == 'delivered',
            'Retry did not acknowledge the same committed alert without duplicating it.')

    rejected = invalid_requests(secret, retry['sender']['deliveries'][0]['message'])
    final_journal = resolve_incident(lab, incident_id)
    _, resolution = attempt(children, token, 4, 'accepted')
    require(resolution['attempt']['id'] != first and len(resolution['receiver']['deliveries']) == 2
            and all(row['state'] == 'delivered' for row in resolution['sender']['deliveries']),
            'The resolution did not reach the receiver as its own durable message.')
    return {'incident_id': incident_id, 'journal': final_journal, 'unavailable': unavailable,
            'lost_ack': lost_ack, 'sender_restart': {'terminated_pid': original_sender.pid,
                'restarted_pid': replacement.pid, 'returncode': returncode, 'signal': 'SIGKILL'},
            'retry': retry, 'invalid_requests': rejected, 'resolution': resolution}


def source_hashes():
    hashes = {}
    for name in SOURCE_FILES:
        path = ROOT / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size < 1024 * 1024,
                'An allowlisted guest source file is missing or unsafe.')
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def exercise(token, virtualization):
    require(not DATA.exists() and not reboot.UNIT_FILE.exists(),
            'Existing disposable lab state or unit cannot be replaced.')
    hashes = source_hashes()
    tools = reboot.base.preflight()
    DATA.mkdir(mode=0o700)
    reboot.store.sync_directory(DATA.parent)
    lab = reboot.monitoring.MonitoringLab(tools, DATA)
    try:
        with ExitStack() as children:
            result = run_delivery(children, lab, token)
    finally:
        try:
            network = lab.cleanup()
        finally:
            try:
                reboot.cleanup(token)
            finally:
                reboot.store.state_path(DATA)
                shutil.rmtree(DATA)
    require(not DATA.exists() and network['ok'] is True and not reboot.UNIT_FILE.exists()
            and source_hashes() == hashes, 'Disposable cleanup or guest source verification failed.')
    return {'ok': True, 'format': 'heltemes-monitor-alert-delivery-guest', 'version': 1,
            'stage': 'exercise', 'boot': reboot.boot_info(virtualization), 'source_sha256': hashes,
            'cleanup': {'ok': True, 'network': network, 'processes_stopped': True,
                        'private_state_removed': True}, **result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('exercise', 'receiver-worker', 'sender-worker'))
    parser.add_argument('--token', required=True)
    parser.add_argument('--hold', action='store_true')
    args = parser.parse_args()
    try:
        virtualization = reboot.guard(args.token)
        if args.stage == 'exercise':
            require(not args.hold, 'Only the disposable sender worker can hold.')
            print(reboot.store.encoded(exercise(args.token, virtualization)))
        elif args.stage == 'receiver-worker':
            require(not args.hold, 'Only the disposable sender worker can hold.')
            delivery.serve_receiver(RECEIVER, SECRET, drop_ack=DROP_ACK)
        else:
            delivery.deliver_once(SENDER, reboot.STATE, SECRET)
            while args.hold:
                signal.pause()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Disposable alert delivery exercise stopped: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
