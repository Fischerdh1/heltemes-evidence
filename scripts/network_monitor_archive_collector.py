"""Explicitly bounded, one-second collector for the disposable archive exercise."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import signal
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor_collector as ordinary
from scripts import network_monitor_reboot_guest as reboot
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store

DATA = Path('/var/lib/heltemes-archive-lab')
STATE, PRIVATE, CONFIG = DATA / 'state', DATA / 'collector', DATA / 'collector.json'
INTERVAL, CANARY_EVERY, MAX_CYCLES = 1.0, 16, 320
FINISH_AFTER_HEALTHY_CYCLE = 270
PORT_START, PORT_BLOCK = ordinary.PORT_START, ordinary.PORT_BLOCK
require = reboot.require


def validate_config(value):
    require(isinstance(value, dict) and set(value) == {'version', 'interval_seconds', 'canary_every', 'max_cycles', 'namespaces'}
            and value['version'] == 1 and value['interval_seconds'] == INTERVAL
            and value['canary_every'] == CANARY_EVERY and value['max_cycles'] == MAX_CYCLES,
            'Unexpected archive collector configuration.')
    return ordinary.validate_config({'version': 1, 'interval_seconds': ordinary.INTERVAL, 'namespaces': value['namespaces']})


def canary_cycle(cycle):
    return cycle == 2 or (cycle > 2 and cycle % CANARY_EVERY == 0)


class Allocation(ordinary.Allocation):
    def reserve(self):
        value = {'next_port': PORT_START, 'cycles': 0}
        if self.path.exists() or self.path.is_symlink():
            info = self.path.lstat()
            require(ordinary.stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                    and ordinary.stat.S_IMODE(info.st_mode) == 0o600 and info.st_size < 1024, 'Unsafe archive allocation.')
            value = store.parse(self.path.read_bytes())
        require(set(value) == {'next_port', 'cycles'} and all(type(v) is int for v in value.values())
                and 0 <= value['cycles'] < MAX_CYCLES and value['next_port'] == PORT_START + PORT_BLOCK * value['cycles'],
                'Archive collector allocation is invalid or exhausted.')
        ordinary.replace_private(self.path, {'next_port': value['next_port'] + PORT_BLOCK, 'cycles': value['cycles'] + 1})
        return value['cycles'] + 1, value['next_port']


class Collector:
    """Persist an exact observation before RPC and retry it without sending packets again."""
    def __init__(self, lab, allocation, *, state=STATE):
        self.lab, self.allocation, self.state = lab, allocation, state
        self.instance_id, self.process_id = uuid.uuid4().hex, os.getpid()
        self.stopping = False
        self.pending = allocation.directory / 'pending.json'

    def stop(self, *_):
        self.stopping = True

    def prepare(self):
        if self.pending.exists() or self.pending.is_symlink():
            info = self.pending.lstat()
            require(ordinary.stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                    and ordinary.stat.S_IMODE(info.st_mode) == 0o600 and info.st_size < store.MAX_REQUEST,
                    'Unsafe pending archive observation.')
            pending = store.parse(self.pending.read_bytes())
            require(set(pending) == {'instance_id', 'process_id', 'cycle', 'request', 'started_monotonic'}
                    and pending['request']['request_id'] == f"archive_{pending['instance_id']}_{pending['cycle']}",
                    'Pending archive identity differs.')
            return pending
        started = time.monotonic()
        cycle, source_port = self.allocation.reserve()
        self.lab.next_source_port = source_port
        self.lab.phase = f'archive_{self.instance_id}_{cycle}'
        probes = []
        if canary_cycle(cycle):
            for source, target, port in ordinary.monitoring.CANARIES:
                probe = self.lab.probe(source, target, port)
                probe['destination_health'] = (self.lab.probe(target, target, port)
                                               if probe['outcome'] == 'connect_timeout' else None)
                probes.append(probe)
        observation = {'phase': self.lab.phase, 'observed_at_utc': reboot.timestamp(),
                       'ruleset': self.lab.ruleset(), 'collection_error': None, 'probes': probes}
        pending = {'instance_id': self.instance_id, 'process_id': self.process_id, 'cycle': cycle,
                   'request': {'command': 'observe', 'request_id': self.lab.phase, 'observation': observation},
                   'started_monotonic': started}
        ordinary.replace_private(self.pending, pending)
        return pending

    def collect(self):
        pending = self.prepare()
        attempts, failures, deadline = 0, [], time.monotonic() + 45
        while True:
            attempts += 1
            try:
                result = service.request(self.state, pending['request'], timeout=3)
                require(result.get('ok') is True, 'Archive observation was rejected; pending evidence is retained.')
                require(type(result.get('duplicate')) is bool and type(result.get('committed_sequence')) is int,
                        'Archive acknowledgement is incomplete.')
                break
            except (OSError, ValueError) as error:
                failures.append(type(error).__name__)
                require(time.monotonic() < deadline, 'Archive service retry deadline exceeded; pending evidence is retained.')
                time.sleep(0.2)
        receipt = {**pending, 'committed_sequence': result['committed_sequence'], 'evaluation': result['evaluation'],
                   'duplicate_acknowledgement': result['duplicate'], 'delivery_attempts': attempts,
                   'transport_failures': failures, 'delivery_process_id': self.process_id,
                   'completed_monotonic': time.monotonic(), 'completed_at_utc': reboot.timestamp()}
        target = self.allocation.directory / f"receipt-{result['committed_sequence']:04d}.json"
        if target.exists() or target.is_symlink():
            info = target.lstat()
            require(ordinary.stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                    and ordinary.stat.S_IMODE(info.st_mode) == 0o600 and info.st_size < store.MAX_REQUEST,
                    'Unsafe existing collector receipt.')
            existing = store.parse(target.read_bytes())
            require(existing['request'] == pending['request'] and existing['committed_sequence'] == result['committed_sequence']
                    and existing['evaluation'] == result['evaluation'], 'Existing receipt differs from the committed observation.')
            receipt = existing
        else:
            store.write_new(target, (store.encoded(receipt) + '\n').encode())
            store.sync_directory(self.allocation.directory)
        self.pending.unlink()
        store.sync_directory(self.allocation.directory)
        return receipt

    def run(self):
        due = time.monotonic()
        while not self.stopping:
            if time.monotonic() < due:
                time.sleep(min(0.1, due - time.monotonic())); continue
            ordinary.replace_private(self.allocation.directory / 'runtime.json', {
                'instance_id': self.instance_id, 'process_id': self.process_id, 'state': 'collecting', 'next_due_monotonic': due})
            receipt = self.collect()
            due += INTERVAL
            while due <= time.monotonic():
                due += INTERVAL
            ordinary.replace_private(self.allocation.directory / 'runtime.json', {
                'instance_id': self.instance_id, 'process_id': self.process_id, 'state': 'idle', 'next_due_monotonic': due,
                'committed_sequence': receipt['committed_sequence'], 'cycle': receipt['cycle'],
                'completed_at_utc': receipt['completed_at_utc']})
            if receipt['cycle'] >= MAX_CYCLES or (receipt['cycle'] >= FINISH_AFTER_HEALTHY_CYCLE
                    and receipt['evaluation']['status'] == 'healthy' and canary_cycle(receipt['cycle'])):
                self.stopping = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('serve',))
    parser.parse_args()
    allocation = None
    try:
        reboot.ordinary(reboot.MARKER)
        require(reboot.MARKER.stat().st_size < 4096, 'Oversized disposable marker.')
        reboot.guard(store.parse(reboot.MARKER.read_bytes())['token'])
        for path in (DATA, PRIVATE, STATE):
            store.state_path(path)
        reboot.ordinary(CONFIG)
        require(CONFIG.stat().st_size < 4096, 'Oversized archive collector configuration.')
        names = validate_config(store.parse(CONFIG.read_bytes()))
        lab = ordinary.AttachedLab(reboot.base.preflight(), PRIVATE,
                                  {'version': 1, 'interval_seconds': ordinary.INTERVAL, 'namespaces': names})
        allocation = Allocation(PRIVATE)
        worker = Collector(lab, allocation)
        signal.signal(signal.SIGTERM, worker.stop); signal.signal(signal.SIGINT, worker.stop)
        worker.run()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        parser.exit(1, 'Disposable archive collector stopped: ' + str(error) + '\n')
    finally:
        if allocation:
            allocation.close()


if __name__ == '__main__':
    main()
