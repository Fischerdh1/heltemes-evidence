"""Boot-bound, finite real-network collection for the disposable archived reboot test.

The guest harness recreates its owned namespaces and publishes a current-boot
configuration before explicitly starting this collector. Only the monitor starts
automatically at boot. Existing observations are never retimestamped on retry.
"""
from __future__ import annotations

import argparse
import math
import os
from pathlib import Path
import re
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

DATA = Path('/var/lib/heltemes-archive-reboot-lab')
STATE, PRIVATE, CONFIG = DATA / 'state', DATA / 'collector', DATA / 'collector.json'
INTERVAL, CANARY_EVERY, MAX_CYCLES = 1.0, 16, 512
BEFORE_STOP_CYCLE, AFTER_STOP_CYCLE = 270, 400
PORT_START, PORT_BLOCK = ordinary.PORT_START, ordinary.PORT_BLOCK
BOOT_ID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
require = reboot.require


def current_boot_id():
    value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    require(BOOT_ID.fullmatch(value), 'Invalid kernel boot identity.')
    return value


def validate_config(value, *, boot_id=None):
    keys = {'version', 'interval_seconds', 'canary_every', 'max_cycles', 'namespaces',
            'boot_id', 'phase', 'stop_after_cycle'}
    require(isinstance(value, dict) and set(value) == keys and type(value['version']) is int
            and value['version'] == 1 and type(value['interval_seconds']) in (int, float)
            and value['interval_seconds'] == INTERVAL and type(value['canary_every']) is int
            and value['canary_every'] == CANARY_EVERY and type(value['max_cycles']) is int
            and value['max_cycles'] == MAX_CYCLES, 'Unexpected archived-reboot collector configuration.')
    require(isinstance(value['boot_id'], str) and BOOT_ID.fullmatch(value['boot_id']),
            'Collector configuration needs an explicit kernel boot identity.')
    require(value['phase'] in ('before', 'after') and type(value['stop_after_cycle']) is int
            and value['stop_after_cycle'] == {'before': BEFORE_STOP_CYCLE, 'after': AFTER_STOP_CYCLE}[value['phase']],
            'Collector phase has an unexpected finite stop boundary.')
    require(boot_id is None or value['boot_id'] == boot_id,
            'Collector configuration belongs to an earlier boot; reconstruct the owned network first.')
    return ordinary.validate_config({'version': 1, 'interval_seconds': ordinary.INTERVAL,
                                     'namespaces': value['namespaces']})


def canary_cycle(cycle, process_cycle):
    """New processes establish two real rule baselines before sending canaries."""
    return process_cycle >= 3 and (process_cycle == 3 or cycle % CANARY_EVERY == 0)


def private_json(path, *, limit=store.MAX_REQUEST):
    info = path.lstat()
    require(ordinary.stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
            and ordinary.stat.S_IMODE(info.st_mode) == 0o600 and info.st_size < limit,
            'Unsafe archived-reboot collector state file.')
    return store.parse(path.read_bytes())


class Allocation(ordinary.Allocation):
    """One lifetime lock and one durable global port reservation across boots."""
    def read(self):
        value = (private_json(self.path, limit=1024) if self.path.exists() or self.path.is_symlink()
                 else {'next_port': PORT_START, 'cycles': 0})
        require(isinstance(value, dict) and set(value) == {'next_port', 'cycles'}
                and all(type(v) is int for v in value.values()) and 0 <= value['cycles'] <= MAX_CYCLES
                and value['next_port'] == PORT_START + PORT_BLOCK * value['cycles'],
                'Archived-reboot allocation is invalid.')
        return value

    def reserve(self):
        value = self.read()
        require(value['cycles'] < MAX_CYCLES, 'Archived-reboot allocation is exhausted.')
        ordinary.replace_private(self.path, {'next_port': value['next_port'] + PORT_BLOCK,
                                            'cycles': value['cycles'] + 1})
        return value['cycles'] + 1, value['next_port']


class Collector:
    def __init__(self, lab, allocation, *, boot_id, phase, state=STATE):
        require(isinstance(boot_id, str) and BOOT_ID.fullmatch(boot_id), 'Invalid collector boot identity.')
        require(phase in ('before', 'after'), 'Invalid collector phase.')
        self.lab, self.allocation, self.state = lab, allocation, state
        self.boot_id, self.phase = boot_id, phase
        self.stop_after_cycle = {'before': BEFORE_STOP_CYCLE, 'after': AFTER_STOP_CYCLE}[phase]
        self.instance_id, self.process_id = uuid.uuid4().hex, os.getpid()
        self.process_cycle, self.stopping = 0, False
        self.pending = allocation.directory / 'pending.json'

    def stop(self, *_):
        self.stopping = True

    def prepare(self):
        if self.pending.exists() or self.pending.is_symlink():
            pending = private_json(self.pending)
            keys = {'instance_id', 'process_id', 'boot_id', 'process_cycle', 'cycle', 'request', 'started_monotonic'}
            require(isinstance(pending, dict) and set(pending) == keys
                    and isinstance(pending['instance_id'], str) and re.fullmatch(r'[0-9a-f]{32}', pending['instance_id'])
                    and type(pending['process_id']) is int and pending['process_id'] > 0
                    and isinstance(pending['boot_id'], str) and BOOT_ID.fullmatch(pending['boot_id'])
                    and type(pending['cycle']) is int and 1 <= pending['cycle'] <= self.stop_after_cycle
                    and type(pending['process_cycle']) is int and 1 <= pending['process_cycle'] <= pending['cycle']
                    and type(pending['started_monotonic']) in (int, float)
                    and math.isfinite(pending['started_monotonic']) and pending['started_monotonic'] >= 0,
                    'Pending archived-reboot producer identity differs.')
            request = pending['request']
            identity = f"archive_reboot_{pending['instance_id']}_{pending['cycle']}"
            require(isinstance(request, dict) and set(request) == {'command', 'request_id', 'observation'}
                    and request['command'] == 'observe' and request['request_id'] == identity
                    and isinstance(request['observation'], dict) and request['observation'].get('phase') == identity
                    and self.allocation.read()['cycles'] == pending['cycle'],
                    'Pending archived-reboot request or durable allocation differs.')
            return pending
        require(self.allocation.read()['cycles'] < self.stop_after_cycle, 'Collector reached its finite phase boundary.')
        started = time.monotonic()
        cycle, source_port = self.allocation.reserve()
        self.process_cycle += 1
        self.lab.next_source_port = source_port
        self.lab.phase = f'archive_reboot_{self.instance_id}_{cycle}'
        probes = []
        if canary_cycle(cycle, self.process_cycle):
            for source, target, port in ordinary.monitoring.CANARIES:
                probe = self.lab.probe(source, target, port)
                probe['destination_health'] = (self.lab.probe(target, target, port)
                                               if probe['outcome'] == 'connect_timeout' else None)
                probes.append(probe)
        observation = {'phase': self.lab.phase, 'observed_at_utc': reboot.timestamp(),
                       'ruleset': self.lab.ruleset(), 'collection_error': None, 'probes': probes}
        pending = {'instance_id': self.instance_id, 'process_id': self.process_id, 'boot_id': self.boot_id,
                   'process_cycle': self.process_cycle, 'cycle': cycle, 'started_monotonic': started,
                   'request': {'command': 'observe', 'request_id': self.lab.phase, 'observation': observation}}
        ordinary.replace_private(self.pending, pending)
        return pending

    def collect(self):
        pending = self.prepare()
        attempts, failures, deadline = 0, [], time.monotonic() + 45
        while True:
            attempts += 1
            try:
                result = service.request(self.state, pending['request'], timeout=3)
                require(result.get('ok') is True, 'Archived-reboot observation was rejected; pending evidence is retained.')
                require(type(result.get('duplicate')) is bool and type(result.get('committed_sequence')) is int,
                        'Archived-reboot acknowledgement is incomplete.')
                break
            except (OSError, ValueError) as error:
                failures.append(type(error).__name__)
                require(time.monotonic() < deadline, 'Archived-reboot retry deadline exceeded; pending evidence is retained.')
                time.sleep(0.2)
        receipt = {**pending, 'committed_sequence': result['committed_sequence'], 'evaluation': result['evaluation'],
                   'duplicate_acknowledgement': result['duplicate'], 'delivery_attempts': attempts,
                   'transport_failures': failures, 'delivery_process_id': self.process_id, 'delivery_boot_id': self.boot_id,
                   'completed_monotonic': time.monotonic(), 'completed_at_utc': reboot.timestamp()}
        target = self.allocation.directory / f"receipt-{result['committed_sequence']:04d}.json"
        if target.exists() or target.is_symlink():
            existing = private_json(target)
            require(all(existing.get(key) == value for key, value in pending.items())
                    and existing['committed_sequence'] == result['committed_sequence']
                    and existing['evaluation'] == result['evaluation'],
                    'Existing receipt differs from the committed observation.')
            receipt = existing
        else:
            store.write_new(target, (store.encoded(receipt) + '\n').encode())
            store.sync_directory(self.allocation.directory)
        self.pending.unlink()
        store.sync_directory(self.allocation.directory)
        return receipt

    def run(self):
        allocated = self.allocation.read()['cycles']
        require((self.phase == 'before' or allocated >= BEFORE_STOP_CYCLE)
                and (allocated < self.stop_after_cycle or self.pending.exists()),
                'Collector allocation is outside the requested unfinished phase.')
        due = time.monotonic()
        identity = {'instance_id': self.instance_id, 'process_id': self.process_id, 'boot_id': self.boot_id,
                    'phase': self.phase, 'stop_after_cycle': self.stop_after_cycle}
        while not self.stopping:
            if time.monotonic() < due:
                time.sleep(min(0.1, due - time.monotonic())); continue
            ordinary.replace_private(self.allocation.directory / 'runtime.json', {
                **identity, 'state': 'collecting', 'next_due_monotonic': due})
            receipt = self.collect()
            due += INTERVAL
            while due <= time.monotonic():
                due += INTERVAL
            complete = receipt['cycle'] == self.stop_after_cycle
            ordinary.replace_private(self.allocation.directory / 'runtime.json', {
                **identity, 'state': 'complete' if complete else 'idle', 'next_due_monotonic': due,
                'committed_sequence': receipt['committed_sequence'], 'cycle': receipt['cycle'],
                'completed_at_utc': receipt['completed_at_utc']})
            if complete:
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
        config = private_json(CONFIG, limit=4096)
        boot_id = current_boot_id()
        names = validate_config(config, boot_id=boot_id)
        lab = ordinary.AttachedLab(reboot.base.preflight(), PRIVATE,
                                  {'version': 1, 'interval_seconds': ordinary.INTERVAL, 'namespaces': names})
        allocation = Allocation(PRIVATE)
        worker = Collector(lab, allocation, boot_id=boot_id, phase=config['phase'])
        signal.signal(signal.SIGTERM, worker.stop); signal.signal(signal.SIGINT, worker.stop)
        worker.run()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        parser.exit(1, 'Disposable archived-reboot collector stopped: ' + str(error) + '\n')
    finally:
        if allocation:
            allocation.close()


if __name__ == '__main__':
    main()
