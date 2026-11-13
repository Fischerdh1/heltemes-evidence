"""Bounded autonomous real-nft/real-canary collector for the marked disposable VM."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor_reboot_guest as reboot
from scripts import network_monitoring_lab as monitoring
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store

DATA = Path('/var/lib/heltemes-automatic-lab')
STATE = DATA / 'state'
PRIVATE = DATA / 'collector'
CONFIG = DATA / 'collector.json'
INTERVAL = 5.0
MAX_CYCLES = 80
PORT_START = 42000
PORT_BLOCK = 6
require = reboot.require


def replace_private(path, value):
    """Durably publish bounded private state; never follow an existing link."""
    store.state_path(path.parent)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600, 'Unsafe collector state file.')
    temporary = path.with_name('.' + path.name + '.' + uuid.uuid4().hex)
    store.write_new(temporary, (store.encoded(value) + '\n').encode())
    os.replace(temporary, path)
    store.sync_directory(path.parent)


class Allocation:
    """One writer; reserve unique ports before sending any packets, including after crash."""
    def __init__(self, directory):
        self.directory = store.state_path(directory)
        self.fd = os.open(self.directory / 'collector.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        info = os.fstat(self.fd)
        try:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                    and stat.S_IMODE(info.st_mode) == 0o600, 'Unsafe collector writer lock.')
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.fd)
            raise
        self.path = self.directory / 'allocation.json'

    def reserve(self):
        value = {'next_port': PORT_START, 'cycles': 0}
        if self.path.exists():
            info = self.path.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size < 1024, 'Unsafe port allocation.')
            value = store.parse(self.path.read_bytes())
        require(set(value) == {'next_port', 'cycles'} and all(type(v) is int for v in value.values())
                and 0 <= value['cycles'] < MAX_CYCLES and value['next_port'] == PORT_START + PORT_BLOCK * value['cycles'],
                'Collector port allocation is invalid or its bounded run is exhausted.')
        start = value['next_port']
        replace_private(self.path, {'next_port': start + PORT_BLOCK, 'cycles': value['cycles'] + 1})
        return start

    def close(self):
        os.close(self.fd)


def validate_config(value):
    require(isinstance(value, dict) and set(value) == {'version', 'interval_seconds', 'namespaces'}
            and value['version'] == 1 and value['interval_seconds'] == INTERVAL, 'Unexpected collector configuration.')
    names = value['namespaces']
    require(isinstance(names, dict) and set(names) == {'user', 'app', 'management', 'router'}, 'Collector namespace inventory differs.')
    prefixes = set()
    for role, name in names.items():
        require(isinstance(name, str) and re.fullmatch(r'he-seg-[0-9a-f]{10}-' + role, name), 'Collector namespace is outside the synthetic lab.')
        prefixes.add(name.rsplit('-', 1)[0])
    require(len(prefixes) == 1, 'Collector namespaces belong to different labs.')
    return names


class AttachedLab(monitoring.MonitoringLab):
    """Read/probe only the namespace names delegated by the guarded harness.

    The collector did not create these namespaces and does not acquire their
    lifecycle ownership. Keep the normal NamespaceLab ownership guard unchanged.
    """
    def __init__(self, tools, staging, config):
        names = validate_config(config)
        super().__init__(tools, staging)
        self.names = dict(names)
        self._authorized_names = dict(names)

    def namespace_command(self, role, arguments):
        require(role in self._authorized_names and self.names.get(role) == self._authorized_names[role],
                'Collector namespace differs from its explicitly delegated lab scope.')
        read_rules = role == 'router' and arguments == [self.tools['nft'], '-j', '-a', 'list', 'ruleset']
        probe_prefix = [sys.executable, '-I', '-S', '-B', '-c', monitoring.segmentation.PROBE_CODE]
        probe = (role in monitoring.segmentation.ZONES and len(arguments) == 10
                 and arguments[:6] == probe_prefix and arguments[6] in monitoring.segmentation.ZONES.values()
                 and arguments[7] in {'8080', '9090'} and arguments[8] == monitoring.segmentation.ZONES[role]
                 and arguments[9].isdecimal() and 40000 <= int(arguments[9]) < 50000)
        require(read_rules or probe, 'An attached collector only reads nft rules and runs bounded synthetic probes.')
        return [self.tools['ip'], 'netns', 'exec', self._authorized_names[role], *arguments]

    def setup(self):
        raise RuntimeError('An attached collector cannot create namespaces.')

    def cleanup(self):
        raise RuntimeError('An attached collector does not own namespace cleanup.')


class Collector:
    def __init__(self, lab, allocation, *, state=STATE, interval=INTERVAL):
        self.lab, self.allocation, self.state, self.interval = lab, allocation, state, interval
        self.instance_id = uuid.uuid4().hex
        self.process_id = os.getpid()
        self.cycle = 0
        self.stopping = False

    def stop(self, *_):
        self.stopping = True  # Finish the current bounded observation before stopping.

    def collect(self):
        started = time.monotonic()
        self.cycle += 1
        self.lab.phase = 'automatic_' + self.instance_id + '_' + str(self.cycle)
        self.lab.next_source_port = self.allocation.reserve()
        probes = []
        # A fresh process first establishes a rules/counter reference. Subsequent
        # cycles independently measure all paths; the harness supplies no samples.
        if self.cycle > 1:
            for source, target, port in monitoring.CANARIES:
                probe = self.lab.probe(source, target, port)
                probe['destination_health'] = (self.lab.probe(target, target, port)
                                               if probe['outcome'] == 'connect_timeout' else None)
                probes.append(probe)
        observation = {'phase': self.lab.phase, 'observed_at_utc': reboot.timestamp(),
                       'ruleset': self.lab.ruleset(), 'collection_error': None, 'probes': probes}
        payload = {'command': 'observe', 'request_id': self.lab.phase, 'observation': observation}
        result = service.request(self.state, payload, timeout=10)
        require(result.get('ok') is True and result.get('duplicate') is False, 'Autonomous observation was not committed once.')
        receipt = {'instance_id': self.instance_id, 'process_id': self.process_id, 'cycle': self.cycle,
                   'request': payload, 'committed_sequence': result['committed_sequence'],
                   'evaluation': result['evaluation'], 'started_monotonic': started,
                   'completed_monotonic': time.monotonic(), 'completed_at_utc': reboot.timestamp()}
        name = f"receipt-{result['committed_sequence']:04d}.json"
        store.write_new(self.allocation.directory / name, (store.encoded(receipt) + '\n').encode())
        store.sync_directory(self.allocation.directory)
        return receipt

    def run(self):
        due = time.monotonic()
        while not self.stopping:
            remaining = due - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.1, remaining))
                continue
            replace_private(self.allocation.directory / 'runtime.json', {
                'instance_id': self.instance_id, 'process_id': self.process_id, 'state': 'collecting', 'next_due_monotonic': due})
            receipt = self.collect()
            # Monotonic cadence; skip missed slots instead of generating a burst.
            due += self.interval
            while due <= time.monotonic():
                due += self.interval
            replace_private(self.allocation.directory / 'runtime.json', {
                'instance_id': self.instance_id, 'process_id': self.process_id, 'state': 'idle',
                'next_due_monotonic': due, 'committed_sequence': receipt['committed_sequence'],
                'completed_at_utc': receipt['completed_at_utc']})


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
        require(CONFIG.stat().st_size < 4096, 'Oversized collector configuration.')
        lab = AttachedLab(reboot.base.preflight(), PRIVATE, store.parse(CONFIG.read_bytes()))
        allocation = Allocation(PRIVATE)
        collector = Collector(lab, allocation)
        signal.signal(signal.SIGTERM, collector.stop)
        signal.signal(signal.SIGINT, collector.stop)
        collector.run()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        parser.exit(1, 'Disposable collector stopped: ' + str(error) + '\n')
    finally:
        if allocation:
            allocation.close()


if __name__ == '__main__':
    main()
