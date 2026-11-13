"""Enable and observe isolated network and collector startup on a marked guest."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor_archive as archive
from scripts import network_monitor_archive_reboot_collector as collector
from scripts import network_monitor_archive_reboot_guest as archived
from scripts import network_monitor_automatic_guest as automatic
from scripts import network_monitor_collector as ordinary_collector
from scripts import network_monitor_reboot_guest as reboot
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store

# These are the existing archived collector's dedicated paths inside a fresh VM.
# The preflight refuses existing state and this exercise never runs both labs.
DATA, STATE, PRIVATE = collector.DATA, collector.STATE, collector.PRIVATE
RUNTIME = Path('/run/heltemes-automatic-boot-lab')
NETWORK_STATE = RUNTIME / 'network.json'
FAULT = DATA / 'inject-firewall-failure'
MONITOR_UNIT = 'heltemes-boot-monitor.service'
NETWORK_UNIT = 'heltemes-boot-network.service'
COLLECTOR_UNIT = 'heltemes-boot-collector.service'
UNITS = {'monitor': MONITOR_UNIT, 'network': NETWORK_UNIT, 'collector': COLLECTOR_UNIT}
SOURCE_FILES = (*archived.SOURCE_FILES, 'scripts/network_monitor_boot_guest.py')
FRESHNESS_SECONDS, SEGMENT_ROWS, MAX_ROWS = 8, 128, 1024
MANAGER_FIELDS = (*reboot.MANAGER_FIELDS, 'ActiveEnterTimestampMonotonic', 'ExecMainStatus', 'Result')
MANAGER_NUMBERS = ('MainPID', 'NRestarts', 'ExecMainStartTimestampMonotonic',
                   'ActiveEnterTimestampMonotonic', 'ExecMainStatus')
FAULT_CONTENT = 'Reject this lab router firewall transaction on the next boot.\n'
BAD_NFT_LINE = 'this_is_not_an_nft_command\n'
require, command, write_new = reboot.require, reboot.command, reboot.write_new


def unit_path(unit):
    require(unit in UNITS.values(), 'Unexpected guest service.')
    return Path('/etc/systemd/system') / unit


def unit_text(unit):
    unit_path(unit)
    role = next(key for key, value in UNITS.items() if value == unit)
    entry = {'monitor': 'monitor-worker', 'network': 'network-worker', 'collector': 'collector-worker'}[role]
    dependencies = ('\nBindsTo=' + NETWORK_UNIT + '\nRequires=' + MONITOR_UNIT
                    + '\nAfter=' + NETWORK_UNIT + ' ' + MONITOR_UNIT if role == 'collector' else '')
    if role == 'network':
        behavior = 'Type=notify\nNotifyAccess=main\nKillMode=mixed\nTimeoutStartSec=45\n'
    else:
        behavior = 'Type=exec\n'
    if role == 'collector':
        # Stop the producer first and let its bounded in-flight probes finish.
        behavior += 'KillMode=mixed\n'
    if role == 'monitor':
        behavior += f'ProtectSystem=strict\nReadWritePaths={STATE}\nRestrictAddressFamilies=AF_UNIX\n'
    return f'''[Unit]
Description=HELTEMES disposable automatic boot {role}
After=local-fs.target{dependencies}
RequiresMountsFor={DATA}

[Service]
{behavior}ExecStart=/usr/bin/python3 -I -S -B {reboot.INSTALL}/scripts/network_monitor_boot_guest.py {entry}
TimeoutStopSec=30
UMask=0077
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
'''


def guard(token):
    virtualization = reboot.guard(token)
    paths = (DATA, STATE, PRIVATE, RUNTIME, NETWORK_STATE, FAULT, collector.CONFIG,
             *(unit_path(unit) for unit in UNITS.values()))
    require(not any(part.is_symlink() for path in paths for part in (path, *path.parents)),
            'Automatic boot paths must not traverse links.')
    return virtualization


def worker_guard():
    reboot.ordinary(reboot.MARKER)
    require(reboot.MARKER.stat().st_size <= 4096, 'Oversized disposable guest marker.')
    guard(store.parse(reboot.MARKER.read_bytes())['token'])
    for path in (DATA, STATE, PRIVATE):
        store.state_path(path)


def manager(unit):
    path = unit_path(unit)
    reboot.ordinary(path, mode=0o644)
    require(path.read_text() == unit_text(unit), 'Installed guest unit differs from the owned definition.')
    result = command(['systemctl', 'show', '--no-pager', '--property=' + ','.join(MANAGER_FIELDS), unit])
    properties = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    require(set(properties) == set(MANAGER_FIELDS) and properties['LoadState'] == 'loaded'
            and properties['UnitFileState'] == 'enabled' and properties['FragmentPath'] == str(path),
            'Required systemd evidence or boot enablement is missing.')
    for key in MANAGER_NUMBERS:
        require(properties[key].isdecimal(), 'A systemd numeric field was invalid.')
        properties[key] = int(properties[key])
    return properties


def status():
    return service.request(STATE, {'command': 'status'}, timeout=3)


def fault_armed():
    if not FAULT.exists():
        return False
    reboot.ordinary(FAULT)
    require(FAULT.read_text() == FAULT_CONTENT, 'Unexpected guest firewall fault marker.')
    return True


def namespaces_present():
    return sorted(line.split()[0] for line in command(['ip', 'netns', 'list']).stdout.splitlines() if line.strip())


def policy_sha(rules):
    return automatic.monitoring.monitor.policy_fingerprint(rules)


def ready_notify():
    address = os.environ.get('NOTIFY_SOCKET', '')
    require(address.startswith(('/', '@')), 'Systemd notify socket is missing.')
    if address.startswith('@'):
        address = '\0' + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
        notifier.sendto(b'READY=1\nSTATUS=Approved firewall and owned synthetic listeners are ready', address)


def firewall(lab, armed):
    # A single nft batch is atomic. The malformed command is inside the same
    # transaction as the approved rules, and only the owned router sees it.
    rules = automatic.monitoring.segmentation.policy_text()
    arguments = [lab.tools['nft'], '-f', '-']
    result = lab.run_in('router', arguments, input=rules + (BAD_NFT_LINE if armed else ''), check=False)
    if armed:
        require(result.returncode != 0 and result.stderr.strip(),
                'nft did not reject the deliberately malformed firewall transaction.')
        require(all(set(entry) == {'metainfo'} for entry in lab.ruleset()['nftables']),
                'The rejected firewall transaction left rules in the new router.')
    return result


def network_worker():
    worker_guard()
    RUNTIME.mkdir(mode=0o700)
    lab = automatic.monitoring.MonitoringLab(reboot.base.preflight(), RUNTIME)
    boot_id = collector.current_boot_id()
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        lab.setup()
        armed = fault_armed()
        result = firewall(lab, armed)
        network = {'boot_id': boot_id, 'namespaces': lab.names, 'nft_returncode': result.returncode,
                   'policy_sha256': None, 'cleanup': None, 'listeners_started': False, 'failure': None}
        if armed:
            network.update(state='firewall_failed', failure='nftables_rejected',
                           nft_error=automatic.sanitize_diagnostic(result.stderr))
        else:
            require(result.returncode == 0, 'Approved nft firewall setup was rejected.')
            approved = store.parse(store.read_private(STATE / 'identity.json', limit=4096))
            fingerprint = policy_sha(lab.ruleset())
            require(fingerprint == approved['approved_policy_sha256'],
                    'Installed rules differ from the recorded approved firewall policy.')
            lab.start_services()
            require(not stopping, 'Topology stopped before readiness.')
            network.update(state='ready', policy_sha256=fingerprint, listeners_started=True)
            write_new(NETWORK_STATE, network)
            ready_notify()
            while not stopping:
                require(all(process.poll() is None for process in lab.processes),
                        'An owned synthetic listener stopped after topology readiness.')
                time.sleep(0.2)
    finally:
        cleaned = lab.cleanup()
    if armed:
        network['cleanup'] = cleaned
        write_new(NETWORK_STATE, network)
        raise RuntimeError('nft rejected the injected firewall batch; collector readiness was not announced.')


def monitor_worker():
    worker_guard()
    service.serve(STATE, freshness_seconds=FRESHNESS_SECONDS, archive_history=True, diagnose_rejections=True)


def collector_worker():
    worker_guard()
    network = store.parse(store.read_private(NETWORK_STATE, limit=4096))
    boot = collector.current_boot_id()
    require(network['state'] == 'ready' and network['boot_id'] == boot
            and network['listeners_started'] is True and network['nft_returncode'] == 0,
            'Collector cannot start without this boot’s verified topology.')
    attached = ordinary_collector.AttachedLab(reboot.base.preflight(), PRIVATE, {
        'version': 1, 'interval_seconds': ordinary_collector.INTERVAL, 'namespaces': network['namespaces']})
    allocation = collector.Allocation(PRIVATE)
    try:
        worker = collector.Collector(attached, allocation, boot_id=boot, phase='before')
        signal.signal(signal.SIGTERM, worker.stop)
        signal.signal(signal.SIGINT, worker.stop)
        worker.run()
    finally:
        allocation.close()


def install():
    require(not any(path.exists() for path in (DATA, RUNTIME, *(unit_path(u) for u in UNITS.values()))),
            'An existing automatic boot installation cannot be replaced.')
    DATA.mkdir(mode=0o700)
    lab = automatic.monitoring.MonitoringLab(reboot.base.preflight(), DATA)
    try:
        # Build only a reference; the boot unit must recreate different
        # namespaces and start listeners itself, even on the baseline boot.
        lab.setup()
        require(firewall(lab, False).returncode == 0, 'Could not create the approved firewall reference.')
        approved = lab.ruleset()
    finally:
        lab.cleanup()
    archive.initialize(STATE, approved, segment_rows=SEGMENT_ROWS, max_rows=MAX_ROWS)
    PRIVATE.mkdir(mode=0o700)
    store.sync_directory(DATA)
    for unit in UNITS.values():
        path = unit_path(unit)
        write_new(path, unit_text(unit))
        path.chmod(0o644)
    command(['systemctl', 'daemon-reload'])
    command(['systemctl', 'enable', '--now', *UNITS.values()], timeout=60)
    return {'approved_policy_sha256': policy_sha(approved),
            'units': {role: unit_text(unit) for role, unit in UNITS.items()}}


def allocation_record():
    path = PRIVATE / 'allocation.json'
    return store.parse(store.read_private(path, limit=1024)) if path.exists() else {
        'next_port': collector.PORT_START, 'cycles': 0}


def coherent_snapshot(boot_id, *, failed, timeout=60):
    deadline = time.monotonic() + timeout
    reason = 'no journal snapshot'
    while time.monotonic() < deadline:
        try:
            history = archived.readonly_history()
            rows = history['rows']
            # Read the persisted gap before any status request. This proves the
            # monitor's own timer committed it without a harness request.
            if failed and (not rows or rows[-1]['sample']['phase'] != 'collector_missing'):
                reason = 'latest journal row is ' + (rows[-1]['sample']['phase'] if rows else 'absent')
            else:
                observed = status()
                if (observed.get('ok') is True and observed['head_digest'] == history['head_digest']
                        and observed['committed_count'] == history['head_sequence']):
                    receipts = archived.all_receipts()
                    allocation = allocation_record()
                    pending = (PRIVATE / 'pending.json').exists()
                    bound_receipts = all(r['committed_sequence'] <= history['head_sequence'] for r in receipts)
                    if not pending and len(receipts) == allocation['cycles'] and bound_receipts:
                        evaluation = observed['current_evaluation']
                        current = [r for r in receipts if r['boot_id'] == boot_id]
                        if failed and evaluation['phase'] == 'collector_missing':
                            return observed, history, receipts, allocation
                        if not failed and evaluation['status'] == 'healthy' and len(current) >= 3:
                            return observed, history, receipts, allocation
                        reason = f"monitor evaluation is {evaluation['phase']}/{evaluation['status']}"
                    else:
                        reason = (f"collector allocation={allocation['cycles']}, receipts={len(receipts)}, "
                                  f"pending={pending}, receipts_within_head={bound_receipts}")
                else:
                    reason = 'monitor and journal heads did not match'
        except (OSError, ValueError, store.sqlite3.OperationalError) as error:
            reason = type(error).__name__ + ' reading bounded boot state'
        time.sleep(0.12)
    raise RuntimeError('A coherent automatic boot snapshot was unavailable: ' + reason + '.')


def snapshot(boot_id, *, failed):
    observed, history, receipts, allocation = coherent_snapshot(boot_id, failed=failed)
    systemd = {role: manager(unit) for role, unit in UNITS.items()}
    network = store.parse(store.read_private(NETWORK_STATE, limit=4096))
    present = namespaces_present()
    monitor, topology, observing = (systemd[role] for role in ('monitor', 'network', 'collector'))
    require(network['boot_id'] == boot_id and monitor['ActiveState'] == 'active'
            and monitor['MainPID'] == observed['process_id'] and monitor['NRestarts'] == 0
            and history['archived_sequence'] == 0 and history['segments'] == [],
            'The monitor or expected bounded history is inconsistent.')
    if failed:
        require(topology['ActiveState'] == 'failed' and topology['Result'] == 'exit-code'
                and network['state'] == 'firewall_failed' and network['nft_returncode'] != 0
                and network['cleanup']['ok'] is True and not network['listeners_started']
                and not set(network['namespaces'].values()).intersection(present),
                'Rejected firewall topology was not safely stopped and removed.')
        require(observing['ActiveState'] == 'inactive' and observing['MainPID'] == 0
                and observing['ExecMainStartTimestampMonotonic'] == 0 and observing['NRestarts'] == 0
                and not any(r['boot_id'] == boot_id or r['delivery_boot_id'] == boot_id for r in receipts)
                and observed['current_evaluation']['status'] == 'unknown'
                and observed['freshness']['last_accepted_request_id'] is None
                and observed['freshness']['gap_recorded'] is True,
                'The collector ran or the monitor asserted coverage during firewall setup failure.')
    else:
        require(topology['ActiveState'] == 'active' and topology['MainPID'] > 0
                and topology['NRestarts'] == 0 and observing['ActiveState'] == 'active'
                and observing['MainPID'] > 0 and observing['NRestarts'] == 0
                and 0 < topology['ActiveEnterTimestampMonotonic'] <= observing['ExecMainStartTimestampMonotonic']
                and set(network['namespaces'].values()).issubset(present)
                and network['state'] == 'ready' and network['nft_returncode'] == 0
                and network['listeners_started'] is True
                and network['policy_sha256'] == history['identity']['approved_policy_sha256'],
                'Topology or collector did not start in the required order.')
    armed = fault_armed()
    require(armed == failed, 'Unexpected firewall fault state for this boot.')
    return {'status': observed, 'history': history, 'services': systemd, 'network': network,
            'receipts': receipts, 'allocation': allocation, 'pending': False, 'fault_armed': armed,
            'units': {role: unit_text(unit) for role, unit in UNITS.items()},
            'storage': archived.storage_info(), 'namespaces_present': present}


def cleanup():
    namespaces = []
    if NETWORK_STATE.exists():
        namespaces = list(store.parse(store.read_private(NETWORK_STATE, limit=4096))['namespaces'].values())
    for role in ('collector', 'network', 'monitor'):
        unit = UNITS[role]
        path = unit_path(unit)
        if path.exists():
            reboot.ordinary(path, mode=0o644)
            require(path.read_text() == unit_text(unit), 'An unexpected unit cannot be removed.')
            command(['systemctl', 'disable', '--now', unit], timeout=40)
            require(command(['systemctl', 'is-active', unit], check=False).stdout.strip()
                    not in ('active', 'activating', 'deactivating'), 'Owned unit did not stop.')
            path.unlink()
    command(['systemctl', 'daemon-reload'])
    require(not set(namespaces).intersection(namespaces_present()), 'Owned namespaces survived shutdown.')
    for path in (DATA, RUNTIME):
        if path.exists():
            store.state_path(path)
            shutil.rmtree(path)
    require(not any(path.exists() for path in (DATA, RUNTIME, *(unit_path(u) for u in UNITS.values()))),
            'Owned boot lab files survived cleanup.')
    return {'services_disabled_removed': True, 'state_removed': True,
            'runtime_removed': True, 'namespaces_removed': True}


def diagnostics():
    """Read bounded current-boot messages for only these three services."""
    result = {}
    for role, unit in UNITS.items():
        commands = {
            'service': ['systemctl', 'show', '--no-pager', '--property=' + ','.join(MANAGER_FIELDS), unit],
            'log': ['journalctl', '-b', '--no-pager', '--output=cat', '--lines=15', '--unit=' + unit],
        }
        result[role] = {label: automatic.sanitize_diagnostic(command(args, check=False, timeout=5).stdout)
                        for label, args in commands.items()}
    return result


def stage(name, token):
    virtualization = guard(token)
    boot = reboot.boot_info(virtualization)
    if name == 'install':
        result = install()
    elif name in ('baseline', 'normal', 'failed', 'recovered'):
        result = snapshot(boot['boot_id'], failed=name == 'failed')
        expected = {source: hashlib.sha256((ROOT / source).read_bytes()).hexdigest() for source in SOURCE_FILES}
        result['source_sha256'] = expected
    elif name == 'arm-failure':
        store.state_path(DATA)
        write_new(FAULT, FAULT_CONTENT)
        result = {'fault_armed': True}
    elif name == 'disarm-failure':
        require(fault_armed(), 'Cannot disarm an absent firewall marker.')
        FAULT.unlink()
        store.sync_directory(DATA)
        result = {'fault_armed': False}
    elif name == 'cleanup':
        result = cleanup()
    else:
        result = {'diagnostics': diagnostics()}
    observed_boot = reboot.boot_info(virtualization)
    require(observed_boot['boot_id'] == boot['boot_id'], 'Kernel changed during a guest stage.')
    return {'ok': True, 'stage': name, 'boot': observed_boot, **result}


def main():
    workers = {'network-worker': network_worker, 'monitor-worker': monitor_worker,
               'collector-worker': collector_worker}
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=('install', 'baseline', 'normal', 'arm-failure',
        'failed', 'disarm-failure', 'recovered', 'cleanup', 'diagnostic', *workers))
    parser.add_argument('--token')
    args = parser.parse_args()
    try:
        if args.stage in workers:
            require(args.token is None, 'Workers only read their root-owned marker.')
            workers[args.stage]()
        else:
            print(store.encoded(stage(args.stage, args.token)))
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Disposable automatic boot operation failed: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
