"""Exercise automatic network monitoring startup after abruptly killing an owned Linux VM."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor_archive_powercut_vm as abrupt
from scripts import network_monitor_boot_vm as boot
from scripts import network_monitor_reboot_vm as reboot

PUBLIC_FILES = ('REPORT.json', 'VM.json', 'BEFORE.json', 'RECOVERED.json')
GUEST_STAGES = {'install', 'arm-powercut', 'inspect-powercut', 'recovered', 'diagnostic', 'cleanup'}
require = boot.require


def source_identity(root=ROOT, environment=None):
    source = boot.source_identity(root, environment)
    for name in ('scripts/network_monitor_powercut_vm.py', 'scripts/network_monitor_boot_powercut_vm.py'):
        raw = (root / name).read_bytes()
        committed = subprocess.check_output(
            ['git', '-C', str(root), 'show', f"{source['commit']}:{name}"], timeout=30)
        require(raw == committed, 'Automatic power-cut source differs from the tested commit.')
        source['source_sha256'][name] = hashlib.sha256(raw).hexdigest()
    return source


class DisposableVM(abrupt.DisposableVM):
    def install_source(self):
        # Reuse the same allowlisted transfers as the graceful boot drill.
        for bundle in (reboot.source_archive(), boot.archive_vm.extra_source_archive(), boot.guest_source()):
            self.ssh('sudo -n mkdir -p ' + reboot.GUEST_ROOT
                     + ' && sudo -n tar -xz --no-same-owner -f - -C ' + reboot.GUEST_ROOT,
                     input=bundle, timeout=60)

    def guest(self, stage):
        require(stage in GUEST_STAGES, 'Unknown automatic power-cut guest stage.')
        result = self.ssh('sudo -n python3 -I -S -B ' + reboot.GUEST_ROOT + '/' + boot.GUEST_FILE
                          + ' ' + stage + ' --token ' + self.token,
                          timeout=150, check=False)
        if result.returncode:
            raw = result.stderr or result.stdout
            message = '<key material omitted>' if b'PRIVATE KEY' in raw else boot.safe_failure(
                self, raw.decode(errors='replace'))
            raise RuntimeError('Guest ' + stage + ' failed: ' + message.strip())
        require(0 < len(result.stdout) <= boot.MAX_STAGE and not any(
            marker in result.stdout for marker in (self.token.encode(), b'PRIVATE KEY', b'/Users/')),
            'Guest stage output is empty, too large, or includes private material.')
        value = boot.store.parse(result.stdout)
        require(isinstance(value, dict) and value.get('ok') is True and value.get('stage') == stage,
                'Automatic power-cut guest stage did not succeed.')
        return value


def gap(row):
    sample = row['sample']
    return (row['request']['kind'] == 'observation' and row['request_id'].startswith('freshness-gap-')
            and sample['phase'] == 'collector_missing'
            and sample['collection_error'] == 'freshness_deadline_exceeded'
            and sample['ruleset'] is None and sample['probes'] == []
            and row['evaluation']['status'] == 'unknown')


def validate_boundary(before, source):
    rows = boot.validate_snapshot(before, 'inspect-powercut', source, before)
    proof, receipts = before['powercut_boundary'], before['receipts']
    require(receipts, 'No committed collector receipt before power cut.')
    latest = receipts[-1]
    expected = {key: latest[key] for key in ('boot_id', 'process_id', 'instance_id', 'cycle', 'committed_sequence')}
    expected['request_id'] = latest['request']['request_id']
    require(proof == expected and proof['boot_id'] == before['boot']['boot_id']
            and proof['process_id'] == before['services']['collector']['MainPID']
            and latest['evaluation']['status'] == 'healthy'
            and len(latest['request']['observation']['probes']) == 3
            and before['allocation'] == {'cycles': latest['cycle'],
                'next_port': boot.collector.PORT_START + boot.collector.PORT_BLOCK * latest['cycle']},
            'Power cut must follow a completed healthy canary receipt from the active collector.')
    sequence = proof['committed_sequence']
    require(1 <= sequence <= len(rows) and rows[sequence - 1]['request_id'] == proof['request_id']
            and len(rows) - sequence <= 1 and all(gap(row) for row in rows[sequence:]),
            'Collector continued collecting after the declared power-cut boundary.')
    return rows


def validate_recovery(before, after, source):
    old_rows = validate_boundary(before, source)
    rows = boot.validate_snapshot(after, 'recovered', source, before)
    require(not set(before['network']['namespaces'].values()).intersection(after['network']['namespaces'].values()),
            'The cold boot reused the old synthetic namespace identities.')
    require(before['boot']['boot_id'] != after['boot']['boot_id'] and all(
        before['services'][name]['InvocationID'] != after['services'][name]['InvocationID']
        for name in before['services']), 'Expected fresh systemd service invocations on a new kernel boot.')
    abrupt.replay_rows(rows, after['history']['approved_policy'])
    receipts = after['receipts']
    previous = before['receipts']
    require(receipts[:len(previous)] == previous and [r['cycle'] for r in receipts] == list(range(1, len(receipts) + 1))
            and rows[:len(old_rows)] == old_rows, 'A held journal row or collector receipt changed across the cut.')
    boundaries = [i for i, row in enumerate(rows) if row['request']['kind'] == 'restart']
    require(len(boundaries) == 2 and boundaries[0] == 0, 'Expected one durable monitor startup per boot.')
    restart = boundaries[1]
    cut_sequence = before['powercut_boundary']['committed_sequence']
    require(restart >= len(old_rows) and restart - cut_sequence <= 1 and all(
        gap(row) for row in rows[cut_sequence:restart])
        and rows[restart]['evaluation']['status'] == 'unknown',
        'Restart did not preserve the pre-cut boundary or begin with unknown coverage.')
    by_sequence = {r['committed_sequence']: r for r in receipts}
    require(len(by_sequence) == len(receipts), 'Duplicate collector receipt.')
    ports = set()
    groups = []
    seen = set()
    for snapshot, start, end in ((before, 0, restart), (after, restart, len(rows))):
        worker = snapshot['services']['collector']
        group = []
        for row in rows[start + 1:end]:
            receipt = by_sequence.get(row['sequence'])
            if receipt is None:
                require(gap(row), 'Unreceipted observation is not an independent coverage gap.')
                continue
            group.append(receipt)
            seen.add(row['sequence'])
            require(receipt['process_id'] == receipt['delivery_process_id'] == worker['MainPID']
                    and receipt['instance_id'] == group[0]['instance_id'],
                    'Collector changed instance or delivered an observation from a different process.')
            boot.validate_receipt(receipt, row, snapshot['boot']['boot_id'], len(group), ports)
        require(len(group) >= 3, 'Expected two baseline samples and fresh canaries.')
        first_canaries = group[2]['committed_sequence']
        require(all(row['evaluation']['status'] != 'healthy' for row in rows[start:first_canaries - 1]),
                'Coverage went healthy before fresh full canaries.')
        groups.append(group)
    require(groups[0] == previous and groups[0][0]['instance_id'] != groups[1][0]['instance_id']
            and seen == set(by_sequence) and rows[-1]['evaluation']['status'] == 'healthy'
            and groups[1][-1]['committed_sequence'] == len(rows), 'Collector continuity or final healthy proof differs.')
    return {'preserved_rows': len(old_rows), 'preserved_receipts': len(previous),
            'recovered_rows': len(rows), 'fresh_receipts': len(groups[1]),
            'restart_sequence': restart + 1, 'fresh_healthy_sequence': groups[1][2]['committed_sequence']}


def validate_cut(cut, before, after, boots):
    old, new = cut['before'], cut['after']
    require(len(boots) == 2 and cut['signal'] == 'SIGKILL' and cut['qemu_wait_returncode'] == -signal.SIGKILL
            and cut['old_qemu_reaped'] is True and cut['ssh_unavailable_observed'] is True
            and cut['guest_shutdown_requested'] is False and cut['qemu_graceful_exit_requested'] is False,
            'Expected a reaped QEMU SIGKILL and guest SSH outage with no graceful shutdown.')
    require(old['boot_id'] == before['boot']['boot_id'] != after['boot']['boot_id'] == new['boot_id']
            and old['qemu_pid'] != new['qemu_pid'] and old['disk_identity'] == new['disk_identity']
            and cut['new_qemu_process'] is True and cut['same_disk'] is True,
            'Power cut did not start a new QEMU process and kernel on the original disk.')
    require(old['observed_elapsed_seconds'] <= cut['power_cut_elapsed_seconds']
            <= cut['qemu_terminated_elapsed_seconds'] <= cut['cold_launch_elapsed_seconds']
            < new['observed_elapsed_seconds'], 'Power-cut observations are out of order.')
    abrupt.validate_cache_record(cut['disk_cache_before_cut'])
    for index, (record, snapshot) in enumerate(zip(boots, (old, new)), 1):
        launch = record['snapshot']
        require(record['boot_number'] == index and record['source_uploaded'] is (index == 1)
                and record['cloud_init']['status'] == record['cloud_init']['extended_status'] == 'done'
                and all(launch[field] == snapshot[field] for field in ('boot_id', 'qemu_pid', 'disk_identity')),
                'Source was uploaded during recovery or the cold boot identity differs.')
        for name in ('disk_cache', 'disk_cache_after_boot'):
            abrupt.validate_cache_record(record[name])
    require(boots[1]['launch_started_elapsed_seconds'] == cut['cold_launch_elapsed_seconds'],
            'The replacement boot did not match the observed cold-launch time.')


def run(output):
    tools = reboot.preflight()
    source = source_identity()
    destination = reboot.monitoring.base.new_output(output)
    staging = destination / 'staging'
    staging.mkdir(mode=0o700)
    vm = DisposableVM(tools)
    report = {'format': 'heltemes-network-monitor-automatic-powercut', 'version': 1, 'ok': False,
              'source': source, 'started_at_utc': reboot.timestamp(),
              'scope': {'synthetic_only': True, 'aws_deployed': False, 'real_evidence_inputs': False,
                        'physical_power_loss_tested': False, 'cut_boundary': 'after_committed_collector_receipt'}}
    evidence = {'image': {'url': reboot.IMAGE_URL, 'sha256': reboot.IMAGE_SHA256}}
    step = 'preparing and launching the pinned disposable VM'
    try:
        boot.progress(step)
        evidence['virtualization'] = vm.prepare()
        vm.launch()
        step = 'installing enabled services and waiting for a committed healthy collector receipt'
        boot.progress(step)
        evidence['installation'] = vm.guest('install')
        armed = vm.guest('arm-powercut')
        require(armed['powercut_armed'] is True, 'Guest did not arm the committed boundary.')
        before = vm.guest('inspect-powercut')
        validate_boundary(before, source)
        held = copy.deepcopy(before)
        old = vm.boot_snapshot()
        require(old is not None and old['boot_id'] == before['boot']['boot_id']
                == armed['boot']['boot_id'] == evidence['installation']['boot']['boot_id'],
                'Pre-cut observations do not refer to the currently running VM.')
        step = 'killing QEMU and starting the same disk cold'
        boot.progress(step)
        evidence['cut'] = vm.cut_and_relaunch(old, 'committed collector receipt')
        evidence['boots'] = vm.boots
        step = 'observing automatic startup and verifying recovered history'
        boot.progress(step)
        after = vm.guest('recovered')
        validate_cut(evidence['cut'], held, after, vm.boots)
        report['recovery'] = validate_recovery(held, after, source)
        require(evidence['installation']['units'] == before['units']
                and evidence['installation']['approved_policy_sha256']
                == before['history']['identity']['approved_policy_sha256'],
                'Boot service or approved policy differs from initial installation.')
        step = 'cleaning up the disposable guest'
        boot.progress(step)
        cleanup = vm.guest('cleanup')
        evidence['guest_cleanup'] = cleanup
        require(cleanup['boot']['boot_id'] == after['boot']['boot_id'] and all(cleanup[key] is True for key in
                ('services_disabled_removed', 'state_removed', 'runtime_removed', 'namespaces_removed'))
                and source_identity() == source, 'Guest cleanup or exact source verification failed.')
    except boot.RUN_ERRORS as error:
        report['error'] = step + ': ' + boot.safe_failure(vm, error).replace(str(destination), '<report>')
        if vm.process is not None and vm.process.poll() is None:
            try:
                evidence['diagnostic'] = vm.guest('diagnostic')
            except boot.RUN_ERRORS as diagnostic_error:
                evidence['diagnostic_unavailable'] = boot.safe_failure(vm, diagnostic_error)[-2048:]
    finally:
        try:
            evidence['cleanup'] = vm.cleanup()
        except boot.RUN_ERRORS as error:
            evidence['cleanup'] = {'ok': False, 'error': boot.safe_failure(vm, error)}
        report['completed_at_utc'] = reboot.timestamp()
    report['cleanup'] = evidence['cleanup']
    report['ok'] = 'error' not in report and evidence['cleanup']['ok'] is True
    if not report['ok']:
        reboot.write_json(staging / 'FAILURE.json', {'report': report, 'evidence': evidence})
        raise RuntimeError('Automatic power-cut exercise failed: ' + report.get('error', 'VM cleanup failed.'))
    publish = destination / 'publish'
    publish.mkdir(mode=0o700)
    for name, value in zip(PUBLIC_FILES, (report, evidence, held, after)):
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
        parser.exit(1, str(error) + '\n')
    print(json.dumps({'ok': report['ok'], 'source_commit': report['source']['commit'],
                      'recovery': report['recovery'], 'cleanup': report['cleanup']}, indent=2))


if __name__ == '__main__':
    main()
