"""Verify automatic network and collector startup on a disposable Linux VM."""
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
from scripts import network_monitor_archive_powercut_vm as replay
from scripts import network_monitor_archive_reboot_collector as collector
from scripts import network_monitor_archive_reboot_vm as archive_vm
from scripts import network_monitor as monitor
from scripts import network_monitor_reboot_vm as reboot
from scripts import network_monitor_store as store

require = reboot.require
GUEST_FILE = 'scripts/network_monitor_boot_guest.py'
HOST_FILE = 'scripts/network_monitor_boot_vm.py'
REPLAY_FILE = 'scripts/network_monitor_archive_powercut_vm.py'
STAGE_OUTPUTS = {
    'baseline': 'BEFORE.json', 'normal': 'NORMAL.json',
    'failed': 'FAILED.json', 'recovered': 'RECOVERED.json',
}
BOOT_CASES = ('normal', 'failed', 'recovered')
STAGES = {'install', 'arm-failure', 'disarm-failure', 'cleanup', 'diagnostic', *STAGE_OUTPUTS}
PUBLIC_FILES = ('REPORT.json', 'VM.json', *STAGE_OUTPUTS.values())
GUEST_SOURCE_FILES = (*archive_vm.GUEST_SOURCE_FILES, GUEST_FILE)
MAX_STAGE = 16 * 1024 * 1024
RUN_ERRORS = (OSError, ValueError, RuntimeError, KeyError, TypeError, IndexError, subprocess.SubprocessError)


def progress(message):
    print('Automatic boot VM: ' + message, file=sys.stderr, flush=True)


def safe_failure(vm, message):
    message = vm.redact(message)
    message = re.sub(r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*', '<key material omitted>', message, flags=re.S)
    message = re.sub(r'(?:ssh-ed25519|ssh-rsa|ecdsa-[^ ]+) [A-Za-z0-9+/=]+', '<SSH key omitted>', message)
    return re.sub(r'(?:/Users|/home)/\S+', '<local path>', message)[-12 * 1024:]


def source_identity(root=ROOT, environment=None):
    source = archive_vm.source_identity(root, environment)
    root = Path(root).resolve()
    for name in (GUEST_FILE, HOST_FILE, REPLAY_FILE):
        raw = (root / name).read_bytes()
        committed = subprocess.check_output(['git', '-C', str(root), 'show',
            f"{source['commit']}:{name}"], timeout=30)
        require(raw == committed, 'Automatic boot source differs from the tested commit.')
        source['source_sha256'][name] = hashlib.sha256(raw).hexdigest()
    return source


def guest_source(root=ROOT):
    raw = (root / GUEST_FILE).read_bytes()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        entry = tarfile.TarInfo(GUEST_FILE)
        entry.mode, entry.size = 0o644, len(raw)
        archive.addfile(entry, io.BytesIO(raw))
    return output.getvalue()


class DisposableVM(archive_vm.DisposableVM):
    def launch(self):
        super().launch()
        self.ssh('sudo -n tar -xz --no-same-owner -f - -C ' + reboot.GUEST_ROOT,
                 input=guest_source(), timeout=30)

    def guest(self, stage):
        require(stage in STAGES, 'Unknown automatic boot guest stage.')
        timeout = {'install': 120, 'baseline': 240, 'cleanup': 60, 'diagnostic': 45}.get(stage, 150)
        result = self.ssh('sudo -n python3 -I -S -B ' + reboot.GUEST_ROOT + '/' + GUEST_FILE
                          + ' ' + stage + ' --token ' + self.token, timeout=timeout, check=False)
        if result.returncode:
            raw = result.stderr or result.stdout
            message = ('<key material omitted>' if b'PRIVATE KEY' in raw
                       else safe_failure(self, raw.decode(errors='replace')))
            raise RuntimeError('Guest ' + stage + ' failed: ' + message.strip())
        require(0 < len(result.stdout) <= MAX_STAGE
                and not any(marker in result.stdout for marker in (self.token.encode(), b'PRIVATE KEY', b'/Users/')),
                'Guest stage output is empty, too large, or includes private material.')
        value = store.parse(result.stdout)
        require(isinstance(value, dict) and value.get('ok') is True and value.get('stage') == stage,
                'Automatic boot guest stage did not succeed.')
        return value


def validate_reboots(snapshots, evidence):
    previous = evidence['initial_boot']
    for name in BOOT_CASES:
        observed = evidence['reboots'][name]
        before, after = observed['before'], observed['after']
        require(before['boot_id'] == previous['boot_id'] == snapshots[
                    {'normal': 'baseline', 'failed': 'normal', 'recovered': 'failed'}[name]]['boot']['boot_id']
                and after['boot_id'] == snapshots[name]['boot']['boot_id']
                and before['qemu_pid'] == previous['qemu_pid']
                and before['disk_identity'] == previous['disk_identity']
                and observed['reboot_command'] == 'systemctl reboot',
                'Guest stage or previous host boot identity differs.')
        reboot.validate_reboot(before, after, observed['ssh_unavailable_observed'],
                               observed['qmp_events'], observed['reboot_requested_elapsed_seconds'])
        previous = after
    require(len({stage['boot']['boot_id'] for stage in snapshots.values()}) == len(STAGE_OUTPUTS),
            'A kernel boot identity was reused.')


def validate_snapshot(stage, name, source, first):
    boot_id, uptime = stage['boot']['boot_id'], stage['boot']['uptime_seconds']
    require(stage['ok'] is True and stage['stage'] == name and reboot.UUID.fullmatch(boot_id)
            and stage['boot']['virtualization'] in {'qemu', 'kvm'}
            and 0 < uptime < 86400, 'Invalid automatic startup stage or boot identity.')
    require(stage['source_sha256'] == {key: source['source_sha256'][key] for key in GUEST_SOURCE_FILES},
            'Guest sources differ from the tested commit.')
    storage, history, status = stage['storage'], stage['history'], stage['status']
    require(storage['uuid'] and storage['uuid'] == first['storage']['uuid']
            and storage['fstype'] == first['storage']['fstype']
            and storage['fstype'] in {'ext4', 'xfs', 'btrfs'} and storage['source'].startswith('/dev/')
            and 'rw' in storage['options'].split(','), 'Persistent filesystem identity differs.')
    identity, rows = history['identity'], history['rows']
    require(identity['format'] == 'heltemes-monitor-archive-journal' and identity['version'] == 1
            and reboot.TOKEN.fullmatch(identity['database_id'])
            and identity['segment_rows'] == 128 and identity['max_rows'] == 1024
            and identity['approved_policy_sha256'] == monitor.policy_fingerprint(history['approved_policy'])
            and history['archived_sequence'] == 0 and history['archived_digest'] == store.ZERO
            and history['segments'] == [] and 0 < len(rows) < 128,
            'Snapshot does not contain the full bounded history and approved policy reference.')
    require(identity == first['history']['identity'] and history['approved_policy'] == first['history']['approved_policy'],
            'The database identity or approved firewall policy changed.')
    require(status['ok'] is True and status['committed_count'] == len(rows) == history['head_sequence']
            and status['head_digest'] == history['head_digest'] == rows[-1]['row_digest']
            and status['archives']['persistence_error'] is None and status['freshness']['enabled'] is True,
            'Status did not come from the same committed history snapshot.')
    services = stage['services']
    require(set(services) == {'monitor', 'network', 'collector'}
            and set(stage['units']) == set(services) and stage['units'] == first['units'],
            'Service unit inventory or boot configuration changed.')
    for entry in services.values():
        require(entry['LoadState'] == 'loaded' and entry['UnitFileState'] == 'enabled'
                and type(entry['MainPID']) is int and entry['NRestarts'] == 0,
                'A service was missing, disabled, or restarted within the boot.')
    manager, network, worker = (services[role] for role in ('monitor', 'network', 'collector'))
    require(manager['ActiveState'] == 'active' and manager['MainPID'] == status['process_id'] > 0
            and 0 < manager['ExecMainStartTimestampMonotonic'] <= uptime * 1_000_000
            and reboot.TOKEN.fullmatch(manager['InvocationID']), 'Monitor did not start in this boot.')
    result = stage['network']
    require(result['boot_id'] == boot_id and set(result['namespaces']) == {'user', 'app', 'management', 'router'}
            and len(set(result['namespaces'].values())) == 4, 'Network result is not bound to this boot.')
    present = set(stage['namespaces_present']).intersection(result['namespaces'].values())
    if name == 'failed':
        require(stage['fault_armed'] is True and result['state'] == 'firewall_failed'
                and result['failure'] == 'nftables_rejected' and type(result['nft_returncode']) is int
                and result['nft_returncode'] > 0 and result['policy_sha256'] is None
                and result['cleanup']['ok'] is True and not present,
                'Firewall rejection did not tear down the partial network.')
        require(network['ActiveState'] == 'failed' and network['Result'] == 'exit-code'
                and network['ExecMainStatus'] != 0 and worker['ActiveState'] == 'inactive'
                and worker['MainPID'] == worker['ExecMainStartTimestampMonotonic'] == 0,
                'Collector executed despite failing firewall dependency.')
        require(status['current_evaluation']['status'] == 'unknown'
                and status['freshness']['last_accepted_request_id'] is None
                and status['freshness']['gap_recorded'] is True
                and status['freshness']['gap_sequence'] == len(rows)
                and 'telemetry_gap:collector' in status['current_evaluation']['active_alert_keys'],
                'Failed boot did not stay unknown through the missing-data deadline.')
    else:
        require(stage['fault_armed'] is False and result['state'] == 'ready' and result['nft_returncode'] == 0
                and result['policy_sha256'] == identity['approved_policy_sha256']
                and present == set(result['namespaces'].values()), 'Approved firewall or namespaces are missing.')
        require(network['ActiveState'] == worker['ActiveState'] == 'active'
                and network['MainPID'] > 0 and worker['MainPID'] > 0
                and 0 < network['ActiveEnterTimestampMonotonic'] <= worker['ExecMainStartTimestampMonotonic']
                <= uptime * 1_000_000 and reboot.TOKEN.fullmatch(worker['InvocationID']),
                'Collector started before boot-scoped network readiness.')
        require(status['current_evaluation']['status'] == 'healthy'
                and status['freshness']['last_accepted_request_id'] == rows[-1]['request_id'],
                'The current boot did not establish fresh healthy coverage.')
    return rows


def validate_receipt(receipt, row, boot_id, local_cycle, ports):
    observation = receipt['request']['observation']
    probes, cycle = observation['probes'], receipt['cycle']
    require(receipt['boot_id'] == receipt['delivery_boot_id'] == boot_id
            and receipt['process_cycle'] == local_cycle
            and receipt['committed_sequence'] == row['sequence'] and receipt['evaluation'] == row['evaluation']
            and receipt['request']['command'] == 'observe' and receipt['request']['request_id'] == row['request_id']
            and row['request'] == {'kind': 'observation', 'observation': observation}
            and observation['ruleset'] is not None and observation['collection_error'] is None,
            'Collector receipt does not bind a fresh current-boot journal observation.')
    expected = collector.canary_cycle(cycle, local_cycle)
    require(len(probes) == (3 if expected else 0), 'Boot probe schedule differs.')
    if not expected:
        require(row['evaluation']['status'] != 'healthy', 'Rule-only observation claimed healthy coverage.')
    for probe in probes:
        for item in (probe, probe.get('destination_health')):
            if item is not None:
                port = item['source_port']
                first = collector.PORT_START + collector.PORT_BLOCK * (cycle - 1)
                require(type(port) is int and first <= port < first + collector.PORT_BLOCK and port not in ports,
                        'A canary port was reused or outside its durable allocation.')
                ports.add(port)
    if local_cycle == 3:
        outcomes = [(p['from'], p['to'], p['port'], p['outcome']) for p in probes]
        require(outcomes == [('user', 'app', 8080, 'response'), ('user', 'app', 9090, 'connect_timeout'),
                             ('management', 'app', 9090, 'response')]
                and monitor.good_response(probes[1]['destination_health'], 'app', 9090)
                and row['evaluation']['status'] == 'healthy'
                and row['evaluation']['policy_matches'] is True and row['evaluation']['telemetry_valid'] is True,
                'Fresh canaries did not prove allowed and blocked paths against a healthy destination.')


def validate_stages(snapshots, source):
    require(set(snapshots) == set(STAGE_OUTPUTS), 'Automatic boot snapshots are incomplete.')
    first, final = snapshots['baseline'], snapshots['recovered']
    rows, receipts = final['history']['rows'], final['receipts']
    replay.replay_rows(rows, first['history']['approved_policy'])
    require([r['cycle'] for r in receipts] == list(range(1, len(receipts) + 1)),
            'Collector cycle continuity differs.')
    by_sequence = {receipt['committed_sequence']: receipt for receipt in receipts}
    require(len(by_sequence) == len(receipts), 'Duplicate committed collector receipt.')
    boundaries = [i for i, row in enumerate(rows) if row['request']['kind'] == 'restart']
    require(len(boundaries) == len(STAGE_OUTPUTS) and boundaries[0] == 0,
            'Expected exactly one durable monitor restart row per boot.')
    worker_invocations, monitor_invocations, instances, boot_ids, ports = set(), set(), set(), set(), set()
    seen = 0
    prior_rows = []
    ends = [*boundaries[1:], len(rows)]
    for name, start, end in zip(STAGE_OUTPUTS, boundaries, ends):
        stage = snapshots[name]
        stage_rows = validate_snapshot(stage, name, source, first)
        length = len(stage_rows)
        require(stage_rows[:len(prior_rows)] == prior_rows and stage_rows == rows[:length]
                and start < length <= end, 'A host-held committed history prefix changed across boot.')
        prior_rows = stage_rows
        boot_id = stage['boot']['boot_id']
        monitor_invocation = stage['services']['monitor']['InvocationID']
        require(boot_id not in boot_ids and monitor_invocation not in monitor_invocations,
                'Boot or monitor invocation identity repeated.')
        boot_ids.add(boot_id); monitor_invocations.add(monitor_invocation)
        require(rows[start]['evaluation']['status'] == 'unknown', 'Boot did not begin with unknown coverage.')
        require(stage['receipts'] == [r for r in receipts if r['committed_sequence'] <= length],
                'Host-held collector receipts changed or do not match the journal head.')
        require(stage['receipts'], 'A completed boot snapshot requires saved collector allocation.')
        cycle = stage['receipts'][-1]['cycle']
        require(stage['allocation'] == {'cycles': cycle,
                    'next_port': collector.PORT_START + collector.PORT_BLOCK * cycle}
                and stage['failed_boot_pending_absent'] is (True if name == 'failed' else None),
                'Coherent snapshot lost committed allocation or a failed boot retained pending state.')
        group = []
        for row in rows[start + 1:end]:
            if row['sequence'] in by_sequence:
                receipt = by_sequence[row['sequence']]
                group.append(receipt)
                validate_receipt(receipt, row, boot_id, len(group), ports)
            else:
                sample = row['sample']
                require(row['request']['kind'] == 'observation' and row['request_id'].startswith('freshness-gap-')
                        and sample['phase'] == 'collector_missing'
                        and sample['collection_error'] == 'freshness_deadline_exceeded'
                        and sample['ruleset'] is None and sample['probes'] == []
                        and row['evaluation']['status'] == 'unknown', 'Unexpected unreceipted journal row.')
        seen += len(group)
        if name == 'failed':
            require(not group and end - start == 2 and length == end,
                    'Failed boot accepted collector data or did not preserve an explicit gap.')
        else:
            worker = stage['services']['collector']
            require(len(group) >= 3 and group[2]['committed_sequence'] <= length
                    and all(r['instance_id'] == group[0]['instance_id'] and r['process_id'] == worker['MainPID']
                            and r['delivery_process_id'] == r['process_id'] for r in group)
                    and group[0]['instance_id'] not in instances and worker['InvocationID'] not in worker_invocations,
                    'A fresh boot did not use one distinct automatic collector instance.')
            row = rows[group[2]['committed_sequence'] - 1]
            require(all(item['evaluation']['status'] != 'healthy' for item in rows[start:row['sequence'] - 1]),
                    'Monitoring reported healthy before the first complete fresh canaries.')
            instances.add(group[0]['instance_id']); worker_invocations.add(worker['InvocationID'])
    require(seen == len(receipts), 'Unbound collector receipts were present.')


def run(output):
    tools = reboot.preflight()
    source = source_identity()
    destination = reboot.monitoring.base.new_output(output)
    staging = destination / 'staging'
    staging.mkdir(mode=0o700)
    vm = DisposableVM(tools)
    report = {'format': 'heltemes-network-monitor-automatic-boot', 'version': 1,
              'ok': False, 'source': source, 'started_at_utc': reboot.timestamp(),
              'scope': {'synthetic_only': True, 'aws_deployed': False, 'real_evidence_inputs': False,
                        'graceful_vm_reboots': True, 'physical_power_loss_tested': False}}
    evidence = {'image': {'url': reboot.IMAGE_URL, 'sha256': reboot.IMAGE_SHA256}, 'reboots': {}}
    snapshots = {}
    step = 'preparing pinned disposable image'; progress(step)
    try:
        evidence['virtualization'] = vm.prepare()
        step = 'booting the VM and installing committed lab sources'; progress(step); vm.launch()
        evidence['cloud_init'] = vm.cloud_init
        evidence['virtualization']['qmp_kvm'] = vm.kvm_status
        evidence['initial_boot'] = vm.boot_snapshot()
        require(evidence['initial_boot'] is not None, 'Initial guest boot identity is unavailable.')
        step = 'installing boot services and collecting the initial baseline'; progress(step)
        evidence['installation'] = vm.guest('install')
        snapshots['baseline'] = vm.guest('baseline')
        for name, setup in zip(BOOT_CASES, (None, 'arm-failure', 'disarm-failure')):
            if setup:
                step = 'changing the disposable firewall test input'; progress(step)
                evidence[setup] = vm.guest(setup)
            step = 'rebooting Linux for the ' + name + ' case'; progress(step)
            evidence['reboots'][name] = vm.reboot()
            step = 'observing boot-started services for the ' + name + ' case'; progress(step)
            snapshots[name] = vm.guest(name)
        step = 'checking actual boot identities, history, observations, and service evidence'; progress(step)
        validate_reboots(snapshots, evidence)
        validate_stages(snapshots, source)
        step = 'removing owned guest services and verifying exact source'; progress(step)
        evidence['guest_cleanup'] = vm.guest('cleanup')
        require(evidence['installation']['boot']['boot_id'] == snapshots['baseline']['boot']['boot_id']
                and evidence['installation']['units'] == snapshots['baseline']['units']
                and evidence['installation']['approved_policy_sha256']
                == snapshots['baseline']['history']['identity']['approved_policy_sha256'],
                'Installation differs from the initial approved policy or boot.')
        for action, stage, armed in (('arm-failure', 'normal', True), ('disarm-failure', 'failed', False)):
            prepared = evidence[action]
            require(prepared['boot']['boot_id'] == snapshots[stage]['boot']['boot_id']
                    and prepared['fault_armed'] is armed,
                    'Firewall test input was changed on the wrong boot.')
        require(evidence['guest_cleanup']['boot']['boot_id'] == snapshots['recovered']['boot']['boot_id']
                and all(evidence['guest_cleanup'][key] is True for key in
                        ('services_disabled_removed', 'state_removed', 'runtime_removed', 'namespaces_removed')),
                'Owned guest services or synthetic network state were not cleaned up.')
        require(source_identity() == source, 'Tested source changed during the exercise.')
    except RUN_ERRORS as error:
        report['error'] = step + ': ' + safe_failure(vm, error).replace(str(destination), '<report>')
        try:
            evidence['diagnostic'] = vm.guest('diagnostic')
        except RUN_ERRORS as diagnostic_error:
            evidence['diagnostic_unavailable'] = safe_failure(vm, diagnostic_error)[-2048:]
    finally:
        try:
            progress('stopping the owned VM and deleting temporary credentials and disk')
            evidence['cleanup'] = vm.cleanup()
        except RUN_ERRORS as error:
            evidence['cleanup'] = {'ok': False, 'error': safe_failure(vm, error)}
        report['completed_at_utc'] = reboot.timestamp()
    report['cleanup'] = evidence['cleanup']
    report['ok'] = 'error' not in report and evidence['cleanup']['ok'] is True
    if not report['ok']:
        reboot.write_json(staging / 'FAILURE.json', {'report': report, 'evidence': evidence})
        raise RuntimeError('Automatic boot exercise failed: ' + report.get('error', 'Private VM cleanup failed.'))
    publish = destination / 'publish'
    publish.mkdir(mode=0o700)
    reboot.write_json(publish / 'REPORT.json', report)
    reboot.write_json(publish / 'VM.json', evidence)
    for name, snapshot in snapshots.items():
        reboot.write_json(publish / STAGE_OUTPUTS[name], snapshot)
    reboot.write_json(publish / 'MANIFEST.json',
                      {name: reboot.sha256_file(publish / name) for name in PUBLIC_FILES})
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='New report directory with an existing parent')
    args = parser.parse_args()
    try:
        report = run(args.output)
    except RUN_ERRORS as error:
        parser.exit(1, str(error) + '\n')
    print(json.dumps({'ok': report['ok'], 'source_commit': report['source']['commit'],
                      'cleanup': report['cleanup']}, indent=2))


if __name__ == '__main__':
    main()
