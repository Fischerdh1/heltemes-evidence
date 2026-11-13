"""Build a practice backup and verify its restore in a freshly booted Linux guest."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import clean_restore_fixture as fixture
from scripts import network_monitor_reboot_vm as reboot

require = reboot.require
GUEST_SCRIPT = 'scripts/clean_restore_guest.py'
APP_SOURCE = (
    'heltemes/__init__.py', 'heltemes/__main__.py', 'heltemes/config.py', 'heltemes/core.py',
    'heltemes/key_recovery.py', 'heltemes/local_accounts.py', 'heltemes/protection.py',
    'heltemes/sec.py', 'heltemes/server.py', 'heltemes/fixtures/demo_submissions.json',
)
TRANSFER_SOURCE = (*APP_SOURCE, GUEST_SCRIPT)
HOST_SOURCE = ('scripts/clean_restore_fixture.py', 'scripts/clean_restore_vm.py')
MAX_STAGE = 8 * 1024 * 1024


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def committed_source():
    source = reboot.source_identity()
    files = {}
    for name in (*TRANSFER_SOURCE, *HOST_SOURCE):
        path = ROOT / name
        raw = path.read_bytes()
        committed = subprocess.check_output(['git', 'show', f"{source['commit']}:{name}"],
                                            cwd=ROOT, timeout=30)
        require(raw == committed, 'The restore drill source differs from the tested commit.')
        source['source_sha256'][name] = sha(raw)
        if name in TRANSFER_SOURCE:
            files[name] = raw
    return source, files


def pack(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in files.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(raw)
            entry.mode = 0o644
            archive.addfile(entry, io.BytesIO(raw))
    value = output.getvalue()
    require(len(value) <= MAX_STAGE, 'Transfer exceeds the restore drill size limit.')
    return value


def guest_stage(vm, stage, files):
    command = ('sudo -n python3 -I -S -B ' + reboot.GUEST_ROOT + '/' + GUEST_SCRIPT
               + ' --stage ' + stage + ' --token ' + vm.token)
    result = vm.ssh(command, input=pack(files), timeout=120, check=False)
    require(0 < len(result.stdout) < 64 * 1024, 'Guest returned no bounded stage report.')
    report = json.loads(result.stdout)
    if result.returncode != 0:
        raise RuntimeError('Guest ' + stage + ' failed: ' + vm.redact(report.get('error', 'unknown')))
    require(report['ok'] is True and report['stage'] == stage, 'Guest returned an unexpected stage report.')
    return report


def validate_restore(staged, report, expected, boot, backups, receipts):
    require(staged['fresh'] is True and staged['boot_id'] == report['boot_id'] == boot['boot_id']
            and all(stage['guest']['boot_id'] == boot['boot_id']
                    and stage['guest']['virtualization'] in ('qemu', 'kvm')
                    and stage['guest']['host_shared_filesystem_absent'] is True
                    for stage in (staged, report))
            and staged['backups'] == report['backups'] == {name: sha(raw) for name, raw in backups.items()}
            and report['receipts'] == {name: sha(raw) for name, raw in receipts.items()}
            and report['cleanup'] is True, 'Guest boot, transfers, or cleanup evidence differs.')
    require(expected['older_sequence'] == 1 and expected['sequence'] == 2
            and expected['older_head'] != expected['head']
            and expected['corruption']['unsigned_consistent'] is True
            and expected['corruption']['signed_issue'] == 'Sealed filings record was changed.',
            'The synthetic source did not establish the rollback and tamper controls.')
    cases = report['cases']
    refusals = {
        'missing_receipt': 'receipt_required',
        'older_with_latest_receipt': 'older_checkpoint',
        'corrupt_with_latest_receipt': 'sealed_record_changed',
    }
    successful = {'older_with_older_receipt': 'older_', 'latest_with_latest_receipt': ''}
    require(set(cases) == set(refusals) | set(successful) | {'signing_without_private_key'},
            'Unexpected restore case inventory.')
    for name, reason in refusals.items():
        case = cases[name]
        require(case['restored'] is False and case['exit_code'] == 1 and case['reason'] == reason
                and case['destination_unchanged'] is True and case['trust_absent'] is True,
                'Restore did not fail closed for ' + name)
    for name, prefix in successful.items():
        case = cases[name]
        require(all(case[key] is True for key in ('restored', 'verified', 'public_only', 'settings_absent'))
                and case['archive_id'] == expected['archive_id']
                and all(case[key] == expected[prefix + key]
                        for key in ('sequence', 'head', 'filing_count', 'object_count', 'filings', 'objects')),
                'Restored evidence differs from the accepted source snapshot.')
    signing = cases['signing_without_private_key']
    require(signing['refused'] is True and signing['exit_code'] == 1 and signing['reason'] == 'private_key_absent'
            and signing['sequence'] == expected['sequence'] and signing['head'] == expected['head']
            and signing['pending_records'] > 0 and signing['pending_filings'] > 0
            and all(signing[key] is True for key in ('pending_retained', 'checkpoint_unchanged',
                                                   'private_key_absent', 'settings_absent')),
            'The verifier-only copy did not safely refuse signing.')


def run(output):
    tools = reboot.preflight()
    source, code = committed_source()
    destination = reboot.monitoring.base.new_output(output)
    vm = reboot.DisposableVM(tools)
    try:
        with tempfile.TemporaryDirectory(prefix='he-clean-restore-') as temp:
            inputs = fixture.build(Path(temp).resolve())
            expected = inputs['expected']
            backups = {name: inputs[key].read_bytes() for name, key in
                       (('latest.zip', 'latest_backup'), ('older.zip', 'older_backup'), ('corrupt.zip', 'corrupt_backup'))}
            receipts = {name: inputs[key].read_bytes() for name, key in
                        (('latest.json', 'receipt'), ('older.json', 'older_receipt'))}
            require(not {inputs[key].parent for key in ('latest_backup', 'older_backup', 'corrupt_backup')}
                    & {inputs[key].parent for key in ('receipt', 'older_receipt')},
                    'The practice receipts must be staged separately from the backups.')
            for name, prefix in (('latest.json', ''), ('older.json', 'older_')):
                receipt = json.loads(receipts[name])
                require(receipt['archive_id'] == expected['archive_id']
                        and receipt['sequence'] == expected[prefix + 'sequence']
                        and receipt['checkpoint_sha256'] == expected[prefix + 'head'],
                        'The host-held receipt does not match its independently saved checkpoint.')
            virtualization = vm.prepare()
            vm.launch()
            virtualization['qmp_kvm'] = vm.kvm_status
            boot = vm.boot_snapshot()
            require(boot is not None, 'Fresh guest boot identity unavailable.')
            vm.ssh('sudo -n tar -x --no-same-owner -f - -C ' + reboot.GUEST_ROOT,
                   input=pack(code), timeout=30)
            print('Transferring three practice backups to the fresh guest.', file=sys.stderr, flush=True)
            staged = guest_stage(vm, 'backups', backups)
            require(staged['fresh'] is True and staged['boot_id'] == boot['boot_id']
                    and staged['backups'] == {name: sha(raw) for name, raw in backups.items()},
                    'Fresh guest or backup delivery evidence differs.')
            print('Delivering the independently held public receipts in a second SSH session.', file=sys.stderr, flush=True)
            report = guest_stage(vm, 'exercise', receipts)
            validate_restore(staged, report, expected, boot, backups, receipts)
            require(all(stage['guest']['virtualization'] == ('kvm' if vm.kvm_status['enabled'] else 'qemu')
                        for stage in (staged, report)), 'Guest and VM monitor disagree about acceleration.')
            require(report['source_sha256'] == {name: sha(raw) for name, raw in code.items()},
                    'Guest restore source differs from its committed transfer.')
            require(committed_source()[0] == source, 'Tested source changed during the restore.')
    finally:
        cleanup = vm.cleanup()
    require(cleanup['ok'] is True and not Path(temp).exists(), 'Owned VM or fixture cleanup failed.')
    evidence = {'format': 'heltemes-clean-machine-restore', 'version': 1, 'ok': True,
                'completed_at_utc': reboot.timestamp(), 'source': source, 'expected': expected,
                'image': {'url': reboot.IMAGE_URL, 'sha256': reboot.IMAGE_SHA256},
                'virtualization': virtualization, 'cloud_init': vm.cloud_init,
                'boot': boot, 'backup_stage': staged, 'restore_stage': report, 'cleanup': cleanup,
                'host_fixture_removed': True,
                'scope': {'synthetic_only': True, 'receipts_delivered_separately': True,
                          'physical_off_device_custody_tested': False, 'real_evidence_inputs': False,
                          'aws_deployed': False}}
    path = destination / 'CLEAN-RESTORE.json'
    reboot.write_json(path, evidence)
    reboot.write_json(destination / 'MANIFEST.json', {path.name: reboot.sha256_file(path)})
    for name, case in report['cases'].items():
        print(name + ': ' + (case.get('reason') or f"verified checkpoint {case['sequence']}"))
    print('Verified all restore cases. Practice state and disposable VM removed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='New directory under an existing parent')
    args = parser.parse_args()
    try:
        run(args.output)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, 'Clean-machine restore drill failed: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
