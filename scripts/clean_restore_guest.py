"""Exercise the public restore and signing commands on a fresh disposable VM."""
from __future__ import annotations

import argparse
from contextlib import closing
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from heltemes import protection
from heltemes.core import Repository
from scripts import network_monitor_reboot_guest as reboot
from scripts import network_monitor_store as store

LAB = Path('/var/lib/heltemes-clean-restore-lab')
BACKUPS = ('latest.zip', 'older.zip', 'corrupt.zip')
RECEIPTS = ('latest.json', 'older.json')
SOURCE = (
    'heltemes/__init__.py', 'heltemes/__main__.py', 'heltemes/config.py', 'heltemes/core.py',
    'heltemes/key_recovery.py', 'heltemes/local_accounts.py', 'heltemes/protection.py',
    'heltemes/sec.py', 'heltemes/server.py', 'heltemes/fixtures/demo_submissions.json',
    'scripts/clean_restore_guest.py',
)
MAX_STAGE = 8 * 1024 * 1024
MAX_MEMBERS = 32
OBJECT_NAME = re.compile(r'(?:raw/[0-9a-f]{2}/[0-9a-f]{64}\.json|documents/[0-9a-f]{2}/[0-9a-f]{64}\.bin)')
CHECKPOINT = re.compile(r'protection/checkpoints/[0-9]{8}\.json')
ACCESSION = re.compile(r'[0-9]{10}-[0-9]{2}-[0-9]{6}')
PRIVATE_KEY = re.compile(rb'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----')
BOOTSTRAP = 'import runpy, sys; sys.path.insert(0, sys.argv.pop(1)); runpy.run_module("heltemes", run_name="__main__", alter_sys=True)'
ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/nonexistent'}


class DrillError(RuntimeError):
    """A fixed diagnostic suitable for the guest's public report."""


def require(condition, message):
    if not condition:
        raise DrillError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def absent(path):
    return not os.path.lexists(path)


def private_directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700,
            'Unexpected restore lab directory identity.')


def boot(token):
    virtualization = reboot.guard(token)
    require(not any(path.is_symlink() for path in (LAB, *LAB.parents)),
            'The restore lab path traverses a symbolic link.')
    mounts = Path('/proc/self/mountinfo').read_text().splitlines()
    shared = {'9p', 'virtiofs', 'vboxsf', 'hgfs', 'fuse.vmhgfs-fuse', 'fuse.sshfs'}
    require(not any(line.split(' - ', 1)[1].split()[0] in shared for line in mounts),
            'A host-sharing filesystem is present in the guest.')
    mount = json.loads(reboot.command(['/usr/bin/findmnt', '--json', '--target', str(LAB.parent),
                                      '--output', 'SOURCE,FSTYPE']).stdout)['filesystems']
    require(len(mount) == 1 and mount[0]['fstype'] in {'ext4', 'xfs', 'btrfs'}
            and mount[0]['source'].startswith('/dev/'), 'The restore lab needs a guest disk filesystem.')
    return {**reboot.boot_info(virtualization), 'disk_filesystem': mount[0]['fstype'],
            'host_shared_filesystem_absent': True}


def source_hashes():
    result = {}
    for name in SOURCE:
        path = ROOT / name
        info = path.lstat()
        require(not any(part.is_symlink() for part in (path, *path.parents))
                and stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                and not info.st_mode & 0o022 and 0 < info.st_size < 1024 * 1024,
                'An installed application input is missing or unsafe.')
        result[name] = sha(path.read_bytes())
    return result


def receive(names, maximum):
    raw = sys.stdin.buffer.read(MAX_STAGE + 1)
    require(0 < len(raw) <= MAX_STAGE, 'The input transfer exceeds its size limit or is empty.')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = archive.getmembers()
        require(len(members) == len(names) and {member.name for member in members} == set(names)
                and all(member.type == tarfile.REGTYPE and not member.pax_headers and not member.linkname
                        and 0 < member.size <= maximum for member in members),
                'The input transfer has an unexpected inventory or entry type.')
        return {name: archive.extractfile(name).read() for name in names}


def stage(folder, files):
    folder.mkdir(mode=0o700)
    for name, raw in files.items():
        with (folder / name).open('xb') as handle:
            handle.write(raw)


def backup_members(path):
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = {entry.filename for entry in entries}
        require(len(entries) <= MAX_MEMBERS and len(entries) == len(names)
                and sum(entry.file_size for entry in entries) <= MAX_STAGE
                and {'manifest.json', 'data.sqlite3', 'protection.json'} <= names,
                'A backup has an unexpected or oversized ZIP inventory.')
        for entry in entries:
            name = entry.filename
            require(stat.S_IFMT(entry.external_attr >> 16) in (0, stat.S_IFREG) and not entry.flag_bits & 1
                    and (name in {'manifest.json', 'data.sqlite3', 'protection.json'}
                         or OBJECT_NAME.fullmatch(name) or CHECKPOINT.fullmatch(name)),
                    'A backup contains unexpected private material or an unsupported ZIP entry.')
        contents = {name: archive.read(name) for name in names}
    require(not any(PRIVATE_KEY.search(raw) for raw in contents.values()),
            'A backup contains apparent private-key material.')
    return contents


def cli(data, *arguments):
    result = subprocess.run(['/usr/bin/python3', '-I', '-S', '-B', '-c', BOOTSTRAP, str(ROOT),
                             '--data-dir', str(data), *map(str, arguments)],
                            cwd='/', env=ENV, stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, encoding='utf-8', timeout=30)
    require(len(result.stdout) < 64 * 1024 and len(result.stderr) < 8 * 1024,
            'A public command exceeded its output limit.')
    return result


def cli_success(data, *arguments):
    result = cli(data, *arguments)
    require(result.returncode == 0 and not result.stderr, 'A public restore drill command failed unexpectedly.')
    return store.parse(result.stdout)


def pinned(state, receipt):
    return all(state[field] == receipt[field] for field in ('archive_id', 'sequence', 'checkpoint_sha256'))


def directory_identity(path):
    info = path.lstat()
    return info.st_dev, info.st_ino, info.st_mode, info.st_mtime_ns, sorted(item.name for item in path.iterdir())


def reject(work, name, backup, receipt, reason, *, existing_empty=False):
    data = work / name
    if existing_empty:
        data.mkdir(mode=0o700)
        before = directory_identity(data)
    else:
        require(absent(data), 'A negative restore target was already present.')
    trust = protection.default_trust_dir(data)
    require(absent(trust), 'A negative restore target already had trust.')
    arguments = () if receipt is None else ('--trust-receipt', receipt)
    result = cli(data, 'restore', backup, data, *arguments)
    message = ('A protected backup requires an independently saved --trust-receipt.' if receipt is None
               else 'Restored evidence does not match the supplied trusted checkpoint.')
    require(result.returncode == 1 and not result.stdout and result.stderr == f'Error: {message}\n',
            'A restore rejection did not reach its expected public validation boundary.')
    unchanged = directory_identity(data) == before if existing_empty else absent(data)
    require(unchanged and absent(trust) and not list(work.glob('.heltemes-restore-*')),
            'A refused restore changed its target, installed trust, or retained staging files.')
    return {'restored': False, 'exit_code': result.returncode, 'reason': reason,
            'destination_unchanged': unchanged, 'trust_absent': True}


def check_signed_refusal(work, backup, receipt, expected_error):
    contents = backup_members(backup)
    manifest = store.parse(contents.pop('manifest.json'))
    require(manifest['protection'] == 'signed-checkpoint' and set(manifest['files']) == set(contents)
            and all(manifest['files'][name] == {'sha256': sha(raw), 'bytes': len(raw)}
                    for name, raw in contents.items()), 'A negative backup did not pass unsigned manifest checks.')
    with tempfile.TemporaryDirectory(prefix='unsigned-check-', dir=work) as temp:
        data = Path(temp)
        for name, raw in contents.items():
            target = data / name
            target.parent.mkdir(exist_ok=True, parents=True)
            target.write_bytes(raw)
        unsigned = Repository(data).verify_integrity(check_protection=False)
        require(unsigned['ok'] and unsigned['checked'] > 0, 'A negative backup failed unsigned evidence checks.')
        signed = protection.validate_backup_protection(data, receipt)
        require(signed['status'] == 'failed' and signed['issues'] == [{'path': 'protection', 'error': expected_error}],
                'A negative backup did not reach its expected signed validation boundary.')


def trust_hashes(data):
    trust = protection.default_trust_dir(data)
    require({path.name for path in trust.iterdir()} == {'anchor.json', 'checkpoints'},
            'The restored public trust vault has unexpected material.')
    paths = [trust / 'anchor.json', *(trust / 'checkpoints').iterdir()]
    require(all(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1 for path in paths),
            'The restored public trust files have an unexpected identity.')
    return {str(path.relative_to(trust)): sha(path.read_bytes()) for path in paths}


def no_private_material(data):
    key_dir = protection.default_key_dir(data)
    require(absent(key_dir.parent) and absent(data / 'settings.json'),
            'The restored archive contains a signing-key directory or local settings.')
    return key_dir


def inventory(data):
    uri = (data / 'data.sqlite3').as_uri() + '?mode=ro'
    with closing(sqlite3.connect(uri, uri=True)) as db:
        db.execute('PRAGMA trusted_schema=OFF')
        objects = db.execute('SELECT path, sha256, bytes FROM assets ORDER BY path').fetchall()
        filings = db.execute('SELECT accession, document_sha256, assets.bytes FROM filings '
                             'JOIN assets ON filings.document_path=assets.path ORDER BY accession').fetchall()
        count = db.execute('SELECT count(*) FROM filings').fetchone()[0]
    require(0 < count == len(filings) <= MAX_MEMBERS and 0 < len(objects) <= MAX_MEMBERS
            and all(ACCESSION.fullmatch(accession) for accession, _, _ in filings),
            'The restored synthetic filing inventory is unexpected.')
    require(all(OBJECT_NAME.fullmatch(path) and len((raw := (data / path).read_bytes())) == size and sha(raw) == digest
                for path, digest, size in objects), 'A restored evidence object differs from its indexed digest.')
    return ([{'accession': accession, 'sha256': digest, 'size': size} for accession, digest, size in filings],
            [{'path': path, 'sha256': digest, 'size': size} for path, digest, size in objects])


def restore(data, backup, receipt_path, receipt):
    require(absent(data), 'A positive restore target was already present.')
    no_private_material(data)
    result = cli_success(data, 'restore', backup, data, '--trust-receipt', receipt_path)
    require(result == {'restored': str(data)}, 'The restore did not activate its intended target.')
    no_private_material(data)
    require({path.name for path in data.iterdir()} == {'data.sqlite3', 'raw', 'documents', 'protection.json', 'protection'},
            'The restored repository has an unexpected inventory.')
    state = cli_success(data, 'protect', 'status')
    integrity = cli_success(data, 'verify')
    require(state['ok'] is True and state['status'] == 'sealed' and state['pending_records'] == 0
            and pinned(state, receipt) and integrity['ok'] is True and integrity['evidence_ok'] is True
            and integrity['protection'] == state, 'Public verification did not accept the restored pinned checkpoint.')
    contents = backup_members(backup)
    expected = {'anchor.json': sha(receipt_path.read_bytes()),
                **{name.removeprefix('protection/'): sha(raw) for name, raw in contents.items()
                   if CHECKPOINT.fullmatch(name)}}
    require(trust_hashes(data) == expected, 'The restored public trust differs from the receipt or checkpoint bytes.')
    filings, objects = inventory(data)
    require(state['sealed_filings'] == len(filings) and integrity['checked'] == len(objects),
            'Verification and recovered inventory counts differ.')
    status = cli_success(data, 'status')
    require(status['config']['live_contact_configured'] is False, 'The restored copy has a configured SEC contact.')
    return {'restored': True, 'verified': True, 'public_only': True, 'settings_absent': True,
            'archive_id': state['archive_id'], 'sequence': state['sequence'], 'head': state['checkpoint_sha256'],
            'filing_count': len(filings), 'object_count': len(objects), 'filings': filings, 'objects': objects}


def refuse_signing(data, backup, receipt_path, receipt):
    restored = restore(data, backup, receipt_path, receipt)
    key_dir = no_private_material(data)
    before = trust_hashes(data)
    demo = cli_success(data, 'demo')
    pending = cli_success(data, 'verify')
    state = pending['protection']
    require(demo['status'] == 'success' and demo['mode'] == 'demo' and demo['filings_added'] > 0
            and pending['ok'] is True and state['status'] == 'pending' and pinned(state, receipt)
            and state['sealed_filings'] == restored['filing_count']
            and state['pending_filings'] == demo['filings_added'] and state['pending_records'] > 0,
            'The synthetic additions did not produce genuinely pending, verifiable records.')
    database = data / 'data.sqlite3'
    pending_digest = sha(database.read_bytes())
    result = cli(data, 'protect', 'seal')
    missing = FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), str(key_dir))
    require(result.returncode == 1 and not result.stdout and result.stderr == f'Error: {missing}\n',
            'Signing did not explicitly fail on the absent private-key directory.')
    after = cli_success(data, 'verify')
    require(after['ok'] is True and after['protection'] == state and sha(database.read_bytes()) == pending_digest
            and trust_hashes(data) == before, 'Refused signing changed the accepted checkpoint or pending records.')
    no_private_material(data)
    return {'refused': True, 'exit_code': result.returncode, 'reason': 'private_key_absent',
            'sequence': state['sequence'], 'head': state['checkpoint_sha256'],
            'pending_records': state['pending_records'], 'pending_filings': state['pending_filings'],
            'pending_retained': True, 'checkpoint_unchanged': True, 'private_key_absent': True,
            'settings_absent': True}


def exercise(backups, receipts, work):
    latest = receipts / 'latest.json'
    older = receipts / 'older.json'
    latest_pin, _ = protection._anchor(latest)
    older_pin, _ = protection._anchor(older)
    require(latest_pin['sequence'] == 2 and older_pin['sequence'] == 1
            and latest_pin['archive_id'] == older_pin['archive_id']
            and latest_pin['public_key'] == older_pin['public_key']
            and latest_pin['checkpoint_sha256'] != older_pin['checkpoint_sha256'],
            'The two independent public receipts do not pin the expected archive history.')
    current_backup, old_backup, corrupt = (backups / name for name in BACKUPS)
    check_signed_refusal(work, old_backup, latest,
                         'Checkpoint inventory differs from the pinned head; missing, extra, or rolled-back checkpoints detected.')
    check_signed_refusal(work, corrupt, latest, 'Sealed filings record was changed.')
    return {
        'missing_receipt': reject(work, 'no-receipt', current_backup, None, 'receipt_required'),
        'older_with_latest_receipt': reject(work, 'stale-backup', old_backup, latest,
                                            'older_checkpoint', existing_empty=True),
        'corrupt_with_latest_receipt': reject(work, 'modified-backup', corrupt, latest, 'sealed_record_changed'),
        'older_with_older_receipt': restore(work / 'older-copy', old_backup, older, older_pin),
        'latest_with_latest_receipt': restore(work / 'latest-copy', current_backup, latest, latest_pin),
        'signing_without_private_key': refuse_signing(work / 'signing-copy', current_backup, latest, latest_pin),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', choices=('backups', 'exercise'), required=True)
    parser.add_argument('--token', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    report = {'ok': False, 'stage': args.stage}
    owned = False
    failure = 'Disposable guest validation failed.'
    try:
        guest = boot(args.token)
        report.update(boot_id=guest['boot_id'], guest=guest)
        require('SEC_USER_AGENT' not in os.environ, 'A SEC contact was supplied to the restore guest environment.')
        backups = LAB / 'backups'
        if args.stage == 'backups':
            require(absent(LAB), 'The guest restore lab already exists.')
            failure = 'The backup transfer could not be staged safely.'
            files = receive(BACKUPS, MAX_STAGE)
            LAB.mkdir(mode=0o700)
            owned = True
            stage(backups, files)
            for name in BACKUPS:
                backup_members(backups / name)
            report.update(fresh=True, backups={name: sha(raw) for name, raw in files.items()})
        else:
            private_directory(LAB)
            require({path.name for path in LAB.iterdir()} == {'backups'}, 'Unexpected material existed before receipt transfer.')
            private_directory(backups)
            owned = True
            failure = 'The public receipt transfer could not be staged safely.'
            require({path.name for path in backups.iterdir()} == set(BACKUPS), 'Unexpected staged backup inventory.')
            report['backups'] = {name: sha(store.read_private(backups / name, limit=MAX_STAGE)) for name in BACKUPS}
            files = receive(RECEIPTS, 16_384)
            require(not any(PRIVATE_KEY.search(raw) for raw in files.values()), 'A receipt contains apparent private-key material.')
            receipts, work = LAB / 'receipts', LAB / 'destinations'
            stage(receipts, files)
            work.mkdir(mode=0o700)
            report['receipts'] = {name: sha(raw) for name, raw in files.items()}
            failure = 'A public restore or signing observation could not be verified.'
            report['cases'] = exercise(backups, receipts, work)
            report['source_sha256'] = source_hashes()
        report['ok'] = True
    except DrillError as error:
        report['error'] = str(error)
    except Exception:
        report['error'] = failure
    finally:
        if owned and (args.stage == 'exercise' or not report['ok']):
            try:
                shutil.rmtree(LAB)
                report['cleanup'] = absent(LAB)
            except OSError:
                report['cleanup'] = False
            if not report['cleanup']:
                report.update(ok=False, error='Guest restore lab cleanup could not be verified.')
    print(json.dumps(report, sort_keys=True))
    return 0 if report['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
