"""User-operated activation: show the concrete plan, then macOS authentication."""
import importlib.util
from datetime import datetime, timezone
import os
from pathlib import Path
import stat
import subprocess
import sys
import uuid
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
RECOVERY_SPEC = ROOT / 'work/local-account-recovery.json'


def open_diagnostic_log():
    """Create a private, unique diagnostic file without following log links."""
    work = ROOT / 'work'
    directory = work / 'activation-logs'
    for path in (work, directory):
        if path.is_symlink():
            raise ValueError('Diagnostic folders must not be symbolic links.')
        path.mkdir(mode=0o700, exist_ok=True)
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise ValueError('Diagnostic folders must belong to your Mac account.')
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError('The diagnostic log folder must be private to your Mac account.')
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        filename = f'{stamp}-{uuid.uuid4().hex[:12]}.log'
        file_descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                  0o600, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    return directory / filename, os.fdopen(file_descriptor, 'w', encoding='utf-8')


def activate(log):
    def emit(message, *, error=False):
        print(message, file=sys.stderr if error else sys.stdout, flush=True)
        log.write(message + '\n')
        log.flush()

    emit('HELTEMES Evidence — Diagnostic retry 2')
    emit('Attempt time (UTC): ' + datetime.now(timezone.utc).isoformat())
    emit('Launcher: ' + str(Path(__file__).resolve()))
    script = ROOT / 'scripts/install_local_accounts.py'
    spec = importlib.util.spec_from_file_location('account_installer_plan', script)
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    try:
        if installer.PREFIX.exists() or installer.PREFIX.is_symlink():
            if (installer.PREFIX / 'installation-report.json').exists():
                raise ValueError('An installation completion report exists. Use Manage Local Protection.command to check its current status.')
            if (installer.PREFIX / 'runtime.json').exists() or (installer.PREFIX / 'runtime.json').is_symlink():
                raise ValueError('A migrated installation already exists. Use Diagnose Local Protection.command to inspect startup; do not run migration again.')
            # Only an explicitly prepared recovery specification enables a
            # retry. The root installer must validate the full live state before
            # any mutation; the frontend never adopts accounts on its own.
            if not RECOVERY_SPEC.is_file():
                raise ValueError('An installation already exists. Use the management menu, or inspect a partial setup before retrying.')
            runtime = str(installer.inspect_runtime(Path(sys.executable)))
            checkpoint = installer.inspect_source(ROOT)
            plan = {'runtime': runtime, 'source_checkpoint': checkpoint, 'actions': [
                'Inspect the partial installation and exact existing account identifiers.',
                'Stop without changes if accounts, permissions, checkpoint, or installation contents differ from the reviewed recovery case.',
                'Retain the collector and group identifiers assigned by macOS; complete only missing service-account settings.',
                'Copy the original evidence and signing identity without changing accepted history.',
                'Test real account permissions and independently verify the archive before starting the dashboard.'
            ]}
            installer_mode = ['--resume-early', '--recovery-spec', str(RECOVERY_SPEC)]
        else:
            plan = installer.installation_plan(ROOT, Path(sys.executable))
            installer_mode = ['--install']
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        emit('Activation stopped before changing accounts: ' + str(error), error=True)
        return 1
    emit('\nHELTEMES Evidence — local account separation\n')
    for number, action in enumerate(plan['actions'], 1):
        emit(f'{number}. {action}')
    checkpoint = plan['source_checkpoint']
    emit(f"\nPreserving checkpoint {checkpoint['sequence']}: {checkpoint['checkpoint_sha256']}")
    emit('The original archive remains available as a legacy recovery copy. AWS stays deferred.')
    emit('macOS administrator authentication is required to create the accounts and assign ownership.')
    emit('Enter your Mac password only at the Terminal Password prompt; typing will be invisible.')
    emit('Authentication goes directly to macOS and is not recorded in this diagnostic log.\n')
    # Authenticate with untouched Terminal streams. Do not capture credential
    # input/output. The logged command below can neither prompt nor read input.
    authentication = subprocess.run(['/usr/bin/sudo', '-v'], check=False)
    if authentication.returncode:
        emit('Administrator authentication did not complete. Installer was not started.')
        return authentication.returncode
    emit('Authentication completed. Running the guarded installer; please keep this window open.')
    result = subprocess.run(['/usr/bin/sudo', '-n', '--', plan['runtime'], '-I', '-S', '-B', str(script),
                             *installer_mode, '--source', str(ROOT), '--runtime', plan['runtime']],
                            check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, errors='replace')
    if result.stdout:
        emit(result.stdout.rstrip('\n'))
    emit('Installer exit status: ' + str(result.returncode))
    if result.returncode:
        emit('\nActivation did not complete. The exact error was saved; do not delete accounts or reset trust.')
        return result.returncode
    emit('\nInstallation and account permission checks passed. Opening the managed dashboard.')
    webbrowser.open('http://127.0.0.1:8765')
    return 0


def main():
    try:
        path, log = open_diagnostic_log()
    except (OSError, ValueError) as error:
        print('Activation stopped before authentication: cannot create a private diagnostic log: ' + str(error),
              file=sys.stderr)
        return 1
    with log:
        print('Diagnostic output will be saved to: ' + str(path), flush=True)
        try:
            return activate(log)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            message = 'Activation stopped: ' + str(error)
            print(message, file=sys.stderr, flush=True)
            log.write(message + '\n')
            return 1
        finally:
            print('\nDiagnostic log: ' + str(path), flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
