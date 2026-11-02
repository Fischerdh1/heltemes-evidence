"""User-operated capture of fixed local startup diagnostics, without migration."""
import importlib.util
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def main():
    spec = importlib.util.spec_from_file_location('activation_log_helper', ROOT / 'scripts/activate_local_accounts.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    try:
        path, log = helper.open_diagnostic_log()
    except (OSError, ValueError) as error:
        print('Inspection stopped before authentication: ' + str(error), file=sys.stderr)
        return 1
    with log:
        def emit(message):
            print(message, flush=True)
            log.write(message + '\n')
            log.flush()
        emit('HELTEMES Evidence — Startup inspection 1')
        emit('Attempt time (UTC): ' + datetime.now(timezone.utc).isoformat())
        emit('Read protected startup details and independently verify the installed archive.')
        emit('This inspection does not start or stop the dashboard, migrate evidence, or sign a checkpoint.')
        emit('Administrator authentication goes directly to macOS and is not recorded.\n')
        emit('Diagnostic log: ' + str(path))
        try:
            authentication = subprocess.run(['/usr/bin/sudo', '-v'], check=False)
            if authentication.returncode:
                emit('Authentication did not complete; inspection was not started.')
                return authentication.returncode
            emit('Authentication completed. Reading startup details; this may take about a minute.')
            result = subprocess.run(
                ['/usr/bin/sudo', '-n', '--', sys.executable, '-I', '-S', '-B',
                 str(ROOT / 'scripts/diagnose_local_startup.py')],
                check=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, errors='replace')
            if result.stdout:
                emit(result.stdout.rstrip('\n'))
            emit('Inspection exit status: ' + str(result.returncode))
            emit('Saved the inspection result. This is not an activation-success message.')
            return result.returncode
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            emit('Inspection stopped: ' + str(error))
            return 1
        finally:
            print('\nDiagnostic log: ' + str(path), flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
