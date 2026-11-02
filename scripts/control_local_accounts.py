"""Small user-operated menu; the installed operator enforces all authority."""
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone

PREFIX = Path('/Library/HELTEMES Evidence')
ROOT = Path(__file__).resolve().parents[1]


def main():
    if not (PREFIX / 'runtime.json').is_file():
        print('Separate-account protection has not been activated. Open Activate Local Protection.command first.')
        return 1
    print('\nHELTEMES Evidence — local protection\n')
    choices = {'1': ('Verify independently', 'verify'), '2': ('Seal reviewed new records', 'seal'),
               '3': ('Save the public trust receipt', 'receipt'), '4': ('Start the dashboard', 'start'),
               '5': ('Stop the dashboard', 'stop'), '6': ('Create an evidence backup', 'backup'),
               '7': ('Update SEC contact', 'configure'), '8': ('Show status', 'status')}
    for number, (label, _) in choices.items():
        print(f'{number}. {label}')
    selected = input('\nChoose an action, or press Enter to exit: ').strip()
    if not selected:
        return 0
    if selected not in choices:
        print('Unknown action; nothing changed.')
        return 1
    action = choices[selected][1]
    if action == 'seal':
        print('Only seal records you have reviewed. Changed previously accepted history will be refused.')
        print('The dashboard pauses during signing. A failed seal leaves it stopped for investigation.')
    # The fixed Python is already running; the installed operator validates its
    # identity against the protected runtime record before dispatching anything.
    command = ['/usr/bin/sudo', '--', sys.executable, '-I', '-S', '-B',
               str(PREFIX / 'app/scripts/local_operator.py'), action]
    if action == 'receipt':
        result = subprocess.run(command, stdout=subprocess.PIPE, check=False)
        if result.returncode:
            return result.returncode
        receipt = json.loads(result.stdout)
        if receipt.get('format') != 'heltemes-trust-anchor':
            raise ValueError('Operator did not return a public trust receipt.')
        folder = ROOT / 'backups'
        folder.mkdir(mode=0o700, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        target = folder / f'checkpoint-{receipt["sequence"]}-{stamp}-trust-receipt.json'
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(result.stdout)
        print('Public receipt saved: ' + str(target))
        print('It covers the last accepted checkpoint. Keep an independent copy with your recovery records.')
        return 0
    return subprocess.run(command, check=False).returncode


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyboardInterrupt, EOFError) as error:
        print('Stopped: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
