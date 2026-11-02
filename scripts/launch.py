"""User-facing launcher. Starts one local service; Ctrl+C shuts it down."""
from pathlib import Path
import sys
import threading
import urllib.request
import webbrowser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from heltemes.core import Repository
from heltemes import __version__
from heltemes.server import serve

MANAGED_ROOT = Path('/Library/HELTEMES Evidence')


def open_managed(url):
    """Never silently resume the legacy archive after a managed installation."""
    import json
    try:
        with urllib.request.urlopen(url + '/api/health', timeout=2) as response:
            result = json.load(response)
        if result.get('scope') == 'local' and result.get('data_dir') == str(MANAGED_ROOT / 'data'):
            webbrowser.open(url)
            print('Opened the managed HELTEMES Evidence dashboard.')
            return True
    except (OSError, ValueError):
        pass
    print('A managed installation exists, but its dashboard could not be confirmed.')
    print('Use the managed operator start/status commands in docs/LOCAL_ACCOUNTS.md.')
    print('The legacy workspace was not started. A partial installation needs inspection.')
    return False


def main():
    url = 'http://127.0.0.1:8765'
    if MANAGED_ROOT.exists() or MANAGED_ROOT.is_symlink():
        open_managed(url)
        return
    data = ROOT / 'data'
    repo = Repository(data)
    if not repo.list_filings() and not repo.dashboard()['runs']:
        repo.seed_demo()
    # Reuse an already-running instance only if it exposes this app's health marker.
    try:
        import json
        with urllib.request.urlopen(url + '/api/health', timeout=1) as response:
            result = json.load(response)
        if result.get('scope') == 'local' and result.get('version') == __version__ and result.get('data_dir') == str(data.resolve()):
            webbrowser.open(url)
            print('The research dashboard is already running.')
            return
        if result.get('scope') == 'local':
            print('An older dashboard or a different archive is using port 8765. Stop it in its Terminal window, then launch again.')
            return
    except (OSError, ValueError):
        pass
    timer = threading.Timer(1.0, lambda: webbrowser.open(url))
    timer.daemon = True
    timer.start()
    serve(data, 8765)


if __name__ == '__main__':
    main()
