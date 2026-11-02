"""Avoid collecting into a legacy archive after account migration."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('heltemes_launcher', Path(__file__).resolve().parents[1] / 'scripts/launch.py')
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


class ManagedLauncherTests(unittest.TestCase):
    def test_partial_or_stopped_installation_never_opens_legacy_archive(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(launcher, 'MANAGED_ROOT', Path(tmp)), patch.object(launcher, 'Repository') as repo, patch.object(launcher.urllib.request, 'urlopen', side_effect=OSError), patch('builtins.print'):
            launcher.main()
            repo.assert_not_called()

    def test_existing_legacy_dashboard_is_not_mistaken_for_managed(self):
        payload = {'scope': 'local', 'data_dir': '/legacy/data'}
        with patch.object(launcher.urllib.request, 'urlopen', return_value=io.BytesIO(json.dumps(payload).encode())), patch.object(launcher.webbrowser, 'open') as opened, patch('builtins.print'):
            self.assertFalse(launcher.open_managed('http://127.0.0.1:8765'))
            opened.assert_not_called()

    def test_matching_managed_dashboard_opens(self):
        payload = {'scope': 'local', 'data_dir': str(launcher.MANAGED_ROOT / 'data')}
        with patch.object(launcher.urllib.request, 'urlopen', return_value=io.BytesIO(json.dumps(payload).encode())), patch.object(launcher.webbrowser, 'open') as opened, patch('builtins.print'):
            self.assertTrue(launcher.open_managed('http://127.0.0.1:8765'))
            opened.assert_called_once_with('http://127.0.0.1:8765')
