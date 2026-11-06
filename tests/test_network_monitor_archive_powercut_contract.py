"""Cross-component packaging and safety contracts for the disposable archive lab."""
from pathlib import Path
import re
import unittest

from scripts import network_monitor_archive_powercut_guest as guest
from scripts import network_monitor_archive_powercut_vm as host

ROOT = Path(__file__).resolve().parents[1]


class ArchivePowercutContractTests(unittest.TestCase):
    def test_exact_guest_source_and_public_file_inventory(self):
        self.assertEqual(tuple(guest.SOURCE_FILES), tuple(host.GUEST_SOURCE_FILES))
        self.assertEqual(set(guest.PUBLIC_FILES), set(host.GUEST_FILES))
        self.assertEqual(len(host.GUEST_FILES), len(set(host.GUEST_FILES)))
        self.assertEqual(len(host.PUBLIC_FILES) + 1, 30)
        self.assertEqual(guest.STAGES, host.STAGES)
        self.assertEqual(tuple(guest.POINTS.values()), host.POINTS)
        self.assertEqual(tuple(guest.REQUEST_IDS.values()), tuple(host.REQUEST_IDS.values()))

    def test_ci_upload_matches_fixed_public_allowlist(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        section = workflow.split('\n  monitor_archive_powercut:', 1)[1].split('\n  reviewer:', 1)[0]
        names = re.findall(r'^\s+work/monitor-archive-powercut/publish/([^\s]+)$', section, re.M)
        self.assertEqual(set(names), set(host.PUBLIC_FILES) | {'MANIFEST.json'})
        self.assertEqual(len(names), len(set(names)))
        self.assertIn('scripts/network_monitor_archive_powercut_vm.py --output work/monitor-archive-powercut', section)
        self.assertNotRegex(section, r'(?m)^\s+work/monitor-archive-powercut/\*')

    def test_only_guarded_guest_installs_archive_pause_callback(self):
        text = (ROOT / 'scripts/network_monitor_archive_powercut_guest.py').read_text()
        worker = text.split('\ndef worker():', 1)[1].split('\ndef cleanup(', 1)[0]
        self.assertIn('guard(', worker)
        self.assertIn('journal_factory=ExerciseJournal', worker)
        self.assertNotIn('freshness_seconds=', worker)
        ordinary = (ROOT / 'scripts/network_monitor_archive.py').read_text()
        self.assertNotIn('archive_powercut', ordinary)
        self.assertNotIn('SIGSTOP', ordinary)


if __name__ == '__main__':
    unittest.main()
