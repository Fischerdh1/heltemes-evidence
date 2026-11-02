import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from heltemes.config import configured, save_contact, user_agent

class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
    def tearDown(self):
        self.tmp.cleanup()
    def test_contact_is_local_private_and_environment_overrides(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(configured(self.root))
            p=save_contact(self.root,'research@heltemes.testdomain.org')
            self.assertEqual(p.stat().st_mode & 0o777,0o600)
            self.assertTrue(configured(self.root))
            self.assertIn('research@heltemes.testdomain.org',user_agent(self.root))
            with patch.dict(os.environ,{'SEC_USER_AGENT':'Project ops@different.testdomain.org'}):
                self.assertEqual(user_agent(self.root),'Project ops@different.testdomain.org')
    def test_placeholder_and_symlink_are_rejected(self):
        with self.assertRaises(ValueError): save_contact(self.root,'person@example.com')
        outside=self.root/'outside';outside.write_text('safe')
        (self.root/'settings.json').symlink_to(outside)
        with self.assertRaises(ValueError):save_contact(self.root,'research@heltemes.testdomain.org')
        self.assertEqual(outside.read_text(),'safe')
    def test_backup_excludes_private_contact(self):
        from heltemes.core import Repository
        import zipfile
        save_contact(self.root,'research@heltemes.testdomain.org')
        repo=Repository(self.root);repo.seed_demo()
        archive=self.root.parent/(self.root.name+'.zip')
        try:
            repo.backup(archive)
            with zipfile.ZipFile(archive) as z:
                self.assertNotIn('settings.json',z.namelist())
                self.assertNotIn(b'research@heltemes.testdomain.org',b''.join(z.read(n) for n in z.namelist()))
        finally:
            archive.unlink(missing_ok=True)
