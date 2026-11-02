"""Production recovery, real Ed25519 keys and fresh-process crash/restart checks."""
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from heltemes.core import Repository, restore_backup
from heltemes import protection as p, key_recovery as r


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name).resolve()
        self.data = self.base / "data"
        self.repo = Repository(self.data)
        self.repo.seed_demo()
        p.initialize_protection(self.data)
        self.trust = p.default_trust_dir(self.data)
        self.keys = p.default_key_dir(self.data)
        self.original = (self.keys / "signing_key").read_bytes()
        self.old_checkpoint = (self.trust / "checkpoints/00000001.json").read_bytes()
        self.candidate = self.make_key("candidate")
        self.receipt = Path(p.export_receipt(self.data, self.base / "receipt.json"))
        self.approval = self.base / "approval.json"
        self.plan = r.plan_recovery(self.data, self.candidate, self.receipt, self.approval)

    def tearDown(self):
        self.tmp.cleanup()

    def make_key(self, name):
        path = self.base / name
        p._crypto(["-q", "-t", "ed25519", "-N", "", "-f", str(path)], input_bytes=b"")
        path.chmod(0o400)
        return path

    def prepare(self):
        return r.prepare_recovery(self.data, self.candidate, self.approval, self.plan["authorization_sha256"])

    def append(self, name):
        with closing(sqlite3.connect(self.repo.db_path)) as db, db:
            db.execute("INSERT INTO runs(id,started_at,finished_at,status,mode,cik,filings_added) VALUES(?,?,?,?,?,?,?)",
                       (name, "2026-01-01", "2026-01-01", "success", "demo", "0000000001", 0))

    def assert_original(self):
        self.assertEqual((self.keys / "signing_key").read_bytes(), self.original)
        self.assertEqual((self.trust / "checkpoints/00000001.json").read_bytes(), self.old_checkpoint)

    def crash(self, boundary):
        code = """import os,sys
from heltemes import key_recovery as r
def crash(name):
    if name == sys.argv[2]: os._exit(71)
r._boundary=crash
r.resume_recovery(sys.argv[1])
"""
        result = subprocess.run([sys.executable, "-c", code, str(self.data), boundary], capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 71, result.stderr)

    def fresh_status(self):
        result = subprocess.run([sys.executable, "-m", "heltemes", "--data-dir", str(self.data), "protect", "recover", "status"], capture_output=True, text=True, timeout=45)
        return json.loads(result.stdout), result.returncode

    def test_plan_has_no_effect_and_wrong_key_or_approval_refused(self):
        self.assertEqual(r.recovery_status(self.data)["state"], "original_identity")
        self.assertFalse(r.recovery_dir(self.trust).exists())
        wrong = self.make_key("wrong")
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            r.prepare_recovery(self.data, wrong, self.approval, self.plan["authorization_sha256"])
        with self.assertRaisesRegex(ValueError, "digest"):
            r.prepare_recovery(self.data, self.candidate, self.approval, "0" * 64)
        self.assert_original()

    def test_prepared_blocks_even_noop_and_alternative_key_directory(self):
        self.prepare()
        self.assertFalse(r.recovery_status(self.data)["signing_allowed"])
        with self.assertRaisesRegex(ValueError, "unfinished"):
            p.seal_checkpoint(self.data)
        other = self.base / "otherkeys"
        shutil.copytree(self.keys, other)
        with self.assertRaisesRegex(ValueError, "unfinished"):
            p.seal_checkpoint(self.data, key_dir=other)
        self.assert_original()

    def test_each_crash_boundary_and_idempotent_restart(self):
        boundaries = ("after_key_install", "after_verification", "after_checkpoint", "before_anchor.json", "after_anchor", "before_completion.json", "after_commit")
        # Each scenario gets its own independently enrolled archive and keys.
        for boundary in boundaries:
            with self.subTest(boundary=boundary):
                if boundary != boundaries[0]:
                    self.tearDown()
                    self.setUp()
                self.prepare()
                self.crash(boundary)
                status, code = self.fresh_status()
                self.assertEqual(status["signing_allowed"], boundary == "after_commit")
                self.assertEqual(code, 0 if boundary == "after_commit" else 1)
                resumed = r.resume_recovery(self.data)
                self.assertTrue(resumed["signing_allowed"])
                before = (self.trust / "anchor.json").read_bytes()
                repeated = r.resume_recovery(self.data)
                self.assertTrue(repeated["already_completed"])
                self.assertEqual((self.trust / "anchor.json").read_bytes(), before)
                self.assertEqual(len(list((self.trust / "checkpoints").iterdir())), 2)
                self.assert_original()

    def test_descendant_signing_and_verifier_only_backup(self):
        self.prepare()
        r.resume_recovery(self.data)
        self.append("after-transition")
        self.assertEqual(p.seal_checkpoint(self.data)["sequence"], 3)
        self.append("second-after-transition")
        self.assertEqual(p.seal_checkpoint(self.data)["sequence"], 4)
        self.assertTrue(r.resume_recovery(self.data)["already_completed"])
        backup = self.repo.backup(self.base / "backup.zip")
        receipt = p.export_receipt(self.data, self.base / "latest-receipt.json")
        restored = restore_backup(backup, self.base / "restored", trust_receipt=receipt)
        self.assertTrue(p.verify_protection(restored)["ok"])
        self.assertFalse(r.recovery_status(restored)["signing_allowed"])
        self.assert_original()

    def test_missing_original_private_key_can_recover_without_reset(self):
        (self.keys / "signing_key").unlink()
        self.assertFalse(r.recovery_status(self.data)["signing_allowed"])
        self.prepare()
        self.assertTrue(r.resume_recovery(self.data)["signing_allowed"])
        self.assertFalse((self.keys / "signing_key").exists())
        self.assertEqual((self.trust / "checkpoints/00000001.json").read_bytes(), self.old_checkpoint)

    def test_pending_rows_not_implicitly_sealed(self):
        self.append("unreviewed")
        self.prepare()
        r.resume_recovery(self.data)
        result = p.verify_protection(self.data)
        self.assertEqual(result["pending_records"], 1)
        self.assertEqual(result["sequence"], 2)

    def test_changed_evidence_refused_after_crash(self):
        self.prepare()
        self.crash("after_verification")
        file = self.data / self.repo.list_filings()[0]["document_path"]
        file.chmod(0o600)
        file.write_bytes(file.read_bytes() + b"changed")
        with self.assertRaises(ValueError):
            r.resume_recovery(self.data)
        self.assertFalse(r.recovery_status(self.data)["signing_allowed"])
        self.assert_original()

    def test_missing_completion_or_authority_blocks_even_valid_new_signature(self):
        self.prepare()
        r.resume_recovery(self.data)
        record = r.recovery_dir(self.trust) / self.plan["transition_id"]
        complete = record / "completion.json"
        raw = complete.read_bytes()
        complete.unlink()
        self.assertTrue(p.verify_protection(self.data)["ok"])
        self.assertFalse(r.recovery_status(self.data)["signing_allowed"])
        r.resume_recovery(self.data)
        self.assertEqual(complete.read_bytes(), raw)
        self.approval.unlink()
        self.assertFalse(r.recovery_status(self.data)["signing_allowed"])
        with self.assertRaises(ValueError):
            r.resume_recovery(self.data)

    def test_malformed_completion_does_not_silently_repair(self):
        self.prepare()
        r.resume_recovery(self.data)
        complete = r.recovery_dir(self.trust) / self.plan["transition_id"] / "completion.json"
        complete.chmod(0o600)
        complete.write_bytes(b"{}")
        with self.assertRaises(ValueError):
            r.resume_recovery(self.data)
        self.assertEqual(complete.read_bytes(), b"{}")

    def test_wrong_installed_key_remains_blocked(self):
        self.prepare()
        self.crash("after_key_install")
        record = r._records(self.trust)[self.plan["transition_id"]][1]
        installed = p.active_key_path(self.keys, record["new_anchor"])
        installed.chmod(0o600)
        installed.write_bytes(self.make_key("wrong").read_bytes())
        installed.chmod(0o400)
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            r.resume_recovery(self.data)
        self.assertFalse(r.recovery_status(self.data)["signing_allowed"])

    def test_two_transitions_preserve_full_authorization_history(self):
        self.prepare()
        r.resume_recovery(self.data)
        second = self.make_key("second")
        receipt = p.export_receipt(self.data, self.base / "receipt2.json")
        approval = self.base / "approval2.json"
        plan = r.plan_recovery(self.data, second, receipt, approval)
        r.prepare_recovery(self.data, second, approval, plan["authorization_sha256"])
        r.resume_recovery(self.data)
        self.assertTrue(r.recovery_status(self.data)["signing_allowed"])
        self.approval.unlink()
        self.assertFalse(r.recovery_status(self.data)["signing_allowed"])

    def test_lock_and_unsafe_key_permissions_fail_closed(self):
        with r.recovery_lock(self.trust), self.assertRaisesRegex(ValueError, "Another"):
            self.prepare()
        self.candidate.chmod(0o644)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_managed_authorization_cannot_be_custodian_owned(self):
        fake_prefix = self.base / "managed"
        fake_prefix.mkdir()
        custody = fake_prefix / "custody"
        custody.mkdir()
        with patch.object(r, "PREFIX", fake_prefix), patch.object(r, "AUTHORIZATIONS", fake_prefix / "recovery-authorizations"):
            with self.assertRaisesRegex(ValueError, "administrator approval"):
                r._authorized(self.approval, self.plan["authorization_sha256"], self.data, custody / "trust", custody / "keys")

    def test_malformed_nested_journal_and_unexpected_trust_block_status(self):
        self.prepare()
        r.resume_recovery(self.data)
        prepared = r.recovery_dir(self.trust) / self.plan["transition_id"] / "prepared.json"
        raw = prepared.read_bytes()
        value = json.loads(raw)
        value["checkpoint"]["payload"] = None
        prepared.chmod(0o600)
        prepared.write_bytes(p._canonical(value))
        self.assertEqual(r.recovery_status(self.data)["state"], "blocked")
        prepared.write_bytes(raw)
        (self.trust / "unexpected").write_bytes(b"unknown")
        self.assertFalse(r.recovery_status(self.data)["signing_allowed"])
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            r.resume_recovery(self.data)


if __name__ == "__main__":
    unittest.main()
