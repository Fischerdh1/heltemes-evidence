"""Boundary rules and hostile-input tests; real UID activation is a separate probe."""
import json
import os
import shutil
import sqlite3
import stat
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from heltemes import local_accounts as accounts
from heltemes.core import Repository
from heltemes.protection import default_key_dir, default_trust_dir, initialize_protection, seal_checkpoint, verify_protection


class SafeCustodySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.data = self.base / "incoming"
        self.repo = Repository(self.data)
        self.repo.seed_demo()
        initialize_protection(self.data)
        self.prefix = self.base / "managed"
        (self.prefix / "custody").mkdir(parents=True)
        self.trust = self.prefix / "custody" / "trust"
        self.keys = self.prefix / "custody" / "keys"
        shutil.copytree(default_trust_dir(self.data), self.trust)
        shutil.copytree(default_key_dir(self.data), self.keys)
        self.policy = accounts.Policy(self.data, self.trust, self.keys, os.geteuid() + 100,
                                      os.geteuid(), os.getegid())
        self.prefix_patch = patch.object(accounts, "PREFIX", self.prefix)
        self.prefix_patch.start()

    def tearDown(self):
        self.prefix_patch.stop()
        self.temporary.cleanup()

    def test_snapshot_is_private_and_original_change_cannot_change_signed_bytes(self):
        with accounts.private_snapshot(self.policy) as staged:
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o700)
            with closing(sqlite3.connect(self.repo.db_path)) as db, db:
                db.execute("UPDATE filings SET company='tampered'")
            self.assertEqual(verify_protection(staged, self.trust)["status"], "sealed")
            self.assertEqual(seal_checkpoint(staged, self.trust, self.keys)["sequence"], 1)
        self.assertEqual(verify_protection(self.data, self.trust)["status"], "failed")

    def test_existing_history_change_cannot_be_resealed(self):
        with closing(sqlite3.connect(self.repo.db_path)) as db, db:
            db.execute("UPDATE filings SET company='tampered'")
        original_anchor = (self.trust / "anchor.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "Refusing"):
            accounts.seal_managed(self.policy)
        self.assertEqual((self.trust / "anchor.json").read_bytes(), original_anchor)

    def test_custodian_verification_uses_public_material_and_preserves_data(self):
        before = self.repo.db_path.read_bytes()
        result = accounts.verify_managed(self.policy)
        self.assertTrue(result["ok"])
        self.assertEqual(result["protection"]["account_isolation"], "separate-local-accounts")
        self.assertEqual(self.repo.db_path.read_bytes(), before)

    def test_public_verification_survives_private_key_loss_but_new_seal_does_not(self):
        (self.keys / "signing_key").unlink()
        self.assertTrue(accounts.verify_managed(self.policy)["ok"])
        receipt = accounts.receipt_managed(self.policy)
        self.assertEqual(receipt["sequence"], 1)
        self.assertNotIn("private_key", receipt)
        with closing(sqlite3.connect(self.repo.db_path)) as db, db:
            db.execute("INSERT INTO runs VALUES ('addition','2026-01-01','2026-01-01','success','demo','1',0,NULL)")
        with self.assertRaisesRegex(ValueError, "private signing key is unavailable"):
            accounts.seal_managed(self.policy)

    def test_new_checkpoint_is_group_readable_and_original_records_preserved(self):
        with closing(sqlite3.connect(self.repo.db_path)) as db, db:
            db.execute("INSERT INTO runs VALUES ('addition','2026-01-01','2026-01-01','success','demo','1',0,NULL)")
        result = accounts.seal_managed(self.policy)
        self.assertEqual(result["sequence"], 2)
        self.assertEqual(result["account_isolation"], "separate-local-accounts")
        self.assertEqual(stat.S_IMODE((self.trust / "anchor.json").stat().st_mode), 0o440)
        self.assertEqual(stat.S_IMODE((self.trust / "checkpoints/00000002.json").stat().st_mode), 0o440)

    def test_collector_identity_cannot_enter_custody_signing(self):
        with patch.object(os, "geteuid", return_value=self.policy.collector_uid):
            with self.assertRaisesRegex(ValueError, "custodian"):
                accounts.seal_managed(self.policy)

    def test_key_directory_must_be_custodian_owned_and_private(self):
        accounts._protected_key_directory(self.policy)
        self.keys.chmod(0o750)
        with self.assertRaisesRegex(ValueError, "owner-only"):
            accounts._protected_key_directory(self.policy)
        self.keys.chmod(0o700)
        self.keys.rename(self.base / "moved-keys")
        self.keys.symlink_to(self.base / "moved-keys", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "owner-only"):
            accounts._protected_key_directory(self.policy)

    def test_rejects_database_symlink_and_hardlink(self):
        original = self.base / "original.sqlite3"
        self.repo.db_path.rename(original)
        self.repo.db_path.symlink_to(original)
        with self.assertRaises(OSError):
            with accounts.private_snapshot(self.policy):
                self.fail("Accepted database symlink")
        self.repo.db_path.unlink()
        os.link(original, self.repo.db_path)
        with self.assertRaisesRegex(ValueError, "hard links"):
            with accounts.private_snapshot(self.policy):
                self.fail("Accepted database hardlink")

    def test_rejects_symlink_in_asset_parent(self):
        documents = self.data / "documents"
        outside = self.base / "outside"
        documents.rename(outside)
        documents.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OSError):
            with accounts.private_snapshot(self.policy):
                self.fail("Accepted asset parent symlink")

    def test_rejects_asset_hardlink(self):
        asset = next((self.data / "raw").glob("*/*.json"))
        os.link(asset, self.base / "linked")
        with self.assertRaisesRegex(ValueError, "hard links"):
            with accounts.private_snapshot(self.policy):
                self.fail("Accepted linked asset")

    def test_rejects_sqlite_sidecars_before_and_after_copy(self):
        sidecar = self.data / "data.sqlite3-wal"
        sidecar.touch()
        with self.assertRaisesRegex(ValueError, "sidecar"):
            with accounts.private_snapshot(self.policy):
                self.fail("Accepted SQLite sidecar")
        sidecar.unlink()
        original = accounts._copy_input
        def copy_then_wal(*args):
            count = original(*args)
            sidecar.touch()
            return count
        with patch.object(accounts, "_copy_input", side_effect=copy_then_wal):
            with self.assertRaisesRegex(ValueError, "SQLite state changed"):
                with accounts.private_snapshot(self.policy):
                    self.fail("Accepted sidecar introduced during copy")

    def test_copy_budget_and_nonregular_file_rejected(self):
        with self.assertRaisesRegex(ValueError, "size limit"):
            accounts._copy_input(self.repo.db_path, self.base / "oversized", 1)
        fifo = self.base / "pipe"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular files"):
            accounts._copy_input(fifo, self.base / "fifo-copy", 100)

    def test_copy_checks_open_descriptor_for_concurrent_change(self):
        source = self.base / "moving"
        source.write_bytes(b"abcdef")
        read = os.read
        def change_after_read(fd, count):
            result = read(fd, count)
            if result:
                with source.open("ab") as target:
                    target.write(b"g")
            return result
        with patch.object(os, "read", side_effect=change_after_read):
            with self.assertRaisesRegex(ValueError, "size limit|changed"):
                accounts._copy_input(source, self.base / "copy", 12)


class ManagedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.prefix = self.base / "managed"
        self.prefix.mkdir()
        self.data = self.prefix / "data"
        self.data.mkdir(mode=0o750)
        (self.data / "protection.json").write_text("{}")
        (self.prefix / "custody/trust/checkpoints").mkdir(parents=True)
        self.config = {"version": 1, "data_dir": str(self.data), "trust_dir": str(self.prefix / "custody/trust"),
                       "key_dir": str(self.prefix / "custody/keys"), "collector_uid": os.geteuid(),
                       "custodian_uid": os.geteuid() + 100, "shared_gid": os.getegid()}
        self.config_path = self.prefix / "runtime.json"
        self.save()
        self.prefix_patch = patch.object(accounts, "PREFIX", self.prefix)
        self.prefix_patch.start()
        # Unit fixtures cannot chown to root. Validate policy parsing separately;
        # actual owner/mode enforcement has focused tests and installer UID probes.
        self.owner_patch = patch.object(accounts, "_protected")
        self.owner_check = self.owner_patch.start()
        self.key_check = patch.object(accounts, "_protected_key_directory")
        self.key_check.start()

    def save(self):
        self.config_path.write_text(json.dumps(self.config))

    def tearDown(self):
        self.key_check.stop()
        self.owner_patch.stop()
        self.prefix_patch.stop()
        self.temporary.cleanup()

    def test_fixed_policy_routes_trust_and_key_and_ignores_environment(self):
        with patch.dict(os.environ, {"HELTEMES_TRUST_DIR": "/tmp/fake", "HELTEMES_KEY_DIR": "/tmp/fake"}):
            policy = accounts.policy_for(self.data)
            self.assertEqual(default_trust_dir(self.data), policy.trust_dir)
            self.assertEqual(default_key_dir(self.data), policy.key_dir)
        self.owner_check.assert_any_call(self.config_path, {0}, mode=0o644)

    def test_missing_policy_and_missing_marker_fail_closed(self):
        self.config_path.unlink()
        self.assertEqual(verify_protection(self.data)["status"], "failed")
        self.save()
        (self.data / "protection.json").unlink()
        self.assertEqual(verify_protection(self.data)["status"], "failed")

    def test_same_identity_and_redirected_paths_refused(self):
        self.config["custodian_uid"] = self.config["collector_uid"]
        self.save()
        with self.assertRaisesRegex(ValueError, "separate"):
            accounts.policy_for(self.data)
        self.config["custodian_uid"] += 100
        self.config["trust_dir"] = "/tmp/attacker-trust"
        self.save()
        with self.assertRaisesRegex(ValueError, "nonstandard"):
            accounts.policy_for(self.data)

    def test_duplicate_config_and_symlink_alias_refused(self):
        self.config_path.write_text('{"version":1,"version":1}')
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            accounts.policy_for(self.data)
        alias = self.base / "alias"
        alias.symlink_to(self.data, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "exact"):
            accounts.policy_for(alias)

    def test_managed_explicit_trust_override_refused(self):
        result = verify_protection(self.data, trust_dir=self.base / "attacker")
        self.assertEqual(result["status"], "failed")
        self.assertIn("override", result["issues"][0]["error"])

    def test_protected_file_checks_owner_permissions_and_hardlinks(self):
        self.owner_patch.stop()
        try:
            path = self.base / "protected"
            path.write_bytes(b"test")
            path.chmod(0o400)
            accounts._protected(path, {os.geteuid()}, mode=0o400)
            with self.assertRaisesRegex(ValueError, "ownership"):
                accounts._protected(path, {os.geteuid() + 1})
            path.chmod(0o420)
            with self.assertRaisesRegex(ValueError, "ownership"):
                accounts._protected(path, {os.geteuid()})
            path.chmod(0o400)
            os.link(path, self.base / "second-link")
            with self.assertRaisesRegex(ValueError, "hard links"):
                accounts._protected(path, {os.geteuid()})
        finally:
            self.owner_patch.start()


if __name__ == "__main__":
    unittest.main()
