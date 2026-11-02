"""Actual local Ed25519 signatures; no SEC, cloud, or persistent user data."""
import hashlib
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

from heltemes.core import Repository
from heltemes.protection import (
    backup_files, default_key_dir, default_trust_dir, export_receipt,
    initialize_protection, install_restored_trust, repository_lock,
    seal_checkpoint, validate_backup_protection, verify_protection,
)


class ProtectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.data = self.base / "data"
        self.repo = Repository(self.data)
        self.repo.seed_demo()

    def tearDown(self):
        self.temporary.cleanup()

    def sql(self, statement, parameters=()):
        with closing(sqlite3.connect(self.repo.db_path)) as db, db:
            db.execute(statement, parameters)

    def seal_initial(self):
        with repository_lock(self.data):
            return initialize_protection(self.data)

    def append_run(self, name="new-run", status="success", finished="2026-01-05T00:00:01Z"):
        self.sql("INSERT INTO runs(id,started_at,finished_at,status,mode,cik,filings_added) VALUES(?,?,?,?,?,?,?)",
                 (name, "2026-01-05T00:00:00Z", finished, status, "demo", "0000000001", 0))

    @staticmethod
    def rewrite(path, value):
        path.chmod(0o600)
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        path.chmod(0o400)

    def make_staging(self):
        staging = self.base / "staged"
        shutil.copytree(self.data, staging)
        for relative, content in backup_files(self.data).items():
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                target.chmod(0o600)
            target.write_bytes(content)
        receipt = Path(export_receipt(self.data, self.base / "receipt.json"))
        return staging, receipt

    def test_unconfigured_initialize_real_signature_and_permissions(self):
        self.assertEqual(verify_protection(self.data)["status"], "unconfigured")
        result = self.seal_initial()
        self.assertEqual(result["status"], "sealed")
        self.assertEqual(result["sealed_filings"], 3)
        self.assertEqual(result["pending_records"], 0)
        self.assertEqual(result["sequence"], 1)
        self.assertTrue(result["key_fingerprint"].startswith("SHA256:"))
        trust, keys = default_trust_dir(self.data), default_key_dir(self.data)
        for directory in (trust, trust / "checkpoints", keys):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for file in (keys / "signing_key", trust / "anchor.json", trust / "checkpoints/00000001.json", self.data / "protection.json"):
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o400)
        self.assertIn("BEGIN SSH SIGNATURE", (trust / "checkpoints/00000001.json").read_text())
        with self.assertRaises(ValueError):
            self.seal_initial()

    def test_new_rows_pending_then_explicitly_sealed(self):
        self.seal_initial()
        self.append_run()
        result = verify_protection(self.data)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["pending_records"], 1)
        self.assertEqual(result["pending_filings"], 0)
        self.assertEqual(result["sealed_filings"], 3)
        with self.assertRaises(ValueError):
            backup_files(self.data)
        receipt = Path(export_receipt(self.data, self.base / "pending-receipt.json"))
        self.assertEqual(json.loads(receipt.read_bytes())["sequence"], 1)
        self.assertEqual(json.loads(receipt.read_bytes())["checkpoint_sha256"], result["checkpoint_sha256"])
        self.assertEqual(verify_protection(self.data)["status"], "pending")
        with repository_lock(self.data):
            sealed = seal_checkpoint(self.data)
        self.assertEqual(sealed["sequence"], 2)
        self.assertEqual(sealed["status"], "sealed")
        with repository_lock(self.data):
            same = seal_checkpoint(self.data)
        self.assertEqual(same["sequence"], 2)

    def test_new_filing_is_pending_and_absent_from_signed_row_map(self):
        self.seal_initial()
        row = dict(self.repo.list_filings()[0])
        row["id"] = 999
        row["accession"] = "0000000001-26-000999"
        row["fingerprint"] = "new-test-observation"
        columns = list(row)
        self.sql(f"INSERT INTO filings ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})", tuple(row.values()))
        result = verify_protection(self.data, include_filing_hashes=True)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["pending_filings"], 1)
        self.assertEqual(result["sealed_filings"], 3)
        self.assertNotIn("999", result["sealed_filing_hashes"])
        with repository_lock(self.data):
            sealed = seal_checkpoint(self.data)
        self.assertEqual(sealed["sealed_filings"], 4)
        self.assertIn("999", verify_protection(self.data, include_filing_hashes=True)["sealed_filing_hashes"])

    def test_direct_initializer_rejects_hardlinks_and_missing_required_columns(self):
        file = self.data / self.repo.list_filings()[0]["document_path"]
        linked = self.base / "hardlink.bin"
        os.link(file, linked)
        with repository_lock(self.data), self.assertRaisesRegex(ValueError, "linked"):
            initialize_protection(self.data)
        self.assertFalse(default_key_dir(self.data).exists())
        linked.unlink()
        self.sql("ALTER TABLE observations RENAME COLUMN observed_at TO missing_observed_at")
        with repository_lock(self.data), self.assertRaisesRegex(ValueError, "columns"):
            initialize_protection(self.data)
        self.assertFalse(default_key_dir(self.data).exists())

    def test_running_run_cannot_initialize_or_seal(self):
        self.append_run(status="running", finished=None)
        with repository_lock(self.data), self.assertRaisesRegex(ValueError, "unfinished"):
            initialize_protection(self.data)
        self.assertFalse(default_key_dir(self.data).exists())
        self.sql("UPDATE runs SET status='success',finished_at='done' WHERE id='new-run'")
        self.seal_initial()
        self.append_run("second-run", "running", None)
        with repository_lock(self.data), self.assertRaisesRegex(ValueError, "unfinished"):
            seal_checkpoint(self.data)

    def test_rewritten_blob_and_all_recorded_hashes_still_fail_signature(self):
        self.seal_initial()
        row = self.repo.list_filings()[0]
        file = self.data / row["document_path"]
        altered = b"X" + file.read_bytes()[1:]
        self.rewrite(file, altered)
        digest = hashlib.sha256(altered).hexdigest()
        self.sql("UPDATE assets SET sha256=? WHERE path=?", (digest, row["document_path"]))
        self.sql("UPDATE filings SET document_sha256=? WHERE document_path=?", (digest, row["document_path"]))
        self.sql("UPDATE observations SET document_sha256=? WHERE document_path=?", (digest, row["document_path"]))
        result = verify_protection(self.data)
        self.assertEqual(result["status"], "failed")
        self.assertIn("changed", result["issues"][0]["error"])
        with repository_lock(self.data), self.assertRaises(ValueError):
            seal_checkpoint(self.data)

    def test_changed_metadata_or_removed_signed_row_fail(self):
        self.seal_initial()
        row = self.repo.list_filings()[0]
        self.sql("UPDATE filings SET company='rewritten name' WHERE id=?", (row["id"],))
        self.assertEqual(verify_protection(self.data)["status"], "failed")
        self.sql("UPDATE filings SET company=? WHERE id=?", (row["company"], row["id"]))
        self.assertEqual(verify_protection(self.data)["status"], "sealed")
        self.sql("DELETE FROM observations WHERE id=(SELECT max(id) FROM observations)")
        result = verify_protection(self.data)
        self.assertEqual(result["status"], "failed")
        self.assertIn("removed", result["issues"][0]["error"])

    def test_database_and_checkpoint_rollback_are_detected_by_current_pin(self):
        self.seal_initial()
        original_db = self.repo.db_path.read_bytes()
        self.append_run()
        with repository_lock(self.data):
            seal_checkpoint(self.data)
        self.repo.db_path.write_bytes(original_db)
        self.assertEqual(verify_protection(self.data)["status"], "failed")
        self.append_run()
        self.assertEqual(verify_protection(self.data)["status"], "sealed")
        (default_trust_dir(self.data) / "checkpoints/00000002.json").unlink()
        self.assertEqual(verify_protection(self.data)["status"], "failed")

    def test_marker_or_vault_removal_cannot_silently_downgrade(self):
        self.seal_initial()
        marker = self.data / "protection.json"
        original = marker.read_bytes()
        marker.unlink()
        self.assertEqual(verify_protection(self.data)["status"], "failed")
        marker.write_bytes(original)
        shutil.rmtree(default_trust_dir(self.data))
        self.assertEqual(verify_protection(self.data)["status"], "failed")
        with self.assertRaises(ValueError):
            initialize_protection(self.data)

    def test_checkpoint_payload_signature_and_pinned_key_substitution_fail(self):
        self.seal_initial()
        trust = default_trust_dir(self.data)
        checkpoint = trust / "checkpoints/00000001.json"
        original = checkpoint.read_bytes()
        envelope = json.loads(original)
        envelope["payload"]["sealed_at"] = "rewritten"
        self.rewrite(checkpoint, envelope)
        self.assertEqual(verify_protection(self.data)["status"], "failed")
        self.rewrite(checkpoint, original)
        other = self.base / "other"
        Repository(other).seed_demo()
        with repository_lock(other):
            initialize_protection(other)
        other_anchor = json.loads((default_trust_dir(other) / "anchor.json").read_bytes())
        anchor = json.loads((trust / "anchor.json").read_bytes())
        anchor["public_key"] = other_anchor["public_key"]
        anchor["key_fingerprint"] = other_anchor["key_fingerprint"]
        self.rewrite(trust / "anchor.json", anchor)
        self.assertEqual(verify_protection(self.data)["status"], "failed")
        self.assertEqual(verify_protection(self.data, default_trust_dir(other))["status"], "failed")

    def test_actual_changed_bytes_cannot_be_signed(self):
        self.seal_initial()
        self.append_run()
        file = self.data / self.repo.list_filings()[0]["document_path"]
        self.rewrite(file, b"corrupt")
        with repository_lock(self.data), self.assertRaisesRegex(ValueError, "bytes"):
            seal_checkpoint(self.data)
        self.assertEqual(json.loads((default_trust_dir(self.data) / "anchor.json").read_bytes())["sequence"], 1)

    def test_schema_change_is_not_treated_as_pending(self):
        self.seal_initial()
        self.sql("ALTER TABLE filings ADD COLUMN unsigned_note TEXT")
        self.assertEqual(verify_protection(self.data)["status"], "failed")

    def test_signer_unavailable_and_missing_key_fail_closed(self):
        with patch("heltemes.protection.SSH_KEYGEN", str(self.base / "not-installed")):
            with repository_lock(self.data), self.assertRaisesRegex(ValueError, "unavailable"):
                initialize_protection(self.data)
        self.assertFalse(default_key_dir(self.data).exists())
        self.seal_initial()
        self.append_run()
        (default_key_dir(self.data) / "signing_key").unlink()
        self.assertEqual(verify_protection(self.data)["status"], "pending")
        with repository_lock(self.data), self.assertRaisesRegex(ValueError, "unavailable"):
            seal_checkpoint(self.data)
        with patch("heltemes.protection.SSH_KEYGEN", str(self.base / "not-installed")):
            self.assertEqual(verify_protection(self.data)["status"], "failed")

    def test_symlink_paths_and_preexisting_directories_are_refused(self):
        linked = self.base / "linked"
        linked.symlink_to(self.data, target_is_directory=True)
        self.assertEqual(verify_protection(linked)["status"], "failed")
        default_key_dir(self.data).mkdir(parents=True)
        with self.assertRaises(ValueError):
            initialize_protection(self.data)
        default_key_dir(self.data).rmdir()
        self.seal_initial()
        trust = default_trust_dir(self.data)
        anchor = trust / "anchor.json"
        outside = self.base / "outside-receipt"
        shutil.copyfile(anchor, outside)
        anchor.unlink()
        anchor.symlink_to(outside)
        self.assertEqual(verify_protection(self.data)["status"], "failed")

    def test_hardlinked_trust_file_and_exposed_private_key_are_refused(self):
        self.seal_initial()
        anchor = default_trust_dir(self.data) / "anchor.json"
        alias = self.base / "anchor-alias.json"
        os.link(anchor, alias)
        self.assertEqual(verify_protection(self.data)["status"], "failed")
        alias.unlink()
        self.append_run()
        (default_key_dir(self.data) / "signing_key").chmod(0o644)
        with repository_lock(self.data), self.assertRaisesRegex(ValueError, "owner-only"):
            seal_checkpoint(self.data)
        self.assertEqual(verify_protection(self.data)["status"], "pending")

    def test_lock_excludes_second_mutator(self):
        with repository_lock(self.data):
            with self.assertRaisesRegex(ValueError, "operation"):
                with repository_lock(self.data):
                    self.fail("Second lock acquired")

    def test_public_backup_material_excludes_anchor_and_private_key(self):
        self.seal_initial()
        files = backup_files(self.data)
        self.assertEqual(set(files), {"protection.json", "protection/checkpoints/00000001.json"})
        self.assertNotIn(b"OPENSSH PRIVATE KEY", b"".join(files.values()))
        receipt = Path(export_receipt(self.data, self.base / "receipt.json"))
        self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o400)
        self.assertEqual(receipt.read_bytes(), (default_trust_dir(self.data) / "anchor.json").read_bytes())
        with self.assertRaises(FileExistsError):
            export_receipt(self.data, receipt)
        with self.assertRaises(ValueError):
            export_receipt(self.data, self.data / "receipt.json")

    def test_backup_validation_requires_external_matching_receipt_and_sealed_rows(self):
        self.seal_initial()
        staging, receipt = self.make_staging()
        self.assertEqual(validate_backup_protection(staging, receipt)["status"], "sealed")
        self.assertEqual(validate_backup_protection(staging, default_trust_dir(self.data) / "anchor.json")["status"], "sealed")
        self.assertEqual(validate_backup_protection(staging)["status"], "failed")
        internal_receipt = staging / "receipt.json"
        shutil.copyfile(receipt, internal_receipt)
        self.assertEqual(validate_backup_protection(staging, internal_receipt)["status"], "failed")
        with closing(sqlite3.connect(staging / "data.sqlite3")) as db, db:
            db.execute("UPDATE filings SET company='rewritten'")
        self.assertEqual(validate_backup_protection(staging, receipt)["status"], "failed")

    def test_restore_installs_only_public_trust_and_cannot_overwrite(self):
        self.seal_initial()
        staging, receipt = self.make_staging()
        destination = self.base / "restored"
        trust = Path(install_restored_trust(staging, destination, receipt))
        self.assertEqual(trust, default_trust_dir(destination))
        self.assertFalse(default_key_dir(destination).exists())
        staging.rename(destination)
        self.assertEqual(verify_protection(destination)["status"], "sealed")
        with self.assertRaises(ValueError):
            install_restored_trust(destination, self.base / "restored", receipt)

    def test_sealed_filing_hashes_match_full_database_row_encoding(self):
        self.seal_initial()
        self.assertNotIn("sealed_filing_hashes", verify_protection(self.data))
        result = verify_protection(self.data, include_filing_hashes=True)
        row = self.repo.list_filings()[0]
        digest = hashlib.sha256(json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        self.assertEqual(result["sealed_filing_hashes"][str(row["id"])], digest)

    def test_duplicate_json_key_and_oversized_marker_are_rejected(self):
        self.seal_initial()
        marker = self.data / "protection.json"
        original = marker.read_bytes()
        self.rewrite(marker, original.rstrip()[:-1] + b',"version":1}')
        self.assertEqual(verify_protection(self.data)["status"], "failed")
        self.rewrite(marker, b"x" * 4097)
        self.assertEqual(verify_protection(self.data)["status"], "failed")


if __name__ == "__main__":
    unittest.main()
