"""Attack-focused integration checks; all archives and keys are temporary fixtures."""
from contextlib import contextmanager, closing
import hashlib
import json
import os
import sqlite3
import tempfile
import threading
import unittest
import zipfile
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch

from heltemes.core import Repository, restore_backup
from heltemes.protection import (
    default_key_dir, export_receipt, initialize_protection,
    repository_lock, seal_checkpoint, verify_protection,
)
from heltemes.server import DashboardServer


class ProtectedIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="heltemes-security-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.data = self.base / "data"
        self.repo = Repository(self.data)
        self.repo.seed_demo()
        with repository_lock(self.data):
            initialize_protection(self.data)
        self.receipt = self.base / "independent-trust-receipt.json"
        export_receipt(self.data, self.receipt)

    def start_server(self):
        server = DashboardServer(("127.0.0.1", 0), self.data)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join()
        self.addCleanup(cleanup)
        return server

    @staticmethod
    def req(server, path, body=None):
        conn = HTTPConnection("127.0.0.1", server.server_port, timeout=10)
        headers = {}
        if body is not None:
            headers = {"Content-Type": "application/json", "X-Heltemes-Token": server.token}
        conn.request("GET" if body is None else "POST", path,
                     None if body is None else json.dumps(body), headers)
        result = conn.getresponse()
        status, content = result.status, result.read()
        conn.close()
        return status, content

    def paired_document_and_reference_rewrite(self):
        """Make unsigned hashes consistent while changing previously sealed evidence."""
        filing = self.repo.list_filings()[0]
        old_path = filing["document_path"]
        content = (self.data / old_path).read_bytes() + b"\nUNAUTHORIZED REWRITE\n"
        sha = hashlib.sha256(content).hexdigest()
        relative = f"documents/{sha[:2]}/{sha}.bin"
        target = self.data / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_bytes(content)
        os.chmod(target, 0o400)
        with closing(sqlite3.connect(self.repo.db_path)) as db, db:
            db.execute("UPDATE assets SET path=?,sha256=?,bytes=? WHERE path=?",
                       (relative, sha, len(content), old_path))
            db.execute("UPDATE filings SET document_path=?,document_sha256=? WHERE document_path=?",
                       (relative, sha, old_path))
            db.execute("UPDATE observations SET document_path=?,document_sha256=? WHERE document_path=?",
                       (relative, sha, old_path))
        return filing["id"]

    def append_completed_run(self, repo=None):
        with closing(sqlite3.connect((repo or self.repo).db_path)) as db, db:
            db.execute("INSERT INTO runs (id,started_at,finished_at,status,mode,cik,filings_added) "
                       "VALUES ('new-run','2026-10-11T04:00:00Z','2026-10-11T04:00:01Z','success','demo','1',0)")

    def test_http_download_refuses_paired_document_and_reference_rewrite(self):
        server = self.start_server()
        filing_id = self.repo.list_filings()[0]["id"]
        self.assertEqual(self.req(server, f"/api/document/{filing_id}")[0], 200)
        self.paired_document_and_reference_rewrite()
        self.assertTrue(self.repo.verify_integrity(check_protection=False)["ok"])
        self.assertFalse(self.repo.verify_integrity()["ok"])
        self.assertEqual(self.req(server, f"/api/document/{filing_id}")[0], 409)

    def test_download_checks_captured_row_against_signed_row_after_state_changes(self):
        server = self.start_server()
        filing = server.repo.get_filing(self.repo.list_filings()[0]["id"])
        forged_content = b"Temporary attacker-controlled document and reference"
        forged_sha = hashlib.sha256(forged_content).hexdigest()
        forged_path = f"documents/{forged_sha[:2]}/{forged_sha}.bin"
        target = self.data / forged_path
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_bytes(forged_content)
        captured = {**filing, "document_path": forged_path, "document_sha256": forged_sha}
        # The captured row is forged; by the fresh verification the DB is back to
        # its valid signed state. Verifying the DB again cannot bless that row.
        with patch.object(server.repo, "get_filing", return_value=captured):
            status, body = self.req(server, f"/api/document/{filing['id']}")
        self.assertEqual(status, 409)
        self.assertNotEqual(body, forged_content)

    def test_download_never_rereads_mutable_reference_after_verification(self):
        server = self.start_server()
        filing = self.repo.list_filings()[0]
        original_content = (self.data / filing["document_path"]).read_bytes()
        original_verify = server.repo.verify_integrity
        changed = False
        def verify_then_change(*args, **kwargs):
            nonlocal changed
            result = original_verify(*args, **kwargs)
            if not changed:
                changed = True
                self.paired_document_and_reference_rewrite()
            return result
        with patch.object(server.repo, "verify_integrity", side_effect=verify_then_change):
            status, body = self.req(server, f"/api/document/{filing['id']}")
        self.assertTrue(changed)
        self.assertIn(status, (200, 409))
        if status == 200:
            self.assertEqual(body, original_content)

    def test_http_cannot_sign_reset_or_replace_trust(self):
        server = self.start_server()
        before = self.receipt.read_bytes()
        for endpoint in ("/api/protect", "/api/seal", "/api/protection/init", "/api/protection/seal",
                         "/api/protection/reset", "/api/protection/import", "/api/unprotect"):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(self.req(server, endpoint, {})[0], 404)
        after = self.base / "receipt-after-http.json"
        export_receipt(self.data, after)
        self.assertEqual(after.read_bytes(), before)

    def test_protected_backup_restore_requires_independent_receipt_and_excludes_keys(self):
        archive = Path(self.repo.backup(self.base / "protected.zip"))
        private_key = (default_key_dir(self.data) / "signing_key").read_bytes()
        with zipfile.ZipFile(archive) as z:
            self.assertIn("protection.json", z.namelist())
            for name in z.namelist():
                with self.subTest(member=name):
                    self.assertNotIn("signing_key", name)
                    self.assertNotIn("anchor.json", name)
                    content = z.read(name)
                    self.assertNotIn(private_key, content)
                    self.assertNotIn(b"BEGIN OPENSSH PRIVATE KEY", content)
        with self.assertRaises(ValueError):
            restore_backup(archive, self.base / "missing-receipt")
        destination = self.base / "restored"
        restore_backup(archive, destination, trust_receipt=self.receipt)
        restored = Repository(destination)
        self.assertTrue(restored.verify_integrity()["ok"])
        self.assertEqual(restored.list_filings(), self.repo.list_filings())
        self.assertFalse((default_key_dir(destination) / "signing_key").exists())
        self.append_completed_run(restored)
        with repository_lock(destination), self.assertRaises((ValueError, OSError)):
            seal_checkpoint(destination)

    def test_backup_and_restore_refuse_unsealed_additions(self):
        self.append_completed_run()
        self.assertTrue(verify_protection(self.data)["ok"])
        with self.assertRaises(ValueError):
            self.repo.backup(self.base / "pending.zip")
        with repository_lock(self.data):
            seal_checkpoint(self.data)
        self.assertTrue(self.repo.verify_integrity()["ok"])
        self.repo.backup(self.base / "sealed.zip")

    def test_current_receipt_rejects_older_valid_archive(self):
        old_archive = self.repo.backup(self.base / "old.zip")
        self.append_completed_run()
        with repository_lock(self.data):
            seal_checkpoint(self.data)
        current_receipt = self.base / "current-receipt.json"
        export_receipt(self.data, current_receipt)
        with self.assertRaises(ValueError):
            restore_backup(old_archive, self.base / "rollback", trust_receipt=current_receipt)
        self.assertFalse((self.base / "rollback").exists())
        new_archive = self.repo.backup(self.base / "new.zip")
        with self.assertRaises(ValueError):
            restore_backup(new_archive, self.base / "stale-anchor", trust_receipt=self.receipt)

    def test_stripped_protection_cannot_downgrade_archive_when_receipt_supplied(self):
        good = self.repo.backup(self.base / "good.zip")
        stripped = self.base / "stripped.zip"
        with zipfile.ZipFile(good) as z:
            content = {name: z.read(name) for name in z.namelist()
                       if name != "protection.json" and not name.startswith("protection/")}
        manifest = json.loads(content["manifest.json"])
        manifest["version"] = 1
        manifest["files"] = {name: entry for name, entry in manifest["files"].items()
                             if name != "protection.json" and not name.startswith("protection/")}
        content["manifest.json"] = json.dumps(manifest).encode()
        with zipfile.ZipFile(stripped, "w") as z:
            for name, body in content.items():
                z.writestr(name, body)
        with self.assertRaises(ValueError):
            restore_backup(stripped, self.base / "downgrade", trust_receipt=self.receipt)
        self.assertFalse((self.base / "downgrade").exists())

    def test_backup_validates_copied_database_against_checkpoint(self):
        original_connect = self.repo._connect
        class CorruptingSource:
            def __init__(self, db):
                self.db = db
            def __getattr__(self, name):
                return getattr(self.db, name)
            def backup(self, target):
                self.db.backup(target)
                target.execute("UPDATE filings SET company='forged copied metadata' WHERE id=1")
                target.commit()
        @contextmanager
        def connect_with_corrupt_backup(*args, **kwargs):
            with original_connect(*args, **kwargs) as db:
                yield CorruptingSource(db)
        with patch.object(self.repo, "_connect", connect_with_corrupt_backup), self.assertRaises(ValueError):
            self.repo.backup(self.base / "copy-corrupt.zip")
        self.assertFalse((self.base / "copy-corrupt.zip").exists())
        self.assertTrue(self.repo.verify_integrity()["ok"])

    def test_deleted_marker_does_not_disable_known_archive_protection(self):
        (self.data / "protection.json").unlink()
        self.assertFalse(self.repo.verify_integrity()["ok"])
        with self.assertRaises(ValueError):
            self.repo.seed_demo()
        with self.assertRaises(ValueError):
            self.repo.backup(self.base / "downgraded.zip")


if __name__ == "__main__":
    unittest.main()
