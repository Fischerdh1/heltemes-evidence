from contextlib import closing
import copy
import hashlib
import json
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from heltemes.core import Repository, restore_backup
from heltemes.sec import SecError

FIXTURE = json.loads((Path(__file__).resolve().parents[1] / "examples/demo_submissions.json").read_text())
CONTACT = "HELTEMES Tests operator@heltemes.dev"


class FakeClient:
    payload = FIXTURE
    document = b"SYNTHETIC TEST DOCUMENT"
    fail_documents = False
    def __init__(self, user_agent):
        pass
    def submissions(self, cik):
        return copy.deepcopy(self.payload), json.dumps(self.payload).encode()
    def primary_document(self, cik, accession, filename):
        if self.fail_documents:
            raise SecError("simulated blocked document")
        return self.document


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.repo = Repository(self.base / "data")
        FakeClient.payload = FIXTURE
        FakeClient.document = b"SYNTHETIC TEST DOCUMENT"
        FakeClient.fail_documents = False
    def tearDown(self):
        self.temp.cleanup()
    def collect(self):
        with patch("heltemes.core.SecClient", FakeClient):
            return self.repo.collect("1", CONTACT, ["10-Q", "10-Q/A"], 3)

    def test_demo_is_idempotent_and_explicitly_synthetic(self):
        first = self.repo.seed_demo()
        second = self.repo.seed_demo()
        self.assertEqual(first, second)
        dash = self.repo.dashboard()
        self.assertEqual(dash["stats"]["filings"], 3)
        self.assertEqual(dash["stats"]["live_filings"], 0)
        self.assertEqual(dash["stats"]["runs"], 1)
        self.assertIsNone(dash["stats"]["latest_success"])
        self.assertTrue(all(r["mode"] == "demo" and "SYNTHETIC" in r["company"] and r["source_url"].startswith("demo:") for r in dash["filings"]))
        self.assertTrue(self.repo.verify_integrity()["ok"])

    def test_duplicate_collections_preserve_observations_without_new_filings(self):
        first = self.collect()
        initial = self.repo.list_filings()
        second = self.collect()
        self.assertEqual(first["filings_added"], 2)
        self.assertEqual(second["filings_added"], 0)
        self.assertEqual(self.repo.list_filings(), initial)
        self.assertEqual(len(self.repo.get_filing(initial[0]["id"])["observations"]), 2)
        self.assertEqual(self.repo.dashboard()["stats"]["runs"], 2)

    def test_amendment_and_document_revision_preserve_history(self):
        self.collect()
        original = self.repo.list_filings()
        self.assertEqual({r["form"] for r in original}, {"10-Q", "10-Q/A"})
        FakeClient.document = b"SYNTHETIC CHANGED TEST DOCUMENT"
        result = self.collect()
        self.assertEqual(result["filings_added"], 2)
        self.assertEqual(len(self.repo.list_filings()), 4)
        for filing in original:
            current = self.repo.get_filing(filing["id"])
            self.assertEqual(current["document_sha256"], filing["document_sha256"])
            self.assertEqual((self.repo.data_dir / current["document_path"]).read_bytes(), b"SYNTHETIC TEST DOCUMENT")

    def test_unrelated_packet_change_does_not_rewrite_index(self):
        self.collect()
        initial = self.repo.list_filings()
        FakeClient.payload = copy.deepcopy(FIXTURE)
        FakeClient.payload["unrelated"] = "new observation"
        result = self.collect()
        self.assertEqual(result["filings_added"], 0)
        self.assertEqual(self.repo.list_filings(), initial)
        observed = self.repo.get_filing(initial[0]["id"])["observations"]
        self.assertNotEqual(observed[0]["raw_sha256"], observed[1]["raw_sha256"])
        self.assertTrue(self.repo.verify_integrity()["ok"])

    def test_invalid_configuration_records_failure_before_network(self):
        with patch("heltemes.sec.build_opener") as opener:
            result = self.repo.collect("1", "Project person@example.com")
            self.assertEqual(result["status"], "failed")
            opener.assert_not_called()
        self.assertIn("placeholder", result["error"])
        self.assertEqual(self.repo.dashboard()["stats"]["runs"], 1)

    def test_partial_document_failure_is_explicit_and_retry_appends(self):
        FakeClient.fail_documents = True
        result = self.collect()
        self.assertEqual(result["status"], "partial")
        self.assertIn("simulated", result["error"])
        self.assertTrue(all(r["status"] == "metadata_only" for r in self.repo.list_filings()))
        FakeClient.fail_documents = False
        self.assertEqual(self.collect()["status"], "success")
        self.assertEqual(len(self.repo.list_filings()), 4)
        self.assertTrue(self.repo.verify_integrity()["ok"])

    def test_malformed_payload_failure_still_preserves_raw_observation(self):
        FakeClient.payload = copy.deepcopy(FIXTURE)
        FakeClient.payload["filings"]["recent"]["form"] = []
        result = self.collect()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(self.repo.dashboard()["stats"]["observations"], 1)
        self.assertTrue(self.repo.verify_integrity()["ok"])

    def test_corruption_missing_files_and_symlinks_are_detected(self):
        self.repo.seed_demo()
        path = self.repo.data_dir / self.repo.list_filings()[0]["document_path"]
        path.chmod(0o600)  # Simulate an owner deliberately overriding read-only evidence.
        path.write_bytes(b"tampered")
        self.assertFalse(self.repo.verify_integrity()["ok"])
        with self.assertRaises(ValueError):
            self.repo.backup(self.base / "corrupt.zip")
        path.unlink()
        self.assertFalse(self.repo.verify_integrity()["ok"])
        outside = self.base / "outside"
        outside.write_text("external")
        path.symlink_to(outside)
        self.assertFalse(self.repo.verify_integrity()["ok"])

    def test_filters_are_parameterized_and_literal(self):
        self.repo.seed_demo()
        self.assertEqual(len(self.repo.list_filings(form="10-Q/A")), 1)
        self.assertEqual(self.repo.list_filings(q="' OR 1=1 --"), [])
        self.assertEqual(self.repo.list_filings(q="%"), [])
        self.assertEqual(self.repo.list_filings(mode="live"), [])

    def test_backup_restore_roundtrip_and_nonempty_refusal(self):
        self.repo.seed_demo()
        self.collect()
        backup = self.repo.backup(self.base / "backup.zip")
        restored_path = restore_backup(backup, self.base / "restored")
        restored = Repository(restored_path)
        self.assertEqual(restored.list_filings(), self.repo.list_filings())
        self.assertEqual(restored.dashboard()["stats"], self.repo.dashboard()["stats"])
        self.assertTrue(restored.verify_integrity()["ok"])
        with self.assertRaises(ValueError):
            restore_backup(backup, self.repo.data_dir)
        with self.assertRaises(FileExistsError):
            self.repo.backup(backup)

    def malicious(self, members):
        path = self.base / "malicious.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name, body in members:
                archive.writestr(name, body)
        return path

    def test_archive_traversal_absolute_and_symlinks_rejected(self):
        for name in ["../escape", "/tmp/escape", "raw/../../escape", "raw\\escape", "raw//escape"]:
            archive = self.malicious([(name, b"evil")])
            with self.subTest(name=name), self.assertRaises(ValueError):
                restore_backup(archive, self.base / "restored")
            self.assertFalse((self.base / "escape").exists())
        info = zipfile.ZipInfo("raw/link")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        archive = self.malicious([(info, b"../../escape")])
        with self.assertRaises(ValueError):
            restore_backup(archive, self.base / "restored")

    def test_archive_tamper_and_inventory_mismatch_rejected(self):
        self.repo.seed_demo()
        backup = self.repo.backup(self.base / "good.zip")
        with zipfile.ZipFile(backup) as archive:
            contents = [(n, archive.read(n)) for n in archive.namelist()]
        contents = [(n, b"tampered" if n.startswith("raw/") else b) for n, b in contents]
        tampered = self.malicious(contents)
        with self.assertRaisesRegex(ValueError, "checksum"):
            restore_backup(tampered, self.base / "restored")
        self.assertFalse((self.base / "restored").exists())

    def test_database_asset_reference_tamper_detected(self):
        self.repo.seed_demo()
        with closing(sqlite3.connect(self.repo.db_path)) as db, db:
            db.execute("UPDATE filings SET sha256='fake' WHERE id=1")
        result = self.repo.verify_integrity()
        self.assertFalse(result["ok"])
        self.assertTrue(any("inconsistent" in issue["error"] for issue in result["issues"]))


if __name__ == "__main__":
    unittest.main()
