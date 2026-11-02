"""Reviewer bundle preserves source/report provenance and excludes private state."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

from scripts import package_reviewer as reviewer


class ReviewerPackageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        fixtures = {"pyproject.toml": '[project]\nversion="0.4.0"\n',
                    "heltemes/__init__.py": '__version__ = "0.4.0"\n',
                    "heltemes/core.py": '# Synthetic source fixture\n',
                    "heltemes/fixtures/demo_submissions.json": '{"synthetic":true}\n',
                    "scripts/reviewer_demo.py": '# Synthetic harness fixture\n',
                    "docs/REVIEWER_GUIDE.md": '# Reviewer guide\n',
                    "docs/ARCHITECTURE.md": '# Architecture\n',
                    "README.md": '# Fixture\n'}
        for name, content in fixtures.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.report = self.base / "report"
        (self.report / "phases").mkdir(parents=True)
        phases = []
        for number, (name, code) in enumerate(reviewer.DEMO_PHASES, 1):
            relative = f"phases/{number:02d}-{name}.json"
            detail = {"phase": name, "returncode": code, "expected_exit": code,
                      "stdout": '{"synthetic":true}', "stderr": ""}
            (self.report / relative).write_text(json.dumps(detail))
            phases.append({"name": name, "expected_exit": code, "observed_exit": code,
                           "passed": True, "report": relative})
        source = reviewer.release.source_bytes(self.root)
        self.result = {"format": "heltemes-reviewer-demo", "version": 1, "ok": True,
                       "scratch_removed": True, "completed_at_utc": "2026-11-01T00:00:00Z",
                       "source_sha256": {name: hashlib.sha256(content).hexdigest() for name, content in source.items()
                                         if name.startswith("heltemes/") or name == "scripts/reviewer_demo.py"},
                       "checks": {name: True for name in reviewer.DEMO_CHECKS}, "phases": phases,
                       "scope": {"synthetic_only": True, "aws_used": False,
                                 "native_account_isolation_tested": False, "physical_power_loss_tested": False,
                                 "same_user_practice_authorization": True, "network_disabled": True,
                                 "real_archive_or_private_key_inputs": False},
                       "summary": {"baseline_checkpoint": 1, "recovery_checkpoint": 2,
                                   "final_checkpoint": 3, "verified_objects": 4, "synthetic_filings": 3}}
        self.save()
        (self.report / "WALKTHROUGH.txt").write_text("Synthetic exercise. Expected rejections passed.\n")
        self.output = self.base / "reviewer.zip"

    def save(self):
        (self.report / "results.json").write_text(json.dumps(self.result))

    def package(self):
        return reviewer.package(self.report, self.output, root=self.root)

    def test_bundle_is_manifested_reproducible_and_contains_only_allowlisted_reports(self):
        (self.report / "throwaway.key").write_text("PRIVATE-RUNTIME-SENTINEL")
        (self.root / "work").mkdir()
        (self.root / "work/runtime.json").write_text("PRIVATE-RUNTIME-SENTINEL")
        result = self.package()
        second = self.base / "second.zip"
        reviewer.package(self.report, second, root=self.root)
        self.assertEqual(self.output.read_bytes(), second.read_bytes())
        self.assertEqual(hashlib.sha256(self.output.read_bytes()).hexdigest(), result["sha256"])
        self.assertFalse(result["aws_deployed"])
        self.assertFalse(result["installed_service_modified"])
        with zipfile.ZipFile(self.output) as archive:
            manifest = json.loads(archive.read("MANIFEST.json"))
            self.assertEqual(set(archive.namelist()), set(manifest) | {"MANIFEST.json"})
            for name, digest in manifest.items():
                content = archive.read(name)
                self.assertEqual(hashlib.sha256(content).hexdigest(), digest)
                self.assertNotIn(b"PRIVATE-RUNTIME-SENTINEL", content)
            self.assertIn("source/scripts/reviewer_demo.py", manifest)
            self.assertIn("report/phases/06-crash.json", manifest)
            self.assertIn(b"Expected crash", archive.read("index.html"))
            self.assertIn(b"Expected rejection", archive.read("index.html"))
            self.assertNotIn(b"<script", archive.read("index.html"))

    def test_changed_runtime_source_refuses_stale_report(self):
        (self.root / "heltemes/core.py").write_text("# changed after demo\n")
        with self.assertRaisesRegex(ValueError, "source hash"):
            self.package()
        self.assertFalse(self.output.exists())

    def test_missing_source_hash_or_failed_check_refused(self):
        del self.result["source_sha256"]["scripts/reviewer_demo.py"]
        self.save()
        with self.assertRaisesRegex(ValueError, "coverage"):
            self.package()
        self.result["source_sha256"]["scripts/reviewer_demo.py"] = hashlib.sha256((self.root / "scripts/reviewer_demo.py").read_bytes()).hexdigest()
        self.result["checks"]["ordinary_signing_blocked_until_explicit_resume"] = False
        self.save()
        with self.assertRaisesRegex(ValueError, "checks"):
            self.package()

    def test_phase_log_must_match_claimed_outcome(self):
        path = self.report / "phases/08-blocked-seal.json"
        detail = json.loads(path.read_text())
        detail["returncode"] = 0
        path.write_text(json.dumps(detail))
        with self.assertRaisesRegex(ValueError, "phase log"):
            self.package()

    def test_report_secret_contact_and_home_path_refused(self):
        path = self.report / "WALKTHROUGH.txt"
        for private in ("-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n", "researcher@example.org", "/Users/sample/private-record"):
            with self.subTest(private=private):
                path.write_text(private)
                with self.assertRaisesRegex(ValueError, "private key material"):
                    self.package()
                self.assertFalse(self.output.exists())

    def test_existing_output_checksum_and_symlink_are_preserved(self):
        self.output.write_bytes(b"historical")
        with self.assertRaises(FileExistsError):
            self.package()
        self.assertEqual(self.output.read_bytes(), b"historical")
        self.output.unlink()
        checksum = self.output.with_suffix(".zip.sha256")
        checksum.write_text("historical checksum")
        with self.assertRaises(FileExistsError):
            self.package()
        checksum.unlink()
        self.output.symlink_to(self.base / "missing")
        with self.assertRaisesRegex(ValueError, "symbolic"):
            self.package()
        self.assertTrue(self.output.is_symlink())

    def test_report_symlink_and_path_traversal_are_refused(self):
        path = self.report / "WALKTHROUGH.txt"
        path.unlink()
        path.symlink_to(self.root / "README.md")
        with self.assertRaisesRegex(ValueError, "symbolic"):
            self.package()
        path.unlink()
        path.write_text("safe")
        self.result["phases"][0]["report"] = "../outside.json"
        self.save()
        with self.assertRaisesRegex(ValueError, "relative report path"):
            self.package()

    def test_failed_or_unclean_demo_cannot_be_published(self):
        self.result["scratch_removed"] = False
        self.save()
        with self.assertRaisesRegex(ValueError, "complete, passing"):
            self.package()
        self.result["scratch_removed"] = True
        self.result["ok"] = False
        self.save()
        with self.assertRaisesRegex(ValueError, "complete, passing"):
            self.package()


if __name__ == "__main__":
    unittest.main()
