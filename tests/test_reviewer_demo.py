"""Reviewer demo must prove failure boundaries without retaining private material."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("reviewer_demo", ROOT / "scripts/reviewer_demo.py")
demo = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(demo)


class ReviewerDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="reviewer-demo-tests-")
        cls.base = Path(cls.tmp.name).resolve()
        cls.report = cls.base / "report"
        cls.process = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(ROOT / "scripts/reviewer_demo.py"), "--output", str(cls.report)],
            cwd=cls.base, capture_output=True, text=True, timeout=150,
        )
        cls.result = json.loads((cls.report / "results.json").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def phase(self, name):
        index = [row["name"] for row in self.result["phases"]].index(name)
        record = self.result["phases"][index]
        return json.loads(json.loads((self.report / record["report"]).read_text())["stdout"])

    def test_fresh_run_demonstrates_correct_negative_and_positive_results(self):
        self.assertEqual(self.process.returncode, 0, self.process.stdout + self.process.stderr)
        self.assertTrue(self.result["ok"])
        self.assertTrue(self.result["scratch_removed"])
        self.assertEqual(len(self.result["phases"]), 12)
        tampered = self.phase("verify-tamper")
        changed = self.phase("tamper")
        self.assertTrue(changed["fingerprint_uses_production_formula"])
        self.assertNotEqual(changed["document_sha256"], changed["filing_fingerprint"])
        self.assertTrue(tampered["metadata_fingerprints_match"])
        self.assertTrue(tampered["ordinary_checks"]["ok"])
        self.assertTrue(tampered["signed_checks"]["evidence_ok"])
        self.assertFalse(tampered["signed_checks"]["ok"])
        interrupted = self.phase("verify-crash")
        self.assertTrue(interrupted["verification"]["ok"])
        self.assertFalse(interrupted["status"]["signing_allowed"])
        self.assertTrue(interrupted["temporary_completion_exists"])
        self.assertFalse(interrupted["final_completion_exists"])
        self.assertIn("completion.json", self.phase("blocked-seal")["error"])
        self.assertTrue(self.phase("restart")["resume"]["already_completed"])
        self.assertTrue(self.phase("restart")["history_unchanged"])
        self.assertEqual(self.phase("restart")["state"]["sequence"], 2)
        self.assertEqual(self.result["summary"]["final_checkpoint"], 3)
        self.assertFalse(self.phase("ordinary-sign")["key_transition"])
        self.assertTrue(self.phase("final-check")["old_history_and_completion_preserved"])

    def test_report_exports_only_normalized_logs_and_bound_source_hashes(self):
        self.assertEqual(self.result["source_sha256"], demo.source_hashes())
        for path in self.report.rglob("*"):
            if path.is_file():
                self.assertIn(path.suffix, {".json", ".txt"})
                raw = path.read_text()
                self.assertNotIn("PRIVATE KEY-----", raw)
                self.assertNotIn(str(ROOT), raw)
                self.assertNotIn(str(self.base), raw)
                self.assertNotIn("/Library/HELTEMES Evidence", raw)
        self.assertFalse(self.result["scope"]["native_account_isolation_tested"])
        self.assertFalse(self.result["scope"]["physical_power_loss_tested"])

    def test_existing_output_is_never_adopted_or_overwritten(self):
        before = (self.report / "results.json").read_bytes()
        with self.assertRaises(FileExistsError):
            demo.run_demo(self.report)
        self.assertEqual((self.report / "results.json").read_bytes(), before)

    def test_rejects_symlink_parent_and_protected_report_destinations(self):
        link = self.base / "report-link"
        link.symlink_to(self.report, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symbolic"):
            demo.new_report_directory(link / "child")
        for name in ("data", "DATA", ".heltemes-keys", ".heltemes-trust", "custody"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "protected"):
                demo.new_report_directory(self.base / name / "report")

    def test_unexpected_child_exit_fails_and_removes_scratch(self):
        output = self.base / "failed-report"
        child = subprocess.CompletedProcess([], 9, "", "synthetic injected worker failure")
        with patch.object(demo.subprocess, "run", return_value=child):
            result = demo.run_demo(output)
        self.assertFalse(result["ok"])
        self.assertTrue(result["scratch_removed"])
        self.assertFalse(result["phases"][0]["passed"])
        self.assertIn("observed 9", result["error"])
        self.assertFalse(json.loads((output / "results.json").read_text())["ok"])


if __name__ == "__main__":
    unittest.main()
