"""CI provenance must identify the exact packaged Git source and execution context."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts import ci_reviewer as ci


class CIReviewerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ci-reviewer-tests-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        fixtures = {
            "README.md": "# Synthetic CI provenance fixture\n",
            "pyproject.toml": '[project]\nversion = "0.4.0"\n',
            "heltemes/__init__.py": '__version__ = "0.4.0"\n',
            "scripts/reviewer_demo.py": "# Synthetic harness fixture\n",
            "docs/REVIEWER_GUIDE.md": "# Synthetic reviewer guide\n",
        }
        for name, content in fixtures.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.git("init", "--quiet")
        self.git("add", ".")
        self.commit("Synthetic test source")
        self.identity = ci.git_identity(self.root)
        self.output = self.base / "result"

    def git(self, *arguments):
        return subprocess.check_output(["git", "-C", str(self.root), *arguments], stderr=subprocess.PIPE)

    def commit(self, message):
        self.git("-c", "user.name=CI Test", "-c", "user.email=ci@example.invalid",
                 "commit", "--quiet", "--allow-empty", "-m", message)

    def fake_demo(self, report):
        """Passing package fixture, leaving behavioral tests to the real demo suite."""
        (report / "phases").mkdir(parents=True)
        source = ci.package_reviewer.release.source_bytes(self.root)
        phases = []
        for number, (name, expected_exit) in enumerate(ci.package_reviewer.DEMO_PHASES, 1):
            relative = f"phases/{number:02d}-{name}.json"
            (report / relative).write_text(json.dumps({
                "phase": name, "expected_exit": expected_exit, "returncode": expected_exit,
                "stdout": '{"synthetic_fixture":true}', "stderr": "",
            }))
            phases.append({"name": name, "expected_exit": expected_exit,
                           "observed_exit": expected_exit, "passed": True, "report": relative})
        result = {
            "format": "heltemes-reviewer-demo", "version": 1, "ok": True,
            "started_at_utc": "2026-11-04T00:00:00+00:00",
            "completed_at_utc": "2026-11-04T00:00:01+00:00",
            "python_version": "3.14.8", "platform": "fixture", "scratch_removed": True,
            "source_sha256": {name: hashlib.sha256(content).hexdigest() for name, content in source.items()
                              if name.startswith("heltemes/") or name == "scripts/reviewer_demo.py"},
            "phases": phases,
            "checks": {name: True for name in ci.package_reviewer.DEMO_CHECKS},
            "summary": {"baseline_checkpoint": 1, "recovery_checkpoint": 2, "final_checkpoint": 3,
                        "verified_objects": 4, "synthetic_filings": 3},
            "scope": {"synthetic_only": True, "aws_used": False, "network_disabled": True,
                      "same_user_practice_authorization": True, "native_account_isolation_tested": False,
                      "physical_power_loss_tested": False, "real_archive_or_private_key_inputs": False},
        }
        (report / "results.json").write_text(json.dumps(result))
        (report / "WALKTHROUGH.txt").write_text("Synthetic CI provenance test fixture.\n")
        return result

    def context(self, **updates):
        context = {
            "GITHUB_ACTIONS": "true", "GITHUB_SHA": self.identity["commit"],
            "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": "sample/repository",
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_SERVER_URL": "https://github.com", "REVIEWER_PR_HEAD_SHA": "",
        }
        return {**context, **updates}

    def build(self, **arguments):
        return ci.build(self.output, root=self.root, environment={}, **arguments)

    def test_clean_local_build_has_exact_source_and_public_metadata_only(self):
        with patch.object(ci.reviewer_demo, "run_demo", side_effect=self.fake_demo):
            result = ci.build(self.output, root=self.root, environment={"GITHUB_TOKEN": "PRIVATE-CI-TOKEN"})
        self.assertEqual(result["source"]["commit"], self.identity["commit"])
        self.assertEqual(result["source"]["tree"], self.identity["tree"])
        self.assertIsNone(result["github"])
        self.assertEqual(result["artifact"], {"state": "local_only", "requested_retention_days": None})
        published = self.output / "publish"
        self.assertEqual({path.name for path in published.iterdir()}, {
            "reviewer.zip", "reviewer.zip.sha256", "CI-VERIFICATION.json", "CI-VERIFICATION.json.sha256",
        })
        metadata = (published / "CI-VERIFICATION.json").read_bytes()
        self.assertEqual(json.loads(metadata), result)
        self.assertNotIn(str(self.base).encode(), metadata)
        self.assertNotIn(b"PRIVATE-CI-TOKEN", metadata)
        self.assertEqual((published / "CI-VERIFICATION.json.sha256").read_text(),
                         hashlib.sha256(metadata).hexdigest() + "  CI-VERIFICATION.json\n")
        with zipfile.ZipFile(published / "reviewer.zip") as archive:
            self.assertEqual(archive.read("source/README.md"), (self.root / "README.md").read_bytes())
        summary = (self.output / "SUMMARY.md").read_text()
        self.assertIn(self.identity["commit"], summary)
        self.assertIn("Artifact prepared locally", summary)
        self.assertIn("Exit 71", summary)
        self.assertFalse((self.output / "staging").exists())

    def test_pull_request_records_tested_merge_and_proposed_head_separately(self):
        environment = self.context(GITHUB_EVENT_NAME="pull_request", REVIEWER_PR_HEAD_SHA="b" * 40)
        with patch.object(ci.reviewer_demo, "run_demo", side_effect=self.fake_demo):
            result = ci.build(self.output, root=self.root, environment=environment)
        context = result["github"]
        self.assertEqual(context["tested_commit"], self.identity["commit"])
        self.assertEqual(context["pull_request_head_commit"], "b" * 40)
        self.assertEqual(context["tested_commit_kind"], "pull_request_merge")
        self.assertEqual(context["run_url"], "https://github.com/sample/repository/actions/runs/123")
        self.assertEqual(result["artifact"]["requested_retention_days"], 30)
        self.assertIn("proposed merge result", (self.output / "SUMMARY.md").read_text())

    def test_invalid_ci_identity_is_rejected_before_creating_output(self):
        invalid = [
            {"GITHUB_SHA": "0" * 40}, {"GITHUB_EVENT_NAME": "pull_request_target"},
            {"GITHUB_REPOSITORY": "sample/repository\nextra"}, {"GITHUB_RUN_ID": "0"},
            {"GITHUB_RUN_ATTEMPT": "bad"}, {"GITHUB_SERVER_URL": "https://example.invalid"},
            {"GITHUB_EVENT_NAME": "pull_request"}, {"REVIEWER_PR_HEAD_SHA": "a" * 40},
            {"GITHUB_ACTIONS": "unknown"},
        ]
        for updates in invalid:
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                ci.build(self.output, root=self.root, environment=self.context(**updates))
            self.assertFalse(self.output.exists())

    def test_changed_missing_or_untracked_eligible_source_is_rejected(self):
        readme = self.root / "README.md"
        original = readme.read_bytes()
        readme.write_text("Changed tracked source\n")
        with self.assertRaisesRegex(ValueError, "source bytes"):
            self.build()
        readme.unlink()
        with self.assertRaisesRegex(ValueError, "source inventory"):
            self.build()
        readme.write_bytes(original)
        (self.root / "docs/untracked.md").write_text("Untracked eligible source\n")
        with self.assertRaisesRegex(ValueError, "source inventory"):
            self.build()
        self.assertFalse(self.output.exists())

    def test_ignored_runtime_files_are_excluded_from_source_snapshot(self):
        (self.root / "work").mkdir()
        (self.root / "work/private.json").write_text("PRIVATE-RUNTIME-SENTINEL")
        expected = ci.tracked_source(self.root, self.identity["commit"])
        ci.require_source_match(self.root, expected)
        self.assertNotIn("work/private.json", expected)

    def test_head_change_during_build_withholds_publish_directory(self):
        def changed_head(report):
            result = self.fake_demo(report)
            self.commit("Changed identity during reviewer build")
            return result
        with patch.object(ci.reviewer_demo, "run_demo", side_effect=changed_head):
            with self.assertRaisesRegex(ValueError, "HEAD changed"):
                self.build()
        self.assertFalse((self.output / "publish").exists())

    def test_non_runtime_source_change_during_demo_cannot_be_bound_to_old_commit(self):
        def changed_readme(report):
            result = self.fake_demo(report)
            (self.root / "README.md").write_text("Different README with unchanged runtime hashes\n")
            return result
        with patch.object(ci.reviewer_demo, "run_demo", side_effect=changed_readme):
            with self.assertRaisesRegex(ValueError, "ZIP source bytes"):
                self.build()
        self.assertFalse((self.output / "publish").exists())

    def test_unsafe_existing_or_source_output_locations_are_preserved(self):
        self.output.mkdir()
        (self.output / "keep.txt").write_text("Keep this existing record\n")
        with self.assertRaises(FileExistsError):
            self.build()
        self.assertEqual((self.output / "keep.txt").read_text(), "Keep this existing record\n")
        link = self.base / "linked-parent"
        link.symlink_to(self.base, target_is_directory=True)
        destinations = [link / "new", self.root / "data/new", self.root / "docs/generated",
                        self.base / "parent/../new"]
        for output in destinations:
            with self.subTest(output=output), self.assertRaises(ValueError):
                ci.build(output, root=self.root, environment={})


if __name__ == "__main__":
    unittest.main()
