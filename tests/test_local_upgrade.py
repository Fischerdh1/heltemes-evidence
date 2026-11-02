"""Code-upgrade safety and interrupted swaps in disposable paths only.

No service accounts, authentication, native installed paths or private keys
are used. Real subprocess tests execute only tiny disposable bootstrap inputs.
"""
from contextlib import ExitStack
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import upgrade_local_protection as upgrade


class SimulatedCrash(BaseException):
    pass


class LocalUpgradeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.prefix = self.root / "managed"
        self.prefix.mkdir()
        self.old = {"heltemes/__init__.py": b"old code\n", "scripts/local_operator.py": b"old operator\n"}
        self.new = {"heltemes/__init__.py": b"new code\n", "scripts/local_operator.py": b"new operator\n",
                    "heltemes/key_recovery.py": b"recovery implementation\n"}
        self.original = {"ok": True, "application_sha256": upgrade.manifest(self.old),
                         "source_checkpoint": {"sequence": 1, "checkpoint_sha256": "1" * 64}}
        self.receipt = {"archive_id": "3775ad31-8e3c-4ef9-9c95-934e78b1cf3d", "sequence": 2,
                        "checkpoint_sha256": "a" * 64, "public_key": "ssh-ed25519 public-key",
                        "key_fingerprint": "SHA256:original-public-identity"}
        self.identity = {"collector_uid": 450, "custodian_uid": 451, "accounts": {"collector": "original"}}
        self.loaded = True
        self.actions = []
        for name, content in self.old.items():
            path = self.prefix / "app" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            path.chmod(0o644)
        (self.prefix / upgrade.REPORT_NAME).write_bytes(upgrade.encoded(self.original))
        (self.prefix / upgrade.REPORT_NAME).chmod(0o644)
        # Immutable sentinels model resources outside the code upgrade scope.
        for name in ("data/filing", "custody/keys/never-read", "custody/trust/anchor", "runtime.json"):
            path = self.prefix / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("unchanged " + name).encode())
        self.sentinels = {path.relative_to(self.prefix): path.read_bytes() for path in self.prefix.rglob("*")
                          if path.is_file() and not path.is_relative_to(self.prefix / "app") and path.name != upgrade.REPORT_NAME}
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(upgrade, "PREFIX", self.prefix))
        stack.enter_context(patch.object(upgrade, "reject_acl"))
        real_metadata = upgrade.safe_metadata
        stack.enter_context(patch.object(upgrade, "safe_metadata", side_effect=lambda value, **kw: real_metadata(value, **{**kw, "protected": False})))
        stack.enter_context(patch.object(upgrade.os, "fchown"))
        stack.enter_context(patch.object(upgrade.os, "chown"))
        stack.enter_context(patch.object(upgrade, "current_identity", side_effect=lambda: copy.deepcopy(self.identity)))
        stack.enter_context(patch.object(upgrade, "service_loaded", side_effect=lambda: self.loaded))
        stack.enter_context(patch.object(upgrade, "require_stopped", side_effect=self.stopped))
        self.native = stack.enter_context(patch.object(upgrade, "operator", side_effect=self.operator))

    def stopped(self):
        if self.loaded:
            raise ValueError("Dashboard still loaded")

    def operator(self, action):
        self.actions.append(action)
        if action == "stop":
            self.loaded = False
            return {"ok": True}
        if action == "start":
            self.loaded = True
            return {"ok": True, "dashboard_loaded": True, "managed_health_confirmed": True,
                    "listener_uid": 450, "listener_pid": 321, "url": "http://127.0.0.1:8765"}
        if action == "receipt":
            return copy.deepcopy(self.receipt)
        if action == "verify":
            return {"ok": True, "issues": [], "protection": {"status": "sealed", **self.receipt}}
        if action == "probe":
            return {"ok": True, "permission_checks": {"collector_cannot_read_key": True, "custodian_cannot_write_data": True}}
        if action == "key-status":
            return {"ok": True, "active_key_matches": True, "signing_allowed": True,
                    "public_key_fingerprint": self.receipt["key_fingerprint"]}
        raise AssertionError("Unexpected native action: " + action)

    def run_upgrade(self):
        hashes = upgrade.manifest(self.new)
        return upgrade.upgrade_locked(self.new, hashes, upgrade.manifest_sha(hashes), self.identity)

    def journal(self):
        return json.loads((self.prefix / upgrade.STATE_NAME / "journal.json").read_text())

    def assert_preserved(self):
        for relative, expected in self.sentinels.items():
            self.assertEqual((self.prefix / relative).read_bytes(), expected)
        self.assertTrue(set(self.actions).issubset({"stop", "start", "verify", "receipt", "probe", "key-status"}))

    def test_success_preserves_actual_head_key_original_report_accounts_and_data(self):
        result = self.run_upgrade()
        self.assertTrue(result["ok"])
        self.assertEqual(result["receipt"], self.receipt)
        self.assertEqual(result["receipt"]["sequence"], 2)
        updated = json.loads((self.prefix / upgrade.REPORT_NAME).read_text())
        self.assertEqual(updated["source_checkpoint"], self.original["source_checkpoint"])
        self.assertEqual(updated["application_sha256"], upgrade.manifest(self.new))
        self.assertEqual(upgrade.existing_manifest(self.prefix / upgrade.STATE_NAME / "old-app"), upgrade.manifest(self.old))
        self.assertEqual(self.journal()["phase"], "complete")
        self.assertTrue(self.loaded)
        self.assert_preserved()

    def test_originally_stopped_dashboard_stays_stopped(self):
        self.loaded = False
        result = self.run_upgrade()
        self.assertFalse(result["dashboard_running"])
        self.assertNotIn("start", self.actions)
        self.assert_preserved()

    def test_retry_at_each_durable_boundary_finishes_same_candidate_without_signing(self):
        for phase in ("prepared", "stopped", "installing", "new_code_active", "report_updated", "verified", "complete"):
            with self.subTest(phase=phase):
                # Each nested case gets a genuinely independent disposable install.
                case = LocalUpgradeTests("test_success_preserves_actual_head_key_original_report_accounts_and_data")
                case.setUp()
                try:
                    original = upgrade.atomic_json
                    fired = False
                    def crash_after(path, value, mode=0o600):
                        nonlocal fired
                        original(path, value, mode)
                        if path.name == "journal.json" and value["phase"] == phase and not fired:
                            fired = True
                            raise SimulatedCrash()
                    with patch.object(upgrade, "atomic_json", side_effect=crash_after):
                        with self.assertRaises(SimulatedCrash):
                            case.run_upgrade()
                    result = case.run_upgrade()
                    self.assertTrue(result["ok"])
                    self.assertEqual(case.journal()["phase"], "complete")
                    case.assert_preserved()
                finally:
                    case.doCleanups()

    def test_retry_after_each_directory_rename_recovers_known_half_swap(self):
        for name in ("app", "new-app"):
            with self.subTest(rename=name):
                case = LocalUpgradeTests("test_success_preserves_actual_head_key_original_report_accounts_and_data")
                case.setUp()
                try:
                    original = upgrade.os.rename
                    fired = False
                    def interrupted(source, destination, *args, **kwargs):
                        nonlocal fired
                        original(source, destination, *args, **kwargs)
                        if Path(source).name == name and not fired:
                            fired = True
                            raise SimulatedCrash()
                    with patch.object(upgrade.os, "rename", side_effect=interrupted):
                        with self.assertRaises(SimulatedCrash):
                            case.run_upgrade()
                    self.assertFalse(case.loaded)
                    self.assertTrue(case.run_upgrade()["ok"])
                    case.assert_preserved()
                finally:
                    case.doCleanups()

    def test_interrupted_staging_payload_is_disposable_and_not_installed(self):
        original = upgrade.new_file
        fired = False
        def interrupted(path, content, mode=0o600):
            nonlocal fired
            if path.name == ".staging-payload" and not fired:
                fired = True
                original(path, content[:2], mode)
                raise SimulatedCrash()
            original(path, content, mode)
        with patch.object(upgrade, "new_file", side_effect=interrupted):
            with self.assertRaises(SimulatedCrash):
                self.run_upgrade()
        self.assertTrue(self.loaded)
        self.assertTrue(self.run_upgrade()["ok"])
        self.assert_preserved()

    def test_empty_interrupted_state_directory_is_reinitialized_before_service_mutation(self):
        path = self.prefix / upgrade.STATE_NAME
        path.mkdir(mode=0o700)
        (path / "journal.json.new-interrupted").write_bytes(b"partial")
        (path / "journal.json.new-interrupted").chmod(0o600)
        self.assertTrue(self.run_upgrade()["ok"])

    def test_unrelated_state_directory_is_not_adopted(self):
        path = self.prefix / upgrade.STATE_NAME
        path.mkdir(mode=0o700)
        (path / "unknown.json").write_text("{}")
        with self.assertRaisesRegex(ValueError, "Unrecognized"):
            self.run_upgrade()
        self.assertNotIn("stop", self.actions)

    def test_unreviewed_installed_code_stops_before_service_mutation(self):
        (self.prefix / "app/heltemes/__init__.py").write_text("changed")
        with self.assertRaisesRegex(ValueError, "proven manifest"):
            self.run_upgrade()
        self.assertEqual(self.actions, [])

    def test_changed_head_after_stop_blocks_swap_and_restart(self):
        original = self.operator
        def changed(action):
            value = original(action)
            if action == "stop":
                self.receipt["sequence"] = 3
            return value
        self.native.side_effect = changed
        with self.assertRaisesRegex(ValueError, "checkpoint or signing identity changed"):
            self.run_upgrade()
        self.assertEqual(upgrade.existing_manifest(self.prefix / "app"), upgrade.manifest(self.old))
        self.assertFalse(self.loaded)
        self.assertNotIn("start", self.actions)

    def test_failed_new_key_check_leaves_dashboard_stopped_and_retry_reverifies(self):
        original = self.operator
        def bad_key(action):
            result = original(action)
            return {**result, "active_key_matches": False} if action == "key-status" else result
        self.native.side_effect = bad_key
        with self.assertRaisesRegex(ValueError, "signing identity"):
            self.run_upgrade()
        self.assertFalse(self.loaded)
        self.assertNotIn("start", self.actions)
        self.native.side_effect = original
        self.assertTrue(self.run_upgrade()["ok"])
        self.assert_preserved()

    def test_completed_retry_does_not_replace_code_or_repeat_service_restart(self):
        self.run_upgrade()
        before = len(self.actions)
        with patch.object(upgrade.os, "rename") as renamed:
            result = self.run_upgrade()
        self.assertTrue(result["already_complete"])
        renamed.assert_not_called()
        self.assertEqual(self.actions[before:], ["verify", "receipt", "key-status"])

    def test_bad_actual_dashboard_proof_stops_service(self):
        original = self.operator
        def bad_listener(action):
            result = original(action)
            return {**result, "listener_uid": 501} if action == "start" else result
        self.native.side_effect = bad_listener
        with self.assertRaisesRegex(ValueError, "restricted collector listener"):
            self.run_upgrade()
        self.assertFalse(self.loaded)
        self.assertEqual(self.actions[-1], "stop")
        self.assertNotEqual(self.journal()["phase"], "complete")

    def test_retry_rejects_changed_candidate_identity_report_and_unknown_placement(self):
        self.run_upgrade()
        for change in ("candidate", "identity", "report", "placement"):
            with self.subTest(change=change):
                if change == "candidate":
                    hashes = upgrade.manifest({**self.new, "extra.py": b"new"})
                    with self.assertRaisesRegex(ValueError, "reviewed candidate"):
                        upgrade.upgrade_locked(self.new, hashes, upgrade.manifest_sha(hashes), self.identity)
                elif change == "identity":
                    with self.assertRaisesRegex(ValueError, "installation identity"):
                        upgrade.upgrade_locked(self.new, upgrade.manifest(self.new), upgrade.manifest_sha(upgrade.manifest(self.new)), {**self.identity, "collector_uid": 999})
                elif change == "report":
                    path = self.prefix / upgrade.REPORT_NAME
                    saved = path.read_bytes()
                    path.write_text("{}")
                    with self.assertRaisesRegex(ValueError, "report changed"):
                        self.run_upgrade()
                    path.write_bytes(saved)
                else:
                    (self.prefix / "app/unrecognized.py").write_text("extra")
                    with self.assertRaisesRegex(ValueError, "application or report changed"):
                        self.run_upgrade()

    def test_public_key_and_signing_block_status_are_mandatory(self):
        valid = self.operator("key-status")
        for fields in ({"ok": False}, {"active_key_matches": False}, {"signing_allowed": False}, {"public_key_fingerprint": "replacement"}):
            with self.assertRaises(ValueError):
                upgrade.validate_key_status({**valid, **fields}, self.receipt)

    def test_file_reader_rejects_symlink_and_hardlink(self):
        target = self.root / "target"
        target.write_text("safe")
        link = self.root / "symlink"
        link.symlink_to(target)
        with self.assertRaises(OSError):
            upgrade.read_file(link)
        hardlink = self.root / "hardlink"
        os.link(target, hardlink)
        with self.assertRaises(ValueError):
            upgrade.read_file(hardlink)


class UpgradeBootstrapTests(unittest.TestCase):
    def run_bootstrap(self, path, expected):
        return subprocess.run([sys.executable, "-I", "-S", "-B", "-c", upgrade.BOOTSTRAP,
                               str(path), expected], capture_output=True, text=True, timeout=10)

    def test_changed_helper_is_rejected_before_its_code_executes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "helper.py"
            path.write_text("raise Exception('MUST NOT EXECUTE')\n")
            result = self.run_bootstrap(path, "0" * 64)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("no helper code executed", result.stderr)
            self.assertNotIn("MUST NOT EXECUTE", result.stderr)

    def test_exact_reviewed_bytes_execute_with_original_filename(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "helper.py"
            content = b"print(__file__)\n"
            path.write_bytes(content)
            result = self.run_bootstrap(path, upgrade.digest(content))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), str(path))

    def test_bootstrap_rejects_linked_helper(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / "helper.py"
            path.write_text("print('unsafe')\n")
            link = path.with_name("link.py")
            link.symlink_to(path)
            result = self.run_bootstrap(link, upgrade.digest(path.read_bytes()))
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("unsafe", result.stdout)

    def test_native_command_contains_only_pinned_bootstrap_and_fixed_operation(self):
        command = upgrade.native_command({"candidate_sha256": "a" * 64, "helper_sha256": "b" * 64})
        self.assertEqual(command[:8], ["/usr/bin/sudo", "-n", "--", str(upgrade.RUNTIME), "-I", "-S", "-B", "-c"])
        self.assertEqual(command[8], upgrade.BOOTSTRAP)
        self.assertEqual(command[-4:], ["--apply", "a" * 64, "--expected-helper-sha256", "b" * 64])


if __name__ == "__main__":
    unittest.main()
