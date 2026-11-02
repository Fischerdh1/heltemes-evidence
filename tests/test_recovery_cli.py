"""Recovery routing and role checks; never use installed accounts or real keys."""
from contextlib import contextmanager, ExitStack, redirect_stdout, redirect_stderr
import importlib.util
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from heltemes.__main__ import main

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("recovery_cli_operator", ROOT / "scripts/local_operator.py")
operator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(operator)


class RecoveryCliTests(unittest.TestCase):
    def setUp(self):
        self.recovery = SimpleNamespace(**{
            name: Mock(return_value={"ok": True, "state": "test"})
            for name in ("recovery_status", "plan_recovery", "prepare_recovery", "resume_recovery")
        })

    def run_recovery(self, arguments, policy=None):
        output = io.StringIO()
        with patch.dict(sys.modules, {"heltemes.key_recovery": self.recovery}), \
                patch("heltemes.local_accounts.policy_for", return_value=policy), \
                patch("heltemes.core.Repository", side_effect=AssertionError("Recovery must not construct Repository")), \
                redirect_stdout(output):
            code = main(["--data-dir", "/test/archive", "protect", "recover", *arguments])
        return code, json.loads(output.getvalue())

    def test_status_does_not_create_repository_or_mutate_recovery(self):
        code, result = self.run_recovery(["status"])
        self.assertEqual(code, 0)
        self.assertEqual(result["state"], "test")
        self.recovery.recovery_status.assert_called_once_with("/test/archive")
        for name in ("plan_recovery", "prepare_recovery", "resume_recovery"):
            getattr(self.recovery, name).assert_not_called()

    def test_managed_resume_precedes_generic_protection_route(self):
        policy = SimpleNamespace(custodian_uid=123, require=Mock())
        code, _ = self.run_recovery(["resume"], policy)
        self.assertEqual(code, 0)
        self.recovery.resume_recovery.assert_called_once_with("/test/archive")

    def test_plan_requires_exact_paths_and_only_calls_plan(self):
        self.run_recovery(["plan", "--candidate-key", "/test/candidate", "--trust-receipt", "/test/receipt", "--output", "/test/request"])
        self.recovery.plan_recovery.assert_called_once_with("/test/archive", "/test/candidate", "/test/receipt", "/test/request")
        self.recovery.prepare_recovery.assert_not_called()
        self.recovery.resume_recovery.assert_not_called()

    def test_prepare_forwards_explicit_authorization_hash(self):
        digest = "a" * 64
        self.run_recovery(["prepare", "--candidate-key", "/test/candidate", "--authorization", "/test/approval", "--authorization-sha256", digest])
        self.recovery.prepare_recovery.assert_called_once_with("/test/archive", "/test/candidate", "/test/approval", digest)
        self.recovery.resume_recovery.assert_not_called()

    def test_missing_authorization_hash_rejected_before_backend(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main(["protect", "recover", "prepare", "--candidate-key", "/test/key", "--authorization", "/test/approval"])
        self.assertEqual(raised.exception.code, 2)
        self.recovery.prepare_recovery.assert_not_called()

    def test_blocked_status_returns_failure_code_without_changing_it(self):
        blocked = {"ok": False, "state": "prepared", "signing_allowed": False, "archive_verified": True}
        self.recovery.recovery_status.return_value = blocked
        code, result = self.run_recovery(["status"])
        self.assertEqual(code, 1)
        self.assertEqual(result, blocked)

    def test_status_operator_dispatches_as_custodian(self):
        config = {"collector_uid": 450, "custodian_uid": 451, "shared_gid": 450}
        with patch.object(operator, "configuration", return_value=config), \
                patch.object(operator.os, "geteuid", return_value=0), \
                patch.object(operator, "execute_worker", return_value={"ok": True}) as dispatch, \
                redirect_stdout(io.StringIO()):
            self.assertEqual(operator.main(["key-status"]), 0)
        dispatch.assert_called_once_with("key-status", config, custodian=True)

    def test_collector_identity_cannot_execute_key_status(self):
        config = {"collector_uid": 450, "custodian_uid": 451, "shared_gid": 450}
        with patch.object(operator.os, "getuid", return_value=450), \
                patch.object(operator.os, "getgrouplist", return_value=[450]), \
                self.assertRaisesRegex(ValueError, "restricted service identity"):
            operator.worker("key-status", config)

    def test_key_check_holds_snapshot_and_recovery_lock_and_uses_gate_selected_key(self):
        events = []
        config = {"collector_uid": 450, "custodian_uid": 451, "shared_gid": 450}
        policy = SimpleNamespace(trust_dir=Path("/test/trust"), key_dir=Path("/test/keys"))
        staged = Path("/test/private-snapshot")
        selected = Path("/test/keys/identities/approved-key.key")
        anchor = {"version": 2, "public_key": "ssh-ed25519 approved-public-key"}

        @contextmanager
        def snapshot(actual):
            self.assertIs(actual, policy)
            events.append("snapshot-enter")
            yield staged
            events.append("snapshot-exit")

        @contextmanager
        def lock(actual):
            self.assertEqual(actual, policy.trust_dir)
            events.append("lock-enter")
            yield
            events.append("lock-exit")

        def gate(data, trust, keys, reference):
            self.assertEqual(events, ["snapshot-enter", "lock-enter"])
            self.assertEqual((data, trust, keys, reference), (staged, policy.trust_dir, policy.key_dir, anchor))
            return selected

        backend = SimpleNamespace(recovery_lock=lock, gate_signing=gate)
        output = io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {"heltemes.key_recovery": backend}))
            stack.enter_context(patch("heltemes.local_accounts.policy_for", return_value=policy))
            stack.enter_context(patch("heltemes.local_accounts.private_snapshot", snapshot))
            stack.enter_context(patch("heltemes.protection._anchor", return_value=(anchor, b"reference")))
            for name, value in (("getuid", 451), ("geteuid", 451), ("getgid", 450), ("getgroups", [450]), ("getgrouplist", [450])):
                stack.enter_context(patch.object(operator.os, name, return_value=value))
            stack.enter_context(patch.object(operator.sys, "path", list(sys.path)))
            stack.enter_context(patch.object(operator, "denied", return_value=True))
            derive = stack.enter_context(patch.object(operator.subprocess, "run", return_value=SimpleNamespace(stdout=anchor["public_key"])))
            stack.enter_context(redirect_stdout(output))
            self.assertEqual(operator.worker("key-check", config), 0)
        self.assertEqual(events, ["snapshot-enter", "lock-enter", "lock-exit", "snapshot-exit"])
        self.assertEqual(derive.call_args.args[0][-1], str(selected))
        result = json.loads(output.getvalue())
        self.assertTrue(result["custodian_key_matches_active_reference"])
        self.assertNotIn("custodian_key_matches_original_reference", result)


if __name__ == "__main__":
    unittest.main()
