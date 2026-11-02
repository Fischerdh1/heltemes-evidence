"""Reviewed-checkpoint and export boundaries without native administrator actions."""
from contextlib import contextmanager
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace, ModuleType
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("test_recovery_operator_module", ROOT / "scripts/recovery_operator.py")
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)

HEAD = {"archive_id": recovery.ARCHIVE_ID, "sequence": 1, "checkpoint_sha256": "a" * 64}
ACCESSION = "0000320193-25-000079"


def snapshot(rows=None):
    return {"schema": {"known": "schema"}, "tables": {
        "filings": {"columns": ["id", "accession", "mode", "status", "retrieved_at"],
                    "rows": rows or [[5, ACCESSION, "live", "preserved", "2026-10-19T06:27:24Z"]]},
        "runs": {"columns": ["id"], "rows": [["reviewed-run"]]},
        "assets": {"columns": ["sha256"], "rows": [["b" * 64]]},
        "observations": {"columns": ["id"], "rows": [[10]]}}}


def approval():
    return {"version": 1, "request_id": "a830a9cd-b9f6-44c3-952a-eb12bd7490c2", "snapshot_sha256": recovery.sha(snapshot()),
            "head": HEAD.copy(), "approved_accessions": [ACCESSION], "was_running": True}


def prior():
    value = snapshot()
    value["tables"]["filings"]["rows"] = []
    return {"snapshot": value}


class RecoveryOperatorTests(unittest.TestCase):
    def test_approval_requires_exact_types_and_fields(self):
        recovery.validate_approval(approval())
        for changes in ({"version": True}, {"was_running": 1}, {"snapshot_sha256": "wrong"},
                        {"approved_accessions": []}, {"approved_accessions": [ACCESSION, ACCESSION]},
                        {"head": {**HEAD, "sequence": True}}, {"untrusted_path": "/private/key"}):
            with self.subTest(changes=changes), self.assertRaises((ValueError, TypeError)):
                recovery.validate_approval({**approval(), **changes})

    def test_new_reviewed_filing_can_be_sealed(self):
        self.assertTrue(recovery.approval_transition(approval(), snapshot(), HEAD, prior()))

    def test_changed_collection_date_or_asset_fingerprint_invalidates_review(self):
        for table, index, changed in (("filings", 4, "earlier date"), ("assets", 0, "c" * 64)):
            current = snapshot()
            current["tables"][table]["rows"][0][index] = changed
            with self.subTest(table=table), self.assertRaisesRegex(ValueError, "snapshot changed"):
                recovery.approval_transition(approval(), current, HEAD, prior())

    def test_unreviewed_accession_or_demo_cannot_be_signed_even_with_matching_digest(self):
        for row in ([5, "0000320193-25-000080", "live", "preserved", "now"], [5, ACCESSION, "demo", "preserved", "now"]):
            current = snapshot([row])
            expected = {**approval(), "snapshot_sha256": recovery.sha(current)}
            with self.assertRaisesRegex(ValueError, "accessions"):
                recovery.approval_transition(expected, current, HEAD, prior())

    def test_changed_head_rejected_before_signing(self):
        for head in ({**HEAD, "checkpoint_sha256": "d" * 64}, {**HEAD, "sequence": 3}):
            with self.assertRaisesRegex(ValueError, "trust advanced"):
                recovery.approval_transition(approval(), snapshot(), head, prior())

    def test_exact_completed_transition_resumes_without_another_signature(self):
        current_head = {**HEAD, "sequence": 2, "checkpoint_sha256": "e" * 64}
        latest = {"snapshot": snapshot(), "previous_checkpoint_sha256": HEAD["checkpoint_sha256"]}
        self.assertFalse(recovery.approval_transition(approval(), snapshot(), current_head, latest))
        latest["previous_checkpoint_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            recovery.approval_transition(approval(), snapshot(), current_head, latest)

    def test_custody_seals_the_same_private_snapshot_inside_its_lock_only_after_approval(self):
        for altered in (False, True):
            with self.subTest(altered=altered):
                stage = Path("/private/test-only-custodian-snapshot")
                policy = SimpleNamespace(trust_dir=Path("/private/test-only-trust"), key_dir=Path("/private/test-only-key"))
                state = {"inside": False, "sealed": False, "sign_calls": 0}
                @contextmanager
                def private_snapshot(selected):
                    self.assertIs(selected, policy)
                    state["inside"] = True
                    try:
                        yield stage
                    finally:
                        state["inside"] = False
                current = snapshot()
                if altered:
                    current["tables"]["runs"]["rows"] = [["not-approved"]]
                def sign(path, **arguments):
                    self.assertTrue(state["inside"])
                    self.assertEqual(path, stage)
                    self.assertEqual(arguments, {"trust_dir": policy.trust_dir, "key_dir": policy.key_dir})
                    state["sign_calls"] += 1
                    state["sealed"] = True
                    return {"status": "sealed", "sequence": 2}
                def anchor(path):
                    self.assertTrue(state["inside"])
                    return ({**HEAD, "sequence": 2 if state["sealed"] else 1,
                             "checkpoint_sha256": "e" * 64 if state["sealed"] else "a" * 64}, b"public")
                def verified(*arguments):
                    return {"ok": True, "status": "sealed" if state["sealed"] else "pending",
                            "checkpoint_sha256": "e" * 64 if state["sealed"] else "a" * 64}
                class Repository:
                    def __init__(self, path):
                        self.path = path
                    def verify_integrity(self, **kwargs):
                        return {"ok": True, "checked": 8}
                modules = {name: ModuleType(name) for name in ("heltemes.local_accounts", "heltemes.core", "heltemes.protection")}
                modules["heltemes.local_accounts"].policy_for = lambda path: policy
                modules["heltemes.local_accounts"].private_snapshot = private_snapshot
                modules["heltemes.core"].Repository = Repository
                protection = modules["heltemes.protection"]
                protection._anchor = anchor
                protection._load_chain = lambda *args: (prior(), {})
                protection._snapshot = lambda *args, **kwargs: current
                protection.seal_checkpoint = sign
                protection.verify_protection = verified
                with patch.dict(recovery.sys.modules, modules):
                    if altered:
                        with self.assertRaisesRegex(ValueError, "snapshot changed"):
                            recovery.custody_snapshot(approval())
                        self.assertEqual(state["sign_calls"], 0)
                    else:
                        result = recovery.custody_snapshot(approval())
                        self.assertEqual(state["sign_calls"], 1)
                        self.assertEqual(result["receipt"]["sequence"], 2)
                        self.assertTrue(result["signed_now"])
                self.assertFalse(state["inside"])

    def test_backup_failure_after_seal_retains_new_head_and_receipt(self):
        new_head = {**HEAD, "sequence": 2, "checkpoint_sha256": "e" * 64}
        state = {"head": new_head, "snapshot_sha256": approval()["snapshot_sha256"], "receipt": {"sequence": 2},
                 "signed_now": True, "verification": {"ok": True}}
        with patch.object(recovery, "service_loaded", return_value=False), patch.object(recovery, "child_action", return_value=state), patch.object(recovery, "operator", side_effect=OSError("backup failed")) as operator:
            result = recovery.run_action("finish", approval(), {})
        self.assertFalse(result["ok"])
        self.assertTrue(result["sealed"])
        self.assertEqual(result["head"], new_head)
        self.assertEqual(result["receipt"], {"sequence": 2})
        operator.assert_called_once_with("backup")
        self.assertIn("without signing again", result["note"])

    def test_prepare_does_not_stop_service_when_preliminary_verification_fails(self):
        with patch.object(recovery, "child_action", side_effect=ValueError("verification failed")), patch.object(recovery, "operator") as operator:
            with self.assertRaises(ValueError):
                recovery.run_action("prepare", None, {})
        operator.assert_not_called()

    def test_prepare_reports_pause_and_guarded_context_when_second_snapshot_fails(self):
        state = {"head": HEAD, "snapshot_sha256": approval()["snapshot_sha256"]}
        with patch.object(recovery, "child_action", side_effect=[state, ValueError("verification failed")]), patch.object(recovery, "service_loaded", return_value=True), patch.object(recovery, "operator") as operator:
            result = recovery.run_action("prepare", None, {})
        self.assertFalse(result["ok"])
        self.assertTrue(result["service_paused"])
        self.assertEqual(result["resume_request"]["head"], HEAD)
        operator.assert_called_once_with("stop")

    def test_resume_requires_exact_current_head_and_snapshot(self):
        expected = {"head": HEAD, "snapshot_sha256": approval()["snapshot_sha256"], "was_running": True}
        for state in ({"head": {**HEAD, "sequence": 2}, "snapshot_sha256": expected["snapshot_sha256"]},
                      {"head": HEAD, "snapshot_sha256": "0" * 64}):
            with patch.object(recovery, "child_action", return_value=state), patch.object(recovery, "operator") as operator:
                with self.assertRaises(ValueError):
                    recovery.run_action("resume", expected, {})
                operator.assert_not_called()

    def test_export_requires_generated_basename_and_bounded_identity(self):
        good = {"name": "heltemes-20261019T010000Z-01234567.zip", "bytes": 1, "sha256": "a" * 64}
        recovery.validate_backup(good)
        for change in ({"name": "../keys/signing_key"}, {"name": "/private/key.zip"}, {"bytes": True},
                       {"bytes": recovery.MAX_BACKUP + 1}, {"sha256": "short"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                recovery.validate_backup({**good, **change})

    def test_stream_exports_exact_bytes_and_rejects_mismatched_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "backup.zip"
            path.write_bytes(b"bounded backup bytes")
            @contextmanager
            def descriptor(*args):
                fd = os.open(path, os.O_RDONLY)
                try:
                    yield fd, os.fstat(fd)
                finally:
                    os.close(fd)
            with patch.object(recovery, "backup_descriptor", descriptor):
                identity = recovery.backup_bytes("fixed.zip", {})
                output = io.BytesIO()
                self.assertEqual(recovery.backup_bytes("fixed.zip", {}, output, identity), identity)
                self.assertEqual(output.getvalue(), path.read_bytes())
                with self.assertRaisesRegex(ValueError, "differ"):
                    recovery.backup_bytes("fixed.zip", {}, io.BytesIO(), {**identity, "sha256": "0" * 64})

    def test_stream_detects_file_change_during_export(self):
        before = SimpleNamespace(st_dev=1, st_ino=2, st_size=3, st_mtime_ns=4, st_ctime_ns=5)
        after = SimpleNamespace(**{**vars(before), "st_mtime_ns": 6})
        @contextmanager
        def descriptor(*args):
            yield 99, before
        with patch.object(recovery, "backup_descriptor", descriptor), patch.object(recovery.os, "read", side_effect=[b"zip", b""]), patch.object(recovery.os, "fstat", return_value=after):
            with self.assertRaisesRegex(ValueError, "changed"):
                recovery.backup_bytes("fixed.zip", {})

    def test_duplicate_or_oversized_request_refused(self):
        for raw in (b'{"head":1,"head":2}', b"x" * 65537):
            with self.assertRaises(ValueError):
                recovery.read_payload(io.BytesIO(raw))

    def test_signal_handler_raises_into_child_cleanup_and_restores_handlers(self):
        handlers = {}
        def register(number, callback):
            previous = handlers.get(number, "original")
            handlers[number] = callback
            return previous
        with patch.object(recovery.signal, "signal", side_effect=register):
            with self.assertRaises(InterruptedError):
                with recovery.interruption_guard():
                    handlers[signal.SIGTERM](signal.SIGTERM, None)
        self.assertEqual(set(handlers.values()), {"original"})

    def test_parent_interruption_kills_and_reaps_restricted_child(self):
        with patch.object(recovery.os, "fork", return_value=424242), patch.object(recovery.os, "kill") as kill, patch.object(recovery.os, "waitpid", return_value=(424242, 0)) as wait, patch.object(recovery.selectors, "DefaultSelector") as selector:
            selector.return_value.select.side_effect = InterruptedError("Terminal closed")
            with self.assertRaises(InterruptedError):
                recovery.child_action({}, "custodian", "snapshot")
        kill.assert_called_once_with(424242, signal.SIGKILL)
        wait.assert_called_once_with(424242, 0)
        selector.return_value.close.assert_called_once()

    def test_identity_drop_precedes_installed_application_import_path(self):
        calls = []
        class Paths(list):
            def insert(self, index, value):
                calls.append(("import_path", value))
                super().insert(index, value)
        config = {"collector_uid": 450, "custodian_uid": 451, "shared_gid": 450}
        with patch.object(recovery.os, "getgrouplist", return_value=[450, 12]), patch.object(recovery.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=80)), patch.object(recovery.os, "setgroups", side_effect=lambda value: calls.append(("groups", value))), patch.object(recovery.os, "setgid", side_effect=lambda value: calls.append(("gid", value))), patch.object(recovery.os, "setuid", side_effect=lambda value: calls.append(("uid", value))), patch.object(recovery.os, "umask"), patch.object(recovery.os, "getuid", return_value=451), patch.object(recovery.os, "geteuid", return_value=451), patch.object(recovery.sys, "path", Paths()), patch.object(recovery.os, "chdir", side_effect=lambda value: calls.append(("cwd", value))), patch.dict(recovery.os.environ, {"ADMIN_SECRET": "must not be inherited"}, clear=True):
            recovery.drop_identity(config, "custodian")
            self.assertEqual(dict(recovery.os.environ), recovery.diagnostics.ENVIRONMENT)
        self.assertEqual(calls, [("groups", [12, 450]), ("gid", 450), ("uid", 451), ("cwd", recovery.PREFIX), ("import_path", str(recovery.PREFIX / "app"))])

    def test_operator_has_no_seal_reset_or_arbitrary_action(self):
        for action in ("seal", "init", "configure", "/bin/sh"):
            with patch.object(recovery.diagnostics, "bounded_command") as command, self.assertRaises(ValueError):
                recovery.operator(action)
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
