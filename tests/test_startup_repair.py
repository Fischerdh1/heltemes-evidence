"""Safety regression tests; no native service/account or installed-path changes."""
from contextlib import contextmanager, ExitStack
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("startup_repair", ROOT / "scripts/repair_local_startup.py")
repair = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repair)


def verification():
    return {"ok": True, "checked": 6, "issues": [], "protection": {"status": "sealed", **repair.CHECKPOINT}}


def dashboard():
    return {"ok": True, "dashboard_loaded": True, "managed_health_confirmed": True, "listener_uid": 450,
            "listener_pid": 1234, "url": "http://127.0.0.1:8765"}


@contextmanager
def pinned(*args, **kwargs):
    yield 99


class StartupRepairTests(unittest.TestCase):
    def test_native_root_required(self):
        with patch.object(repair.os, "getuid", return_value=501):
            with self.assertRaisesRegex(ValueError, "administrator"):
                repair.require_native_root()

    def test_exact_checkpoint_and_clean_integrity_required(self):
        self.assertEqual(repair.verify_checkpoint(verification())["sequence"], 1)
        cases = [{"ok": False}, {"checked": 5}, {"issues": ["changed"]}]
        cases += [{"protection": {**verification()["protection"], field: value}} for field, value in (
            ("archive_id", "another"), ("sequence", 2), ("checkpoint_sha256", "0" * 64), ("status", "pending"))]
        for change in cases:
            with self.subTest(change=change), self.assertRaises(ValueError):
                repair.verify_checkpoint({**verification(), **change})

    def test_dashboard_requires_actual_uid_pid_and_managed_health(self):
        repair.validate_dashboard(dashboard())
        for field, value in (("managed_health_confirmed", False), ("listener_uid", 501), ("listener_pid", True),
                             ("listener_pid", 0), ("dashboard_loaded", False), ("url", "http://remote/")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                repair.validate_dashboard({**dashboard(), field: value})

    def test_stopped_job_must_be_confirmed_not_missing_for_unrelated_error(self):
        for response in ({"returncode": 0, "limited": None, "output": "running"},
                         {"returncode": 113, "limited": None, "output": "permission denied"},
                         {"returncode": 113, "limited": "time_limit", "output": ""}):
            with patch.object(repair.diagnostics, "bounded_command", return_value=response), patch.object(repair.socket, "socket") as socket:
                with self.assertRaises(ValueError):
                    repair.require_stopped()
                socket.assert_not_called()

    def test_only_validated_log_descriptor_mode_changes_without_truncation(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "log"
            path.write_bytes(b"retained prior diagnostic\n")
            path.chmod(0o640)
            descriptor = os.open(path, os.O_RDONLY)
            try:
                with patch.object(repair.diagnostics, "validate_metadata"):
                    result = repair.repair_log(descriptor)
                self.assertEqual(result["old_mode"], "0640")
                self.assertEqual(result["new_mode"], "0660")
                self.assertEqual(path.read_bytes(), b"retained prior diagnostic\n")
                self.assertEqual(path.stat().st_mode & 0o777, 0o660)
                with patch.object(repair.diagnostics, "validate_metadata"), patch.object(repair.os, "fchmod") as chmod:
                    repair.repair_log(descriptor)
                chmod.assert_not_called()
            finally:
                os.close(descriptor)

    def test_unsafe_log_identity_rejected_before_chmod(self):
        for changed in ({"st_uid": 450}, {"st_gid": 20}, {"st_mode": 0o100666}, {"st_nlink": 2}):
            meta = {"st_uid": 0, "st_gid": 450, "st_mode": 0o100640, "st_nlink": 1}
            meta.update(changed)
            with patch.object(repair.os, "fstat", return_value=SimpleNamespace(**meta)), patch.object(repair.os, "fchmod") as chmod:
                with self.assertRaises(ValueError):
                    repair.repair_log(99)
                chmod.assert_not_called()

    def test_existing_report_including_symlink_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            target = parent / "installation-report.json"
            target.symlink_to(parent / "missing-target")
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaisesRegex(ValueError, "already exists"):
                    repair.report_absent(descriptor)
                with patch.object(repair.os, "fchown"), patch.object(repair.diagnostics, "validate_metadata"), self.assertRaises(FileExistsError):
                    repair.write_report(descriptor, {"new": True})
                self.assertTrue(target.is_symlink())
                self.assertFalse((parent / "missing-target").exists())
                self.assertEqual([item.name for item in parent.iterdir()], ["installation-report.json"])
            finally:
                os.close(descriptor)

    def test_report_is_published_complete_and_failed_write_leaves_no_partial_report(self):
        for failure in (False, True):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as folder:
                parent = Path(folder)
                descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with ExitStack() as stack:
                        stack.enter_context(patch.object(repair.os, "fchown"))
                        stack.enter_context(patch.object(repair.diagnostics, "validate_metadata"))
                        if failure:
                            stack.enter_context(patch.object(repair.os, "fsync", side_effect=OSError("disk full")))
                            with self.assertRaises(OSError):
                                repair.write_report(descriptor, {"complete": True})
                            self.assertEqual(list(parent.iterdir()), [])
                        else:
                            repair.write_report(descriptor, {"complete": True})
                            self.assertEqual(json.loads((parent / "installation-report.json").read_text()), {"complete": True})
                            self.assertEqual((parent / "installation-report.json").stat().st_nlink, 1)
                            self.assertEqual(len(list(parent.iterdir())), 1)
                finally:
                    os.close(descriptor)

    def test_probe_requires_all_checks_true_and_exact_account_identities(self):
        with self.assertRaises(ValueError):
            repair.validate_probe({"ok": True, "permission_checks": {"some_check": True}, "collector_uid": 450, "custodian_uid": 451})
        with self.assertRaises(ValueError):
            repair.validate_probe({"ok": True, "permission_checks": {}, "collector_uid": 501, "custodian_uid": 451})

    def test_future_installs_protect_log_parent_and_allow_service_file_writes(self):
        with patch.object(repair.installer, "mkdir_owned") as mkdir, patch.object(repair.installer, "write_owned") as write:
            repair.installer.create_logs(450)
        mkdir.assert_called_once_with(repair.PREFIX / "logs", 0, 450, 0o750)
        self.assertEqual(write.call_count, 2)
        for name, call in zip(repair.LOG_NAMES, write.call_args_list):
            self.assertEqual(call.args, (repair.PREFIX / "logs" / name, b"", 0, 450, 0o660))

    @contextmanager
    def workflow(self, operations):
        with ExitStack() as stack:
            for name, replacement in (("require_native_root", None), ("load_spec", {"application_sha256": {"known": "hash"}}),
                                      ("report_absent", None), ("installed_preflight", {}), ("require_stopped", None),
                                      ("repair_log", {"old_mode": "0640", "new_mode": "0660"}), ("validate_probe", {"boundaries": True})):
                stack.enter_context(patch.object(repair, name, return_value=replacement))
            stack.enter_context(patch.object(repair.os, "umask"))
            stack.enter_context(patch.object(repair, "protected_prefix", pinned))
            stack.enter_context(patch.object(repair, "repair_lock", pinned))
            stack.enter_context(patch.object(repair.diagnostics, "fixed_file", pinned))
            diagnostic = stack.enter_context(patch.object(repair.diagnostics, "diagnostic", return_value={"safe": "details"}))
            operator = stack.enter_context(patch.object(repair, "operator", side_effect=operations))
            writer = stack.enter_context(patch.object(repair, "write_report"))
            yield operator, writer, diagnostic

    def test_success_requires_verify_probe_verify_start_before_report(self):
        with self.workflow([verification(), {"probe": "fresh"}, verification(), dashboard()]) as (operator, writer, diagnostic):
            result = repair.repair()
        self.assertTrue(result["ok"])
        self.assertTrue(result["installation_report_written"])
        self.assertEqual([call.args[0] for call in operator.call_args_list], ["verify", "probe", "verify", "start"])
        writer.assert_called_once()
        diagnostic.assert_not_called()
        self.assertNotIn("migration_bytes_preserved", result)
        self.assertTrue(result["accounts_preexisting"])

    def test_failed_start_stops_unproved_service_then_collects_diagnostics(self):
        with self.workflow([verification(), {}, verification(), ValueError("startup failed"), {"ok": True}]) as (operator, writer, diagnostic):
            result = repair.repair()
        self.assertFalse(result["ok"])
        self.assertFalse(result["installation_report_written"])
        self.assertEqual([call.args[0] for call in operator.call_args_list][-2:], ["start", "stop"])
        writer.assert_not_called()
        diagnostic.assert_called_once()

    def test_interrupted_start_runs_stop_cleanup_and_never_writes_report(self):
        for interruption in (KeyboardInterrupt(), InterruptedError("Terminal closed")):
            with self.subTest(interruption=type(interruption).__name__), self.workflow([verification(), {}, verification(), interruption, {"ok": True}]) as (operator, writer, diagnostic):
                result = repair.repair()
            self.assertFalse(result["ok"])
            self.assertTrue(result["interrupted"])
            self.assertEqual(operator.call_args_list[-1].args, ("stop",))
            writer.assert_not_called()

    def test_signal_guard_restores_handlers_and_requests_cleanup(self):
        callbacks = {}
        def handler(signum, callback):
            old = callbacks.get(signum, "previous")
            callbacks[signum] = callback
            return old
        with patch.object(repair.signal, "signal", side_effect=handler):
            with self.assertRaises(InterruptedError):
                with repair.interruption_guard():
                    callbacks[repair.signal.SIGHUP](repair.signal.SIGHUP, None)
        self.assertEqual(set(callbacks.values()), {"previous"})

    def test_changed_checkpoint_never_reaches_permission_changes_or_start(self):
        value = verification()
        value["protection"]["sequence"] = 2
        with self.workflow([value]) as (operator, writer, diagnostic), patch.object(repair, "repair_log") as change:
            result = repair.repair()
        self.assertFalse(result["ok"])
        change.assert_not_called()
        writer.assert_not_called()
        self.assertEqual([call.args[0] for call in operator.call_args_list], ["verify"])

    def test_failed_report_write_stops_service_and_does_not_claim_success(self):
        with self.workflow([verification(), {}, verification(), dashboard(), {"ok": True}]) as (operator, writer, diagnostic):
            writer.side_effect = OSError("disk full")
            result = repair.repair()
        self.assertFalse(result["ok"])
        self.assertEqual(operator.call_args_list[-1].args, ("stop",))

    def test_arbitrary_paths_or_actions_are_not_accepted(self):
        with self.assertRaises(SystemExit):
            repair.main(["--path", "/arbitrary"])
        with patch.object(repair.diagnostics, "bounded_command") as command, self.assertRaises(ValueError):
            repair.operator("seal")
        command.assert_not_called()


if __name__ == "__main__":
    unittest.main()
