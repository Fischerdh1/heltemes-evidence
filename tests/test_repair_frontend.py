"""Startup repair frontend; all authentication, native repair, and browser calls mocked."""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, call, patch


SPEC = importlib.util.spec_from_file_location(
    "repair_frontend", Path(__file__).resolve().parents[1] / "scripts/repair_local_protection.py"
)
repair = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repair)


class RepairFrontendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.source = self.base / "reviewed source"
        self.source.mkdir()
        self.log_path = self.base / "repair.log"
        self.helper = SimpleNamespace(open_diagnostic_log=Mock(
            side_effect=lambda: (self.log_path, self.log_path.open("x", encoding="utf-8"))))
        self.loader = SimpleNamespace(exec_module=Mock())
        self.success = {"ok": True, "dashboard_started": True, "installation_report_written": True,
                        "dashboard": {"managed_health_confirmed": True, "listener_uid": 450, "listener_pid": 123}}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(repair, "ROOT", self.source))
        self.stack.enter_context(patch.object(repair.importlib.util, "spec_from_file_location",
                                              return_value=SimpleNamespace(loader=self.loader)))
        self.stack.enter_context(patch.object(repair.importlib.util, "module_from_spec", return_value=self.helper))
        self.native = self.stack.enter_context(patch.object(repair.subprocess, "run"))
        self.native.side_effect = [SimpleNamespace(returncode=0),
                                  SimpleNamespace(returncode=0, stdout=json.dumps(self.success))]
        self.browser = self.stack.enter_context(patch.object(repair.webbrowser, "open", return_value=True))
        self.signals = self.stack.enter_context(patch.object(repair.signal, "signal", return_value="old-handler"))
        self.output = self.stack.enter_context(patch("sys.stdout", new_callable=io.StringIO))
        self.errors = self.stack.enter_context(patch("sys.stderr", new_callable=io.StringIO))

    def expected_command(self):
        return ["/usr/bin/sudo", "-n", "--", repair.RUNTIME, "-I", "-S", "-B",
                str(self.source / "scripts/repair_local_startup.py")]

    def test_native_authentication_is_uncaptured_and_repair_cannot_prompt(self):
        self.native.side_effect = [SimpleNamespace(returncode=0, stdout="AUTH-SENTINEL", stderr="AUTH-ERROR-SENTINEL"),
                                  SimpleNamespace(returncode=0, stdout=json.dumps(self.success))]
        self.assertEqual(repair.main(), 0)
        self.assertEqual(self.native.call_args_list, [
            call(["/usr/bin/sudo", "-v"], check=False),
            call(self.expected_command(), check=False, stdin=repair.subprocess.DEVNULL,
                 stdout=repair.subprocess.PIPE, stderr=repair.subprocess.STDOUT, text=True, errors="replace")])
        for text in (self.log_path.read_text(), self.output.getvalue(), self.errors.getvalue()):
            self.assertNotIn("AUTH-SENTINEL", text)
            self.assertNotIn("AUTH-ERROR-SENTINEL", text)

    def test_only_explicit_verified_success_opens_browser(self):
        self.assertEqual(repair.main(), 0)
        self.browser.assert_called_once_with("http://127.0.0.1:8765")
        saved = self.log_path.read_text()
        self.assertIn("Startup repair 1", saved)
        self.assertIn("Repair status: COMPLETE.", saved)
        self.assertIn('"installation_report_written": true', saved)
        self.assertIn("Repair helper exit status: 0", saved)
        self.assertIn("AWS remains deferred", saved)
        self.loader.exec_module.assert_called_once_with(self.helper)

    def test_authentication_failure_never_runs_repair_or_browser(self):
        self.native.side_effect = [SimpleNamespace(returncode=19, stdout="AUTH-SENTINEL")]
        self.assertEqual(repair.main(), 19)
        self.native.assert_called_once_with(["/usr/bin/sudo", "-v"], check=False)
        self.browser.assert_not_called()
        saved = self.log_path.read_text()
        self.assertIn("repair helper was not started", saved)
        self.assertIn("Repair status: NOT COMPLETED", saved)
        self.assertNotIn("AUTH-SENTINEL", saved)

    def test_zero_exit_without_success_contract_never_opens_browser(self):
        self.native.side_effect = [SimpleNamespace(returncode=0), SimpleNamespace(returncode=0, stdout='{"ok": true}')]
        self.assertEqual(repair.main(), 1)
        self.browser.assert_not_called()
        self.assertIn("complete verified success result was not returned", self.log_path.read_text())
        self.assertNotIn("Repair status: COMPLETE.", self.log_path.read_text())

    def test_malformed_native_output_never_claims_complete(self):
        self.native.side_effect = [SimpleNamespace(returncode=0), SimpleNamespace(returncode=0, stdout="unexpected output\n")]
        self.assertEqual(repair.main(), 1)
        self.browser.assert_not_called()
        self.assertIn("unexpected output", self.log_path.read_text())
        self.assertIn("Repair status: NOT CONFIRMED", self.log_path.read_text())

    def test_success_contract_requires_real_booleans_and_confirmed_health(self):
        self.assertTrue(repair.confirmed_success(self.success))
        for field in ("ok", "dashboard_started", "installation_report_written"):
            for value in (False, None, 1, "true"):
                result = dict(self.success, **{field: value})
                with self.subTest(field=field, value=value):
                    self.assertFalse(repair.confirmed_success(result))
        for dashboard in (None, {}, {"managed_health_confirmed": False}, {"managed_health_confirmed": 1}):
            self.assertFalse(repair.confirmed_success(dict(self.success, dashboard=dashboard)))

    def test_failed_native_result_is_saved_and_never_opens_browser(self):
        self.native.side_effect = [SimpleNamespace(returncode=0),
                                  SimpleNamespace(returncode=41, stdout='{"ok":false,"diagnostic":"permission mismatch"}\n')]
        self.assertEqual(repair.main(), 41)
        self.browser.assert_not_called()
        self.assertIn("permission mismatch", self.log_path.read_text())
        self.assertIn("Repair helper exit status: 41", self.log_path.read_text())

    def test_log_failure_never_authenticates(self):
        self.helper.open_diagnostic_log.side_effect = OSError("private log unavailable")
        self.assertEqual(repair.main(), 1)
        self.native.assert_not_called()
        self.browser.assert_not_called()
        self.assertIn("before authentication", self.errors.getvalue())

    def test_authentication_interruption_is_explicitly_recorded(self):
        self.native.side_effect = KeyboardInterrupt()
        self.assertEqual(repair.main(), 130)
        self.native.assert_called_once_with(["/usr/bin/sudo", "-v"], check=False)
        self.browser.assert_not_called()
        saved = self.log_path.read_text()
        self.assertIn("INCOMPLETE until verified success", saved)
        self.assertIn("Repair status: INTERRUPTED; completion was not confirmed", saved)
        self.assertIn("Terminal interruption", saved)

    def test_native_repair_interruption_is_explicitly_recorded(self):
        self.native.side_effect = [SimpleNamespace(returncode=0), InterruptedError("Received signal 1")]
        self.assertEqual(repair.main(), 130)
        self.assertEqual(self.native.call_count, 2)
        self.browser.assert_not_called()
        saved = self.log_path.read_text()
        self.assertIn("Authentication completed", saved)
        self.assertIn("Repair status: INTERRUPTED", saved)
        self.assertIn("Received signal 1", saved)

    def test_signal_handlers_are_restored_after_attempt(self):
        self.assertEqual(repair.main(), 0)
        for name in ("SIGHUP", "SIGTERM"):
            number = getattr(repair.signal, name, None)
            if number is not None:
                self.signals.assert_any_call(number, "old-handler")

    def test_failed_browser_does_not_erase_verified_repair(self):
        self.browser.side_effect = OSError("browser unavailable")
        self.assertEqual(repair.main(), 0)
        saved = self.log_path.read_text()
        self.assertIn("Repair status: COMPLETE.", saved)
        self.assertIn("repair passed, but the browser could not open", saved)

    def test_interrupting_browser_does_not_erase_verified_repair(self):
        self.browser.side_effect = KeyboardInterrupt()
        self.assertEqual(repair.main(), 0)
        self.assertIn("Repair remains COMPLETE.", self.log_path.read_text())
        self.assertNotIn("Repair status: INTERRUPTED", self.log_path.read_text())


if __name__ == "__main__":
    unittest.main()
