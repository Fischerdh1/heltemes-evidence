"""Inspection frontend tests: every import-helper and native action is mocked."""
import importlib.util
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, call, patch


SPEC = importlib.util.spec_from_file_location(
    "diagnostic_frontend", Path(__file__).resolve().parents[1] / "scripts/diagnose_local_protection.py"
)
diagnostic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostic)


class DiagnosticFrontendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.source = self.base / "reviewed source"
        self.source.mkdir()
        self.log_path = self.base / "inspection.log"
        self.helper = SimpleNamespace(open_diagnostic_log=Mock(
            side_effect=lambda: (self.log_path, self.log_path.open("x", encoding="utf-8"))))
        self.loader = SimpleNamespace(exec_module=Mock())
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(diagnostic, "ROOT", self.source))
        self.spec_factory = self.stack.enter_context(patch.object(
            diagnostic.importlib.util, "spec_from_file_location",
            return_value=SimpleNamespace(loader=self.loader)))
        self.stack.enter_context(patch.object(
            diagnostic.importlib.util, "module_from_spec", return_value=self.helper))
        self.native = self.stack.enter_context(patch.object(
            diagnostic.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="")))
        self.browser = self.stack.enter_context(patch("webbrowser.open"))
        self.output = self.stack.enter_context(patch("sys.stdout", new_callable=io.StringIO))
        self.errors = self.stack.enter_context(patch("sys.stderr", new_callable=io.StringIO))

    def expected_inspection(self):
        return ["/usr/bin/sudo", "-n", "--", diagnostic.sys.executable, "-I", "-S", "-B",
                str(self.source / "scripts/diagnose_local_startup.py")]

    def test_authentication_keeps_terminal_streams_and_never_logs_them(self):
        self.native.side_effect = [
            SimpleNamespace(returncode=0, stdout="AUTHENTICATION-SENTINEL", stderr="AUTH-ERROR-SENTINEL"),
            SimpleNamespace(returncode=0, stdout="Protected diagnostic result\n")]
        self.assertEqual(diagnostic.main(), 0)
        self.assertEqual(self.native.call_args_list[0], call(["/usr/bin/sudo", "-v"], check=False))
        for content in (self.log_path.read_text(), self.output.getvalue(), self.errors.getvalue()):
            self.assertNotIn("AUTHENTICATION-SENTINEL", content)
            self.assertNotIn("AUTH-ERROR-SENTINEL", content)
        self.assertIn("Protected diagnostic result", self.log_path.read_text())
        self.browser.assert_not_called()

    def test_inspection_cannot_prompt_and_captures_both_output_streams(self):
        self.assertEqual(diagnostic.main(), 0)
        self.assertEqual(self.native.call_args_list, [
            call(["/usr/bin/sudo", "-v"], check=False),
            call(self.expected_inspection(), check=False,
                 stdin=diagnostic.subprocess.DEVNULL, stdout=diagnostic.subprocess.PIPE,
                 stderr=diagnostic.subprocess.STDOUT, text=True, errors="replace")])
        self.spec_factory.assert_called_once_with(
            "activation_log_helper", self.source / "scripts/activate_local_accounts.py")
        self.loader.exec_module.assert_called_once_with(self.helper)
        self.helper.open_diagnostic_log.assert_called_once_with()

    def test_authentication_failure_never_starts_inspection(self):
        self.native.return_value = SimpleNamespace(returncode=17, stdout="AUTHENTICATION-SENTINEL")
        self.assertEqual(diagnostic.main(), 17)
        self.native.assert_called_once_with(["/usr/bin/sudo", "-v"], check=False)
        self.browser.assert_not_called()
        saved = self.log_path.read_text()
        self.assertIn("Authentication did not complete; inspection was not started.", saved)
        self.assertNotIn("AUTHENTICATION-SENTINEL", saved)
        self.assertNotIn("Reading startup details", saved)

    def test_saved_success_is_not_reported_as_activation_or_browser_open(self):
        self.native.side_effect = [SimpleNamespace(returncode=0),
                                  SimpleNamespace(returncode=0, stdout='{"independent_verification": "passed"}\n')]
        self.assertEqual(diagnostic.main(), 0)
        saved = self.log_path.read_text()
        self.assertIn('"independent_verification": "passed"', saved)
        self.assertIn("Inspection exit status: 0", saved)
        self.assertIn("This is not an activation-success message.", saved)
        self.assertIn("does not start or stop the dashboard", saved)
        self.assertIn("migrate evidence, or sign a checkpoint", saved)
        self.assertIn(str(self.log_path), self.output.getvalue())
        self.assertNotIn("Opening the managed dashboard", saved)
        self.assertNotIn("Installation and account permission checks passed", saved)
        self.assertEqual(self.native.call_count, 2)
        self.browser.assert_not_called()

    def test_failed_inspection_output_and_exit_code_are_saved(self):
        self.native.side_effect = [SimpleNamespace(returncode=0),
                                  SimpleNamespace(returncode=42, stdout="Native startup diagnostic: denied\n")]
        self.assertEqual(diagnostic.main(), 42)
        saved = self.log_path.read_text()
        self.assertIn("Native startup diagnostic: denied", saved)
        self.assertIn("Inspection exit status: 42", saved)
        self.assertIn("This is not an activation-success message.", saved)
        self.assertIn("Native startup diagnostic: denied", self.output.getvalue())
        self.browser.assert_not_called()

    def test_private_log_failure_stops_before_any_authentication(self):
        for error in (OSError("private log unavailable"), ValueError("unsafe diagnostic folder")):
            with self.subTest(error=type(error).__name__):
                self.helper.open_diagnostic_log.side_effect = error
                self.assertEqual(diagnostic.main(), 1)
                self.native.assert_not_called()
                self.browser.assert_not_called()
                self.assertFalse(self.log_path.exists())
                self.assertIn("Inspection stopped before authentication", self.errors.getvalue())

    def test_native_launch_error_is_saved_without_followup_action(self):
        self.native.side_effect = [SimpleNamespace(returncode=0), OSError("inspection process unavailable")]
        self.assertEqual(diagnostic.main(), 1)
        self.assertIn("Inspection stopped: inspection process unavailable", self.log_path.read_text())
        self.assertEqual(self.native.call_count, 2)
        self.assertIn(str(self.log_path), self.output.getvalue())
        self.browser.assert_not_called()


if __name__ == "__main__":
    unittest.main()
