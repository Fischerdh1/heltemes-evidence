"""Activation dispatch only; every installer import and native action is mocked."""
import importlib.util
import io
import os
from pathlib import Path
import stat
from types import SimpleNamespace
import tempfile
import unittest
from contextlib import ExitStack
from unittest.mock import Mock, call, patch


SPEC = importlib.util.spec_from_file_location(
    "activation_frontend", Path(__file__).resolve().parents[1] / "scripts/activate_local_accounts.py"
)
activation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(activation)


class ActivationFrontendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.source = self.base / "reviewed source"
        self.source.mkdir()
        self.prefix = self.base / "managed installation"
        self.recovery = self.source / "work/local-account-recovery.json"
        self.runtime = "/trusted/python3"
        self.checkpoint = {"sequence": 1, "checkpoint_sha256": "a" * 64}
        self.plan = {"runtime": self.runtime, "source_checkpoint": self.checkpoint,
                     "actions": ["Preserve the reviewed archive and verify separate accounts."]}
        self.installer = SimpleNamespace(
            PREFIX=self.prefix,
            installation_plan=Mock(return_value=self.plan),
            inspect_runtime=Mock(return_value=Path(self.runtime)),
            inspect_source=Mock(return_value=self.checkpoint),
        )
        self.loader = SimpleNamespace(exec_module=Mock())
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(activation, "ROOT", self.source))
        self.stack.enter_context(patch.object(activation, "RECOVERY_SPEC", self.recovery))
        self.spec_factory = self.stack.enter_context(patch.object(
            activation.importlib.util, "spec_from_file_location",
            return_value=SimpleNamespace(loader=self.loader)))
        self.stack.enter_context(patch.object(
            activation.importlib.util, "module_from_spec", return_value=self.installer))
        self.native = self.stack.enter_context(patch.object(
            activation.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="")))
        self.browser = self.stack.enter_context(patch.object(activation.webbrowser, "open"))
        self.output = self.stack.enter_context(patch("sys.stdout", new_callable=io.StringIO))
        self.errors = self.stack.enter_context(patch("sys.stderr", new_callable=io.StringIO))

    def expected_command(self, mode):
        return ["/usr/bin/sudo", "-n", "--", self.runtime, "-I", "-S", "-B",
                str(self.source / "scripts/install_local_accounts.py"), *mode,
                "--source", str(self.source), "--runtime", self.runtime]

    def expected_native_calls(self, mode):
        return [call(["/usr/bin/sudo", "-v"], check=False),
                call(self.expected_command(mode), check=False,
                     stdin=activation.subprocess.DEVNULL, stdout=activation.subprocess.PIPE,
                     stderr=activation.subprocess.STDOUT, text=True, errors="replace")]

    def diagnostic(self):
        files = list((self.source / "work/activation-logs").glob("*.log"))
        self.assertEqual(len(files), 1)
        return files[0], files[0].read_text()

    def prepare_recovery(self):
        self.prefix.mkdir()
        self.recovery.parent.mkdir(parents=True)
        # The privileged installer validates the contents and actual OS state;
        # the frontend only dispatches this fixed, previously prepared path.
        self.recovery.write_text("{}\n")

    def test_normal_install_dispatches_reviewed_runtime_and_source(self):
        self.assertEqual(activation.main(), 0)
        self.installer.installation_plan.assert_called_once_with(
            self.source, Path(activation.sys.executable))
        self.installer.inspect_runtime.assert_not_called()
        self.installer.inspect_source.assert_not_called()
        self.assertEqual(self.native.call_args_list, self.expected_native_calls(["--install"]))
        self.loader.exec_module.assert_called_once_with(self.installer)
        self.assertIn(self.checkpoint["checkpoint_sha256"], self.output.getvalue())

    def test_prepared_recovery_dispatches_only_exact_recovery_path(self):
        self.prepare_recovery()
        self.assertEqual(activation.main(), 0)
        self.installer.installation_plan.assert_not_called()
        self.installer.inspect_runtime.assert_called_once_with(Path(activation.sys.executable))
        self.installer.inspect_source.assert_called_once_with(self.source)
        self.assertEqual(self.native.call_args_list, self.expected_native_calls(
            ["--resume-early", "--recovery-spec", str(self.recovery)]))
        self.assertIn("Stop without changes", self.output.getvalue())

    def test_existing_installation_without_recovery_spec_never_invokes_sudo(self):
        self.prefix.mkdir()
        self.assertEqual(activation.main(), 1)
        self.native.assert_not_called()
        self.browser.assert_not_called()
        self.installer.installation_plan.assert_not_called()
        self.installer.inspect_runtime.assert_not_called()
        self.assertIn("before changing accounts", self.errors.getvalue())

    def test_migrated_partial_installation_directs_to_diagnostics_without_authentication(self):
        self.prepare_recovery()
        (self.prefix / 'runtime.json').write_text('{}')
        self.assertEqual(activation.main(), 1)
        self.native.assert_not_called()
        self.browser.assert_not_called()
        self.assertIn('Diagnose Local Protection.command', self.errors.getvalue())

    def test_existing_completion_report_directs_to_status_without_reinstalling(self):
        self.prefix.mkdir()
        (self.prefix / 'installation-report.json').write_text('{}')
        self.assertEqual(activation.main(), 1)
        self.native.assert_not_called()
        self.browser.assert_not_called()
        self.assertIn('Manage Local Protection.command', self.errors.getvalue())

    def test_failed_source_preflight_never_invokes_sudo(self):
        self.installer.installation_plan.side_effect = ValueError("Source checkpoint differs")
        self.assertEqual(activation.main(), 1)
        self.native.assert_not_called()
        self.browser.assert_not_called()
        self.assertIn("Source checkpoint differs", self.errors.getvalue())

    def test_failed_native_install_preserves_exit_code_and_does_not_open_browser(self):
        self.native.side_effect = [SimpleNamespace(returncode=0),
                                  SimpleNamespace(returncode=40, stdout="Native diagnostic: denied\n")]
        self.assertEqual(activation.main(), 40)
        self.browser.assert_not_called()
        self.assertIn("do not delete accounts or reset trust", self.output.getvalue())
        _, diagnostic = self.diagnostic()
        self.assertIn("Native diagnostic: denied", diagnostic)
        self.assertIn("Installer exit status: 40", diagnostic)
        self.assertIn("Native diagnostic: denied", self.output.getvalue())

    def test_failed_native_recovery_does_not_open_browser(self):
        self.prepare_recovery()
        self.native.side_effect = [SimpleNamespace(returncode=0),
                                  SimpleNamespace(returncode=1, stdout="Recovery stopped\n")]
        self.assertEqual(activation.main(), 1)
        self.browser.assert_not_called()

    def test_successful_native_result_opens_managed_dashboard(self):
        self.assertEqual(activation.main(), 0)
        self.assertEqual(self.native.call_count, 2)
        self.browser.assert_called_once_with("http://127.0.0.1:8765")

    def test_authentication_streams_are_inherited_and_never_logged(self):
        self.native.side_effect = [SimpleNamespace(returncode=0, stdout="AUTHENTICATION-STREAM-SENTINEL"),
                                  SimpleNamespace(returncode=0, stdout="Installer completed\n")]
        self.assertEqual(activation.main(), 0)
        self.assertEqual(self.native.call_args_list[0], call(["/usr/bin/sudo", "-v"], check=False))
        _, diagnostic = self.diagnostic()
        self.assertNotIn("AUTHENTICATION-STREAM-SENTINEL", diagnostic)
        self.assertNotIn("AUTHENTICATION-STREAM-SENTINEL", self.output.getvalue())
        self.assertIn("Installer completed", diagnostic)

    def test_authentication_failure_never_starts_installer_or_browser(self):
        self.native.return_value = SimpleNamespace(returncode=1, stdout="AUTHENTICATION-STREAM-SENTINEL")
        self.assertEqual(activation.main(), 1)
        self.native.assert_called_once_with(["/usr/bin/sudo", "-v"], check=False)
        self.browser.assert_not_called()
        _, diagnostic = self.diagnostic()
        self.assertIn("Installer was not started", diagnostic)
        self.assertNotIn("AUTHENTICATION-STREAM-SENTINEL", diagnostic)

    def test_diagnostic_file_and_directory_are_private(self):
        self.assertEqual(activation.main(), 0)
        path, diagnostic = self.diagnostic()
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(path.stat().st_uid, os.geteuid())
        self.assertIn("Attempt time (UTC):", diagnostic)
        self.assertIn(self.checkpoint["checkpoint_sha256"], diagnostic)
        self.assertIn(str(path), self.output.getvalue())

    def test_linked_work_directory_is_refused_before_authentication(self):
        destination = self.base / "elsewhere"
        destination.mkdir()
        (self.source / "work").symlink_to(destination, target_is_directory=True)
        self.assertEqual(activation.main(), 1)
        self.native.assert_not_called()
        self.browser.assert_not_called()
        self.assertEqual(list(destination.iterdir()), [])

    def test_linked_log_directory_is_refused_before_authentication(self):
        destination = self.base / "elsewhere"
        destination.mkdir()
        (self.source / "work").mkdir()
        (self.source / "work/activation-logs").symlink_to(destination, target_is_directory=True)
        self.assertEqual(activation.main(), 1)
        self.native.assert_not_called()
        self.browser.assert_not_called()
        self.assertEqual(list(destination.iterdir()), [])

    def test_nonprivate_log_directory_is_refused_before_authentication(self):
        directory = self.source / "work/activation-logs"
        directory.mkdir(parents=True)
        directory.chmod(0o755)
        self.assertEqual(activation.main(), 1)
        self.native.assert_not_called()
        self.browser.assert_not_called()
        self.assertEqual(list(directory.iterdir()), [])

    def test_diagnostic_filename_collision_never_overwrites_existing_log(self):
        with patch.object(activation, "datetime") as clock, patch.object(activation.uuid, "uuid4") as identifier:
            clock.now.return_value.strftime.return_value = "20261011T120000Z"
            identifier.return_value.hex = "a" * 32
            path, log = activation.open_diagnostic_log()
            with log:
                log.write("Original diagnostic\n")
            with self.assertRaises(FileExistsError):
                activation.open_diagnostic_log()
        self.assertEqual(path.read_text(), "Original diagnostic\n")

    def test_native_launch_error_is_saved_and_does_not_open_browser(self):
        self.native.side_effect = [SimpleNamespace(returncode=0), OSError("native launch failed")]
        self.assertEqual(activation.main(), 1)
        self.browser.assert_not_called()
        path, diagnostic = self.diagnostic()
        self.assertIn("native launch failed", diagnostic)
        self.assertIn(str(path), self.output.getvalue())


if __name__ == "__main__":
    unittest.main()
