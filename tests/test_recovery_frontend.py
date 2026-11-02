"""Recovery frontend tests: no administrator authentication or managed actions run."""
from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch
import uuid

from scripts import run_recovery_workflow as flow


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


class RecoveryFrontendTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.head = {"archive_id": str(uuid.uuid4()), "sequence": 1, "checkpoint_sha256": "a" * 64}
        self.snapshot = {"schema": {}, "tables": {}}
        self.prepared = {"ok": True, "request_id": str(uuid.uuid4()), "was_running": True,
                         "head": self.head, "snapshot": self.snapshot,
                         "snapshot_sha256": hashlib.sha256(encoded(self.snapshot)).hexdigest(),
                         "verification": {"ok": True}}
        self.approval = {"version": 1, **{key: self.prepared[key] for key in
                         ("request_id", "was_running", "head", "snapshot_sha256")},
                         "approved_accessions": ["0000320193-26-000001"]}
        self.new_head = {**self.head, "sequence": 2, "checkpoint_sha256": "b" * 64}
        self.backup = {"name": "heltemes-20261019T120000Z-12345678.zip", "bytes": 5,
                       "sha256": hashlib.sha256(b"hello").hexdigest()}
        self.finished = {"ok": True, "sealed": True, "request_id": self.prepared["request_id"],
                         "was_running": True, "snapshot_sha256": self.prepared["snapshot_sha256"],
                         "head": self.new_head, "receipt": self.new_head, "backup": self.backup}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(flow, "ROOT", self.root))
        self.stack.enter_context(patch.object(flow.signal, "signal", return_value="previous"))
        self.output = self.stack.enter_context(patch("sys.stdout", new_callable=io.StringIO))
        self.errors = self.stack.enter_context(patch("sys.stderr", new_callable=io.StringIO))
        self.browser = self.stack.enter_context(patch("webbrowser.open"))

    def folder(self):
        folders = list((self.root / "work").glob("managed-recovery-*"))
        self.assertEqual(len(folders), 1)
        return folders[0]

    def native_mock(self, finish=None):
        values = {"prepare": self.prepared, "finish": finish or self.finished,
                  "resume": {"ok": True, "resumed": True, "head": self.new_head}}
        return Mock(side_effect=lambda action, payload=None, **kwargs: (values[action], encoded(values[action])))

    def test_authentication_uncaptured_and_fixed_json_request_has_no_user_path(self):
        with patch.object(flow.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as native:
            flow.authenticate()
            native.assert_called_once_with(["/usr/bin/sudo", "-v"], check=False)
        reply = SimpleNamespace(returncode=0, stdout=json.dumps(self.finished), stderr="")
        with patch.object(flow.subprocess, "run", return_value=reply) as native:
            flow.native_json("finish", self.approval)
            args, options = native.call_args
            self.assertEqual(args[0], flow.command("finish"))
            self.assertIn("-n", args[0])
            self.assertEqual(json.loads(options["input"]), self.approval)
            self.assertNotIn(str(self.root / "work"), options["input"])
            self.assertEqual(options["stderr"], subprocess.PIPE)
            self.assertEqual(options["stdout"], subprocess.PIPE)
            self.assertGreaterEqual(options["timeout"], 600)
        with patch.object(flow.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout='{"ok":true}', stderr="")) as native:
            flow.native_json("prepare")
            self.assertEqual(native.call_args.kwargs["stdin"], subprocess.DEVNULL)
            self.assertNotIn("input", native.call_args.kwargs)

    def test_private_unique_folder_and_exclusive_files(self):
        first, second = flow.create_run_folder(), flow.create_run_folder()
        self.assertNotEqual(first, second)
        self.assertEqual(stat.S_IMODE(first.stat().st_mode), 0o700)
        path = flow.write_private(first / "receipt.json", "{}")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            flow.write_private(path, "replacement")
        self.assertEqual(path.read_text(), "{}")

    def test_approval_requires_exact_request_and_private_unlinked_file(self):
        folder = flow.create_run_folder()
        path = flow.write_private(folder / "approval.json", encoded(self.approval))
        self.assertEqual(flow.wait_for_approval(folder, self.prepared), self.approval)
        path.chmod(0o644)
        with self.assertRaises(flow.VerificationFailure):
            flow.read_approval(path)
        path.chmod(0o600)
        path.unlink()
        flow.write_private(path, encoded({**self.approval, "snapshot_sha256": "c" * 64}))
        with self.assertRaisesRegex(flow.VerificationFailure, "exact reviewed"):
            flow.wait_for_approval(folder, self.prepared)
        path.unlink()
        elsewhere = flow.write_private(folder / "elsewhere", encoded(self.approval))
        path.symlink_to(elsewhere)
        with self.assertRaises(OSError):
            flow.read_approval(path)

    def test_prepare_digest_mismatch_rejected_before_review(self):
        flow.check_prepare(self.prepared)
        with self.assertRaisesRegex(flow.VerificationFailure, "fingerprint"):
            flow.check_prepare({**self.prepared, "snapshot_sha256": "c" * 64})

    def test_bounded_approval_timeout(self):
        folder = flow.create_run_folder()
        with patch.object(flow.time, "monotonic", side_effect=[0, flow.APPROVAL_TIMEOUT + 1]):
            with self.assertRaises(TimeoutError):
                flow.wait_for_approval(folder, self.prepared)

    def test_full_sequence_saves_separate_receipt_and_reports_local_only_success(self):
        native = self.native_mock()
        def export(folder, metadata):
            return flow.write_private(folder / "evidence-backup.zip", b"hello")
        with patch.object(flow, "authenticate"), patch.object(flow, "native_json", native), \
                patch.object(flow, "wait_for_approval", return_value=self.approval), \
                patch.object(flow, "export_backup", side_effect=export), \
                patch.object(flow, "restore_and_verify", return_value={"ok": True, "checked": 6}):
            self.assertEqual(flow.main(), 0)
        self.assertEqual([item.args[0] for item in native.call_args_list], ["prepare", "finish", "resume"])
        folder = self.folder()
        self.assertEqual(json.loads((folder / "review-request.json").read_text()), self.prepared)
        self.assertEqual(json.loads((folder / "public-receipt.json").read_text()), self.new_head)
        result = json.loads((folder / "workflow-result.json").read_text())
        self.assertFalse(result["off_device_copy_verified"])
        self.assertFalse(result["aws_deployed"])
        self.assertIn("dashboard is stopped", (folder / "workflow.log").read_text())
        self.assertIn("COMPLETE locally", (folder / "workflow.log").read_text())
        self.browser.assert_not_called()

    def test_timeout_resumes_only_against_prepared_snapshot(self):
        native = self.native_mock()
        with patch.object(flow, "authenticate"), patch.object(flow, "native_json", native), \
                patch.object(flow, "wait_for_approval", side_effect=TimeoutError("review deadline")):
            self.assertEqual(flow.main(), 1)
        self.assertEqual([item.args[0] for item in native.call_args_list], ["prepare", "resume"])
        self.assertEqual(native.call_args.args[1], flow.resume_payload(self.prepared))
        self.assertFalse((self.folder() / "workflow-result.json").exists())

    def test_auth_failure_after_prepare_attempts_guarded_resume_without_sealing(self):
        native = self.native_mock()
        with patch.object(flow, "authenticate", side_effect=[None, flow.AuthenticationFailure("cancelled")]), \
                patch.object(flow, "native_json", native), patch.object(flow, "wait_for_approval", return_value=self.approval):
            self.assertEqual(flow.main(), 1)
        self.assertEqual([item.args[0] for item in native.call_args_list], ["prepare", "resume"])

    def test_restore_failure_does_not_resume_or_claim_complete(self):
        native = self.native_mock()
        with patch.object(flow, "authenticate"), patch.object(flow, "native_json", native), \
                patch.object(flow, "wait_for_approval", return_value=self.approval), \
                patch.object(flow, "export_backup", return_value=self.root / "unused.zip"), \
                patch.object(flow, "restore_and_verify", side_effect=flow.VerificationFailure("mismatch")):
            self.assertEqual(flow.main(), 1)
        self.assertEqual([item.args[0] for item in native.call_args_list], ["prepare", "finish"])
        self.assertIn("checkpoint is accepted", (self.folder() / "workflow.log").read_text())
        self.assertFalse((self.folder() / "workflow-result.json").exists())

    def test_invalid_approval_attempts_only_guarded_resume(self):
        native = self.native_mock()
        with patch.object(flow, "authenticate"), patch.object(flow, "native_json", native), \
                patch.object(flow, "wait_for_approval", side_effect=flow.VerificationFailure("approval mismatch")):
            self.assertEqual(flow.main(), 1)
        self.assertEqual([item.args[0] for item in native.call_args_list], ["prepare", "resume"])

    def test_native_partial_seal_result_saved_before_failure(self):
        folder = flow.create_run_folder()
        partial = {**self.finished, "ok": False, "error": "backup failed"}
        reply = SimpleNamespace(returncode=1, stdout=json.dumps(partial), stderr="")
        with patch.object(flow.subprocess, "run", return_value=reply):
            with self.assertRaises(flow.VerificationFailure) as failure:
                flow.native_json("finish", self.approval, record_dir=folder)
        self.assertEqual(json.loads((folder / "finish-result.json").read_text()), partial)
        self.assertTrue(failure.exception.native_response["sealed"])

    def test_post_seal_failure_retains_receipt_and_does_not_resume(self):
        partial = {**self.finished, "ok": False, "error": "backup failed"}
        failure = flow.VerificationFailure("backup failed")
        failure.native_action, failure.native_response = "finish", partial
        native = Mock(side_effect=[(self.prepared, encoded(self.prepared)), failure])
        with patch.object(flow, "authenticate"), patch.object(flow, "native_json", native), \
                patch.object(flow, "wait_for_approval", return_value=self.approval):
            self.assertEqual(flow.main(), 1)
        self.assertEqual([item.args[0] for item in native.call_args_list], ["prepare", "finish"])
        folder = self.folder()
        self.assertEqual(json.loads((folder / "public-receipt.json").read_text()), self.new_head)
        self.assertIn("checkpoint 2 already accepted", (folder / "workflow.log").read_text())

    def test_interruption_before_sealing_attempts_guarded_resume(self):
        native = self.native_mock()
        with patch.object(flow, "authenticate"), patch.object(flow, "native_json", native), \
                patch.object(flow, "wait_for_approval", side_effect=KeyboardInterrupt()):
            self.assertEqual(flow.main(), 130)
        self.assertEqual([item.args[0] for item in native.call_args_list], ["prepare", "resume"])
        self.assertIn("INTERRUPTED", (self.folder() / "workflow.log").read_text())

    def test_export_stream_checks_bytes_and_no_overwrite_without_native_commands(self):
        folder = flow.create_run_folder()
        real_popen = subprocess.Popen
        def substitute(command, **options):
            self.assertEqual(command, flow.command("export"))
            return real_popen([sys.executable, "-c", "import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'hello')"], **options)
        with patch.object(flow.subprocess, "Popen", side_effect=substitute):
            result = flow.export_backup(folder, self.backup)
            self.assertEqual(result.read_bytes(), b"hello")
            self.assertEqual(stat.S_IMODE(result.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                flow.export_backup(folder, self.backup)
        self.assertEqual(result.read_bytes(), b"hello")

    def test_export_rejects_mismatch_and_oversize_without_publishing(self):
        folder = flow.create_run_folder()
        real_popen = subprocess.Popen
        def substitute(command, **options):
            return real_popen([sys.executable, "-c", "import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'wrong!')"], **options)
        with patch.object(flow.subprocess, "Popen", side_effect=substitute):
            with self.assertRaises(flow.VerificationFailure):
                flow.export_backup(folder, self.backup)
        self.assertFalse((folder / "evidence-backup.zip").exists())
        self.assertFalse((folder / ".backup-download").exists())

    def test_real_verifier_restore_uses_receipt_and_has_no_signing_key(self):
        from heltemes.core import Repository
        from heltemes.protection import initialize_protection, export_receipt, default_key_dir
        source = self.root / "source-data"
        repository = Repository(source)
        repository.seed_demo()
        sealed = initialize_protection(source)
        folder = flow.create_run_folder()
        receipt = folder / "receipt.json"
        export_receipt(source, receipt)
        backup = folder / "source.zip"
        repository.backup(backup)
        expected = {key: sealed[key] for key in self.head}
        result = flow.restore_and_verify(folder, backup, receipt, expected)
        self.assertTrue(result["ok"])
        self.assertFalse(default_key_dir(folder / "restored-verifier").exists())


if __name__ == "__main__":
    unittest.main()
