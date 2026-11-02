"""Exact public approval installation; no real keys, sudo, or service changes."""
import base64
from contextlib import contextmanager, ExitStack, redirect_stdout
import importlib.util
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

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("key_recovery_authorization", ROOT / "scripts/authorize_key_recovery.py")
approval = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(approval)


def key(byte):
    return "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes([byte]) * 32).decode()


def request():
    old = {"format": "heltemes-trust-anchor", "version": 1, "archive_id": "3775ad31-8e3c-4ef9-9c95-934e78b1cf3d",
           "public_key": key(1), "key_fingerprint": approval.key_fingerprint(key(1)), "sequence": 2,
           "checkpoint_sha256": "a" * 64, "checkpoint_at": "2026-01-01T00:00:00Z"}
    return {"format": "heltemes-key-recovery-authorization", "version": 1, "action": "replace_signing_key",
            "transition_id": "11111111-2222-4333-8444-555555555555", "archive_id": old["archive_id"],
            "old_receipt": old, "old_receipt_sha256": approval.digest(approval.canonical(old)),
            "candidate_public_key": key(2), "candidate_key_fingerprint": approval.key_fingerprint(key(2))}


class RecoveryAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.prefix = self.base / "managed"
        self.prefix.mkdir()
        self.request = request()
        self.raw = approval.canonical(self.request)
        self.sha = approval.digest(self.raw)
        self.path = self.base / "request.json"
        self.path.write_bytes(self.raw)

    @contextmanager
    def mocked_native(self, receipt=None):
        # Root ownership and macOS operations are separately checked; these
        # fixtures exercise only safe files in an isolated temporary directory.
        with ExitStack() as stack:
            stack.enter_context(patch.object(approval, "PREFIX", self.prefix))
            stack.enter_context(patch.object(approval, "AUTHORIZATIONS", self.prefix / "recovery-authorizations"))
            stack.enter_context(patch.object(approval, "installed_preflight"))
            stack.enter_context(patch.object(approval, "protected_metadata"))
            stack.enter_context(patch.object(approval, "reject_acl"))
            stack.enter_context(patch.object(approval.os, "fchown"))
            stack.enter_context(patch.object(approval.os, "chown"))
            current = stack.enter_context(patch.object(approval, "current_receipt", return_value=receipt or self.request["old_receipt"]))
            yield current

    def test_canonical_request_and_exact_digest_required(self):
        self.assertEqual(approval.validate_request(self.raw, self.sha), self.request)
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            approval.validate_request(self.raw, "0" * 64)
        raw = json.dumps(self.request, indent=2).encode()
        with self.assertRaisesRegex(ValueError, "canonical"):
            approval.validate_request(raw, approval.digest(raw))

    def test_wrong_key_receipt_identity_action_and_boolean_version_rejected(self):
        changes = (("candidate_key_fingerprint", self.request["old_receipt"]["key_fingerprint"]),
                   ("candidate_public_key", key(1)), ("archive_id", "99999999-2222-4333-8444-555555555555"),
                   ("old_receipt_sha256", "0" * 64), ("version", True), ("action", "reset_trust"),
                   ("transition_id", "../overwrite"))
        for name, value in changes:
            changed = {**self.request, name: value}
            raw = approval.canonical(changed)
            with self.subTest(name=name), self.assertRaises(ValueError):
                approval.validate_request(raw, approval.digest(raw))

    def test_duplicate_fields_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            approval.parse_json(b'{"version":1,"version":1}')

    def test_linked_request_and_symlink_parent_rejected(self):
        os.link(self.path, self.base / "hardlink.json")
        with self.assertRaises(ValueError):
            approval.read_regular(self.path)
        (self.base / "hardlink.json").unlink()
        alias = self.base / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(OSError):
            approval.read_regular(alias / self.path.name)

    def test_fifo_refused_without_waiting(self):
        pipe = self.base / "pipe"
        os.mkfifo(pipe)
        with self.assertRaises(ValueError):
            approval.read_regular(pipe)

    def test_nonadministrator_preflight_rejected(self):
        with patch.object(approval.os, "getuid", return_value=501), self.assertRaisesRegex(ValueError, "native approval"):
            approval.installed_preflight()

    def test_protected_metadata_rejects_writers_and_nonroot_owner(self):
        info = {"st_uid": 0, "st_gid": 0, "st_mode": 0o100444, "st_nlink": 1}
        approval.protected_metadata(SimpleNamespace(**info), mode=0o444)
        for change in ({"st_uid": 501}, {"st_gid": 450}, {"st_mode": 0o100664}, {"st_nlink": 2}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                approval.protected_metadata(SimpleNamespace(**{**info, **change}), mode=0o444)

    def test_exact_current_head_installs_only_public_document_and_digest(self):
        with self.mocked_native() as current:
            result = approval.install_authorization(self.path, self.sha)
        target = Path(result["authorization"])
        self.assertEqual(target.read_bytes(), self.raw)
        self.assertEqual(target.with_suffix(".json.sha256").read_text(), self.sha + "\n")
        self.assertEqual(target.stat().st_mode & 0o777, 0o444)
        self.assertEqual(target.parent.stat().st_mode & 0o777, 0o755)
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertFalse(result["transition_started"])
        self.assertEqual(len(list(target.parent.iterdir())), 2)
        current.assert_called_once_with()

    def test_stale_head_refused_before_approval_publication(self):
        with self.mocked_native({**self.request["old_receipt"], "sequence": 3}), self.assertRaisesRegex(ValueError, "currently accepted"):
            approval.install_authorization(self.path, self.sha)
        self.assertFalse(list((self.prefix / "recovery-authorizations").iterdir()))

    def test_complete_retry_is_idempotent_even_after_archive_advances(self):
        with self.mocked_native():
            original = approval.install_authorization(self.path, self.sha)
        target = Path(original["authorization"])
        inode = target.stat().st_ino
        with self.mocked_native({**self.request["old_receipt"], "sequence": 3}) as current:
            retried = approval.install_authorization(self.path, self.sha)
        current.assert_not_called()
        self.assertTrue(retried["already_installed"])
        self.assertEqual(target.stat().st_ino, inode)

    def test_conflicting_existing_approval_is_never_replaced(self):
        with self.mocked_native():
            result = approval.install_authorization(self.path, self.sha)
        target = Path(result["authorization"])
        target.chmod(0o600)
        target.write_bytes(b"existing conflicting content")
        target.chmod(0o444)
        with self.mocked_native(), self.assertRaisesRegex(ValueError, "conflicts"):
            approval.install_authorization(self.path, self.sha)
        self.assertEqual(target.read_bytes(), b"existing conflicting content")

    def test_native_receipt_action_never_requests_key_or_signing(self):
        result = SimpleNamespace(returncode=0, stdout=approval.canonical(self.request["old_receipt"]))
        with patch.object(approval.subprocess, "run", return_value=result) as native:
            self.assertEqual(approval.current_receipt(), self.request["old_receipt"])
        args = native.call_args.args[0]
        self.assertEqual(args[-1], "receipt")
        self.assertEqual(args[1:4], ["-I", "-S", "-B"])
        self.assertNotIn("seal", args)

    def test_frontend_rejects_changed_request_before_authentication(self):
        with patch.object(approval.subprocess, "run") as native, self.assertRaises(ValueError):
            approval.frontend(self.path, "0" * 64)
        native.assert_not_called()

    def test_frontend_authenticates_once_then_pins_helper_and_request(self):
        with patch.object(approval.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as native, redirect_stdout(io.StringIO()):
            self.assertEqual(approval.frontend(self.path, self.sha), 0)
        calls = [call.args[0] for call in native.call_args_list]
        self.assertEqual(calls[0], ["/usr/bin/sudo", "-v"])
        self.assertEqual(calls[1][:3], ["/usr/bin/sudo", "-n", "--"])
        self.assertIn(approval.BOOTSTRAP, calls[1])
        self.assertEqual(calls[1][-3:], [str(self.path), "--expected-sha256", self.sha])
        self.assertEqual(calls[1][10], approval.digest(approval.read_regular(ROOT / "scripts/authorize_key_recovery.py", maximum=approval.MAX_HELPER)))

    def test_exact_interrupted_publication_is_completed_on_retry(self):
        with self.mocked_native():
            result = approval.install_authorization(self.path, self.sha)
        target = Path(result["authorization"])
        pending = target.parent / (".pending-" + "b" * 32)
        os.link(target, pending)
        with self.mocked_native() as current:
            retried = approval.install_authorization(self.path, self.sha)
        self.assertTrue(retried["already_installed"])
        self.assertEqual(target.stat().st_nlink, 1)
        self.assertFalse(pending.exists())
        current.assert_not_called()

    def test_unknown_link_is_not_removed_during_retry(self):
        with self.mocked_native():
            result = approval.install_authorization(self.path, self.sha)
        target = Path(result["authorization"])
        extra = target.parent / "unknown-link"
        os.link(target, extra)
        with self.mocked_native(), self.assertRaisesRegex(ValueError, "unknown or ambiguous"):
            approval.install_authorization(self.path, self.sha)
        self.assertTrue(extra.exists())
        self.assertEqual(target.stat().st_nlink, 2)

    def test_bootstrap_executes_only_the_exact_reviewed_bytes(self):
        helper = self.base / "helper.py"
        helper.write_bytes(b"print('reviewed helper executed')\n")
        expected = approval.digest(helper.read_bytes())
        command = [sys.executable, "-I", "-S", "-B", "-c", approval.BOOTSTRAP, str(helper), expected]
        accepted = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(accepted.returncode, 0)
        self.assertEqual(accepted.stdout.strip(), "reviewed helper executed")
        helper.write_bytes(b"print('changed helper executed')\n")
        refused = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(refused.stdout, "")
        self.assertIn("changed after review", refused.stderr)


if __name__ == "__main__":
    unittest.main()
