import importlib.util
from contextlib import contextmanager
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("startup_diagnostic", ROOT / "scripts/diagnose_local_startup.py")
diagnostics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diagnostics)


class StartupDiagnosticTests(unittest.TestCase):
    def test_non_root_execution_refused(self):
        with patch.object(diagnostics.sys, "platform", "darwin"), patch.object(diagnostics.os, "getuid", return_value=501):
            with self.assertRaisesRegex(ValueError, "administrator"):
                diagnostics.diagnostic()

    def test_metadata_refuses_links_foreign_owner_and_unexpected_mode(self):
        for changed in ({"st_uid": 450}, {"st_nlink": 2}, {"st_mode": 0o100666}, {"st_mode": 0o120640}):
            values = {"st_uid": 0, "st_gid": 450, "st_nlink": 1, "st_mode": 0o100640}
            values.update(changed)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                diagnostics.validate_metadata(SimpleNamespace(**values), gid=450, modes={0o640, 0o660})

    def test_root_owned_log_modes_accepted_but_parent_write_refused(self):
        for mode in (0o640, 0o660):
            diagnostics.validate_metadata(SimpleNamespace(st_uid=0, st_gid=450, st_nlink=1, st_mode=0o100000 | mode), gid=450, modes={0o640, 0o660})
        with self.assertRaisesRegex(ValueError, "parent"):
            diagnostics.validate_metadata(SimpleNamespace(st_uid=0, st_gid=450, st_mode=0o40770), directory=True)

    def test_log_metadata_and_tail_come_from_one_validated_descriptor(self):
        @contextmanager
        def pinned(*args, **kwargs):
            yield 89
        account = {"uid": 450, "gid": 450, "groups": [450, 12]}
        for mode, allowed in ((0o100640, False), (0o100660, True)):
            metadata = SimpleNamespace(st_uid=0, st_gid=450, st_mode=mode, st_size=0)
            with patch.object(diagnostics, "fixed_file", pinned), patch.object(diagnostics.os, "fstat", return_value=metadata) as information, patch.object(diagnostics.os, "read", return_value=b"") as reader:
                result = diagnostics.log_snapshot("collector.stdout.log", {"shared_gid": 450}, account)
            information.assert_called_once_with(89)
            reader.assert_called_once_with(89, 16384)
            self.assertEqual(result["mode"], format(mode & 0o7777, "04o"))
            self.assertEqual(result["size_bytes"], 0)
            self.assertEqual(result["collector_append_allowed_by_mode"], allowed)
        with self.assertRaises(ValueError):
            diagnostics.log_snapshot("runtime.json", {}, None)

    def test_journal_summary_omits_commands_and_errors(self):
        result = diagnostics.journal_summary(json.dumps({"stage": "accounts_verified_before_migration", "completed_commands": [["private-value"]], "last_error": "private-error", "account_uuids": {"secret": "ignored"}}))
        self.assertEqual(result, {"stage": "accounts_verified_before_migration", "completed_command_count": 1})
        self.assertNotIn("private", json.dumps(result))

    def test_redaction_omits_contacts_and_private_key_blocks(self):
        text = "email@example.com\n-----BEGIN OPENSSH PRIVATE KEY-----\nsecret bytes\n-----END OPENSSH PRIVATE KEY-----\nstartup error"
        result = diagnostics.redact(text)
        self.assertNotIn("email@example.com", result)
        self.assertNotIn("secret bytes", result)
        self.assertIn("startup error", result)

    def test_configuration_refuses_path_redirect_and_shared_identity(self):
        config = {"version": 1, "data_dir": str(diagnostics.PREFIX / "data"), "trust_dir": str(diagnostics.PREFIX / "custody/trust"),
                  "key_dir": str(diagnostics.PREFIX / "custody/keys"), "collector_uid": 450, "custodian_uid": 451, "shared_gid": 450}
        self.assertEqual(diagnostics.expected_configuration(config), config)
        for changes in ({"key_dir": "/private/secret"}, {"custodian_uid": 450}, {"version": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                diagnostics.expected_configuration({**config, **changes})

    def test_command_output_and_time_are_bounded(self):
        result = diagnostics.bounded_command([os.sys.executable, "-I", "-S", "-c", "print('x' * 100000)"], limit=1000)
        self.assertEqual(len(result["output"]), 1000)
        self.assertEqual(result["limited"], "output_limit")
        timed = diagnostics.bounded_command([os.sys.executable, "-I", "-S", "-c", "import time;time.sleep(2)"], timeout=0.05)
        self.assertEqual(timed["limited"], "time_limit")

    def test_fixed_log_predicate_and_cli_have_no_arbitrary_arguments(self):
        self.assertIn('process == "launchd"', diagnostics.LOG_PREDICATE)
        self.assertIn(diagnostics.LABEL, diagnostics.LOG_PREDICATE)
        with self.assertRaises(SystemExit):
            diagnostics.main(["--path", "/private/secret"])


if __name__ == "__main__":
    unittest.main()
