"""Installer safety checks that do not create accounts or require administrator access."""
import importlib.util
from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import plistlib
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("local_installer", ROOT / "scripts/install_local_accounts.py")
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)
OP_SPEC = importlib.util.spec_from_file_location("local_operator", ROOT / "scripts/local_operator.py")
operator = importlib.util.module_from_spec(OP_SPEC)
OP_SPEC.loader.exec_module(operator)


class LocalInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def file(self, name, content=b"example"):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_source_file_symlink_rejected(self):
        original = self.file("original")
        alias = self.root / "alias"
        alias.symlink_to(original)
        with self.assertRaises(ValueError):
            installer.read_regular(alias)

    def test_source_parent_symlink_rejected(self):
        original = self.file("original/item")
        (self.root / "alias").symlink_to(original.parent, target_is_directory=True)
        with self.assertRaises(ValueError):
            installer.read_regular(self.root / "alias/item")

    def test_source_hardlink_rejected(self):
        original = self.file("original")
        os.link(original, self.root / "copy")
        with self.assertRaises(ValueError):
            installer.read_regular(original)

    def test_named_pipe_rejected_without_blocking(self):
        os.mkfifo(self.root / "pipe")
        with self.assertRaises(ValueError):
            installer.read_regular(self.root / "pipe")

    def test_snapshot_roundtrip_preserves_exact_bytes(self):
        self.file("source/raw/ab/example.json", b"\x00\nsource bytes\xff")
        self.file("source/data.sqlite3", b"database bytes")
        before = installer.snapshot_tree(self.root / "source")
        installer.copy_snapshot(before, self.root / "copy", os.getuid(), os.getgid(), 0o750, installer.data_mode)
        self.assertEqual(before, installer.snapshot_tree(self.root / "copy"))
        self.assertEqual((self.root / "copy/data.sqlite3").stat().st_mode & 0o777, 0o640)
        self.assertEqual((self.root / "copy/raw/ab/example.json").stat().st_mode & 0o777, 0o440)

    def test_write_owned_never_overwrites(self):
        path = self.file("protected", b"original")
        with self.assertRaises(FileExistsError):
            installer.write_owned(path, b"new", os.getuid(), os.getgid(), 0o600)
        self.assertEqual(path.read_bytes(), b"original")

    def test_service_ids_do_not_reuse_users_or_groups(self):
        users = [SimpleNamespace(pw_uid=450), SimpleNamespace(pw_uid=452)]
        groups = [SimpleNamespace(gr_gid=450)]
        self.assertEqual(installer.allocate_ids(users, groups), (451, 453, 451))

    def test_id_exhaustion_fails_closed(self):
        users = [SimpleNamespace(pw_uid=n) for n in range(450, 500)]
        with self.assertRaises(ValueError):
            installer.allocate_ids(users, [])

    def test_launchd_uses_collector_and_isolated_python(self):
        result = installer.daemon_definition(Path("/trusted/python3"))
        self.assertEqual(result["UserName"], installer.COLLECTOR)
        self.assertEqual(result["GroupName"], installer.GROUP)
        self.assertEqual(result["ProgramArguments"][1:4], ["-I", "-S", "-B"])
        self.assertEqual(result["ProgramArguments"][-2:], ["--worker", "serve"])
        self.assertNotIn("sudo", json.dumps(result))
        self.assertNotIn("seal", json.dumps(result))
        self.assertEqual(Path(result["StandardOutPath"]).parent, installer.PREFIX / "logs")

    def test_policy_paths_are_fixed_and_roles_distinct(self):
        policy = installer.runtime_config(451, 452, 450)
        self.assertEqual(policy["data_dir"], "/Library/HELTEMES Evidence/data")
        self.assertEqual(policy["key_dir"], "/Library/HELTEMES Evidence/custody/keys")
        self.assertEqual(set(policy), {"version", "data_dir", "trust_dir", "key_dir", "collector_uid", "custodian_uid", "shared_gid"})

    def test_source_app_copy_excludes_private_material_and_bytecode(self):
        self.file("heltemes/local_accounts.py", b"# managed")
        self.file("heltemes/__init__.py", b"# package")
        self.file("heltemes/__pycache__/cached.pyc", b"bytecode")
        self.file("scripts/local_operator.py", b"# operator")
        self.file("scripts/install_local_accounts.py", b"# installer")
        self.file(".heltemes-keys/key/signing_key", b"PRIVATE KEY SECRET")
        self.file("data/settings.json", b"CONTACT SECRET")
        result = installer.app_snapshot(self.root)
        self.assertEqual(len(result), 4)
        self.assertNotIn(b"PRIVATE KEY SECRET", result.values())
        self.assertNotIn(b"CONTACT SECRET", result.values())

    def test_old_release_without_managed_runtime_refused(self):
        self.file("heltemes/__init__.py")
        self.file("scripts/local_operator.py")
        self.file("scripts/install_local_accounts.py")
        with self.assertRaisesRegex(ValueError, "Managed runtime"):
            installer.app_snapshot(self.root)

    def test_non_root_install_refused_before_any_mutation(self):
        with patch.object(installer.sys, "platform", "darwin"), patch.object(installer.os, "geteuid", return_value=501), patch.object(installer, "installation_plan") as plan:
            with self.assertRaisesRegex(ValueError, "administrator"):
                installer.install(self.root)
        plan.assert_not_called()

    def test_nonadministrator_cannot_dispatch_worker(self):
        with patch.object(operator.os, "geteuid", return_value=501):
            with self.assertRaisesRegex(ValueError, "administrator"):
                operator.execute_worker("seal", {})

    def test_operator_permission_probe_does_not_swallow_unrelated_errors(self):
        def missing():
            raise FileNotFoundError(2, "missing")
        def permission():
            raise PermissionError(13, "denied")
        self.assertTrue(operator.denied(permission))
        self.assertFalse(operator.denied(lambda: None))
        with self.assertRaises(FileNotFoundError):
            operator.denied(missing)

    def test_start_uses_independent_custodian_verification(self):
        with patch.object(operator, "execute_worker", return_value={"ok": False}) as worker:
            with self.assertRaisesRegex(ValueError, "Verification failed"):
                operator.start({"custodian_uid": 452})
        worker.assert_called_once_with("verify", {"custodian_uid": 452}, custodian=True)

    def test_listener_identity_pairs_pid_with_its_own_uid(self):
        result = operator.listener_owners("p101\nu501\np102\nu451\n")
        self.assertEqual(result, {101: 501, 102: 451})
        self.assertNotEqual(result[101], 451)

    def test_assigned_uuid_is_read_and_never_changed(self):
        identifier = "FFFFEEEE-DDDD-CCCC-BBBB-AAAA000001C2"
        response = SimpleNamespace(stdout=plistlib.dumps({"dsAttrTypeStandard:GeneratedUID": [identifier]}).decode())
        with patch.object(installer, "run", return_value=response) as command:
            self.assertEqual(installer.assigned_uuid("/Users/_hevidence_collect"), identifier)
        command.assert_called_once_with(["/usr/bin/dscl", "-plist", ".", "-read", "/Users/_hevidence_collect", "GeneratedUID"])

    def test_missing_malformed_and_multiple_assigned_uuid_fail_closed(self):
        for value in ({}, {"dsAttrTypeStandard:GeneratedUID": ["not a uuid"]},
                      {"dsAttrTypeStandard:GeneratedUID": ["00000000-0000-0000-0000-000000000001"] * 2}):
            with self.subTest(value=value), patch.object(installer, "run", return_value=SimpleNamespace(stdout=plistlib.dumps(value).decode())):
                with self.assertRaisesRegex(ValueError, "Cannot safely read"):
                    installer.assigned_uuid("/Users/_hevidence_collect")

    def test_native_failure_diagnostic_is_retained(self):
        native = SimpleNamespace(returncode=40, stderr="DS Error: -14120 (eDSPermissionError)\n", stdout="")
        with patch.object(installer.subprocess, "run", return_value=native):
            with self.assertRaisesRegex(ValueError, r"exit 40.*eDSPermissionError"):
                installer.run(["/usr/bin/dscl", ".", "-create", "/Users/_hevidence_collect"])

    def recovery_fixture(self):
        spec = {"version": 1, "stage": "collector-generateduid-write", "collector_uid": 450,
                "custodian_uid": 451, "shared_gid": 450, "collector_uuid": "11111111-2222-4333-8444-555555555555",
                "group_uuid": "66666666-7777-4888-8999-AAAAAAAAAAAA", "prefix_device": 123,
                "prefix_inode": 456, "archive_id": "3775ad31-8e3c-4ef9-9c95-934e78b1cf3d",
                "sequence": 1, "checkpoint_sha256": "a" * 64}
        user = SimpleNamespace(pw_name=installer.COLLECTOR, pw_uid=450, pw_gid=450,
                               pw_passwd="********", pw_gecos="", pw_dir="/var/empty", pw_shell="/usr/bin/false")
        group = SimpleNamespace(gr_name=installer.GROUP, gr_gid=450, gr_mem=[])
        collector_record = {"RecordName": [installer.COLLECTOR], "UniqueID": ["450"], "PrimaryGroupID": ["450"],
                            "GeneratedUID": [spec["collector_uuid"]], "UserShell": ["/usr/bin/false"],
                            "NFSHomeDirectory": ["/var/empty"], "Password": ["********"],
                            "_writers_UserCertificate": [installer.COLLECTOR]}
        group_record = {"RecordName": [installer.GROUP], "PrimaryGroupID": ["450"],
                        "GeneratedUID": [spec["group_uuid"]], "Password": ["*"]}
        metadata = SimpleNamespace(st_dev=123, st_ino=456, st_uid=0, st_gid=0, st_mode=0o40700)
        state = {"spec": spec, "user": user, "users": [user], "group": group, "groups": [group],
                 "collector": collector_record, "group_record": group_record, "metadata": metadata,
                 "prefix_entries": [], "source": {k: spec[k] for k in ("archive_id", "sequence", "checkpoint_sha256")}}
        return state

    def read_recovery_fixture(self, state):
        prefix = SimpleNamespace(stat=lambda: state["metadata"], iterdir=lambda: iter(state["prefix_entries"]))
        absent = SimpleNamespace(exists=lambda: False, is_symlink=lambda: False)
        with ExitStack() as patches:
            patches.enter_context(patch.object(installer, "plain_path", return_value=prefix))
            patches.enter_context(patch.object(installer, "PLIST", absent))
            patches.enter_context(patch.object(installer, "has_acl", return_value=False))
            patches.enter_context(patch.object(installer.subprocess, "run", return_value=SimpleNamespace(returncode=1)))
            patches.enter_context(patch.object(installer.pwd, "getpwall", return_value=state["users"]))
            patches.enter_context(patch.object(installer.pwd, "getpwnam", return_value=state["user"]))
            patches.enter_context(patch.object(installer.grp, "getgrall", return_value=state["groups"]))
            patches.enter_context(patch.object(installer.grp, "getgrnam", side_effect=lambda name: SimpleNamespace(gr_gid=80) if name == "admin" else state["group"]))
            patches.enter_context(patch.object(installer.os, "getgrouplist", return_value=[450, 12, 61]))
            commands = patches.enter_context(patch.object(installer, "run", return_value=SimpleNamespace(stdout=installer.COLLECTOR + "\n")))
            patches.enter_context(patch.object(installer, "directory_record", side_effect=lambda path: state["collector"] if path.startswith("/Users") else state["group_record"]))
            patches.enter_context(patch.object(installer, "inspect_source", return_value=state["source"]))
            result = installer.recovery_state(state["spec"], self.root)
        for call in commands.call_args_list:
            self.assertNotIn("-create", call.args[0])
        return result

    def test_exact_early_recovery_accepts_os_uuid_and_masked_pwd_without_writing(self):
        state = self.recovery_fixture()
        result = self.read_recovery_fixture(state)
        self.assertEqual(len(result["state_sha256"]), 64)
        self.assertEqual(result["source_checkpoint"]["sequence"], 1)

    def test_exact_early_recovery_accepts_absent_raw_shell_and_home_with_disabled_effective_defaults(self):
        for absent in (("UserShell",), ("NFSHomeDirectory",), ("UserShell", "NFSHomeDirectory")):
            with self.subTest(absent=absent):
                state = self.recovery_fixture()
                for key in absent:
                    state["collector"].pop(key)
                self.assertEqual(self.read_recovery_fixture(state)["source_checkpoint"]["sequence"], 1)

    def test_account_shape_diagnostic_contains_no_raw_attribute_values(self):
        record = {"Password": ["sensitive marker"], "AuthenticationAuthority": ["sensitive authority"],
                  "RealName": ["private name"], "UserShell": ["/unexpected", "/another"]}
        shapes = installer.account_attribute_shapes(record)
        self.assertEqual(shapes["UserShell"], {"present": True, "value_count": 2})
        self.assertEqual(shapes["NFSHomeDirectory"], {"present": False, "value_count": None})
        output = json.dumps(shapes)
        for value in ("sensitive", "private name", "/unexpected", "/another"):
            self.assertNotIn(value, output)

    def test_early_recovery_rejects_explicit_conflicting_or_malformed_shell_and_home(self):
        for key in ("UserShell", "NFSHomeDirectory"):
            for values in (None, [], [""], ["/unexpected"], ["/usr/bin/false", "/bin/sh"], [123]):
                with self.subTest(key=key, values=values):
                    state = self.recovery_fixture()
                    state["collector"][key] = values
                    with self.assertRaises(ValueError):
                        self.read_recovery_fixture(state)

    def test_early_recovery_rejects_inconsistent_effective_identity_or_enabled_defaults(self):
        for field, value in (("pw_name", "foreign"), ("pw_uid", 451), ("pw_gid", 80),
                             ("pw_shell", "/bin/zsh"), ("pw_dir", "/Users/foreign")):
            with self.subTest(field=field):
                state = self.recovery_fixture()
                state["collector"].pop("UserShell")
                state["collector"].pop("NFSHomeDirectory")
                setattr(state["user"], field, value)
                with self.assertRaises(ValueError):
                    self.read_recovery_fixture(state)

    def test_recovery_refuses_nonempty_prefix_wrong_inode_and_uuid(self):
        for mutation in (lambda x: x["prefix_entries"].append("unreviewed-data"),
                         lambda x: setattr(x["metadata"], "st_ino", 999),
                         lambda x: x["collector"].update(GeneratedUID=["00000000-0000-0000-0000-000000000001"]),
                         lambda x: x["group_record"].update(GeneratedUID=["00000000-0000-0000-0000-000000000001"])):
            with self.subTest(mutation=mutation):
                state = self.recovery_fixture()
                mutation(state)
                with self.assertRaises(ValueError):
                    self.read_recovery_fixture(state)

    def test_recovery_refuses_foreign_members_custodian_or_identity_alias(self):
        for mutation in (lambda x: x["group_record"].update(GroupMembership=["foreign"]),
                         lambda x: x["users"].append(SimpleNamespace(pw_name=installer.CUSTODIAN, pw_uid=451, pw_gid=450)),
                         lambda x: x["users"].append(SimpleNamespace(pw_name="alias", pw_uid=450, pw_gid=999)),
                         lambda x: x["users"].append(SimpleNamespace(pw_name="foreign", pw_uid=999, pw_gid=450))):
            with self.subTest(mutation=mutation):
                state = self.recovery_fixture()
                mutation(state)
                with self.assertRaises(ValueError):
                    self.read_recovery_fixture(state)

    def test_recovery_refuses_existing_authentication_material_or_changed_checkpoint(self):
        for key, values in (("AuthenticationAuthority", [";ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>"]),
                            ("ShadowHashData", [b"credential"]), ("UserCertificate", [b"certificate"]),
                            ("AltSecurityIdentities", ["external identity"]), ("PasswordServerList", ["server"]),
                            ("Password", ["unexpected-password-material"]), ("RecordName", [installer.COLLECTOR, "alias"])):
            with self.subTest(key=key):
                state = self.recovery_fixture()
                state["collector"][key] = values
                with self.assertRaises(ValueError):
                    self.read_recovery_fixture(state)
        state = self.recovery_fixture()
        state["source"]["sequence"] = 2
        with self.assertRaisesRegex(ValueError, "Source checkpoint changed"):
            self.read_recovery_fixture(state)

    def test_recovery_state_fingerprint_detects_other_attribute_changes(self):
        state = self.recovery_fixture()
        before = self.read_recovery_fixture(state)
        state["collector"]["AppleMetaNodeLocation"] = ["/Local/Default"]
        after = self.read_recovery_fixture(state)
        self.assertNotEqual(before["state_sha256"], after["state_sha256"])

    def test_recovery_spec_rejects_boolean_version_and_bad_types(self):
        spec = self.recovery_fixture()["spec"]
        for key, value in (("version", True), ("collector_uuid", 42), ("checkpoint_sha256", None), ("collector_uid", True)):
            with self.subTest(key=key):
                changed = copy.deepcopy(spec)
                changed[key] = value
                path = self.file("spec.json", json.dumps(changed).encode())
                with self.assertRaises(ValueError):
                    installer.load_recovery_spec(path)

    def test_final_disabled_account_check_requires_root_directory_locked_marker(self):
        state = self.recovery_fixture()
        state["collector"]["RealName"] = ["HELTEMES Evidence Collector"]
        with patch.object(installer.pwd, "getpwnam", return_value=state["user"]), patch.object(installer.os, "getgrouplist", return_value=[450]), patch.object(installer.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=80)):
            with self.assertRaisesRegex(ValueError, "locked password marker"):
                installer.validate_disabled_record(state["collector"], installer.COLLECTOR, 450, 450)
            state["collector"]["Password"] = ["*"]
            installer.validate_disabled_record(state["collector"], installer.COLLECTOR, 450, 450)

    def test_final_disabled_account_check_requires_explicit_raw_shell_and_home(self):
        for key in ("UserShell", "NFSHomeDirectory"):
            with self.subTest(key=key):
                state = self.recovery_fixture()
                state["collector"]["RealName"] = ["HELTEMES Evidence Collector"]
                state["collector"]["Password"] = ["*"]
                state["collector"].pop(key)
                with patch.object(installer.pwd, "getpwnam", return_value=state["user"]), patch.object(installer.os, "getgrouplist", return_value=[450]), patch.object(installer.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=80)):
                    with self.assertRaisesRegex(ValueError, "missing required attribute: " + key):
                        installer.validate_disabled_record(state["collector"], installer.COLLECTOR, 450, 450)

    def test_account_resume_preserves_uuids_and_journals_before_mutating(self):
        state = self.recovery_fixture()
        state["collector"].pop("UserShell")
        state["collector"].pop("NFSHomeDirectory")
        records = {"/Users/" + installer.COLLECTOR: state["collector"], "/Groups/" + installer.GROUP: state["group_record"]}
        events = []
        custodian_uuid = "00000000-0000-0000-0000-000000000003"
        def execute(arguments):
            events.append(("command", copy.deepcopy(arguments)))
            self.assertEqual(arguments[:3], ["/usr/bin/dscl", ".", "-create"])
            path = arguments[3]
            if len(arguments) == 4:
                self.assertNotIn(path, records)
                records[path] = {"RecordName": [installer.CUSTODIAN], "GeneratedUID": [custodian_uuid],
                                 "Password": ["********"], "UserShell": ["/usr/bin/false"], "NFSHomeDirectory": ["/var/empty"]}
            else:
                self.assertNotIn(arguments[4], {"GeneratedUID", "AuthenticationAuthority"})
                records[path][arguments[4]] = arguments[5:]
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        def account(name):
            entry = records["/Users/" + name]
            return SimpleNamespace(pw_name=name, pw_uid=int(entry["UniqueID"][0]), pw_gid=int(entry["PrimaryGroupID"][0]),
                                   pw_shell=entry["UserShell"][0], pw_dir=entry["NFSHomeDirectory"][0], pw_passwd="********")
        with patch.object(installer, "run", side_effect=execute), patch.object(installer, "directory_record", side_effect=lambda path: copy.deepcopy(records[path])), patch.object(installer, "assigned_uuid", side_effect=lambda path: records[path]["GeneratedUID"][0]), patch.object(installer, "journal", side_effect=lambda path, entry: events.append(("journal", copy.deepcopy(entry)))), patch.object(installer.pwd, "getpwnam", side_effect=account), patch.object(installer.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=80)), patch.object(installer.os, "getgrouplist", return_value=[450, 12, 61]):
            installer.create_accounts(450, 451, 450, existing_collector=True)
        self.assertEqual(records["/Users/" + installer.COLLECTOR]["GeneratedUID"], [state["spec"]["collector_uuid"]])
        self.assertEqual(records["/Groups/" + installer.GROUP]["GeneratedUID"], [state["spec"]["group_uuid"]])
        self.assertEqual(records["/Users/" + installer.COLLECTOR]["Password"], ["*"])
        self.assertEqual(records["/Users/" + installer.CUSTODIAN]["Password"], ["*"])
        self.assertEqual(records["/Users/" + installer.COLLECTOR]["UserShell"], ["/usr/bin/false"])
        self.assertEqual(records["/Users/" + installer.COLLECTOR]["NFSHomeDirectory"], ["/var/empty"])
        for index, (kind, value) in enumerate(events):
            if kind == "command":
                self.assertEqual(events[index - 1][0], "journal")
                self.assertEqual(events[index - 1][1]["next_command"], value)


if __name__ == "__main__":
    unittest.main()
