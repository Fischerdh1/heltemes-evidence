#!/usr/bin/env python3
"""Repair only reviewed collector log permissions, then prove local activation."""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import pwd
import signal
import socket
import stat
import sys
import uuid


def sibling(name):
    path = Path(__file__).resolve().parent / (name + ".py")
    specification = importlib.util.spec_from_file_location("repair_" + name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


diagnostics = sibling("diagnose_local_startup")
installer = sibling("install_local_accounts")
PREFIX = diagnostics.PREFIX
SPEC_PATH = Path(__file__).resolve().parents[1] / "work/local-startup-repair.json"
LOG_NAMES = ("collector.stdout.log", "collector.stderr.log")
CHECKPOINT = {"archive_id": "3775ad31-8e3c-4ef9-9c95-934e78b1cf3d", "sequence": 1,
              "checkpoint_sha256": "90a62432678481d201c6b850473cc515478cd16718575ba88e6810a0f4cecc76"}
IDENTITIES = {"collector_uid": 450, "custodian_uid": 451, "shared_gid": 450}


def require_native_root():
    if (sys.platform != "darwin" or os.getuid() != 0 or os.geteuid() != 0
            or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode):
        raise ValueError("Use the native Mac administrator prompt with the fixed Python runtime and -I -S -B.")


def load_spec():
    raw = installer.read_regular(SPEC_PATH)
    if len(raw) > 128 * 1024:
        raise ValueError("Repair binding exceeds its size limit.")
    value = json.loads(raw)
    fields = {"version", "prefix_device", "prefix_inode", "collector_uuid", "group_uuid", "application_sha256"}
    if not isinstance(value, dict) or set(value) != fields or type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("Unsupported repair binding.")
    for name in ("prefix_device", "prefix_inode"):
        if type(value[name]) is not int or value[name] <= 0:
            raise ValueError("Invalid installation directory binding.")
    for name in ("collector_uuid", "group_uuid"):
        if not isinstance(value[name], str) or str(uuid.UUID(value[name])).upper() != value[name]:
            raise ValueError("Invalid account UUID binding.")
    hashes = value["application_sha256"]
    if not isinstance(hashes, dict) or not hashes or "scripts/local_operator.py" not in hashes:
        raise ValueError("Missing reviewed application identity.")
    for name, digest in hashes.items():
        if (not isinstance(name, str) or Path(name).is_absolute() or ".." in Path(name).parts
                or not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)):
            raise ValueError("Invalid reviewed application identity.")
    return value


@contextmanager
def protected_prefix(spec):
    # Pin every ancestor before creating the fixed repair lock or final report.
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    current = Path("/")
    try:
        diagnostics.validate_metadata(os.fstat(descriptor), directory=True)
        for part in PREFIX.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            current /= part
            diagnostics.validate_metadata(os.fstat(descriptor), directory=True)
            diagnostics.reject_acl(current)
        metadata = os.fstat(descriptor)
        diagnostics.validate_metadata(metadata, directory=True, gid=0, modes={0o755})
        if (metadata.st_dev, metadata.st_ino) != (spec["prefix_device"], spec["prefix_inode"]):
            raise ValueError("Installation directory differs from the inspected installation.")
        yield descriptor
    finally:
        os.close(descriptor)


def report_absent(prefix_fd):
    try:
        os.stat("installation-report.json", dir_fd=prefix_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise ValueError("An installation report already exists; this narrowly scoped repair refuses to replace it.")


@contextmanager
def repair_lock(prefix_fd):
    descriptor = os.open(".startup-repair.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                         0o600, dir_fd=prefix_fd)
    try:
        diagnostics.validate_metadata(os.fstat(descriptor), gid=0, modes={0o600})
        diagnostics.reject_acl(PREFIX / ".startup-repair.lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def require_stopped():
    result = diagnostics.bounded_command(["/bin/launchctl", "print", "system/" + diagnostics.LABEL], timeout=10, limit=16384)
    if (result["limited"] is not None or result["returncode"] != 113
            or ('Could not find service "' + diagnostics.LABEL + '"') not in result["output"]):
        raise ValueError("The fixed service must be confirmed absent before this repair; no running job is adopted or stopped by preflight.")
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", 8765))
        except OSError as error:
            raise ValueError("Dashboard port 8765 is occupied; no repair was applied.") from error


def validate_accounts(config, journal, spec):
    accounts = {name: diagnostics.account_summary(name) for name in (diagnostics.COLLECTOR, diagnostics.CUSTODIAN)}
    identifiers = journal.get("account_uuids")
    if not isinstance(identifiers, dict) or set(identifiers) != set(accounts):
        raise ValueError("The protected journal does not bind both existing account UUIDs.")
    if identifiers[diagnostics.COLLECTOR] != spec["collector_uuid"] or journal.get("group_uuid") != spec["group_uuid"]:
        raise ValueError("The journal account identity differs from the inspected installation.")
    for name, field in ((diagnostics.COLLECTOR, "collector_uid"), (diagnostics.CUSTODIAN, "custodian_uid")):
        record = installer.directory_record("/Users/" + name)
        installer.validate_disabled_record(record, name, config[field], config["shared_gid"])
        if installer.single(record, "GeneratedUID") != identifiers[name]:
            raise ValueError("An existing account UUID no longer matches the protected installation journal.")
        uuid.UUID(identifiers[name])
        if {entry.pw_name for entry in pwd.getpwall() if entry.pw_uid == config[field]} != {name}:
            raise ValueError("An account UID has another directory identity.")
    group = installer.directory_record("/Groups/" + diagnostics.GROUP)
    if (installer.single(group, "GeneratedUID") != spec["group_uuid"]
            or installer.single(group, "PrimaryGroupID") != str(config["shared_gid"])
            or group.get("RecordName") != [diagnostics.GROUP]
            or set(group.get("GroupMembership", [])) != set(accounts)
            or set(group.get("GroupMembers", [])) != set(identifiers.values())
            or group.get("NestedGroups", [])
            or {entry.gr_name for entry in grp.getgrall() if entry.gr_gid == config["shared_gid"]} != {diagnostics.GROUP}
            or {entry.pw_name for entry in pwd.getpwall() if entry.pw_gid == config["shared_gid"]} != set(accounts)):
        raise ValueError("The existing service group has changed membership or identity.")
    return accounts


def application_hashes():
    hashes = {}
    for folder, directories, files in os.walk(PREFIX / "app", followlinks=False):
        for name in files:
            path = Path(folder) / name
            content = diagnostics.read_fixed(path, maximum=4 * 1024 * 1024, gid=0, modes={0o644})
            hashes[path.relative_to(PREFIX / "app").as_posix()] = hashlib.sha256(content).hexdigest()
    return hashes


def installed_preflight(spec, prefix_fd):
    report_absent(prefix_fd)
    require_stopped()
    config = diagnostics.expected_configuration(json.loads(diagnostics.read_fixed(PREFIX / "runtime.json", maximum=8192, gid=0, modes={0o644})))
    if any(config[field] != expected for field, expected in IDENTITIES.items()):
        raise ValueError("This repair is bound to the inspected service identities.")
    journal = json.loads(diagnostics.read_fixed(PREFIX / ".installation-journal.json", maximum=65536, gid=0, modes={0o600}))
    if (journal.get("stage") != "accounts_verified_before_migration"
            or any(journal.get(field) != expected for field, expected in IDENTITIES.items())
            or any(journal.get("source_checkpoint", {}).get(field) != expected for field, expected in CHECKPOINT.items())):
        raise ValueError("The protected installation journal does not match this exact incomplete activation.")
    accounts = validate_accounts(config, journal, spec)
    diagnostics.validate_verifier(config, accounts)
    if application_hashes() != spec["application_sha256"]:
        raise ValueError("Installed application bytes differ from the reviewed repair binding.")
    definition = plistlib.loads(diagnostics.read_fixed(diagnostics.PLIST, maximum=16384, gid=0, modes={0o644}))
    if definition != installer.daemon_definition(diagnostics.RUNTIME):
        raise ValueError("The fixed daemon definition differs from the reviewed installation.")
    # This manifest is consumed only after the collector UID drop by the probe.
    diagnostics.read_fixed(PREFIX / "migration-source.json", maximum=8192, gid=0, modes={0o644})
    return config


def operator(action):
    if action not in {"verify", "probe", "start", "stop"}:
        raise ValueError("Unsupported repair operation.")
    response = diagnostics.bounded_command([diagnostics.RUNTIME, "-I", "-S", "-B", PREFIX / "app/scripts/local_operator.py", action], timeout=180)
    if response["returncode"] or response["limited"]:
        raise ValueError("Installed " + action + " failed: " + diagnostics.redact(response["output"][:8192]))
    value = json.loads(response["output"])
    if not isinstance(value, dict) or value.get("ok") is not True:
        raise ValueError("Installed " + action + " did not return successful proof.")
    return value


def verify_checkpoint(value):
    protection = value.get("protection", {})
    if (value.get("ok") is not True or value.get("checked") != 6 or value.get("issues") != []
            or protection.get("status") != "sealed"
            or any(protection.get(field) != expected for field, expected in CHECKPOINT.items())):
        raise ValueError("The installed archive does not independently verify against the exact preserved checkpoint.")
    return {"ok": True, "checked": 6, "protection_status": "sealed", **CHECKPOINT}


def repair_log(descriptor):
    before = os.fstat(descriptor)
    diagnostics.validate_metadata(before, gid=450, modes={0o640, 0o660})
    if stat.S_IMODE(before.st_mode) == 0o640:
        os.fchmod(descriptor, 0o660)
        os.fsync(descriptor)
    after = os.fstat(descriptor)
    diagnostics.validate_metadata(after, gid=450, modes={0o660})
    if (before.st_dev, before.st_ino, before.st_size) != (after.st_dev, after.st_ino, after.st_size):
        raise ValueError("The diagnostic log identity or size changed during its permission repair.")
    return {"old_mode": format(stat.S_IMODE(before.st_mode), "04o"), "new_mode": "0660",
            "owner_uid": after.st_uid, "group_gid": after.st_gid, "size_bytes_unchanged": after.st_size}


def validate_probe(proof):
    checks = proof.get("permission_checks")
    required = {"collector_cannot_read_private_key", "collector_cannot_read_original_legacy_key", "collector_cannot_edit_trust",
                "collector_cannot_remove_trust", "collector_cannot_change_trust_mode", "collector_cannot_change_trust_owner",
                "collector_cannot_replace_trust", "collector_cannot_create_trust", "collector_cannot_change_custody_parent",
                "collector_cannot_change_install_parent", "collector_cannot_rename_custody_sibling", "collector_cannot_edit_application",
                "collector_cannot_edit_runtime_configuration", "collector_cannot_replace_launchd_log", "collector_can_read_public_reference",
                "collector_can_write_evidence_directory", "custodian_key_matches_original_reference", "custodian_cannot_write_collector_data"}
    if (proof.get("ok") is not True or not isinstance(checks, dict) or set(checks) != required
            or any(value is not True for value in checks.values())
            or proof.get("collector_uid") != 450 or proof.get("custodian_uid") != 451):
        raise ValueError("Actual-account permission checks did not prove every required boundary.")
    verify_checkpoint(proof.get("verification", {}))
    verify_checkpoint(proof.get("custodian_verification", {}))
    return checks


def validate_dashboard(value):
    if (value.get("ok") is not True or value.get("dashboard_loaded") is not True
            or value.get("managed_health_confirmed") is not True or value.get("listener_uid") != 450
            or type(value.get("listener_pid")) is not int or value["listener_pid"] <= 0
            or value.get("url") != "http://127.0.0.1:8765"):
        raise ValueError("The managed listener identity and health were not proven.")
    return value


def write_report(prefix_fd, proof):
    content = (json.dumps(proof, indent=2) + "\n").encode()
    temporary = ".startup-report-" + uuid.uuid4().hex + ".tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=prefix_fd)
    published = False
    try:
        os.fchown(descriptor, 0, 0)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        diagnostics.validate_metadata(os.fstat(descriptor), gid=0, modes={0o644})
        # Publish the complete file without replacing an existing report. The
        # temporary hard link is removed immediately; the final file has one link.
        os.link(temporary, "installation-report.json", src_dir_fd=prefix_fd, dst_dir_fd=prefix_fd, follow_symlinks=False)
        published = True
        os.unlink(temporary, dir_fd=prefix_fd)
        diagnostics.validate_metadata(os.fstat(descriptor), gid=0, modes={0o644})
        os.fsync(prefix_fd)
    except BaseException:
        if published:
            current = os.stat("installation-report.json", dir_fd=prefix_fd, follow_symlinks=False)
            held = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) == (held.st_dev, held.st_ino):
                os.unlink("installation-report.json", dir_fd=prefix_fd)
        raise
    finally:
        os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=prefix_fd)
        except FileNotFoundError:
            pass


def repair():
    require_native_root()
    os.umask(0o077)
    spec = load_spec()
    trusted_operator = False
    start_attempted = False
    with protected_prefix(spec) as prefix_fd:
        report_absent(prefix_fd)
        with repair_lock(prefix_fd):
            try:
                installed_preflight(spec, prefix_fd)
                trusted_operator = True
                before = verify_checkpoint(operator("verify"))
                # Both paths are validated and pinned before either mode changes.
                with ExitStack() as stack:
                    logs = {name: stack.enter_context(diagnostics.fixed_file(PREFIX / "logs" / name, gid=450, modes={0o640, 0o660})) for name in LOG_NAMES}
                    report_absent(prefix_fd)
                    require_stopped()
                    changes = {name: repair_log(descriptor) for name, descriptor in logs.items()}
                checks = validate_probe(operator("probe"))
                verified = verify_checkpoint(operator("verify"))
                require_stopped()
                start_attempted = True
                dashboard = validate_dashboard(operator("start"))
                proof = {"ok": True, "dashboard_started": True, "installation_report_written": True,
                         "completed_at": datetime.now(timezone.utc).isoformat(), "completion_method": "guarded_log_permission_repair",
                         "repair_scope": "Two existing diagnostic log files changed to root-owned shared-group writable 0660. Log directories, application, accounts, evidence, key, and trust were preserved.",
                         "log_permissions": changes, "accounts_preexisting": True, "collector_uid": 450, "custodian_uid": 451,
                         "source_checkpoint": CHECKPOINT, "checkpoint_unchanged": before == verified,
                         "permission_checks": checks, "independent_verification": verified, "dashboard": dashboard,
                         "application_sha256": spec["application_sha256"], "aws_deployed": False}
                write_report(prefix_fd, proof)
                return proof
            except BaseException as error:
                result = {"ok": False, "dashboard_started": False, "installation_report_written": False,
                          "error": diagnostics.redact(str(error) or type(error).__name__)[:8192], "evidence_or_trust_reset": False,
                          "interrupted": isinstance(error, (KeyboardInterrupt, InterruptedError))}
                if trusted_operator and start_attempted:
                    try:
                        result["service_stop"] = operator("stop")
                    except Exception as stop_error:
                        result["service_stop_error"] = diagnostics.redact(str(stop_error))[:4096]
                try:
                    result["diagnostic"] = diagnostics.diagnostic()
                except Exception as diagnostic_error:
                    result["diagnostic_error"] = diagnostics.redact(str(diagnostic_error))[:4096]
                return result


@contextmanager
def interruption_guard():
    previous = {}
    def interrupted(signum, frame):
        raise InterruptedError("Native repair interrupted by signal " + str(signum))
    try:
        for signum in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
            previous[signum] = signal.signal(signum, interrupted)
        yield
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    try:
        with interruption_guard():
            result = repair()
    except (ValueError, OSError, KeyError, TypeError) as error:
        result = {"ok": False, "dashboard_started": False, "installation_report_written": False,
                  "error": diagnostics.redact(str(error))[:4096], "evidence_or_trust_reset": False}
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
