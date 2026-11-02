#!/usr/bin/env python3
"""Fixed native recovery actions; no installation, key export, or trust reset."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import grp
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import sys
import time
import uuid

PREFIX = Path("/Library/HELTEMES Evidence")
RUNTIME = Path("/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14")
ARCHIVE_ID = "3775ad31-8e3c-4ef9-9c95-934e78b1cf3d"
MAX_JSON = 8 * 1024 * 1024
MAX_BACKUP = 200 * 1024 * 1024
BACKUP_NAME = re.compile(r"heltemes-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}\.zip\Z")
HEAD_FIELDS = {"archive_id", "sequence", "checkpoint_sha256"}


def sibling(name):
    path = Path(__file__).resolve().parent / (name + ".py")
    specification = importlib.util.spec_from_file_location("recovery_" + name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


diagnostics = sibling("diagnose_local_startup")


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode()


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def is_hash(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def valid_head(value):
    if (not isinstance(value, dict) or set(value) != HEAD_FIELDS or value.get("archive_id") != ARCHIVE_ID
            or type(value.get("sequence")) is not int or value["sequence"] < 1 or not is_hash(value.get("checkpoint_sha256"))):
        raise ValueError("Invalid expected public checkpoint identity.")
    return value


def validate_approval(value):
    expected = {"version", "request_id", "snapshot_sha256", "head", "approved_accessions", "was_running"}
    if (not isinstance(value, dict) or set(value) != expected or type(value["version"]) is not int or value["version"] != 1
            or not isinstance(value["request_id"], str) or not is_hash(value["snapshot_sha256"])
            or type(value["was_running"]) is not bool):
        raise ValueError("Unsupported reviewed sealing approval.")
    if str(uuid.UUID(value["request_id"])) != value["request_id"]:
        raise ValueError("Invalid review request identity.")
    valid_head(value["head"])
    accessions = value["approved_accessions"]
    if (not isinstance(accessions, list) or not accessions or len(accessions) > 20
            or any(not isinstance(item, str) or re.fullmatch(r"[0-9]{10}-[0-9]{2}-[0-9]{6}", item) is None for item in accessions)
            or len(set(accessions)) != len(accessions)):
        raise ValueError("Approval requires an exact list of reviewed filing accessions.")
    return value


def validate_resume(value):
    if (not isinstance(value, dict) or set(value) != {"head", "snapshot_sha256", "was_running"}
            or type(value.get("was_running")) is not bool or not is_hash(value.get("snapshot_sha256"))):
        raise ValueError("Invalid guarded restart request.")
    valid_head(value["head"])
    return value


def validate_backup(value):
    if (not isinstance(value, dict) or set(value) != {"name", "bytes", "sha256"}
            or not isinstance(value.get("name"), str) or BACKUP_NAME.fullmatch(value["name"]) is None
            or type(value.get("bytes")) is not int or not 0 < value["bytes"] <= MAX_BACKUP or not is_hash(value.get("sha256"))):
        raise ValueError("Invalid fixed backup export identity.")
    return value


def preflight():
    if (sys.platform != "darwin" or os.getuid() != 0 or os.geteuid() != 0 or not sys.flags.isolated
            or not sys.flags.no_site or not sys.dont_write_bytecode):
        raise ValueError("Use the native administrator launcher with the fixed Python runtime and -I -S -B.")
    config = diagnostics.expected_configuration(json.loads(diagnostics.read_fixed(PREFIX / "runtime.json", maximum=8192, gid=0, modes={0o644})))
    accounts = {name: diagnostics.account_summary(name) for name in (diagnostics.COLLECTOR, diagnostics.CUSTODIAN)}
    diagnostics.validate_verifier(config, accounts)
    report = json.loads(diagnostics.read_fixed(PREFIX / "installation-report.json", gid=0, modes={0o644}))
    expected = report.get("application_sha256")
    actual = {}
    for folder, directories, files in os.walk(PREFIX / "app", followlinks=False):
        for name in files:
            path = Path(folder) / name
            actual[path.relative_to(PREFIX / "app").as_posix()] = hashlib.sha256(diagnostics.read_fixed(path, maximum=4 * 1024 * 1024, gid=0, modes={0o644})).hexdigest()
    if report.get("ok") is not True or not isinstance(expected, dict) or actual != expected:
        raise ValueError("Installed application differs from the proven administrator-owned installation.")
    return config


@contextmanager
def workflow_lock():
    parent = os.open(PREFIX, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        diagnostics.validate_metadata(os.fstat(parent), directory=True, gid=0, modes={0o755})
        descriptor = os.open(".recovery-workflow.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
        try:
            diagnostics.validate_metadata(os.fstat(descriptor), gid=0, modes={0o600})
            diagnostics.reject_acl(PREFIX / ".recovery-workflow.lock")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def drop_identity(config, role):
    name = diagnostics.CUSTODIAN if role == "custodian" else diagnostics.COLLECTOR
    uid = config["custodian_uid" if role == "custodian" else "collector_uid"]
    groups = sorted(set(os.getgrouplist(name, config["shared_gid"])))
    if set(groups) & {0, grp.getgrnam("admin").gr_gid}:
        raise ValueError("Service identities cannot inherit administrator groups.")
    os.setgroups(groups)
    os.setgid(config["shared_gid"])
    os.setuid(uid)
    os.umask(0o027)
    if os.getuid() != uid or os.geteuid() != uid:
        raise ValueError("Service identity drop failed.")
    os.environ.clear()
    os.environ.update(diagnostics.ENVIRONMENT)
    os.chdir(PREFIX)
    # No installed application import occurs before this identity drop.
    sys.path.insert(0, str(PREFIX / "app"))


def filing_rows(snapshot):
    table = snapshot["tables"]["filings"]
    return {row[table["columns"].index("id")]: dict(zip(table["columns"], row)) for row in table["rows"]}


def approval_transition(approval, snapshot, current_head, latest):
    """Return whether signing is needed; a completed identical retry never signs again."""
    if sha(snapshot) != approval["snapshot_sha256"]:
        raise ValueError("The exact reviewed snapshot changed; no checkpoint was signed.")
    old = approval["head"]
    if current_head == old:
        before = filing_rows(latest["snapshot"])
        additions = [row for identity, row in filing_rows(snapshot).items() if identity not in before]
        if (sorted(row["accession"] for row in additions) != sorted(approval["approved_accessions"])
                or any(row["mode"] != "live" or row["status"] != "preserved" for row in additions)):
            raise ValueError("Pending filings differ from the explicitly reviewed live accessions.")
        return True
    if (current_head["archive_id"] == old["archive_id"] and current_head["sequence"] == old["sequence"] + 1
            and latest.get("previous_checkpoint_sha256") == old["checkpoint_sha256"]
            and sha(latest["snapshot"]) == approval["snapshot_sha256"]):
        return False
    raise ValueError("Accepted trust advanced outside the reviewed transition; no checkpoint was signed.")


def custody_snapshot(approval=None):
    from heltemes.local_accounts import policy_for, private_snapshot
    from heltemes.core import Repository
    from heltemes.protection import _anchor, _load_chain, _snapshot, seal_checkpoint, verify_protection
    policy = policy_for(PREFIX / "data")
    with private_snapshot(policy) as staging:
        evidence = Repository(staging).verify_integrity(check_protection=False)
        protection = verify_protection(staging, policy.trust_dir)
        if not evidence.get("ok") or not protection.get("ok") or protection.get("status") not in {"sealed", "pending"}:
            raise ValueError("Independent custodian verification failed; trust was not reset.")
        snapshot = _snapshot(staging, require_finished=True)
        anchor, _ = _anchor(policy.trust_dir / "anchor.json")
        head = {field: anchor[field] for field in HEAD_FIELDS}
        valid_head(head)
        latest, _ = _load_chain(policy.trust_dir / "checkpoints", anchor)
        did_sign = False
        if approval is not None:
            needed = approval_transition(approval, snapshot, head, latest)
            if needed:
                result = seal_checkpoint(staging, trust_dir=policy.trust_dir, key_dir=policy.key_dir)
                if result.get("status") != "sealed" or result.get("sequence") != head["sequence"] + 1:
                    raise ValueError("Reviewed checkpoint did not complete as expected; inspect the retained trust state.")
                did_sign = True
            protection = verify_protection(staging, policy.trust_dir)
            anchor, _ = _anchor(policy.trust_dir / "anchor.json")
            head = {field: anchor[field] for field in HEAD_FIELDS}
            if protection.get("status") != "sealed" or protection.get("checkpoint_sha256") != head["checkpoint_sha256"]:
                raise ValueError("Post-seal independent verification failed; preserve the existing trust state.")
        return {"ok": True, "head": head, "snapshot_sha256": sha(snapshot), "snapshot": snapshot,
                "verification": {"ok": True, "checked": evidence["checked"], "protection": protection},
                "receipt": anchor, "signed_now": did_sign}


@contextmanager
def backup_descriptor(name, config):
    if not isinstance(name, str) or BACKUP_NAME.fullmatch(name) is None:
        raise ValueError("Only a generated managed backup basename may be exported.")
    from heltemes.local_accounts import _open_directory, _reject_acl
    with _open_directory(PREFIX / "backups") as parent:
        folder = os.fstat(parent)
        if (folder.st_uid, folder.st_gid, stat.S_IMODE(folder.st_mode)) != (config["collector_uid"], config["shared_gid"], 0o750):
            raise ValueError("Managed backup directory has unexpected ownership or permissions.")
        _reject_acl(PREFIX / "backups")
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (config["collector_uid"], config["shared_gid"], 0o600)
                    or not 0 < info.st_size <= MAX_BACKUP):
                raise ValueError("Managed backup is linked, oversized, or has unexpected ownership or permissions.")
            _reject_acl(PREFIX / "backups" / name)
            yield descriptor, info
        finally:
            os.close(descriptor)


def backup_bytes(name, config, destination=None, expected=None):
    with backup_descriptor(name, config) as (descriptor, before):
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_BACKUP:
                raise ValueError("Managed backup grew beyond its export limit.")
            digest.update(chunk)
            if destination is not None:
                destination.write(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or size != before.st_size:
            raise ValueError("Managed backup changed during export.")
        metadata = {"name": name, "bytes": size, "sha256": digest.hexdigest()}
        if expected is not None and metadata != expected:
            raise ValueError("Exported bytes differ from the verified backup identity.")
        return metadata


def child_action(config, role, action, payload=None):
    """Fork already loaded helper code; restricted users never traverse Documents."""
    reader, writer = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(reader)
        try:
            # Do not give a restricted worker the parent's root-opened lock or
            # directory descriptors. The response pipe is its only extra FD.
            for name in os.listdir("/dev/fd"):
                if name.isdigit() and int(name) >= 3 and int(name) != writer:
                    try:
                        os.close(int(name))
                    except OSError:
                        pass
            drop_identity(config, role)
            value = custody_snapshot(payload) if action == "snapshot" else backup_bytes(payload, config)
        except BaseException as error:
            value = {"ok": False, "error": diagnostics.redact(str(error) or type(error).__name__)[:4096]}
        try:
            data = canonical(value)
            if len(data) > MAX_JSON:
                data = canonical({"ok": False, "error": "Custodian review output exceeds its limit."})
            with os.fdopen(writer, "wb") as output:
                output.write(data)
        finally:
            os._exit(0)
    os.close(writer)
    output = bytearray()
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + 180
    waited = False
    try:
        selector.register(reader, selectors.EVENT_READ)
        while True:
            if time.monotonic() >= deadline:
                raise ValueError("Restricted recovery operation exceeded its time limit.")
            if not selector.select(0.25):
                continue
            chunk = os.read(reader, 65536)
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > MAX_JSON:
                raise ValueError("Restricted recovery output exceeded its size limit.")
        _, status = os.waitpid(child, 0)
        waited = True
        if status:
            raise ValueError("Restricted recovery worker did not complete normally.")
        value = json.loads(output)
        if value.get("ok") is False:
            raise ValueError(value.get("error", "Restricted recovery operation failed."))
        return value
    finally:
        selector.close()
        os.close(reader)
        if not waited:
            try:
                os.kill(child, signal.SIGKILL)
            except ProcessLookupError:
                pass
            os.waitpid(child, 0)


def operator(action):
    if action not in {"start", "stop", "backup"}:
        raise ValueError("Unsupported installed recovery action.")
    result = diagnostics.bounded_command([RUNTIME, "-I", "-S", "-B", PREFIX / "app/scripts/local_operator.py", action], timeout=180)
    if result["returncode"] or result["limited"]:
        raise ValueError("Installed " + action + " failed: " + diagnostics.redact(result["output"][:4096]))
    return json.loads(result["output"])


def service_loaded():
    result = diagnostics.bounded_command(["/bin/launchctl", "print", "system/" + diagnostics.LABEL], timeout=10, limit=16384)
    if result["limited"]:
        raise ValueError("Could not establish managed service state.")
    if result["returncode"] == 0:
        return True
    if result["returncode"] == 113 and ('Could not find service "' + diagnostics.LABEL + '"') in result["output"]:
        return False
    raise ValueError("Could not establish managed service state.")


def run_action(action, payload, config):
    if action == "prepare":
        # Validate evidence before pausing a healthy service. This preliminary
        # snapshot is not the review request; the stopped snapshot below is.
        preliminary = child_action(config, "custodian", "snapshot")
        was_running = service_loaded()
        if was_running:
            operator("stop")
        try:
            state = child_action(config, "custodian", "snapshot")
        except BaseException as error:
            return {"ok": False, "was_running": was_running, "service_paused": was_running,
                    "error": diagnostics.redact(str(error) or type(error).__name__)[:4096],
                    "resume_request": {"head": preliminary["head"], "snapshot_sha256": preliminary["snapshot_sha256"], "was_running": was_running},
                    "note": "Verification did not complete after collection stopped. No checkpoint was signed. Review this failure before requesting a guarded restart."}
        return {"ok": True, "request_id": str(uuid.uuid4()), "was_running": was_running,
                "service_paused_for_review": was_running, **state}
    if action == "finish":
        approval = validate_approval(payload)
        if service_loaded():
            raise ValueError("Collection resumed during review; prepare a fresh review before sealing.")
        state = child_action(config, "custodian", "snapshot", approval)
        result = {"ok": True, "sealed": True, "request_id": approval["request_id"], "was_running": approval["was_running"],
                  "head": state["head"], "snapshot_sha256": state["snapshot_sha256"], "receipt": state["receipt"],
                  "signed_now": state["signed_now"], "verification": state["verification"]}
        try:
            backup_path = operator("backup").get("backup")
            if not isinstance(backup_path, str) or Path(backup_path).parent != PREFIX / "backups":
                raise ValueError("Installed backup returned an unexpected path.")
            result["backup"] = child_action(config, "collector", "backup-info", Path(backup_path).name)
            current = child_action(config, "custodian", "snapshot")
            if current["head"] != state["head"] or current["snapshot_sha256"] != state["snapshot_sha256"]:
                raise ValueError("Evidence or trust changed after the reviewed checkpoint; backup is not released as complete.")
            return result
        except Exception as error:
            return {**result, "ok": False, "error": diagnostics.redact(str(error))[:4096],
                    "note": "The reviewed checkpoint is already accepted. Do not reset trust; the same approval may safely resume backup without signing again."}
    if action == "resume":
        request = validate_resume(payload)
        state = child_action(config, "custodian", "snapshot")
        if state["head"] != request["head"] or state["snapshot_sha256"] != request["snapshot_sha256"]:
            raise ValueError("Archive changed since review; guarded restart refused.")
        dashboard = operator("start") if request["was_running"] else None
        return {"ok": True, "resumed": request["was_running"], "dashboard": dashboard, "head": state["head"]}
    raise ValueError("Unsupported fixed recovery action.")


def read_payload(stream):
    raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("Recovery request exceeds its size limit.")
    def unique(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("Duplicate recovery request field.")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique)


@contextmanager
def interruption_guard():
    previous = {}
    def interrupted(number, frame):
        # A second close/interrupt must not prevent child termination and reap.
        for signal_number in previous:
            signal.signal(signal_number, signal.SIG_IGN)
        raise InterruptedError("Native recovery interrupted by signal " + str(number))
    try:
        for number in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
            previous[number] = signal.signal(number, interrupted)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "finish", "export", "resume"))
    args = parser.parse_args(argv)
    try:
        with interruption_guard():
            config = preflight()
            payload = None if args.action == "prepare" else read_payload(sys.stdin.buffer)
            if args.action == "export":
                if not isinstance(payload, dict) or set(payload) != {"backup"}:
                    raise ValueError("Only an exact managed backup identity may be exported.")
                expected = validate_backup(payload["backup"])
                drop_identity(config, "collector")
                backup_bytes(expected["name"], config, sys.stdout.buffer, expected)
                sys.stdout.buffer.flush()
                return 0
            with workflow_lock():
                result = run_action(args.action, payload, config)
    except BaseException as error:
        result = {"ok": False, "error": diagnostics.redact(str(error) or type(error).__name__)[:4096],
                  "checkpoint_may_have_advanced": args.action == "finish",
                  "note": "No trust reset was attempted. Inspect the retained state before continuing."}
        if args.action == "export":
            print(json.dumps(result), file=sys.stderr)
            return 1
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
