#!/usr/bin/env python3
"""Guarded code-only local upgrade. Never migrates, signs, exports, or resets trust.

Without arguments this is the user-side Terminal launcher. --plan is read-only.
The fixed --apply operation requires native administrator authentication. It
keeps an old application snapshot and a durable journal, and completes a known
interrupted swap on retry. Evidence, custody, account records and runtime
configuration are never write destinations in this module.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import selectors
import socket
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
PREFIX = Path("/Library/HELTEMES Evidence")
RUNTIME = Path("/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14")
PLIST = Path("/Library/LaunchDaemons/com.heltemes.evidence.collector.plist")
LABEL = "com.heltemes.evidence.collector"
ENV = {"PATH": "/usr/bin:/bin", "HOME": "/var/empty", "TMPDIR": "/private/tmp", "LANG": "C"}
MAX_FILE = 4 * 1024 * 1024
MAX_APP = 64 * 1024 * 1024
MAX_OUTPUT = 1024 * 1024
STATE_NAME = ".code-upgrade"
REPORT_NAME = "installation-report.json"
PHASES = {"prepared", "stopped", "installing", "new_code_active", "report_updated", "verified", "complete"}
# This literal bootstrap executes before any source helper code has root
# privileges. It pins every ancestor, reads bounded immutable bytes, checks
# the fingerprint approved before authentication, then compiles those SAME
# bytes. Reopening the workspace script for execution would reintroduce a race.
BOOTSTRAP = '''import hashlib, os, stat, sys
p, expected = sys.argv[1:3]
parts = p.split("/")
if not p.startswith("/") or ".." in parts:
    raise SystemExit("Invalid reviewed helper path")
d = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    for part in parts[1:-1]:
        n = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=d)
        os.close(d)
        d = n
    f = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=d)
finally:
    os.close(d)
try:
    before = os.fstat(f)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > 4194304:
        raise SystemExit("Unsafe reviewed helper file")
    chunks = []
    count = 0
    while True:
        chunk = os.read(f, 65536)
        if not chunk:
            break
        count += len(chunk)
        if count > 4194304:
            raise SystemExit("Reviewed helper exceeds limit")
        chunks.append(chunk)
    raw = b"".join(chunks)
    after = os.fstat(f)
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise SystemExit("Reviewed helper changed while being read")
    if hashlib.sha256(raw).hexdigest() != expected:
        raise SystemExit("Reviewed helper fingerprint changed; no helper code executed")
finally:
    os.close(f)
sys.argv = [p, *sys.argv[3:]]
exec(compile(raw, p, "exec"), {"__name__": "__main__", "__file__": p})
'''


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def parse_json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("Duplicate JSON fields are not accepted.")
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object.")
    return value


def safe_metadata(meta, *, directory=False, protected=False, mode=None):
    if not (stat.S_ISDIR(meta.st_mode) if directory else stat.S_ISREG(meta.st_mode)):
        raise ValueError("Upgrade paths must be ordinary files or directories.")
    if not directory and meta.st_nlink != 1:
        raise ValueError("Upgrade files cannot have hard links.")
    if protected and (meta.st_uid != 0 or meta.st_mode & 0o022):
        raise ValueError("Installed upgrade paths must be root-owned and service-read-only.")
    if mode is not None and stat.S_IMODE(meta.st_mode) != mode:
        raise ValueError("Unexpected permissions on a protected upgrade path.")


def reject_acl(path):
    result = bounded_command(["/bin/ls", "-lde", str(path)], timeout=10, limit=4096)
    if result["returncode"] or not result["output"].split() or "+" in result["output"].split()[0]:
        raise ValueError("A protected upgrade path has an unreadable or unexpected ACL.")


@contextmanager
def pinned_directory(path, *, protected=False):
    path = Path(path).absolute()
    if ".." in path.parts:
        raise ValueError("Parent traversal is not allowed.")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    current = Path("/")
    try:
        safe_metadata(os.fstat(descriptor), directory=True, protected=protected)
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            current /= part
            safe_metadata(os.fstat(descriptor), directory=True, protected=protected)
            if protected:
                reject_acl(current)
        yield descriptor
    finally:
        os.close(descriptor)


def read_file(path, *, protected=False, maximum=MAX_FILE, mode=None):
    path = Path(path).absolute()
    with pinned_directory(path.parent, protected=protected) as parent:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(descriptor)
            safe_metadata(before, protected=protected, mode=mode)
            if before.st_size > maximum:
                raise ValueError("Upgrade input exceeds its size limit.")
            if protected:
                reject_acl(path)
            result = bytearray()
            while True:
                chunk = os.read(descriptor, min(65536, maximum + 1 - len(result)))
                if not chunk:
                    break
                result.extend(chunk)
                if len(result) > maximum:
                    raise ValueError("Upgrade input grew beyond its size limit.")
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("Upgrade input changed while it was being read.")
            return bytes(result)
        finally:
            os.close(descriptor)


def snapshot_tree(path, *, protected=False):
    result = {}
    total = 0
    with pinned_directory(path, protected=protected):
        for folder, directories, names in os.walk(path, followlinks=False):
            for name in directories:
                child = Path(folder) / name
                safe_metadata(child.lstat(), directory=True, protected=protected)
                if protected:
                    reject_acl(child)
            for name in names:
                item = Path(folder) / name
                content = read_file(item, protected=protected, mode=0o644 if protected else None)
                total += len(content)
                if total > MAX_APP:
                    raise ValueError("Application snapshot exceeds its size limit.")
                result[item.relative_to(path).as_posix()] = content
    return result


def source_snapshot():
    result = {}
    allowed = {".py", ".html", ".css", ".js", ".json", ".svg", ".ico"}
    for name, content in snapshot_tree(ROOT / "heltemes").items():
        relative = Path(name)
        if "__pycache__" in relative.parts or relative.suffix == ".pyc":
            continue
        if relative.suffix not in allowed:
            raise ValueError("Unexpected candidate application file: " + name)
        result["heltemes/" + name] = content
    for name in ("local_operator.py", "install_local_accounts.py"):
        result["scripts/" + name] = read_file(ROOT / "scripts" / name)
    if not {"heltemes/local_accounts.py", "heltemes/protection.py", "heltemes/key_recovery.py"}.issubset(result):
        raise ValueError("The crash-safe recovery candidate is incomplete.")
    return result


def manifest(snapshot):
    return {name: digest(content) for name, content in sorted(snapshot.items())}


def manifest_sha(value):
    return digest(encoded(value))


def sync_directory(path):
    with pinned_directory(path, protected=True) as descriptor:
        os.fsync(descriptor)


def new_file(path, content, mode=0o600):
    with pinned_directory(path.parent, protected=True) as parent:
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
        with os.fdopen(descriptor, "wb") as handle:
            os.fchown(handle.fileno(), 0, 0)
            os.fchmod(handle.fileno(), mode)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(parent)


def atomic_json(path, value, mode=0o600):
    temporary = path.with_name(path.name + ".new-" + uuid.uuid4().hex)
    new_file(temporary, encoded(value), mode)
    os.replace(temporary, path)
    sync_directory(path.parent)


def new_directory(path, mode=0o700):
    with pinned_directory(path.parent, protected=True) as parent:
        os.mkdir(path.name, mode, dir_fd=parent)
        os.chown(path.name, 0, 0, dir_fd=parent, follow_symlinks=False)
        os.chmod(path.name, mode, dir_fd=parent, follow_symlinks=False)
        os.fsync(parent)


def write_snapshot(snapshot, path):
    new_directory(path, 0o755)
    for name, content in sorted(snapshot.items()):
        target = path / name
        for parent in reversed(target.parents):
            if parent.is_relative_to(path) and not parent.exists():
                new_directory(parent, 0o755)
        new_file(target, content, 0o644)
    sync_directory(path)


def bounded_command(arguments, *, timeout=240, limit=MAX_OUTPUT):
    process = subprocess.Popen([str(item) for item in arguments], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=ENV)
    output = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError("Native upgrade action exceeded its time limit.")
            if selector.select(0.1):
                chunk = os.read(process.stdout.fileno(), min(8192, limit + 1 - len(output)))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > limit:
                    raise ValueError("Native upgrade action exceeded its output limit.")
        return {"returncode": process.wait(timeout=5), "output": output.decode("utf-8", errors="replace")}
    finally:
        selector.close()
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)


def operator(action):
    if action not in {"verify", "receipt", "probe", "key-status", "stop", "start"}:
        raise ValueError("Only fixed, non-signing upgrade checks are permitted.")
    result = bounded_command([RUNTIME, "-I", "-S", "-B", PREFIX / "app/scripts/local_operator.py", action])
    if result["returncode"]:
        raise ValueError("Installed " + action + " failed: " + result["output"][:4096])
    return parse_json(result["output"])


def service_loaded():
    result = bounded_command(["/bin/launchctl", "print", "system/" + LABEL], timeout=20, limit=32768)
    if result["returncode"] == 0:
        return True
    if result["returncode"] == 113 and ('Could not find service "' + LABEL + '"') in result["output"]:
        return False
    raise ValueError("Could not establish the managed dashboard state.")


def require_stopped():
    if service_loaded():
        raise ValueError("The managed dashboard is still loaded.")
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", 8765))
        except OSError as error:
            raise ValueError("Port 8765 is occupied; the code swap remains blocked.") from error


def current_identity():
    config_raw = read_file(PREFIX / "runtime.json", protected=True, mode=0o644)
    config = parse_json(config_raw)
    if config.get("data_dir") != str(PREFIX / "data") or config.get("trust_dir") != str(PREFIX / "custody/trust") or config.get("key_dir") != str(PREFIX / "custody/keys"):
        raise ValueError("Installed runtime paths differ from the fixed managed layout.")
    ids = [config.get(name) for name in ("collector_uid", "custodian_uid", "shared_gid")]
    if any(type(item) is not int or item <= 0 for item in ids) or ids[0] == ids[1]:
        raise ValueError("Installed service identities are invalid.")
    forbidden = {0, grp.getgrnam("admin").gr_gid}
    accounts = {}
    for name, field in (("_hevidence_collect", "collector_uid"), ("_hevidence_custody", "custodian_uid")):
        account = pwd.getpwnam(name)
        groups = sorted(set(os.getgrouplist(name, account.pw_gid)))
        if account.pw_uid != config[field] or account.pw_gid != config["shared_gid"] or account.pw_shell != "/usr/bin/false" or set(groups) & forbidden:
            raise ValueError("A service account no longer matches its separated, disabled-login policy.")
        record = bounded_command(["/usr/bin/dscl", ".", "-read", "/Users/" + name, "GeneratedUID"], limit=4096)
        if record["returncode"]:
            raise ValueError("Could not read the managed account's persistent identity.")
        accounts[name] = {"uid": account.pw_uid, "gid": account.pw_gid, "shell": account.pw_shell,
                          "groups": groups, "generated_uid": record["output"].strip()}
    if grp.getgrnam("_hevidence").gr_gid != config["shared_gid"]:
        raise ValueError("Managed group identity changed.")
    runtime = read_file(PREFIX / "runtime-python.txt", protected=True, mode=0o644).decode().strip()
    if runtime != str(RUNTIME) or Path(sys.executable).resolve() != RUNTIME:
        raise ValueError("Use the installed fixed Python runtime.")
    # The signed Python framework is administrator-managed on this Mac. Its
    # root/admin or root/wheel group-write modes are allowed; service groups are not.
    for path in (RUNTIME, *RUNTIME.parents):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o002 or (metadata.st_mode & 0o020 and metadata.st_gid not in forbidden):
            raise ValueError("The installed Python runtime is writable outside trusted administration.")
        reject_acl(path)
    metadata = PREFIX.lstat()
    return {"prefix_device": metadata.st_dev, "prefix_inode": metadata.st_ino, "accounts": accounts,
            "collector_uid": config["collector_uid"], "custodian_uid": config["custodian_uid"],
            "configuration_sha256": digest(config_raw), "runtime_sha256": digest(read_file(PREFIX / "runtime-python.txt", protected=True)),
            "migration_source_sha256": digest(read_file(PREFIX / "migration-source.json", protected=True)),
            "daemon_sha256": digest(read_file(PLIST, protected=True))}


def receipt_identity(receipt):
    names = ("archive_id", "sequence", "checkpoint_sha256", "public_key", "key_fingerprint")
    if not all(name in receipt for name in names) or type(receipt["sequence"]) is not int or receipt["sequence"] < 1:
        raise ValueError("Custodian receipt has no valid accepted checkpoint and public identity.")
    if not isinstance(receipt["checkpoint_sha256"], str) or len(receipt["checkpoint_sha256"]) != 64:
        raise ValueError("Custodian checkpoint digest is invalid.")
    return {name: receipt[name] for name in names}


def verified_receipt(expected=None):
    check = operator("verify")
    protection = check.get("protection", {})
    if check.get("ok") is not True or check.get("issues") != [] or protection.get("status") != "sealed":
        raise ValueError("A fully verified, sealed archive is required for this code-only update.")
    receipt = receipt_identity(operator("receipt"))
    for name in ("archive_id", "sequence", "checkpoint_sha256", "key_fingerprint"):
        if protection.get(name) != receipt[name]:
            raise ValueError("Independent verification and public receipt do not agree.")
    if expected is not None and receipt != expected:
        raise ValueError("The accepted checkpoint or signing identity changed; code update stopped.")
    return receipt


@contextmanager
def upgrade_locks():
    descriptors = []
    try:
        for name in (".code-upgrade.lock", ".recovery-workflow.lock"):
            with pinned_directory(PREFIX, protected=True) as parent:
                descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
            descriptors.append(descriptor)
            safe_metadata(os.fstat(descriptor), protected=True, mode=0o600)
            reject_acl(PREFIX / name)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def save_phase(state, journal, phase):
    journal["phase"] = phase
    atomic_json(state / "journal.json", journal)


def existing_manifest(path):
    if not path.exists() and not path.is_symlink():
        return None
    return manifest(snapshot_tree(path, protected=True))


def reconcile_code(state, journal):
    """Complete only the three known physical states of the journaled swap."""
    app, old, candidate = PREFIX / "app", state / "old-app", state / "new-app"
    actual = (existing_manifest(app), existing_manifest(old), existing_manifest(candidate))
    old_hashes, new_hashes = journal["old_manifest"], journal["new_manifest"]
    if actual == (old_hashes, None, new_hashes):
        os.rename(app, old)
        sync_directory(PREFIX)
        sync_directory(state)
        actual = (None, old_hashes, new_hashes)
    if actual == (None, old_hashes, new_hashes):
        os.rename(candidate, app)
        sync_directory(PREFIX)
        sync_directory(state)
    elif actual != (new_hashes, old_hashes, None):
        raise ValueError("Application placement differs from every known interrupted upgrade state.")
    save_phase(state, journal, "new_code_active")


def update_report(original, journal):
    result = dict(original)
    result["application_sha256"] = journal["new_manifest"]
    result["code_upgrade"] = {"version": 1, "candidate_sha256": journal["candidate_sha256"],
                              "preserved_receipt": journal["receipt"], "started_at": journal["started_at"],
                              "original_report_sha256": journal["original_report_sha256"]}
    return result


def validate_dashboard(value, identity):
    if (value.get("ok") is not True or value.get("dashboard_loaded") is not True
            or value.get("managed_health_confirmed") is not True or value.get("listener_uid") != identity["collector_uid"]
            or type(value.get("listener_pid")) is not int or value["listener_pid"] <= 0
            or value.get("url") != "http://127.0.0.1:8765"):
        raise ValueError("The actual restricted collector listener was not proved.")


def validate_journal(journal, expected, identity):
    fields = {"version", "phase", "candidate_sha256", "identity", "receipt", "was_running", "old_manifest", "new_manifest", "original_report_sha256", "original_report", "started_at"}
    if set(journal) != fields or journal["version"] != 1 or journal["phase"] not in PHASES or type(journal["was_running"]) is not bool:
        raise ValueError("Unrecognized code-upgrade journal.")
    if journal["candidate_sha256"] != expected or manifest_sha(journal["new_manifest"]) != expected or journal["identity"] != identity:
        raise ValueError("Upgrade retry does not match the reviewed candidate or original installation identity.")
    receipt_identity(journal["receipt"])


def apply_upgrade(expected, expected_helper):
    if sys.platform != "darwin" or os.getuid() != 0 or os.geteuid() != 0 or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode:
        raise ValueError("Use native administrator authentication and fixed isolated Python -I -S -B.")
    if digest(read_file(Path(__file__))) != expected_helper:
        raise ValueError("The reviewed upgrade helper changed before authentication finished.")
    candidate = source_snapshot()
    candidate_manifest = manifest(candidate)
    if manifest_sha(candidate_manifest) != expected:
        raise ValueError("Candidate code changed after review; no installed files were changed.")
    identity = current_identity()
    with upgrade_locks():
        return upgrade_locked(candidate, candidate_manifest, expected, identity)


def upgrade_locked(candidate, candidate_manifest, expected, identity):
    state = PREFIX / STATE_NAME
    if state.exists() or state.is_symlink():
        with pinned_directory(state, protected=True) as descriptor:
            safe_metadata(os.fstat(descriptor), directory=True, protected=True, mode=0o700)
    if not (state / "journal.json").exists():
        # Before a journal is published no app/service mutation has happened.
        # Only an empty state directory or an interrupted atomic journal write
        # is a recoverable initialization; anything else requires inspection.
        if state.exists():
            for item in state.iterdir():
                if not item.name.startswith("journal.json.new-"):
                    raise ValueError("Unrecognized files in an uninitialized upgrade state.")
                read_file(item, protected=True, mode=0o600)
        original_bytes = read_file(PREFIX / REPORT_NAME, protected=True, mode=0o644)
        original = parse_json(original_bytes)
        old_manifest = existing_manifest(PREFIX / "app")
        if original.get("ok") is not True or old_manifest != original.get("application_sha256"):
            raise ValueError("Installed code does not match its original proven manifest.")
        if old_manifest == candidate_manifest:
            raise ValueError("This candidate is already installed without this update record; inspect before retrying.")
        receipt = verified_receipt()
        was_running = service_loaded()
        # Establish a journal before the first managed mutation. A staging
        # interruption remains diagnosable and never touches evidence/custody.
        if not state.exists():
            new_directory(state)
        journal = {"version": 1, "phase": "prepared", "candidate_sha256": expected, "identity": identity,
                   "receipt": receipt, "was_running": was_running, "old_manifest": old_manifest,
                   "new_manifest": candidate_manifest, "original_report_sha256": digest(original_bytes), "original_report": original,
                   "started_at": datetime.now(timezone.utc).isoformat()}
        atomic_json(state / "journal.json", journal)
    else:
        journal = parse_json(read_file(state / "journal.json", protected=True, mode=0o600))
        validate_journal(journal, expected, identity)
        original = journal["original_report"]
        if not isinstance(original, dict) or original.get("ok") is not True or original.get("application_sha256") != journal["old_manifest"]:
            raise ValueError("The retained original application report is invalid.")
    next_report = update_report(original, journal)
    report = parse_json(read_file(PREFIX / REPORT_NAME, protected=True, mode=0o644))
    if report not in (original, next_report):
        raise ValueError("Installation report changed outside this recorded code upgrade.")
    # Staging can be retried file by file only while the old installed code and
    # report remain exact. Partial files never become installed application code.
    if journal["phase"] == "prepared":
        if existing_manifest(PREFIX / "app") != journal["old_manifest"] or report != original:
            raise ValueError("Prepared upgrade no longer has its original installed code and report.")
        stage_snapshot(candidate, state / "new-app")
    if journal["phase"] == "complete":
        if existing_manifest(PREFIX / "app") != candidate_manifest or report != next_report:
            raise ValueError("Completed upgrade application or report changed.")
        verified_receipt(journal["receipt"])
        key = validate_key_status(operator("key-status"), journal["receipt"])
        return {"ok": True, "already_complete": True, "candidate_sha256": expected,
                "receipt": journal["receipt"], "key_status": key, "dashboard_running": service_loaded(),
                "report": str(state / "result.json"), "aws_deployed": False}
    # On interruption, the previously loaded dashboard is stopped again before
    # any reconciliation. A half-swap only occurs after bootout was confirmed.
    if service_loaded():
        if existing_manifest(PREFIX / "app") not in (journal["old_manifest"], candidate_manifest):
            raise ValueError("Cannot dispatch an unrecognized installed application.")
        operator("stop")
    require_stopped()
    if journal["phase"] == "prepared":
        save_phase(state, journal, "stopped")
    if existing_manifest(PREFIX / "app") == journal["old_manifest"]:
        verified_receipt(journal["receipt"])
    if current_identity() != identity:
        raise ValueError("The managed installation identity changed during preflight.")
    save_phase(state, journal, "installing")
    reconcile_code(state, journal)
    atomic_json(PREFIX / REPORT_NAME, next_report, 0o644)
    save_phase(state, journal, "report_updated")
    verified_receipt(journal["receipt"])
    key = validate_key_status(operator("key-status"), journal["receipt"])
    boundary = operator("probe")
    if boundary.get("ok") is not True or not boundary.get("permission_checks") or not all(value is True for value in boundary["permission_checks"].values()):
        raise ValueError("Actual collector/custodian permission checks did not pass.")
    verified_receipt(journal["receipt"])
    if current_identity() != identity:
        raise ValueError("The managed account/runtime identity changed during upgrade.")
    save_phase(state, journal, "verified")
    dashboard = None
    if journal["was_running"]:
        try:
            dashboard = operator("start")
            validate_dashboard(dashboard, identity)
        except Exception:
            operator("stop")
            require_stopped()
            raise
    else:
        require_stopped()
    result = {"ok": True, "code_only": True, "candidate_sha256": expected, "receipt": journal["receipt"],
              "original_key_and_checkpoint_preserved": True, "key_status": key,
              "permission_checks": boundary["permission_checks"], "dashboard": dashboard,
              "dashboard_running": journal["was_running"], "aws_deployed": False,
              "report": str(state / "result.json")}
    atomic_json(state / "result.json", result)
    save_phase(state, journal, "complete")
    return result


def stage_snapshot(snapshot, path):
    if not path.exists() and not path.is_symlink():
        new_directory(path, 0o755)
    actual = snapshot_tree(path, protected=True)
    if any(name not in snapshot or snapshot[name] != content for name, content in actual.items()):
        raise ValueError("Candidate staging contains unrelated or incomplete file contents.")
    for name, content in sorted(snapshot.items()):
        if name in actual:
            continue
        target = path / name
        for parent in reversed(target.parents):
            if parent.is_relative_to(path) and not parent.exists():
                new_directory(parent, 0o755)
        temporary = path.parent / ".staging-payload"
        if temporary.exists() or temporary.is_symlink():
            # This one unpublished staging payload is the sole disposable
            # write. It cannot be an installed file, symlink or hard link.
            read_file(temporary, protected=True, mode=0o644)
            temporary.unlink()
            sync_directory(temporary.parent)
        new_file(temporary, content, 0o644)
        os.rename(temporary, target)
        sync_directory(target.parent)
        sync_directory(temporary.parent)
    if existing_manifest(path) != manifest(snapshot):
        raise ValueError("Protected candidate snapshot did not match its reviewed manifest.")


def validate_key_status(value, receipt):
    if (value.get("ok") is not True or value.get("active_key_matches") is not True
            or value.get("signing_allowed") is not True or value.get("public_key_fingerprint") != receipt["key_fingerprint"]):
        raise ValueError("The active private/public signing identity or recovery state was not verified.")
    return value


def prepare_plan():
    hashes = manifest(source_snapshot())
    return {"candidate_sha256": manifest_sha(hashes), "helper_sha256": digest(read_file(Path(__file__))),
            "files": len(hashes), "scope": "application code and installation manifest only",
            "preserves": ["filings", "accepted checkpoint", "signing key", "trust history", "service accounts", "runtime configuration"],
            "aws_deployed": False}


def native_command(plan):
    return ["/usr/bin/sudo", "-n", "--", str(RUNTIME), "-I", "-S", "-B", "-c", BOOTSTRAP,
            str(Path(__file__)), plan["helper_sha256"], "--apply", plan["candidate_sha256"],
            "--expected-helper-sha256", plan["helper_sha256"]]


def frontend():
    plan = prepare_plan()
    folder = ROOT / "work" / "upgrade-logs"
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = folder / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8] + ".log")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as log:
        def emit(value):
            log.write(value + "\n")
            log.flush()
            print(value, flush=True)
        emit("HELTEMES Evidence — guarded local application update")
        emit("Candidate code fingerprint: " + plan["candidate_sha256"])
        emit("Preserve existing filings, signing identity, accepted checkpoint, accounts, and runtime. AWS remains deferred.")
        emit("The dashboard pauses during checks and resumes only if it was running before this update.")
        emit("Diagnostic log: " + str(path))
        emit("Enter your Mac password only at Terminal's native Password prompt. It is not recorded in this log.")
        authentication = subprocess.run(["/usr/bin/sudo", "-v"], check=False)
        if authentication.returncode:
            emit("Authentication did not complete. No privileged update was started.")
            return authentication.returncode
        emit("Authentication completed. Verifying, staging, and checking the code-only update.")
        result = bounded_command(native_command(plan), timeout=900)
        emit(result["output"])
        if result["returncode"]:
            emit("Update not confirmed. The saved protected journal supports a checked retry; do not rerun migration or reset trust.")
            return result["returncode"]
        value = parse_json(result["output"])
        if value.get("ok") is not True or value.get("candidate_sha256") != plan["candidate_sha256"]:
            emit("Update not confirmed: native success evidence did not match the reviewed code.")
            return 1
        emit("Update complete. Existing accepted checkpoint and signing identity verified; separate-account checks passed.")
        return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--plan", action="store_true")
    group.add_argument("--apply", metavar="EXPECTED_MANIFEST_SHA256")
    parser.add_argument("--expected-helper-sha256")
    args = parser.parse_args(argv)
    try:
        if args.plan:
            print(json.dumps(prepare_plan(), indent=2))
            return 0
        if args.apply:
            if len(args.apply) != 64 or not args.expected_helper_sha256 or len(args.expected_helper_sha256) != 64:
                raise ValueError("A reviewed candidate and helper fingerprint are required.")
            print(json.dumps(apply_upgrade(args.apply, args.expected_helper_sha256), indent=2))
            return 0
        return frontend()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, TimeoutError) as error:
        print("Code update stopped without resetting evidence, keys, or trust: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
