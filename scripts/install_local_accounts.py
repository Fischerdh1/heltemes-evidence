#!/usr/bin/env python3
"""Reviewable, one-time macOS migration. --plan is read-only; --install needs root.

No password, sudo rule, network request, or new signing identity is created.
On failure, retain the original archive and leave the new service stopped.
"""
from __future__ import annotations

import argparse
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import plistlib
import pwd
import stat
import subprocess
import sys
import uuid

PREFIX = Path("/Library/HELTEMES Evidence")
PLIST = Path("/Library/LaunchDaemons/com.heltemes.evidence.collector.plist")
LABEL = "com.heltemes.evidence.collector"
COLLECTOR = "_hevidence_collect"
CUSTODIAN = "_hevidence_custody"
GROUP = "_hevidence"
DEFAULT_RUNTIME = Path("/Library/Frameworks/Python.framework/Versions/3.14/bin/python3")
SOURCE = Path(__file__).resolve().parents[1]
MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024


def run(args, **kwargs):
    arguments = [str(a) for a in args]
    result = subprocess.run(arguments, check=False, capture_output=True,
                            text=True, env={"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": "/var/empty"},
                            timeout=120, **kwargs)
    if result.returncode:
        detail = (result.stderr or result.stdout or "No diagnostic output was returned.").strip()
        # Commands contain fixed service-account names and attributes, never a
        # login password or signing-key contents. Keep the native error visible.
        raise ValueError(f"{Path(arguments[0]).name} failed (exit {result.returncode}): {detail[:4096]}")
    return result


def assigned_uuid(record):
    """Preserve the identifier assigned by macOS; never replace GeneratedUID."""
    response = run(["/usr/bin/dscl", "-plist", ".", "-read", record, "GeneratedUID"])
    try:
        values = plistlib.loads(response.stdout.encode())["dsAttrTypeStandard:GeneratedUID"]
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str):
            raise ValueError("Expected exactly one macOS-assigned UUID.")
        parsed = uuid.UUID(values[0])
        if str(parsed).upper() != values[0].upper():
            raise ValueError("macOS returned an invalid UUID representation.")
        return str(parsed).upper()
    except (ValueError, TypeError, KeyError, plistlib.InvalidFileException) as error:
        raise ValueError("Cannot safely read the existing macOS-assigned GeneratedUID for " + record) from error


def directory_record(record):
    """Read a reserved service record without printing its attribute values."""
    response = run(["/usr/bin/dscl", "-plist", ".", "-read", record])
    try:
        raw = plistlib.loads(response.stdout.encode())
        if not isinstance(raw, dict):
            raise ValueError("Directory record is not a dictionary.")
        result = {}
        for name, values in raw.items():
            key = name.split(":", 1)[-1]
            if key in result or not isinstance(values, list):
                raise ValueError("Unexpected duplicate directory attribute.")
            result[key] = values
        return result
    except (ValueError, TypeError, plistlib.InvalidFileException) as error:
        raise ValueError("Cannot safely inspect reserved directory record: " + record) from error


def single(record, key, *, optional=False):
    if key not in record:
        if optional:
            return None
        raise ValueError("Directory record is missing required attribute: " + key)
    values = record[key]
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], str):
        raise ValueError("Directory attribute must contain exactly one text value: " + key)
    return values[0]


def validate_disabled_record(record, name, uid, gid, *, early_recovery=False):
    required = {"RecordName": name, "UniqueID": str(uid), "PrimaryGroupID": str(gid)}
    for key, value in required.items():
        if single(record, key) != value:
            raise ValueError("Reserved account has an unexpected " + key + "; no repair was applied.")
    account = pwd.getpwnam(name)
    if (account.pw_name, account.pw_uid, account.pw_gid, account.pw_shell, account.pw_dir) != (
            name, uid, gid, "/usr/bin/false", "/var/empty"):
        raise ValueError("Effective account identity, shell, or home differs from the reviewed disabled service account.")
    for key, value in {"UserShell": "/usr/bin/false", "NFSHomeDirectory": "/var/empty"}.items():
        actual = single(record, key, optional=early_recovery)
        # The observed early failure happened before these attributes were
        # written. Only the exact identity-bound recovery may rely on verified
        # macOS lookup defaults; setup writes both fields before final validation.
        if actual is None and early_recovery:
            continue
        if actual != value:
            raise ValueError("Reserved account has an unexpected " + key + "; no repair was applied.")
    # pwd masks local password fields as '********' on modern macOS. The root
    # directory record, absent credentials, and disabled shell establish the
    # boundary; the masked lookup is not evidence of an enabled password.
    password = single(record, "Password", optional=True)
    permitted_passwords = {None, "*", "********"} if early_recovery else {"*"}
    if password not in permitted_passwords or account.pw_passwd not in {"*", "********"}:
        raise ValueError("Reserved service account does not have a locked password marker.")
    auth = record.get("AuthenticationAuthority", [])
    if auth not in ([], [";DisabledUser;"]):
        raise ValueError("Reserved service account has an unexpected authentication method.")
    for key, values in record.items():
        lower = key.lower()
        if lower.startswith("_writers_"):
            own_uuid = single(record, "GeneratedUID", optional=True)
            allowed_writers = {name, "root"}
            if own_uuid:
                allowed_writers.add(own_uuid)
            if any(value not in allowed_writers for value in values):
                raise ValueError("Reserved service account has an unexpected attribute writer.")
            continue
        if lower in {"altsecurityidentities", "passwordserverlist"} or any(word in lower for word in ("shadowhash", "securetoken", "kerberos", "certificate", "ssh")):
            raise ValueError("Reserved service account contains unexpected authentication material: " + key)
    hidden = single(record, "IsHidden", optional=True)
    if hidden not in {None, "1"}:
        raise ValueError("Reserved service account has an unexpected visibility setting.")
    title = single(record, "RealName", optional=True)
    expected = "HELTEMES Evidence Collector" if name == COLLECTOR else "HELTEMES Evidence Custodian"
    if title != expected and not (early_recovery and title in {None, ""}):
        raise ValueError("Reserved service account has an unexpected display name.")
    groups = set(os.getgrouplist(name, gid))
    if groups & {0, grp.getgrnam("admin").gr_gid}:
        raise ValueError("Reserved service account has administrator-group membership.")


def journal(path, entry):
    """Atomic administrator-owned progress record, saved before each command."""
    temporary = path.with_name(path.name + ".new")
    write_owned(temporary, (json.dumps(entry, sort_keys=True, indent=2) + "\n").encode(), 0, 0, 0o600)
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


RECOVERY_FIELDS = {"version", "stage", "collector_uid", "custodian_uid", "shared_gid", "collector_uuid", "group_uuid",
                   "prefix_device", "prefix_inode", "archive_id", "sequence", "checkpoint_sha256"}


def load_recovery_spec(path):
    value = json.loads(read_regular(path))
    if not isinstance(value, dict) or set(value) != RECOVERY_FIELDS or type(value["version"]) is not int or value["version"] != 1 or value["stage"] != "collector-generateduid-write":
        raise ValueError("Unsupported narrow recovery specification.")
    for key in ("collector_uid", "custodian_uid", "shared_gid", "prefix_device", "prefix_inode", "sequence"):
        if type(value[key]) is not int or value[key] <= 0:
            raise ValueError("Recovery specification contains an invalid numeric identity.")
    if not (450 <= value["collector_uid"] < 500 and 450 <= value["custodian_uid"] < 500 and 450 <= value["shared_gid"] < 500):
        raise ValueError("Recovery specification is outside this installer's service identity range.")
    if value["collector_uid"] == value["custodian_uid"]:
        raise ValueError("Recovery requires two distinct service identities.")
    for key in ("collector_uuid", "group_uuid", "archive_id"):
        if not isinstance(value[key], str) or str(uuid.UUID(value[key])).upper() != value[key].upper():
            raise ValueError("Invalid recovery UUID.")
    if not isinstance(value["checkpoint_sha256"], str) or len(value["checkpoint_sha256"]) != 64 or any(char not in "0123456789abcdef" for char in value["checkpoint_sha256"]):
        raise ValueError("Invalid expected checkpoint fingerprint.")
    return value


def account_attribute_shapes(record):
    """Diagnostic structure only: never print credentials or directory values."""
    return {key: {"present": key in record, "value_count": len(record[key]) if isinstance(record.get(key), list) else None}
            for key in ("UserShell", "NFSHomeDirectory", "RealName", "Password", "AuthenticationAuthority")}


def recovery_state(spec, source, *, diagnostics=False):
    """Accept only the reviewed failure before any application/evidence copy."""
    prefix = plain_path(PREFIX, directory=True)
    metadata = prefix.stat()
    if (metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)) != (
            spec["prefix_device"], spec["prefix_inode"], 0, 0, 0o700):
        raise ValueError("The partial installation directory differs from the reviewed recovery case.")
    if any(prefix.iterdir()) or has_acl(prefix):
        raise ValueError("Recovery requires the original empty administrator-owned installation directory.")
    if PLIST.exists() or PLIST.is_symlink():
        raise ValueError("Recovery cannot replace an existing launch daemon.")
    job = subprocess.run(["/bin/launchctl", "print", "system/" + LABEL], capture_output=True, text=True, timeout=10, check=False)
    if job.returncode == 0:
        raise ValueError("Recovery cannot continue while the reserved service exists.")
    users = pwd.getpwall()
    groups = grp.getgrall()
    if [u.pw_name for u in users if u.pw_uid == spec["collector_uid"]] != [COLLECTOR]:
        raise ValueError("Collector UID is missing or shared by another account.")
    if any(u.pw_name == CUSTODIAN or u.pw_uid == spec["custodian_uid"] for u in users):
        raise ValueError("Custodian identity already exists; this early recovery does not apply.")
    # Also detect a partial record that does not yet have a POSIX UID.
    names = run(["/usr/bin/dscl", ".", "-list", "/Users"]).stdout.splitlines()
    if CUSTODIAN in names:
        raise ValueError("A partial custodian directory record already exists.")
    if [g.gr_name for g in groups if g.gr_gid == spec["shared_gid"]] != [GROUP]:
        raise ValueError("Shared GID is missing or belongs to another group.")
    if [u.pw_name for u in users if u.pw_gid == spec["shared_gid"]] != [COLLECTOR]:
        raise ValueError("An unexpected account already uses the proposed primary group.")
    group = directory_record("/Groups/" + GROUP)
    collector = directory_record("/Users/" + COLLECTOR)
    if diagnostics:
        print("Recovery account attribute shapes (values omitted): " + json.dumps(account_attribute_shapes(collector), sort_keys=True), file=sys.stderr)
    if single(group, "RecordName") != GROUP or single(group, "PrimaryGroupID") != str(spec["shared_gid"]):
        raise ValueError("Partial group identity differs from the reviewed recovery case.")
    if single(group, "GeneratedUID").upper() != spec["group_uuid"].upper() or single(collector, "GeneratedUID").upper() != spec["collector_uuid"].upper():
        raise ValueError("A macOS account UUID changed; recovery refuses to adopt another identity.")
    if any(group.get(key, []) for key in ("GroupMembers", "GroupMembership", "NestedGroups")) or grp.getgrnam(GROUP).gr_mem:
        raise ValueError("The partial group has unexpected members.")
    if single(group, "Password", optional=True) not in {None, "*"}:
        raise ValueError("The partial group has unexpected authentication data.")
    validate_disabled_record(collector, COLLECTOR, spec["collector_uid"], spec["shared_gid"], early_recovery=True)
    if single(collector, "RealName", optional=True) not in {None, ""} or pwd.getpwnam(COLLECTOR).pw_gecos != "":
        raise ValueError("Collector attributes differ from the observed early failure.")
    details = inspect_source(source)
    for key in ("archive_id", "sequence", "checkpoint_sha256"):
        if details[key] != spec[key]:
            raise ValueError("Source checkpoint changed; a new recovery review is required.")
    state = {"prefix_device": metadata.st_dev, "prefix_inode": metadata.st_ino, "collector": collector,
             "group": group, "source_checkpoint": details}
    # Byte-valued OS metadata is represented deterministically without printing it.
    canonical = plistlib.dumps(state, sort_keys=True)
    return {"state_sha256": hashlib.sha256(canonical).hexdigest(), "source_checkpoint": details}


def recovery_plan(source, runtime, spec):
    if sys.platform != "darwin" or os.geteuid() != 0:
        raise ValueError("The narrow recovery inspection requires the native Mac administrator prompt.")
    state = recovery_state(spec, source, diagnostics=True)
    return {"mode": "reviewed_early_recovery", "source": str(Path(source).absolute()), "destination": str(PREFIX),
            "runtime": str(inspect_runtime(runtime)), "source_checkpoint": state["source_checkpoint"],
            "state_sha256": state["state_sha256"], "recovery_spec": spec,
            "actions": ["Preserve the existing collector and group UUIDs.", "Complete only missing expected collector attributes.",
                        "Create the absent custodian with a separate UID, preserving its macOS-assigned UUID.",
                        "Continue original byte-preserving migration and all real-account verification probes."],
            "deletions": []}


def plain_path(path, *, directory=False):
    path = Path(path).absolute()
    if ".." in path.parts:
        raise ValueError("Parent traversal is not allowed.")
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError("Symbolic links are not allowed: " + str(part))
    metadata = path.lstat()
    if directory:
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("Expected a directory: " + str(path))
    elif not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("Expected an ordinary, unlinked file: " + str(path))
    return path


def read_regular(path):
    path = plain_path(path)
    # Pin every ancestor before opening a workspace-owned input. A source owner
    # cannot race a parent symlink into a root read of an unrelated file.
    parent_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > MAX_FILE:
            raise ValueError("Unsafe or oversized migration file: " + str(path))
        content = handle.read(MAX_FILE + 1)
        after = os.fstat(handle.fileno())
    if len(content) > MAX_FILE or (metadata.st_ino, metadata.st_size, metadata.st_mtime_ns) != (
            after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError("Source changed while being read; stop collection and try again.")
    return content


def tree_files(root):
    root = plain_path(root, directory=True)
    result = []
    for folder, directories, files in os.walk(root, followlinks=False):
        for name in directories:
            plain_path(Path(folder) / name, directory=True)
        for name in files:
            result.append(plain_path(Path(folder) / name))
    return sorted(result)


def source_paths(source):
    source = plain_path(source, directory=True)
    data = plain_path(source / "data", directory=True)
    identity = hashlib.sha256(str(data).encode()).hexdigest()[:16]
    return data, source / ".heltemes-trust" / identity, source / ".heltemes-keys" / identity


def inspect_source(source):
    data, trust, keys = source_paths(source)
    for folder in (data, trust, keys):
        tree_files(folder)
    anchor = json.loads(read_regular(trust / "anchor.json"))
    marker = json.loads(read_regular(data / "protection.json"))
    if anchor.get("archive_id") != marker.get("archive_id") or not anchor.get("checkpoint_sha256"):
        raise ValueError("Source marker and trust receipt do not match.")
    if any((data / ("data.sqlite3" + suffix)).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise ValueError("The archive has a SQLite sidecar; stop its dashboard and complete recovery first.")
    for name in ("data.sqlite3", "protection.json", "settings.json", ".operation.lock"):
        plain_path(data / name)
    if {p.name for p in tree_files(keys)} != {"signing_key", "signing_key.pub"}:
        raise ValueError("Unexpected signing-key directory inventory.")
    public = read_regular(keys / "signing_key.pub").decode("ascii").split()
    if " ".join(public[:2]) != " ".join(anchor["public_key"].split()[:2]):
        raise ValueError("Public signing key differs from the independently saved trust receipt.")
    return {"archive_id": anchor["archive_id"], "sequence": anchor["sequence"],
            "checkpoint_sha256": anchor["checkpoint_sha256"], "data_dir": str(data),
            "trust_dir": str(trust), "key_dir": str(keys)}


def runtime_path(runtime):
    """Allow the framework's root-owned symlink, then inspect its resolved chain.

    root:admin and root:wheel group writes are acceptable because neither service
    identity is an administrator. The dedicated service group is never trusted.
    """
    runtime = Path(runtime).absolute()
    if runtime.is_symlink() and runtime.lstat().st_uid != 0:
        raise ValueError("Python executable symlink is not root-owned.")
    resolved = runtime.resolve(strict=True)
    trusted_groups = {0}
    for name in ("wheel", "admin"):
        try:
            trusted_groups.add(grp.getgrnam(name).gr_gid)
        except KeyError:
            pass
    for path in (resolved, *resolved.parents):
        metadata = path.stat()
        if metadata.st_uid != 0 or metadata.st_mode & 0o002 or (
                metadata.st_mode & 0o020 and metadata.st_gid not in trusted_groups):
            raise ValueError("Python requires root-owned paths writable only by trusted administrators: " + str(path))
        if sys.platform == "darwin" and has_acl(path):
            raise ValueError("Unexpected ACL on Python runtime path: " + str(path))
    return resolved


def inspect_runtime(runtime):
    resolved = runtime_path(runtime)
    details = json.loads(run([resolved, "-I", "-S", "-B", "-c",
                              "import json,sys,sysconfig; print(json.dumps({'version':list(sys.version_info[:2]),'stdlib':sysconfig.get_path('stdlib')}))"]).stdout)
    if details["version"] < [3, 11]:
        raise ValueError("The protected runtime requires Python 3.11 or newer.")
    library = Path(details["stdlib"])
    runtime_path(library)
    trusted_groups = {0, grp.getgrnam("admin").gr_gid}
    protected = []
    for folder, directories, files in os.walk(library, followlinks=False):
        # -S prevents site packages and .pth startup code from being loaded.
        directories[:] = [name for name in directories if name != "site-packages"]
        for name in [*directories, *files]:
            path = Path(folder) / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                runtime_path(path)
            elif metadata.st_uid != 0 or metadata.st_mode & 0o002 or (
                    metadata.st_mode & 0o020 and metadata.st_gid not in trusted_groups):
                raise ValueError("A standard-library path is writable outside trusted administration: " + str(path))
            protected.append(path)
    if sys.platform == "darwin":
        for offset in range(0, len(protected), 64):
            listing = run(["/bin/ls", "-lde", *protected[offset:offset + 64]]).stdout
            if any(line and "+" in line.split()[0] for line in listing.splitlines()):
                raise ValueError("The Python standard library has an unexpected ACL grant.")
    return resolved


def has_acl(path):
    first = run(["/bin/ls", "-lde", str(path)]).stdout.splitlines()[0].split()[0]
    return "+" in first


def ensure_absent_accounts():
    for name in (COLLECTOR, CUSTODIAN):
        try:
            pwd.getpwnam(name)
        except KeyError:
            continue
        raise ValueError("Reserved account already exists; refusing to reuse or modify it: " + name)
    try:
        grp.getgrnam(GROUP)
    except KeyError:
        return
    raise ValueError("Reserved group already exists; refusing to modify it: " + GROUP)


def allocate_ids(users, groups):
    used_users = {entry.pw_uid for entry in users}
    used_groups = {entry.gr_gid for entry in groups}
    user_ids = [number for number in range(450, 500) if number not in used_users]
    group_ids = [number for number in range(450, 500) if number not in used_groups]
    if len(user_ids) < 2 or not group_ids:
        raise ValueError("No unused service IDs in the reserved installation range.")
    return user_ids[0], user_ids[1], group_ids[0]


def runtime_config(collector_uid, custodian_uid, shared_gid):
    return {"version": 1, "data_dir": str(PREFIX / "data"),
            "trust_dir": str(PREFIX / "custody/trust"), "key_dir": str(PREFIX / "custody/keys"),
            "collector_uid": collector_uid, "custodian_uid": custodian_uid, "shared_gid": shared_gid}


def daemon_definition(runtime):
    return {"Label": LABEL, "UserName": COLLECTOR, "GroupName": GROUP,
            "InitGroups": True,
            "ProgramArguments": [str(runtime), "-I", "-S", "-B", str(PREFIX / "app/scripts/local_operator.py"), "--worker", "serve"],
            "WorkingDirectory": str(PREFIX), "RunAtLoad": True, "KeepAlive": True,
            "ThrottleInterval": 30, "Umask": 0o027,
            "EnvironmentVariables": {"PATH": "/usr/bin:/bin", "HOME": "/var/empty", "TMPDIR": "/private/tmp"},
            "StandardOutPath": str(PREFIX / "logs/collector.stdout.log"),
            "StandardErrorPath": str(PREFIX / "logs/collector.stderr.log")}


def installation_plan(source=SOURCE, runtime=DEFAULT_RUNTIME):
    source = Path(source).absolute()
    details = inspect_source(source)
    if PREFIX.exists() or PREFIX.is_symlink() or PLIST.exists() or PLIST.is_symlink():
        raise ValueError("An installation destination already exists; this installer never overwrites it.")
    if sys.platform == "darwin":
        existing_job = subprocess.run(["/bin/launchctl", "print", "system/" + LABEL], capture_output=True,
                                      text=True, timeout=10, check=False)
        if existing_job.returncode == 0:
            raise ValueError("The reserved service label already exists; it will not be replaced.")
    ensure_absent_accounts()
    resolved_runtime = inspect_runtime(runtime)
    return {"mode": "plan_only", "source": str(source), "destination": str(PREFIX),
            "runtime": str(resolved_runtime), "source_checkpoint": details,
            "accounts": [COLLECTOR, CUSTODIAN], "group": GROUP,
            "actions": ["Create two hidden disabled-login non-administrator service accounts.",
                        "Copy application into root-owned, service-read-only storage.",
                        "Copy existing evidence, original signing key, and accepted checkpoint without reinitializing or changing identity.",
                        "Give the collector write access to evidence; give the custodian exclusive key and trust-reference write access.",
                        "Verify the copied archive and original signing identity as real service accounts.",
                        "Test denied reads, replacements, removals, and permission changes as the collector.",
                        "Start the loopback-only dashboard only after all checks pass."],
            "unchanged": ["Original workspace archive and key remain in place as administrator-controlled legacy copies.",
                          "No AWS deployment, passwordless sudo rule, or signing web endpoint."]}


def write_owned(path, content, uid, gid, mode):
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fchown(handle.fileno(), uid, gid)
        os.fchmod(handle.fileno(), mode)
        os.fsync(handle.fileno())


def mkdir_owned(path, uid, gid, mode):
    path.mkdir(mode=mode)
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def snapshot_tree(root):
    result = {}
    size = 0
    for file in tree_files(root):
        content = read_regular(file)
        size += len(content)
        if size > MAX_TOTAL:
            raise ValueError("Migration exceeds the one-gigabyte safety limit.")
        result[str(file.relative_to(root))] = content
    return result


def copy_snapshot(snapshot, destination, uid, gid, dir_mode, file_mode):
    mkdir_owned(destination, uid, gid, dir_mode)
    for relative, content in sorted(snapshot.items()):
        target = destination / relative
        for parent in reversed(target.parents):
            if parent == destination or parent.is_relative_to(destination):
                if not parent.exists():
                    mkdir_owned(parent, uid, gid, dir_mode)
        mode = file_mode(relative) if callable(file_mode) else file_mode
        write_owned(target, content, uid, gid, mode)


def app_snapshot(source):
    files = {}
    for path in tree_files(source / "heltemes"):
        relative = path.relative_to(source)
        if "__pycache__" in relative.parts or path.suffix == ".pyc":
            continue
        if path.suffix not in {".py", ".html", ".css", ".js", ".json", ".svg", ".ico"}:
            raise ValueError("Unexpected application file: " + str(relative))
        files[str(relative)] = read_regular(path)
    for name in ("local_operator.py", "install_local_accounts.py"):
        files["scripts/" + name] = read_regular(source / "scripts" / name)
    if "heltemes/local_accounts.py" not in files:
        raise ValueError("Managed runtime implementation is missing; do not install an older release.")
    return files


def create_accounts(collector_uid, custodian_uid, shared_gid, *, existing_collector=False, progress=None):
    progress = progress if progress is not None else {"stage": "account_creation", "completed_commands": []}
    def mutate(arguments):
        progress["next_command"] = arguments
        journal(PREFIX / ".installation-journal.json", progress)
        try:
            run(arguments)
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            progress["last_error"] = str(error)
            journal(PREFIX / ".installation-journal.json", progress)
            raise
        progress.setdefault("completed_commands", []).append(arguments)
        progress.pop("next_command", None)
        progress.pop("last_error", None)
        journal(PREFIX / ".installation-journal.json", progress)

    def set_missing(record_path, key, value, *, fresh=False):
        current = single(directory_record(record_path), key, optional=True)
        if current == value:
            return
        if current is not None and not fresh:
            raise ValueError("An existing account attribute conflicts with the reviewed recovery: " + key)
        mutate(["/usr/bin/dscl", ".", "-create", record_path, key, value])

    group_path = "/Groups/" + GROUP
    if not existing_collector:
        mutate(["/usr/bin/dscl", ".", "-create", group_path])
        set_missing(group_path, "PrimaryGroupID", str(shared_gid), fresh=True)
    group_uuid = assigned_uuid(group_path)
    progress["group_uuid"] = group_uuid
    identifiers = []
    for name, uid, title in ((COLLECTOR, collector_uid, "HELTEMES Evidence Collector"),
                             (CUSTODIAN, custodian_uid, "HELTEMES Evidence Custodian")):
        record = "/Users/" + name
        is_existing = existing_collector and name == COLLECTOR
        if not is_existing:
            mutate(["/usr/bin/dscl", ".", "-create", record])
        # These two writes succeeded before the observed UUID failure. Read the
        # OS UUID after its POSIX identity exists, then preserve it throughout.
        set_missing(record, "UniqueID", str(uid), fresh=not is_existing)
        set_missing(record, "PrimaryGroupID", str(shared_gid), fresh=not is_existing)
        identifier = assigned_uuid(record)
        progress.setdefault("account_uuids", {})[name] = identifier
        journal(PREFIX / ".installation-journal.json", progress)
        for attribute, value in {"RealName": title, "UserShell": "/usr/bin/false",
                                 "NFSHomeDirectory": "/var/empty", "IsHidden": "1"}.items():
            # An empty display name is the specific observed failure state.
            existing = single(directory_record(record), attribute, optional=True)
            if is_existing and attribute == "RealName" and existing == "":
                mutate(["/usr/bin/dscl", ".", "-create", record, attribute, value])
            else:
                set_missing(record, attribute, value, fresh=not is_existing)
        password = single(directory_record(record), "Password", optional=True)
        if password not in {None, "*", "********"}:
            raise ValueError("Unexpected password material; account setup stopped without replacing it.")
        if password != "*":
            mutate(["/usr/bin/dscl", ".", "-create", record, "Password", "*"])
        # A locked password marker and no usable authentication method are
        # verified; we do not manufacture or overwrite authentication authorities.
        validate_disabled_record(directory_record(record), name, uid, shared_gid)
        if assigned_uuid(record) != identifier:
            raise ValueError("macOS-assigned account UUID changed during setup.")
        identifiers.append(identifier)
    if assigned_uuid(group_path) != group_uuid:
        raise ValueError("macOS-assigned group UUID changed during setup.")
    mutate(["/usr/bin/dscl", ".", "-create", group_path, "GroupMembership", COLLECTOR, CUSTODIAN])
    mutate(["/usr/bin/dscl", ".", "-create", group_path, "GroupMembers", *identifiers])
    for name, uid in ((COLLECTOR, collector_uid), (CUSTODIAN, custodian_uid)):
        account = pwd.getpwnam(name)
        if (account.pw_uid, account.pw_gid, account.pw_shell) != (uid, shared_gid, "/usr/bin/false"):
            raise ValueError("Created service account did not match the reviewed configuration.")
        denied_groups = {0, grp.getgrnam("admin").gr_gid}
        if set(os.getgrouplist(name, shared_gid)) & denied_groups:
            raise ValueError("Service account unexpectedly belongs to an administrator group.")


def create_logs(shared_gid):
    # launchd may open output after dropping to the service identity. Only
    # these diagnostic files are group writable; their protected parent
    # prevents the collector from replacing them with symbolic links.
    mkdir_owned(PREFIX / "logs", 0, shared_gid, 0o750)
    for filename in ("collector.stdout.log", "collector.stderr.log"):
        write_owned(PREFIX / "logs" / filename, b"", 0, shared_gid, 0o660)


def data_mode(relative):
    if relative == "settings.json":
        return 0o600
    if relative in {"data.sqlite3", ".operation.lock"}:
        return 0o640
    return 0o440


def install(source=SOURCE, runtime=DEFAULT_RUNTIME, *, recovery_spec=None):
    if sys.platform != "darwin" or os.geteuid() != 0:
        raise ValueError("Installation must be run by a Mac administrator through the native administrator prompt.")
    plan = recovery_plan(source, runtime, recovery_spec) if recovery_spec is not None else installation_plan(source, runtime)
    source, runtime = Path(plan["source"]), Path(plan["runtime"])
    data, trust, keys = source_paths(source)
    # Reject a legacy dashboard before creating any persistent account or path.
    import socket
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", 8765))
        except OSError as error:
            raise ValueError("Port 8765 is already occupied. Quit the old dashboard before activating separate accounts.") from error
    plain_path(PREFIX.parent, directory=True)
    plain_path(PLIST.parent, directory=True)
    for parent in (PREFIX.parent, PLIST.parent):
        meta = parent.stat()
        if meta.st_uid != 0 or meta.st_mode & 0o022 or has_acl(parent):
            raise ValueError("Installation parent is not protected by root ownership: " + str(parent))
    lock = os.open(data / ".operation.lock", os.O_RDONLY | os.O_NOFOLLOW)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        evidence, public, private = snapshot_tree(data), snapshot_tree(trust), snapshot_tree(keys)
        captured_anchor = json.loads(public["anchor.json"])
        for field in ("archive_id", "sequence", "checkpoint_sha256"):
            if captured_anchor[field] != plan["source_checkpoint"][field]:
                raise ValueError("The accepted source checkpoint changed after preflight; review the updated plan.")
        application = app_snapshot(source)
        if recovery_spec is not None:
            collector_uid, custodian_uid, shared_gid = (recovery_spec[key] for key in ("collector_uid", "custodian_uid", "shared_gid"))
        else:
            collector_uid, custodian_uid, shared_gid = allocate_ids(pwd.getpwall(), grp.getgrall())
        # Make the root private before copying anything; a partially failed install
        # stays stopped and is retained for an administrator to inspect.
        if recovery_spec is not None:
            if recovery_state(recovery_spec, source)["state_sha256"] != plan["state_sha256"]:
                raise ValueError("The inspected recovery state changed before the first write; stopped.")
        else:
            mkdir_owned(PREFIX, 0, 0, 0o700)
        progress = {"version": 1, "stage": "account_creation", "source_checkpoint": plan["source_checkpoint"],
                    "collector_uid": collector_uid, "custodian_uid": custodian_uid, "shared_gid": shared_gid,
                    "completed_commands": [], "recovery_state_sha256": plan.get("state_sha256")}
        journal(PREFIX / ".installation-journal.json", progress)
        create_accounts(collector_uid, custodian_uid, shared_gid, existing_collector=recovery_spec is not None, progress=progress)
        progress["stage"] = "accounts_verified_before_migration"
        journal(PREFIX / ".installation-journal.json", progress)
        copy_snapshot(application, PREFIX / "app", 0, 0, 0o755, 0o644)
        copy_snapshot(evidence, PREFIX / "data", collector_uid, shared_gid, 0o750, data_mode)
        mkdir_owned(PREFIX / "custody", custodian_uid, shared_gid, 0o750)
        copy_snapshot(public, PREFIX / "custody/trust", custodian_uid, shared_gid, 0o750, 0o440)
        copy_snapshot(private, PREFIX / "custody/keys", custodian_uid, shared_gid, 0o700, 0o400)
        mkdir_owned(PREFIX / "backups", collector_uid, shared_gid, 0o750)
        create_logs(shared_gid)
        configuration = runtime_config(collector_uid, custodian_uid, shared_gid)
        write_owned(PREFIX / "runtime.json", (json.dumps(configuration, indent=2) + "\n").encode(), 0, 0, 0o644)
        write_owned(PREFIX / "runtime-python.txt", (str(runtime) + "\n").encode(), 0, 0, 0o644)
        write_owned(PREFIX / "migration-source.json", (json.dumps({"original_key_path": str(keys / "signing_key")}) + "\n").encode(), 0, 0, 0o644)
        # Remove inherited ACLs as well as enforcing mode bits. Never alter the
        # system interpreter or any pre-existing user data.
        run(["/bin/chmod", "-RN", str(PREFIX)])
        os.chmod(PREFIX, 0o755)
        if snapshot_tree(data) != evidence or snapshot_tree(trust) != public or snapshot_tree(keys) != private:
            raise ValueError("Original archive changed during migration; the new service remains stopped.")
        for copied, expected in ((PREFIX / "data", evidence), (PREFIX / "custody/trust", public),
                                 (PREFIX / "custody/keys", private)):
            if snapshot_tree(copied) != expected:
                raise ValueError("Byte-preservation check failed; the new service remains stopped.")
        operator = PREFIX / "app/scripts/local_operator.py"
        probe = run([runtime, "-I", "-S", "-B", operator, "probe"])
        proof = json.loads(probe.stdout)
        if not proof.get("ok"):
            raise ValueError("Separate-account verification failed; the dashboard remains stopped.")
        proof.update({"source_checkpoint": plan["source_checkpoint"], "migration_bytes_preserved": True,
                      "original_preserved": True, "aws_deployed": False, "accounts_created": True,
                      "application_sha256": {name: hashlib.sha256(content).hexdigest() for name, content in application.items()}})
        write_owned(PLIST, plistlib.dumps(daemon_definition(runtime)), 0, 0, 0o644)
        run(["/bin/chmod", "-N", str(PLIST)])
        start_result = json.loads(run([runtime, "-I", "-S", "-B", operator, "start"]).stdout)
        proof["dashboard_started"] = True
        proof["dashboard"] = start_result
        write_owned(PREFIX / "installation-report.json", (json.dumps(proof, indent=2) + "\n").encode(), 0, 0, 0o644)
        progress["stage"] = "complete"
        journal(PREFIX / ".installation-journal.json", progress)
        return proof
    except BaseException:
        if PREFIX.exists():
            # This prefix and job were absent at preflight. Keep every copied
            # archive/key and account, but never leave an unproved service active.
            subprocess.run(["/bin/launchctl", "bootout", "system/" + LABEL], capture_output=True,
                           text=True, timeout=30, check=False)
        raise
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true", help="Read-only inspection and exact migration plan (default)")
    mode.add_argument("--install", action="store_true", help="Create accounts, migrate, prove permissions, and start; requires root")
    mode.add_argument("--resume-early", action="store_true", help="Resume only the explicitly reviewed empty-directory/partial-collector failure")
    mode.add_argument("--recovery-plan", action="store_true", help="Read-only administrator inspection of the reviewed early failure")
    parser.add_argument("--recovery-spec", type=Path, help="Exact previously reviewed identities and checkpoint for narrow recovery")
    parser.add_argument("--source", type=Path, default=SOURCE)
    parser.add_argument("--runtime", type=Path, default=DEFAULT_RUNTIME)
    args = parser.parse_args(argv)
    try:
        if args.resume_early or args.recovery_plan:
            if args.recovery_spec is None:
                raise ValueError("Narrow recovery requires the reviewed recovery specification.")
            spec = load_recovery_spec(args.recovery_spec)
            result = recovery_plan(args.source, args.runtime, spec) if args.recovery_plan else install(args.source, args.runtime, recovery_spec=spec)
        elif args.recovery_spec is not None:
            raise ValueError("A recovery specification must be used with an explicit recovery mode.")
        else:
            result = install(args.source, args.runtime) if args.install else installation_plan(args.source, args.runtime)
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as error:
        parser.exit(1, "Stopped without resetting evidence or trust: " + str(error) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
