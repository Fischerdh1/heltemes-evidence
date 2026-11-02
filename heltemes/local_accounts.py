"""Fixed, administrator-installed local account boundary (no environment policy).

The operating system, protected application code, and custodian remain trusted.
Collector-owned bytes are always untrusted inputs, even when a lock is held.
"""
from __future__ import annotations

import fcntl
import json
import os
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

PREFIX = Path("/Library/HELTEMES Evidence")
MAX_COPY_BYTES = 200 * 1024 * 1024
MAX_ASSETS = 20_000


def _absolute(path):
    value = Path(path).expanduser().absolute()
    if ".." in value.parts:
        raise ValueError("Managed paths cannot contain parent traversal.")
    return value


@contextmanager
def _open_directory(path):
    """Pin every ancestor with openat, rejecting symlinks at each hop."""
    path = _absolute(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


@contextmanager
def _open_file(path):
    path = _absolute(path)
    with _open_directory(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("Managed inputs must be regular files without hard links.")
            yield fd
        finally:
            os.close(fd)


def _reject_acl(path):
    # macOS ACL entries can grant access that is not reflected in POSIX mode bits.
    if sys.platform == "darwin":
        try:
            result = subprocess.run(["/bin/ls", "-lde", str(path)], capture_output=True,
                                    text=True, check=True, timeout=5, env={"LC_ALL": "C"})
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError("Managed access-control metadata could not be checked.") from error
        token = result.stdout.split(None, 1)[0]
        if "+" in token:
            raise ValueError("Managed protected paths must not contain additional ACL grants.")


def _protected(path, owners, *, directory=False, mode=None, group=None):
    manager = _open_directory(path) if directory else _open_file(path)
    with manager as fd:
        metadata = os.fstat(fd)
        if metadata.st_uid not in owners or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ValueError("Managed trust, policy, and code must have protected ownership and permissions.")
        if mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
            raise ValueError("Managed protected path permissions differ from the installed policy.")
        if group is not None and metadata.st_gid != group:
            raise ValueError("Managed shared-group ownership differs from the installed policy.")
        _reject_acl(path)


@dataclass(frozen=True)
class Policy:
    data_dir: Path
    trust_dir: Path
    key_dir: Path
    collector_uid: int
    custodian_uid: int
    shared_gid: int

    def require(self, role):
        expected = self.collector_uid if role == "collector" else self.custodian_uid
        if os.geteuid() != expected:
            raise ValueError(f"This managed operation must run as the {role} account.")


def _protected_key_directory(policy):
    with _open_directory(policy.key_dir.parent) as parent_fd:
        metadata = os.stat(policy.key_dir.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != policy.custodian_uid or stat.S_IMODE(metadata.st_mode) != 0o700:
            raise ValueError("Managed private-key directory must be custodian-owned and owner-only.")
    _reject_acl(policy.key_dir)


def policy_for(data_dir) -> Policy | None:
    """Fail closed for the reserved managed data path, including unsafe aliases."""
    candidate = Path(data_dir).expanduser().absolute()
    managed = PREFIX / "data"
    if candidate != managed:
        if candidate.resolve() == managed.resolve() or candidate.is_relative_to(managed):
            raise ValueError("Use the exact administrator-installed managed data path.")
        return None
    candidate = _absolute(candidate)
    for parent in (PREFIX, *PREFIX.parents):
        _protected(parent, {0}, directory=True)
    config_path = PREFIX / "runtime.json"
    _protected(config_path, {0}, mode=0o644)
    with _open_file(config_path) as fd:
        raw = os.read(fd, 8193)
    if len(raw) > 8192:
        raise ValueError("Managed runtime policy is too large.")
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate managed runtime policy field.")
            result[key] = value
        return result
    config = json.loads(raw, object_pairs_hook=unique)
    expected = {"version", "data_dir", "trust_dir", "key_dir", "collector_uid", "custodian_uid", "shared_gid"}
    if not isinstance(config, dict) or set(config) != expected or type(config["version"]) is not int or config["version"] != 1:
        raise ValueError("Unsupported managed runtime policy.")
    for name, value in {"data_dir": managed, "trust_dir": PREFIX / "custody" / "trust", "key_dir": PREFIX / "custody" / "keys"}.items():
        if config[name] != str(value):
            raise ValueError("Managed policy contains a nonstandard path.")
    for key in ("collector_uid", "custodian_uid", "shared_gid"):
        if type(config[key]) is not int or config[key] <= 0:
            raise ValueError("Managed identities must be non-root numeric identities.")
    if config["collector_uid"] == config["custodian_uid"]:
        raise ValueError("Collector and custodian must be separate operating-system accounts.")
    policy = Policy(managed, PREFIX / "custody" / "trust", PREFIX / "custody" / "keys",
                    config["collector_uid"], config["custodian_uid"], config["shared_gid"])
    _protected(PREFIX / "app", {0}, directory=True)
    _protected(PREFIX / "custody", {policy.custodian_uid}, directory=True, mode=0o750, group=policy.shared_gid)
    _protected(policy.trust_dir, {policy.custodian_uid}, directory=True, mode=0o750, group=policy.shared_gid)
    _protected(policy.trust_dir / "checkpoints", {policy.custodian_uid}, directory=True, mode=0o750, group=policy.shared_gid)
    _protected(policy.trust_dir / "anchor.json", {policy.custodian_uid}, mode=0o440, group=policy.shared_gid)
    for entry in (policy.trust_dir / "checkpoints").iterdir():
        _protected(entry, {policy.custodian_uid}, mode=0o440, group=policy.shared_gid)
    # The collector may inspect directory metadata without opening its contents.
    # This catches an accidentally collector-owned/readable key directory too.
    _protected_key_directory(policy)
    # Only its owning custodian can validate the private key inside that directory.
    if os.geteuid() == policy.custodian_uid:
        _protected(policy.key_dir, {policy.custodian_uid}, directory=True, mode=0o700)
        if os.path.lexists(policy.key_dir / "signing_key"):
            _protected(policy.key_dir / "signing_key", {policy.custodian_uid}, mode=0o400)
    with _open_directory(policy.data_dir) as fd:
        metadata = os.fstat(fd)
        if metadata.st_uid != policy.collector_uid or metadata.st_gid != policy.shared_gid or stat.S_IMODE(metadata.st_mode) != 0o750:
            raise ValueError("Managed evidence directory ownership or permissions changed.")
    if not (policy.data_dir / "protection.json").is_file():
        raise ValueError("Managed evidence requires its protection marker; unsigned downgrade refused.")
    return policy


def require_role(data_dir, role):
    policy = policy_for(data_dir)
    if policy:
        policy.require(role)
    return policy


def public_trust_mode(path):
    """Only the fixed custody vault receives group-readable public files."""
    path = _absolute(path)
    return path.is_relative_to(PREFIX / "custody" / "trust")


def _copy_input(source, destination, budget):
    with _open_file(source) as fd:
        before = os.fstat(fd)
        if before.st_size > budget or before.st_size < 0:
            raise ValueError("Custodian snapshot exceeds its size limit.")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        copied = 0
        with destination.open("xb") as target:
            os.fchmod(target.fileno(), 0o600)
            while True:
                chunk = os.read(fd, min(1024 * 1024, budget - copied + 1))
                if not chunk:
                    break
                copied += len(chunk)
                if copied > budget:
                    raise ValueError("Custodian snapshot exceeds its size limit.")
                target.write(chunk)
            target.flush()
            os.fsync(target.fileno())
        after = os.fstat(fd)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or copied != before.st_size:
            raise ValueError("Collector input changed during custody snapshot; retry while collection is stopped.")
        return copied


@contextmanager
def private_snapshot(policy):
    """Copy hostile inputs before parsing; never sign a mutable collector path."""
    policy.require("custodian")
    stage_parent = PREFIX / "custody" / "staging"
    stage_parent.mkdir(mode=0o700, exist_ok=True)
    _protected(stage_parent, {policy.custodian_uid}, directory=True, mode=0o700)
    lock = stage_parent / ".signing.lock"
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(fd).st_nlink != 1 or not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Invalid custodian signing lock.")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with tempfile.TemporaryDirectory(prefix="checkpoint-", dir=stage_parent) as temporary:
            staging = Path(temporary)
            # Managed collection uses DELETE journaling. Any sidecar means the
            # collector has not reached an idle, safely copyable checkpoint.
            with _open_directory(policy.data_dir) as data_fd:
                for suffix in ("-wal", "-shm", "-journal"):
                    try:
                        os.stat("data.sqlite3" + suffix, dir_fd=data_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise ValueError("Stop collection before sealing; SQLite sidecar files are present.")
            used = _copy_input(policy.data_dir / "protection.json", staging / "protection.json", 4096)
            used += _copy_input(policy.data_dir / "data.sqlite3", staging / "data.sqlite3", MAX_COPY_BYTES - used)
            from .protection import _snapshot, _check_evidence
            snapshot = _snapshot(staging, require_finished=True)
            table = snapshot["tables"]["assets"]
            if len(table["rows"]) > MAX_ASSETS:
                raise ValueError("Custodian snapshot contains too many evidence assets.")
            from .core import _safe_relative
            for row in table["rows"]:
                asset = dict(zip(table["columns"], row))
                relative = _safe_relative(asset["path"])
                used += _copy_input(policy.data_dir.joinpath(*relative.parts), staging.joinpath(*relative.parts), MAX_COPY_BYTES - used)
            _check_evidence(staging, snapshot)
            with _open_directory(policy.data_dir) as data_fd:
                for suffix in ("-wal", "-shm", "-journal"):
                    try:
                        os.stat("data.sqlite3" + suffix, dir_fd=data_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise ValueError("Collector SQLite state changed during custody snapshot; sealing refused.")
            yield staging
    finally:
        os.close(fd)


def seal_managed(policy):
    """Existing signed history remains mandatory; only additions can be accepted."""
    from .protection import seal_checkpoint
    with private_snapshot(policy) as staging:
        result = seal_checkpoint(staging, trust_dir=policy.trust_dir, key_dir=policy.key_dir)
        result["account_isolation"] = "separate-local-accounts"
        result["meaning"] = "A private custodian snapshot was verified and sealed. Collector and custodian use separate operating-system accounts; the operating system, installed application, and custodian remain trusted."
        return result


def verify_managed(policy):
    """Independent custody verification parses only a private, stable copy."""
    from .core import Repository, utc_now
    from .protection import verify_protection
    with private_snapshot(policy) as staging:
        result = Repository(staging).verify_integrity(check_protection=False)
        protection = verify_protection(staging, policy.trust_dir)
        protection["account_isolation"] = "separate-local-accounts"
        protection["meaning"] = "A private custodian snapshot was compared with separately protected trust. The operating system, installed application, and custodian remain trusted."
        result["protection"] = protection
        result["issues"].extend(protection["issues"])
        result["ok"] = result["ok"] and protection["ok"]
        result["meaning"] = protection["meaning"]
        result["accounted_snapshot"] = {"source": str(policy.data_dir), "verified_at": utc_now(),
                                        "scope": "private custodian copy", "checkpoint_created": False}
        return result


def receipt_managed(policy):
    """Return a public receipt only after independent custodian verification."""
    from .protection import _anchor
    result = verify_managed(policy)
    if not result["ok"] or result["protection"]["status"] not in {"sealed", "pending"}:
        raise ValueError("Custodian verification failed; no trust receipt was released.")
    anchor, _ = _anchor(policy.trust_dir / "anchor.json")
    if anchor["checkpoint_sha256"] != result["protection"]["checkpoint_sha256"]:
        raise ValueError("Custodian trust head changed after verification; retry receipt export.")
    return anchor
