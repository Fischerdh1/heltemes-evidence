#!/usr/bin/env python3
"""Install one explicitly reviewed public recovery authorization, never a key.

The administrator branch imports only the standard library and dispatches only
the verified installed operator's read-only receipt action. It cannot prepare,
resume, sign, change accounts, or write outside its fixed authorization folder.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import uuid

PREFIX = Path("/Library/HELTEMES Evidence")
AUTHORIZATIONS = PREFIX / "recovery-authorizations"
RUNTIME = Path("/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14")
MAX_REQUEST = 32_768
MAX_HELPER = 256 * 1024
ENV = {"PATH": "/usr/bin:/bin", "HOME": "/var/empty", "TMPDIR": "/private/tmp"}

# Hash before executing any source bytes as administrator. The parent process
# supplies the digest of the helper it reviewed before native authentication.
BOOTSTRAP = """import hashlib,os,stat,sys
source,expected=sys.argv[1:3]
fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
try:
 info=os.fstat(fd)
 if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>262144: raise SystemExit('Unsafe approval helper.')
 raw=os.read(fd,262145)
finally: os.close(fd)
if hashlib.sha256(raw).hexdigest()!=expected: raise SystemExit('Approval helper changed after review.')
sys.argv=[source,*sys.argv[3:]]
exec(compile(raw,source,'exec'),{'__name__':'__main__','__file__':source})
"""


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def parse_json(raw):
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate authorization field.")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON value.")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("Malformed authorization JSON.") from error
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object.")
    return value


def identifier(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("Malformed archive or transition identity.")


def is_hash(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def key_fingerprint(value):
    if not isinstance(value, str) or len(value) > 1024 or "\n" in value or "\r" in value:
        raise ValueError("Malformed public key.")
    parts = value.split(" ")
    if len(parts) != 2 or parts[0] != "ssh-ed25519":
        raise ValueError("A canonical Ed25519 public key is required.")
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except ValueError as error:
        raise ValueError("Malformed public key encoding.") from error
    if len(raw) != 51 or not raw.startswith(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"):
        raise ValueError("Malformed Ed25519 public key structure.")
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")


def validate_receipt(receipt):
    fields = {"format", "version", "archive_id", "public_key", "key_fingerprint", "sequence", "checkpoint_sha256", "checkpoint_at"}
    if isinstance(receipt, dict) and receipt.get("version") == 2:
        fields.add("key_epochs")
    if (not isinstance(receipt, dict) or set(receipt) != fields or receipt.get("format") != "heltemes-trust-anchor"
            or type(receipt.get("version")) is not int or receipt["version"] not in {1, 2}
            or type(receipt.get("sequence")) is not int or not 1 <= receipt["sequence"] < 1000
            or not is_hash(receipt.get("checkpoint_sha256")) or not isinstance(receipt.get("checkpoint_at"), str)
            or len(receipt["checkpoint_at"]) > 40 or len(canonical(receipt)) > 16_384):
        raise ValueError("Unsupported recovery receipt.")
    identifier(receipt["archive_id"])
    if key_fingerprint(receipt["public_key"]) != receipt["key_fingerprint"]:
        raise ValueError("Receipt public-key fingerprint mismatch.")
    keys = {receipt["public_key"]}
    if receipt["version"] == 2:
        epochs = receipt["key_epochs"]
        if not isinstance(epochs, list) or not 2 <= len(epochs) < 32:
            raise ValueError("Unsupported key epoch count.")
        keys, transitions, previous = set(), set(), 0
        for index, epoch in enumerate(epochs):
            fields = {"start_sequence", "public_key", "key_fingerprint", "transition_id", "approval_sha256", "previous_checkpoint_sha256"}
            if not isinstance(epoch, dict) or set(epoch) != fields:
                raise ValueError("Malformed key epoch.")
            start = epoch["start_sequence"]
            if type(start) is not int or not previous < start <= receipt["sequence"] or (index == 0 and start != 1):
                raise ValueError("Invalid key epoch sequence.")
            if key_fingerprint(epoch["public_key"]) != epoch["key_fingerprint"] or epoch["public_key"] in keys:
                raise ValueError("Invalid or repeated epoch public key.")
            if index == 0:
                if any(epoch[name] is not None for name in ("transition_id", "approval_sha256", "previous_checkpoint_sha256")):
                    raise ValueError("Original key epoch cannot have a transition authorization.")
            else:
                identifier(epoch["transition_id"])
                if epoch["transition_id"] in transitions or not all(is_hash(epoch[name]) for name in ("approval_sha256", "previous_checkpoint_sha256")):
                    raise ValueError("Invalid key epoch authorization.")
                transitions.add(epoch["transition_id"])
            keys.add(epoch["public_key"])
            previous = start
        if (receipt["public_key"], receipt["key_fingerprint"]) != (epochs[-1]["public_key"], epochs[-1]["key_fingerprint"]):
            raise ValueError("Receipt active key differs from the final key epoch.")
    return keys


def validate_request(raw, expected_sha256):
    if len(raw) > MAX_REQUEST or not is_hash(expected_sha256) or digest(raw) != expected_sha256:
        raise ValueError("Request differs from the independently reviewed SHA-256.")
    value = parse_json(raw)
    fields = {"format", "version", "action", "transition_id", "archive_id", "old_receipt", "old_receipt_sha256", "candidate_public_key", "candidate_key_fingerprint"}
    if (set(value) != fields or value.get("format") != "heltemes-key-recovery-authorization"
            or type(value.get("version")) is not int or value["version"] != 1 or value.get("action") != "replace_signing_key"):
        raise ValueError("Unsupported recovery authorization request.")
    identifier(value["transition_id"])
    keys = validate_receipt(value["old_receipt"])
    if (value["archive_id"] != value["old_receipt"]["archive_id"]
            or value["old_receipt_sha256"] != digest(canonical(value["old_receipt"]))
            or key_fingerprint(value["candidate_public_key"]) != value["candidate_key_fingerprint"]
            or value["candidate_public_key"] in keys or canonical(value) != raw):
        raise ValueError("Recovery request identity, key, receipt, or canonical encoding mismatch.")
    return value


def reject_acl(path):
    if sys.platform == "darwin":
        result = subprocess.run(["/bin/ls", "-lde", str(path)], stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=10, check=True, env=ENV)
        if len(result.stdout.splitlines()) != 1:
            raise ValueError("Approval paths must not carry extended ACLs.")


def protected_metadata(info, *, directory=False, mode=None, links=1):
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022
            or (not directory and info.st_nlink != links)
            or (mode is not None and stat.S_IMODE(info.st_mode) != mode)):
        raise ValueError("Approval infrastructure must be root-owned and service-read-only.")


@contextmanager
def directory_fd(path, *, protected=False):
    path = Path(path).expanduser().absolute()
    if ".." in path.parts:
        raise ValueError("Parent traversal is not allowed.")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            if protected:
                protected_metadata(os.fstat(fd), directory=True)
        if protected:
            reject_acl(path)
        yield fd
    finally:
        os.close(fd)


def read_regular(path, *, maximum=MAX_REQUEST, protected=False, mode=None):
    path = Path(path).expanduser().absolute()
    with directory_fd(path.parent, protected=protected) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
                raise ValueError("Expected a bounded, ordinary, unlinked file.")
            if protected:
                protected_metadata(info, mode=mode)
                reject_acl(path)
            raw = bytearray()
            while len(raw) <= maximum:
                chunk = os.read(fd, min(65_536, maximum + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) > maximum:
                raise ValueError("File exceeds its size limit.")
            return bytes(raw)
        finally:
            os.close(fd)


def installed_preflight():
    if (sys.platform != "darwin" or os.getuid() != 0 or os.geteuid() != 0
            or not sys.flags.isolated or not sys.flags.no_site or not sys.dont_write_bytecode):
        raise ValueError("Use the native approval launcher and isolated installed runtime.")
    runtime = read_regular(PREFIX / "runtime-python.txt", protected=True, mode=0o644, maximum=4096).decode().strip()
    if runtime != str(RUNTIME) or Path(sys.executable).resolve() != RUNTIME:
        raise ValueError("The installed runtime does not match the fixed approval runtime.")
    # Python.framework is root/admin-managed on this Mac. Only trusted root or
    # admin group writers are allowed; collector/custodian/world writers are not.
    trusted_groups = {0, grp.getgrnam("admin").gr_gid}
    for path in (RUNTIME, *RUNTIME.parents):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o002 or (info.st_mode & 0o020 and info.st_gid not in trusted_groups):
            raise ValueError("The installed runtime is writable outside trusted administration.")
        reject_acl(path)
    report = parse_json(read_regular(PREFIX / "installation-report.json", protected=True, mode=0o644, maximum=2 * 1024 * 1024))
    actual = {}
    app = PREFIX / "app"
    with directory_fd(app, protected=True):
        for folder, directories, files in os.walk(app, followlinks=False):
            for name in directories:
                with directory_fd(Path(folder) / name, protected=True):
                    pass
            for name in files:
                path = Path(folder) / name
                actual[path.relative_to(app).as_posix()] = digest(read_regular(path, protected=True, mode=0o644, maximum=4 * 1024 * 1024))
    if report.get("ok") is not True or not actual or actual != report.get("application_sha256"):
        raise ValueError("Installed application differs from its protected manifest.")


def current_receipt():
    result = subprocess.run([str(RUNTIME), "-I", "-S", "-B", str(PREFIX / "app/scripts/local_operator.py"), "receipt"],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=240, check=False, env=ENV, cwd=PREFIX)
    if result.returncode or len(result.stdout) > MAX_REQUEST:
        raise ValueError("Independent custodian receipt verification failed; no approval installed.")
    receipt = parse_json(result.stdout)
    validate_receipt(receipt)
    return receipt


@contextmanager
def approval_lock():
    with directory_fd(PREFIX, protected=True) as parent:
        fd = os.open(".key-recovery-approval.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=parent)
        try:
            protected_metadata(os.fstat(fd), mode=0o600)
            reject_acl(PREFIX / ".key-recovery-approval.lock")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)


def ensure_authorization_directory():
    with directory_fd(PREFIX, protected=True) as parent:
        try:
            os.mkdir(AUTHORIZATIONS.name, 0o755, dir_fd=parent)
            os.chown(AUTHORIZATIONS.name, 0, 0, dir_fd=parent, follow_symlinks=False)
            os.chmod(AUTHORIZATIONS.name, 0o755, dir_fd=parent, follow_symlinks=False)
            os.fsync(parent)
        except FileExistsError:
            pass
    with directory_fd(AUTHORIZATIONS, protected=True) as parent:
        protected_metadata(os.fstat(parent), directory=True, mode=0o755)


def publish_exact(path, raw):
    """Publish a complete file without ever replacing an existing authorization."""
    with directory_fd(AUTHORIZATIONS, protected=True) as parent:
        try:
            existing = read_regular(path, protected=True, mode=0o444)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if existing != raw:
                raise ValueError("An existing authorization differs; it was not replaced.")
            return False
        temporary = ".pending-" + uuid.uuid4().hex
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                os.fchown(handle.fileno(), 0, 0)
                handle.write(raw)
                handle.flush()
                os.fchmod(handle.fileno(), 0o444)
                os.fsync(handle.fileno())
            # link is an atomic no-replace publication. The short nlink=2 window
            # fails closed for readers. A retry removes only the exact pending
            # alias after matching the reviewed bytes and both inode identities.
            os.link(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
            os.unlink(temporary, dir_fd=parent)
            os.fsync(parent)
        finally:
            try:
                os.unlink(temporary, dir_fd=parent)
            except FileNotFoundError:
                pass
        return True


def finish_exact_publication(path, raw):
    """Finish only a proven interrupted link/unlink publication under our lock."""
    with directory_fd(AUTHORIZATIONS, protected=True) as parent:
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except FileNotFoundError:
            return
        try:
            info = os.fstat(fd)
            if info.st_nlink == 1:
                return
            protected_metadata(info, mode=0o444, links=2)
            if info.st_size != len(raw) or os.read(fd, MAX_REQUEST + 1) != raw:
                raise ValueError("Interrupted approval publication does not match the reviewed bytes.")
            matches = []
            for name in os.listdir(parent):
                if not re.fullmatch(r"\.pending-[0-9a-f]{32}", name):
                    continue
                candidate = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (candidate.st_dev, candidate.st_ino) == (info.st_dev, info.st_ino):
                    protected_metadata(candidate, mode=0o444, links=2)
                    matches.append(name)
            if len(matches) != 1:
                raise ValueError("Interrupted approval has an unknown or ambiguous link; stopped.")
            os.unlink(matches[0], dir_fd=parent)
            os.fsync(parent)
            protected_metadata(os.fstat(fd), mode=0o444)
        finally:
            os.close(fd)


def install_authorization(request_path, expected_sha256):
    installed_preflight()
    raw = read_regular(request_path)
    request = validate_request(raw, expected_sha256)
    destination = AUTHORIZATIONS / (request["transition_id"] + ".json")
    sidecar = destination.with_suffix(".json.sha256")
    with approval_lock():
        ensure_authorization_directory()
        finish_exact_publication(sidecar, (expected_sha256 + "\n").encode())
        finish_exact_publication(destination, raw)
        # An exact already installed authorization is a retry, not fresh authority.
        try:
            existing = read_regular(destination, protected=True, mode=0o444)
            sidecar_raw = read_regular(sidecar, protected=True, mode=0o444)
        except FileNotFoundError:
            existing, sidecar_raw = None, None
        if existing == raw and sidecar_raw == (expected_sha256 + "\n").encode():
            return {"ok": True, "authorization": str(destination), "authorization_sha256": expected_sha256,
                    "transition_id": request["transition_id"], "already_installed": True, "transition_started": False}
        if current_receipt() != request["old_receipt"]:
            raise ValueError("The reviewed receipt is not the currently accepted archive head; no approval installed.")
        # Check both destinations before publishing either on an incomplete retry.
        for path, content in ((destination, raw), (sidecar, (expected_sha256 + "\n").encode())):
            try:
                if read_regular(path, protected=True, mode=0o444) != content:
                    raise ValueError("Existing approval material conflicts with this exact request.")
            except FileNotFoundError:
                pass
        publish_exact(sidecar, (expected_sha256 + "\n").encode())
        publish_exact(destination, raw)
    return {"ok": True, "authorization": str(destination), "authorization_sha256": expected_sha256,
            "transition_id": request["transition_id"], "already_installed": False, "transition_started": False}


def frontend(request_path, expected_sha256):
    path = Path(request_path).expanduser().absolute()
    request = validate_request(read_regular(path), expected_sha256)
    helper = Path(__file__).absolute()
    helper_sha = digest(read_regular(helper, maximum=MAX_HELPER))
    old = request["old_receipt"]
    print("HELTEMES Evidence — authorize one reviewed recovery")
    print("Archive: " + request["archive_id"])
    print(f"Accepted checkpoint: {old['sequence']} / {old['checkpoint_sha256']}")
    print("Previously accepted key: " + old["key_fingerprint"])
    print("Approved replacement key: " + request["candidate_key_fingerprint"])
    print("Authorization SHA-256: " + expected_sha256)
    print("This installs public approval only. It does not install a key or begin recovery.")
    print("Enter your Mac password only at the native Terminal prompt.", flush=True)
    authentication = subprocess.run(["/usr/bin/sudo", "-v"], check=False)
    if authentication.returncode:
        raise ValueError("Mac authentication did not complete; no approval installed.")
    command = ["/usr/bin/sudo", "-n", "--", str(RUNTIME), "-I", "-S", "-B", "-c", BOOTSTRAP,
               str(helper), helper_sha, "--administrator", str(path), "--expected-sha256", expected_sha256]
    return subprocess.run(command, check=False).returncode


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", help="Canonical public request that was independently reviewed")
    parser.add_argument("--expected-sha256", required=True, help="Exact independently approved request digest")
    parser.add_argument("--administrator", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.administrator:
            print(json.dumps(install_authorization(args.request, args.expected_sha256), indent=2))
            return 0
        if os.geteuid() == 0:
            raise ValueError("Run the review frontend as your normal account; it opens native authentication.")
        return frontend(args.request, args.expected_sha256)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, "Stopped without starting key recovery: " + str(error) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
