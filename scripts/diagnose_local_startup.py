#!/usr/bin/env python3
"""Read fixed local startup diagnostics; never start, stop, repair, or reinitialize."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import grp
import json
import os
from pathlib import Path
import plistlib
import pwd
import re
import selectors
import stat
import subprocess
import sys
import time

PREFIX = Path("/Library/HELTEMES Evidence")
PLIST = Path("/Library/LaunchDaemons/com.heltemes.evidence.collector.plist")
LABEL = "com.heltemes.evidence.collector"
RUNTIME = Path("/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14")
COLLECTOR = "_hevidence_collect"
CUSTODIAN = "_hevidence_custody"
GROUP = "_hevidence"
LIMIT = 64 * 1024
ENVIRONMENT = {"PATH": "/usr/bin:/bin", "LANG": "C", "HOME": "/var/empty", "TMPDIR": "/private/tmp"}
LOG_PREDICATE = 'process == "launchd" AND (eventMessage CONTAINS "com.heltemes.evidence.collector" OR eventMessage CONTAINS "/Library/HELTEMES Evidence/")'


def bounded_command(arguments, timeout=15, limit=LIMIT):
    """Drain fixed command output with a memory and time ceiling."""
    process = subprocess.Popen([str(a) for a in arguments], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=ENVIRONMENT)
    output = bytearray()
    reason = None
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    try:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                reason = "time_limit"
                break
            if selector.select(min(remaining, 0.25)):
                chunk = os.read(process.stdout.fileno(), min(8192, limit - len(output) + 1))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > limit:
                    reason = "output_limit"
                    break
            elif process.poll() is not None:
                continue
        if reason is not None:
            process.kill()
        status = process.wait(timeout=5)
    finally:
        selector.close()
        process.stdout.close()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    return {"returncode": status, "output": bytes(output[:limit]).decode("utf-8", errors="replace"),
            "limited": reason}


def redact(text):
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[private material omitted]", text, flags=re.DOTALL)
    return re.sub(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[contact omitted]", text)


def reject_acl(path):
    result = bounded_command(["/bin/ls", "-lde", path], timeout=5, limit=4096)
    if result["returncode"] or result["limited"] or not result["output"].split():
        raise ValueError("Could not validate the protected path ACL.")
    if "+" in result["output"].split()[0]:
        raise ValueError("Unexpected ACL on a protected diagnostic path.")


def validate_metadata(metadata, *, directory=False, gid=None, modes=None):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(metadata.st_mode) or metadata.st_uid != 0:
        raise ValueError("Expected a root-owned ordinary diagnostic path.")
    if not directory and metadata.st_nlink != 1:
        raise ValueError("Diagnostic files must not have hard links.")
    mode = stat.S_IMODE(metadata.st_mode)
    if gid is not None and metadata.st_gid != gid:
        raise ValueError("Diagnostic path group differs from the installed policy.")
    if modes is not None and mode not in modes:
        raise ValueError("Diagnostic path mode differs from the installed policy.")
    if directory and mode & 0o022:
        raise ValueError("Diagnostic parent is writable outside root administration.")


@contextmanager
def fixed_file(path, *, gid=None, modes=None):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Only fixed absolute diagnostic paths are allowed.")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    current = Path("/")
    descriptor = None
    try:
        validate_metadata(os.fstat(directory), directory=True)
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
            current /= part
            validate_metadata(os.fstat(directory), directory=True)
            if current == PREFIX / "logs":
                validate_metadata(os.fstat(directory), directory=True, gid=gid, modes={0o750})
            reject_acl(current)
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        validate_metadata(os.fstat(descriptor), gid=gid, modes=modes)
        reject_acl(path)
        yield descriptor
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(directory)


def read_fixed(path, *, maximum=LIMIT, tail=False, gid=None, modes=None):
    with fixed_file(path, gid=gid, modes=modes) as descriptor:
        size = os.fstat(descriptor).st_size
        if size > maximum and not tail:
            raise ValueError("Diagnostic file exceeds its read limit.")
        if tail and size > maximum:
            os.lseek(descriptor, size - maximum, os.SEEK_SET)
        result = os.read(descriptor, maximum + (0 if tail else 1))
        if len(result) > maximum:
            raise ValueError("Diagnostic file grew beyond its read limit.")
        return result


def log_snapshot(name, config, account):
    if name not in {"collector.stdout.log", "collector.stderr.log"}:
        raise ValueError("Only the two fixed collector logs may be inspected.")
    with fixed_file(PREFIX / "logs" / name, gid=config["shared_gid"], modes={0o640, 0o660}) as descriptor:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        maximum = 16384
        if metadata.st_size > maximum:
            os.lseek(descriptor, metadata.st_size - maximum, os.SEEK_SET)
        tail = os.read(descriptor, maximum).decode("utf-8", errors="replace")
        append_allowed = None
        if account:
            permission = 0o200 if account["uid"] == metadata.st_uid else (
                0o020 if metadata.st_gid in set(account["groups"]) | {account["gid"]} else 0o002)
            append_allowed = bool(mode & permission)
        return {"uid": metadata.st_uid, "gid": metadata.st_gid, "mode": format(mode, "04o"),
                "size_bytes": metadata.st_size, "tail": redact(tail),
                "collector_append_allowed_by_mode": append_allowed,
                "permission_scope": "File mode calculation only; no write probe was run."}


def journal_summary(raw):
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Invalid installation journal.")
    stage = value.get("stage")
    known = {"account_creation", "accounts_verified_before_migration", "complete"}
    return {"stage": stage if stage in known else "unrecognized", "completed_command_count": len(value.get("completed_commands", []))
            if isinstance(value.get("completed_commands", []), list) else None}


def expected_configuration(value):
    fields = {"version", "data_dir", "trust_dir", "key_dir", "collector_uid", "custodian_uid", "shared_gid"}
    if not isinstance(value, dict) or set(value) != fields or type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("Unsupported installed runtime configuration.")
    for field, path in {"data_dir": PREFIX / "data", "trust_dir": PREFIX / "custody/trust", "key_dir": PREFIX / "custody/keys"}.items():
        if value[field] != str(path):
            raise ValueError("Installed runtime contains a nonstandard path.")
    for field in ("collector_uid", "custodian_uid", "shared_gid"):
        if type(value[field]) is not int or value[field] <= 0:
            raise ValueError("Invalid installed service identity.")
    if value["collector_uid"] == value["custodian_uid"]:
        raise ValueError("Service identities are not separate.")
    return value


def account_summary(name):
    account = pwd.getpwnam(name)
    return {"name": account.pw_name, "uid": account.pw_uid, "gid": account.pw_gid,
            "shell": account.pw_shell, "home": account.pw_dir,
            "groups": sorted(set(os.getgrouplist(name, account.pw_gid)))}


def validate_verifier(config, accounts):
    recorded = read_fixed(PREFIX / "runtime-python.txt", maximum=4096, gid=0, modes={0o644}).decode().strip()
    if recorded != str(RUNTIME) or Path(sys.executable).resolve() != RUNTIME:
        raise ValueError("The fixed trusted Python runtime does not match the installed runtime.")
    admin_gid = grp.getgrnam("admin").gr_gid
    for path in (RUNTIME, *RUNTIME.parents):
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o002 or (
                metadata.st_mode & 0o020 and metadata.st_gid not in {0, admin_gid}):
            raise ValueError("Python runtime is writable outside trusted administration.")
        reject_acl(path)
    if grp.getgrnam(GROUP).gr_gid != config["shared_gid"]:
        raise ValueError("Installed service group differs from the runtime policy.")
    for name, field in ((COLLECTOR, "collector_uid"), (CUSTODIAN, "custodian_uid")):
        account = accounts[name]
        if (account["name"], account["uid"], account["gid"], account["shell"], account["home"]) != (
                name, config[field], config["shared_gid"], "/usr/bin/false", "/var/empty") or set(account["groups"]) & {0, admin_gid}:
            raise ValueError("Installed service identity does not match the reviewed policy.")
    for folder, directories, files in os.walk(PREFIX / "app", followlinks=False):
        for name in directories:
            path = Path(folder) / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError("Installed application contains a directory link.")
            validate_metadata(metadata, directory=True, gid=0, modes={0o755})
            reject_acl(path)
        for name in files:
            # Read only metadata; no application contents are returned.
            with fixed_file(Path(folder) / name, gid=0, modes={0o644}):
                pass
    with fixed_file(PREFIX / "app/scripts/local_operator.py", gid=0, modes={0o644}):
        pass


def diagnostic():
    if sys.platform != "darwin" or os.getuid() != 0 or os.geteuid() != 0 or not sys.flags.isolated or not sys.flags.no_site:
        raise ValueError("Run this fixed diagnostic through the native Mac administrator prompt using Python -I -S -B.")
    result = {"scope": "Read fixed startup metadata and bounded logs. Do not start, stop, repair, copy evidence, change permissions, or change accounts.",
              "verification_scope": "Independent verification may create and remove a temporary custodian snapshot; it does not sign or change evidence or trust.",
              "activation_confirmed": False, "errors": []}
    def attempt(label, operation):
        try:
            value = operation()
            result[label] = value
            return value
        except (OSError, ValueError, KeyError, subprocess.SubprocessError, plistlib.InvalidFileException) as error:
            result["errors"].append({"operation": label, "error": redact(str(error))[:4096]})
            return None
    config = attempt("runtime_configuration", lambda: expected_configuration(json.loads(read_fixed(PREFIX / "runtime.json", maximum=8192, gid=0, modes={0o644}))))
    attempt("journal", lambda: journal_summary(read_fixed(PREFIX / ".installation-journal.json", maximum=LIMIT, gid=0, modes={0o600})))
    report = attempt("final_report_present", lambda: bool(read_fixed(PREFIX / "installation-report.json", maximum=LIMIT, gid=0, modes={0o644})))
    result["final_report_present"] = bool(report)
    accounts = {}
    for name in (COLLECTOR, CUSTODIAN):
        accounts[name] = attempt("account_" + name, lambda name=name: account_summary(name))
    if config:
        for name in ("collector.stdout.log", "collector.stderr.log"):
            attempt(name, lambda name=name: log_snapshot(name, config, accounts.get(COLLECTOR)))
    def daemon():
        value = plistlib.loads(read_fixed(PLIST, maximum=16384, gid=0, modes={0o644}))
        expected_args = [str(RUNTIME), "-I", "-S", "-B", str(PREFIX / "app/scripts/local_operator.py"), "--worker", "serve"]
        checks = {"label_matches": value.get("Label") == LABEL, "collector_matches": value.get("UserName") == COLLECTOR,
                  "group_matches": value.get("GroupName") == GROUP, "arguments_match": value.get("ProgramArguments") == expected_args,
                  "working_directory_matches": value.get("WorkingDirectory") == str(PREFIX),
                  "stdout_path_matches": value.get("StandardOutPath") == str(PREFIX / "logs/collector.stdout.log"),
                  "stderr_path_matches": value.get("StandardErrorPath") == str(PREFIX / "logs/collector.stderr.log")}
        return {"expected_fixed_definition": all(checks.values()), "checks": checks,
                "run_at_load": value.get("RunAtLoad") is True, "keep_alive": value.get("KeepAlive") is True,
                "initialize_groups": value.get("InitGroups") is True}
    attempt("daemon_definition", daemon)
    attempt("launchd_job", lambda: bounded_command(["/bin/launchctl", "print", "system/" + LABEL], timeout=10, limit=16384))
    attempt("recent_launchd_messages", lambda: bounded_command(["/usr/bin/log", "show", "--last", "30m", "--style", "compact", "--predicate", LOG_PREDICATE], timeout=15))
    if config and all(accounts.values()):
        def verify():
            validate_verifier(config, accounts)
            verification = bounded_command([RUNTIME, "-I", "-S", "-B", PREFIX / "app/scripts/local_operator.py", "verify"], timeout=120)
            if verification["returncode"] or verification["limited"]:
                raise ValueError("Installed independent verification failed: " + redact(verification["output"][:8192]))
            value = json.loads(verification["output"])
            protection = value.get("protection", {})
            return {"ok": value.get("ok") is True, "checked": value.get("checked"),
                    "protection_status": protection.get("status"), "checkpoint_sequence": protection.get("sequence"),
                    "checkpoint_sha256": protection.get("checkpoint_sha256"),
                    "issue_count": len(value.get("issues", [])) if isinstance(value.get("issues", []), list) else None}
        attempt("independent_verification", verify)
    # A completed report alone is not proof that the service currently runs.
    result["activation_confirmed"] = False
    result["active_status_note"] = "This read-only diagnostic does not establish or enable live dashboard protection."
    for key in ("launchd_job", "recent_launchd_messages"):
        if isinstance(result.get(key), dict):
            result[key]["output"] = redact(result[key]["output"])
    return result


def main(argv=None):
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    try:
        print(json.dumps(diagnostic(), indent=2))
        return 0
    except (ValueError, OSError) as error:
        print(json.dumps({"scope": "read-only startup diagnostic", "activation_confirmed": False, "error": str(error)}, indent=2))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
