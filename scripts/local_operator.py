#!/usr/bin/env python3
"""Fixed administrative actions for the separately owned local installation.

Run the installed root-owned copy using the recorded Python with -I -S -B.
There are no command, path, destination, user, or arbitrary Python arguments.
"""
from __future__ import annotations

import argparse
import errno
import grp
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys
import time
import urllib.request
import uuid
from datetime import datetime, timezone

PREFIX = Path("/Library/HELTEMES Evidence")
LABEL = "com.heltemes.evidence.collector"
PLIST = Path("/Library/LaunchDaemons/com.heltemes.evidence.collector.plist")
COLLECTOR = "_hevidence_collect"
CUSTODIAN = "_hevidence_custody"
GROUP = "_hevidence"


def configuration():
    if not sys.flags.isolated or not sys.flags.no_site:
        raise ValueError("Use the installed runtime with Python isolation flags -I -S -B.")
    for item in (PREFIX, PREFIX / "runtime.json", PREFIX / "runtime-python.txt", PREFIX / "migration-source.json", PREFIX / "app", Path(__file__)):
        for path in (item, *item.parents):
            if path.is_symlink():
                raise ValueError("Managed application paths cannot be symbolic links.")
            metadata = path.stat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ValueError("Managed application paths must be root-owned and service-read-only.")
    result = json.loads((PREFIX / "runtime.json").read_text())
    for name, field in ((COLLECTOR, "collector_uid"), (CUSTODIAN, "custodian_uid")):
        account = pwd.getpwnam(name)
        if account.pw_uid != result[field] or account.pw_gid != result["shared_gid"]:
            raise ValueError("Managed account identity no longer matches its trusted configuration.")
        denied_groups = {0, grp.getgrnam("admin").gr_gid}
        if account.pw_shell != "/usr/bin/false" or set(os.getgrouplist(name, result["shared_gid"])) & denied_groups:
            raise ValueError("Managed accounts must remain disabled-login non-administrators.")
    if grp.getgrnam(GROUP).gr_gid != result["shared_gid"]:
        raise ValueError("Managed group identity changed.")
    if result["collector_uid"] == result["custodian_uid"] or min(result["collector_uid"], result["custodian_uid"], result["shared_gid"]) <= 0:
        raise ValueError("Distinct unprivileged service identities are required.")
    return result


def command(action):
    runtime = (PREFIX / "runtime-python.txt").read_text().strip()
    if Path(runtime).resolve() != Path(sys.executable).resolve():
        raise ValueError("Use the runtime selected and verified during installation.")
    return [runtime, "-I", "-S", "-B", str(PREFIX / "app/scripts/local_operator.py"), "--worker", action]


def execute_worker(action, config, *, custodian=False, interactive=False):
    if os.geteuid() != 0:
        raise ValueError("Only an administrator can dispatch service identities.")
    uid = config["custodian_uid" if custodian else "collector_uid"]
    gid = config["shared_gid"]
    name = CUSTODIAN if custodian else COLLECTOR
    groups = sorted(set(os.getgrouplist(name, gid)))
    if {0, grp.getgrnam("admin").gr_gid} & set(groups):
        raise ValueError("Service identities cannot inherit administrator groups.")
    def drop_identity():
        # Match launchd InitGroups, so the permission probes test the actual
        # service membership rather than an artificially narrower account.
        os.setgroups(groups)
        os.setgid(gid)
        os.setuid(uid)
        os.umask(0o027)
    result = subprocess.run(command(action), stdin=None if interactive else subprocess.DEVNULL,
                            stdout=None if interactive else subprocess.PIPE, stderr=None if interactive else subprocess.PIPE, text=True,
                            env={"PATH": "/usr/bin:/bin", "HOME": "/var/empty", "TMPDIR": "/private/tmp"},
                            cwd=PREFIX, preexec_fn=drop_identity, timeout=180, check=False)
    if result.returncode:
        raise ValueError("Service operation failed as its restricted account: " + (result.stderr or "See the terminal message.").strip())
    if interactive:
        return {"ok": True, "contact_configured": True}
    return json.loads(result.stdout)


def launchctl(*args, required=True):
    result = subprocess.run(["/bin/launchctl", *args], capture_output=True, text=True, timeout=60, check=False)
    if required and result.returncode:
        raise ValueError("macOS service operation failed: " + result.stderr.strip())
    return result


def loaded():
    return launchctl("print", "system/" + LABEL, required=False).returncode == 0


def listener_owners(output):
    result = {}
    current = None
    for line in output.splitlines():
        if line.startswith("p") and line[1:].isdigit():
            current = int(line[1:])
        elif line.startswith("u") and line[1:].isdigit() and current is not None:
            result[current] = int(line[1:])
    return result


def prove_running(config):
    """Require the actual listener PID/UID and managed health response, not a job registration alone."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for attempt in range(30):
        job = launchctl("print", "system/" + LABEL, required=False)
        match = re.search(r"^\s*pid = (\d+)\s*$", job.stdout, re.MULTILINE)
        if match:
            pid = int(match.group(1))
            listener = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-iTCP@127.0.0.1:8765", "-sTCP:LISTEN", "-Fp", "-Fu"],
                                      capture_output=True, text=True, timeout=10, check=False)
            if listener_owners(listener.stdout).get(pid) == config["collector_uid"]:
                try:
                    with opener.open("http://127.0.0.1:8765/api/health", timeout=2) as response:
                        health = json.loads(response.read(16384))
                    if health.get("status") == "ok" and health.get("data_dir") == str(PREFIX / "data"):
                        return {"listener_pid": pid, "listener_uid": config["collector_uid"], "managed_health_confirmed": True}
                except (OSError, ValueError):
                    pass
        time.sleep(0.3)
    raise ValueError("The managed collector did not become the verified loopback listener. Inspect its protected installation logs.")


def start(config):
    verification = execute_worker("verify", config, custodian=True)
    if not verification.get("ok"):
        raise ValueError("Verification failed; dashboard was not started.")
    was_loaded = loaded()
    if not was_loaded:
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", 8765))
            except OSError as error:
                raise ValueError("Port 8765 belongs to another process; quit the old dashboard first.") from error
        launchctl("bootstrap", "system", str(PLIST))
    try:
        evidence = prove_running(config)
    except (ValueError, OSError):
        stop()
        raise
    return {"ok": True, "dashboard_loaded": True, "url": "http://127.0.0.1:8765", **evidence}


def stop():
    if loaded():
        launchctl("bootout", "system/" + LABEL)
    return {"ok": True, "dashboard_running": False}


def denied(operation):
    try:
        operation()
    except OSError as error:
        if error.errno in {errno.EACCES, errno.EPERM}:
            return True
        raise
    return False


def write_test(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)
    path.unlink()


def probe_collector(config):
    token = (PREFIX / "probe-token.txt").read_text().strip()
    if len(token) != 32 or any(char not in "0123456789abcdef" for char in token):
        raise ValueError("Invalid administrator-created probe token.")
    trust = PREFIX / "custody/trust"
    canary = trust / (".boundary-" + token)
    scratch = PREFIX / "data" / (".boundary-" + token)
    legacy_key = Path(json.loads((PREFIX / "migration-source.json").read_text())["original_key_path"])
    scratch.write_bytes(b"disposable permission probe\n")
    def attempt_open(path, mode):
        with path.open(mode):
            pass
    checks = {
        "collector_cannot_read_private_key": denied(lambda: attempt_open(PREFIX / "custody/keys/signing_key", "rb")),
        "collector_cannot_read_original_legacy_key": denied(lambda: attempt_open(legacy_key, "rb")),
        "collector_cannot_edit_trust": denied(lambda: attempt_open(canary, "r+b")),
        "collector_cannot_remove_trust": denied(lambda: canary.unlink()),
        "collector_cannot_change_trust_mode": denied(lambda: os.chmod(canary, 0o600)),
        "collector_cannot_change_trust_owner": denied(lambda: os.chown(canary, os.getuid(), config["shared_gid"])),
        "collector_cannot_replace_trust": denied(lambda: os.replace(scratch, canary)),
        "collector_cannot_create_trust": denied(lambda: write_test(trust / (".new-" + token))),
        "collector_cannot_change_custody_parent": denied(lambda: write_test(PREFIX / "custody" / (".new-" + token))),
        "collector_cannot_change_install_parent": denied(lambda: write_test(PREFIX / (".new-" + token))),
        "collector_cannot_rename_custody_sibling": denied(lambda: os.rename(PREFIX / (".boundary-" + token), PREFIX / (".moved-" + token))),
        "collector_cannot_edit_application": denied(lambda: attempt_open(PREFIX / "app/scripts/local_operator.py", "r+b")),
        "collector_cannot_edit_runtime_configuration": denied(lambda: attempt_open(PREFIX / "runtime.json", "r+b")),
        "collector_cannot_replace_launchd_log": denied(lambda: write_test(PREFIX / "logs" / (".new-" + token))),
        "collector_can_read_public_reference": (trust / "anchor.json").is_file(),
    }
    if scratch.exists():
        scratch.unlink()
    write_test(PREFIX / "data" / (".write-" + token))
    checks["collector_can_write_evidence_directory"] = True
    if not all(checks.values()):
        raise ValueError("Account separation probe failed: " + ", ".join(k for k, v in checks.items() if not v))
    return checks


def worker(action, config):
    is_custodian = action in {"seal", "key-check", "key-status", "verify", "receipt"}
    expected = config["custodian_uid"] if is_custodian else config["collector_uid"]
    name = CUSTODIAN if is_custodian else COLLECTOR
    allowed_groups = set(os.getgrouplist(name, config["shared_gid"]))
    if (os.getuid() != expected or os.geteuid() != expected or os.getgid() != config["shared_gid"]
            or not set(os.getgroups()).issubset(allowed_groups)):
        raise ValueError("This action requires its designated restricted service identity.")
    # No application import occurs in the root dispatcher or before the identity
    # drop. Isolated/no-site Python excludes user packages and environment paths.
    sys.path.insert(0, str(PREFIX / "app"))
    if action == "probe-collector":
        print(json.dumps(probe_collector(config)))
        return 0
    if action == "key-check":
        from heltemes.local_accounts import policy_for, private_snapshot
        from heltemes.key_recovery import recovery_lock, gate_signing
        from heltemes.protection import _anchor
        policy = policy_for(PREFIX / "data")
        with private_snapshot(policy) as staging, recovery_lock(policy.trust_dir):
            anchor, _ = _anchor(policy.trust_dir / "anchor.json")
            key = gate_signing(staging, policy.trust_dir, policy.key_dir, anchor)
            derived = subprocess.run(["/usr/bin/ssh-keygen", "-y", "-f", str(key)], stdin=subprocess.DEVNULL,
                                     capture_output=True, text=True, timeout=20, check=True).stdout.split()
            if derived[:2] != anchor["public_key"].split()[:2]:
                raise ValueError("Active private key does not match the accepted public key.")
        if not denied(lambda: write_test(PREFIX / "data/.custodian-write-probe")):
            raise ValueError("Custodian unexpectedly has write access to collector evidence.")
        result = {"custodian_key_matches_active_reference": True, "custodian_cannot_write_collector_data": True}
        if anchor["version"] == 1:
            result["custodian_key_matches_original_reference"] = True
        print(json.dumps(result))
        return 0
    if action == "key-status":
        from heltemes.key_recovery import recovery_status
        print(json.dumps(recovery_status(PREFIX / "data")))
        return 0
    if action == "receipt":
        from heltemes.local_accounts import policy_for, receipt_managed
        print(json.dumps(receipt_managed(policy_for(PREFIX / "data"))))
        return 0
    from heltemes.__main__ import main
    arguments = {"serve": ["serve", "--port", "8765"], "verify": ["verify"], "collector-verify": ["verify"],
                 "seal": ["protect", "seal"], "configure": ["configure"],
                 "backup": ["backup", str(PREFIX / "backups" / ("heltemes-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8] + ".zip"))]}
    if action not in arguments:
        raise ValueError("Unknown fixed service action.")
    return main(["--data-dir", str(PREFIX / "data"), *arguments[action]])


def probe(config):
    token = uuid.uuid4().hex
    token_path = PREFIX / "probe-token.txt"
    canary = PREFIX / "custody/trust" / (".boundary-" + token)
    sibling = PREFIX / (".boundary-" + token)
    try:
        with token_path.open("x") as handle:
            handle.write(token)
        os.chmod(token_path, 0o644)
        with canary.open("xb") as handle:
            handle.write(b"disposable boundary test; not a checkpoint\n")
        os.chown(canary, config["custodian_uid"], config["shared_gid"])
        os.chmod(canary, 0o440)
        sibling.mkdir(mode=0o755)
        checks = execute_worker("probe-collector", config)
        canary.unlink()  # Remove the intentionally unrecognized file before verification.
        verification = execute_worker("collector-verify", config)
        if not verification.get("ok") or verification.get("protection", {}).get("status") != "sealed":
            raise ValueError("Migrated archive must verify as sealed before activation.")
        checks.update(execute_worker("key-check", config, custodian=True))
        independent = execute_worker("verify", config, custodian=True)
        if not independent.get("ok") or independent.get("protection", {}).get("status") != "sealed":
            raise ValueError("Independent custodian verification failed.")
        return {"ok": True, "permission_checks": checks, "verification": verification, "custodian_verification": independent,
                "collector_uid": config["collector_uid"], "custodian_uid": config["custodian_uid"]}
    finally:
        for item in (canary, token_path):
            if item.exists():
                item.unlink()
        if sibling.exists():
            sibling.rmdir()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("action", choices=["status", "start", "stop", "verify", "receipt", "seal", "configure", "backup", "probe", "serve", "key-check", "key-status", "probe-collector", "collector-verify"])
    args = parser.parse_args(argv)
    try:
        config = configuration()
        if args.worker:
            return worker(args.action, config)
        if os.geteuid() != 0:
            raise ValueError("Use the Mac administrator prompt for this installed operator; no passwordless privilege is configured.")
        if args.action == "status":
            result = {"ok": True, "dashboard_loaded": loaded(), "verification": execute_worker("verify", config, custodian=True)}
        elif args.action == "stop":
            result = stop()
        elif args.action == "start":
            result = start(config)
        elif args.action == "seal":
            was_loaded = loaded()
            stop()
            result = execute_worker("seal", config, custodian=True)
            if was_loaded:
                start(config)
            result["dashboard_restarted"] = was_loaded
        elif args.action in {"verify", "receipt", "backup", "key-status"}:
            result = execute_worker(args.action, config, custodian=args.action != "backup")
        elif args.action == "configure":
            result = execute_worker("configure", config, interactive=True)
        elif args.action == "probe":
            if loaded():
                raise ValueError("Stop the dashboard before running boundary probes.")
            result = probe(config)
        else:
            raise ValueError("Internal worker actions cannot be dispatched as administrator actions.")
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(1, "Stopped: " + str(error) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
