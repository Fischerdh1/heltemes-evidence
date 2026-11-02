"""Private user-side custody review, backup export, and verifier-only recovery."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
APPROVAL_TIMEOUT = 20 * 60
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_BACKUP_BYTES = 200 * 1024 * 1024
EXPORT_TIMEOUT = 180


class AuthenticationFailure(ValueError):
    pass


class VerificationFailure(ValueError):
    pass


def command(action):
    if action not in {"prepare", "finish", "export", "resume"}:
        raise ValueError("Unknown fixed recovery action.")
    return ["/usr/bin/sudo", "-n", "--", RUNTIME, "-I", "-S", "-B",
            str(ROOT / "scripts/recovery_operator.py"), action]


def authenticate():
    result = subprocess.run(["/usr/bin/sudo", "-v"], check=False)
    if result.returncode:
        raise AuthenticationFailure("Administrator authentication did not complete.")


def parse_json(raw, maximum=MAX_JSON_BYTES):
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not isinstance(raw, bytes) or len(raw) > maximum:
        raise VerificationFailure("Recovery JSON exceeds its size limit.")
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise VerificationFailure("Recovery JSON contains duplicate fields.")
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(result, dict):
        raise VerificationFailure("Recovery response must be a JSON object.")
    return result


def native_json(action, payload=None, *, record_dir=None):
    options = {"check": False, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE,
               "text": True, "errors": "replace", "timeout": 600}
    if payload is None:
        options["stdin"] = subprocess.DEVNULL
    else:
        options["input"] = json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    result = subprocess.run(command(action), **options)
    try:
        response = parse_json(result.stdout)
    except (ValueError, TypeError):
        response = None
    # Retain structured failures before interpreting their success status:
    # finish may have accepted a checkpoint before a later backup failure.
    if record_dir is not None:
        try:
            write_private(record_dir / (action + "-result.json"), result.stdout.encode()[:MAX_JSON_BYTES])
            write_private(record_dir / (action + "-stderr.log"), result.stderr.encode()[:65_536])
        except (OSError, ValueError) as error:
            error.native_action, error.native_response = action, response
            raise
    if result.returncode:
        detail = (result.stderr or result.stdout or "No helper diagnostic was returned.").strip()[:8000]
        if result.returncode == 1 and "sudo:" in detail:
            raise AuthenticationFailure("The noninteractive administrator request was refused: " + detail)
        error = VerificationFailure(f"The {action} helper failed ({result.returncode}): {detail}")
        error.native_action, error.native_output = action, result.stdout
        error.native_stderr = result.stderr
        error.native_response = response
        raise error
    if response is None or response.get("ok") is not True:
        error = VerificationFailure("The recovery helper did not return confirmed success.")
        error.native_action, error.native_response = action, response
        raise error
    return response, result.stdout.encode("utf-8")


def create_run_folder():
    work = ROOT / "work"
    if work.is_symlink():
        raise ValueError("Recovery workspace cannot be a symbolic link.")
    work.mkdir(mode=0o700, exist_ok=True)
    parent_fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(parent_fd)
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ValueError("Recovery workspace must belong to your account and reject other writers.")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        name = f"managed-recovery-{stamp}-{uuid.uuid4().hex[:12]}"
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return work / name


def write_private(path, content):
    content = content.encode("utf-8") if isinstance(content, str) else content
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    return path


def read_approval(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(descriptor)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise VerificationFailure("Approval must be an ordinary private file owned by your account.")
        return parse_json(os.read(descriptor, 65_537), 65_536)
    finally:
        os.close(descriptor)


def checked_head(head):
    if (not isinstance(head, dict) or set(head) != {"archive_id", "sequence", "checkpoint_sha256"}
            or type(head.get("sequence")) is not int or head["sequence"] < 1
            or not isinstance(head.get("checkpoint_sha256"), str)
            or not re.fullmatch("[0-9a-f]{64}", head["checkpoint_sha256"])):
        raise VerificationFailure("Malformed trusted checkpoint identity.")
    if str(uuid.UUID(head["archive_id"])) != head["archive_id"]:
        raise VerificationFailure("Malformed archive identifier.")
    return head


def check_prepare(prepared):
    checked_head(prepared.get("head"))
    if (prepared.get("ok") is not True or type(prepared.get("was_running")) is not bool
            or not isinstance(prepared.get("snapshot"), dict)
            or set(prepared["snapshot"]) != {"schema", "tables"}
            or not isinstance(prepared.get("snapshot_sha256"), str)
            or not re.fullmatch("[0-9a-f]{64}", prepared["snapshot_sha256"])
            or not isinstance(prepared.get("verification"), dict)
            or prepared["verification"].get("ok") is not True):
        raise VerificationFailure("Prepared custody snapshot is incomplete or unverified.")
    if str(uuid.UUID(prepared["request_id"])) != prepared["request_id"]:
        raise VerificationFailure("Prepared request identifier is malformed.")
    canonical = (json.dumps(prepared["snapshot"], sort_keys=True, ensure_ascii=False,
                            separators=(",", ":"), allow_nan=False) + "\n").encode()
    if hashlib.sha256(canonical).hexdigest() != prepared["snapshot_sha256"]:
        raise VerificationFailure("Prepared snapshot does not match its review fingerprint.")


def wait_for_approval(folder, prepared):
    deadline = time.monotonic() + APPROVAL_TIMEOUT
    path = folder / "approval.json"
    while time.monotonic() < deadline:
        if os.path.lexists(path):
            approval = read_approval(path)
            required = {"version", "request_id", "snapshot_sha256", "head", "approved_accessions", "was_running"}
            if (set(approval) != required or type(approval["version"]) is not int or approval["version"] != 1
                    or any(approval[key] != prepared[key] for key in ("request_id", "snapshot_sha256", "head", "was_running"))
                    or type(approval["was_running"]) is not bool
                    or not isinstance(approval["approved_accessions"], list)
                    or not all(isinstance(item, str) for item in approval["approved_accessions"])
                    or len(approval["approved_accessions"]) != len(set(approval["approved_accessions"]))):
                raise VerificationFailure("Approval does not match this exact reviewed custody snapshot.")
            return approval
        time.sleep(0.5)
    raise TimeoutError("No matching review approval arrived within 20 minutes.")


def check_finish(finished, prepared):
    checked_head(finished.get("head"))
    if (finished.get("ok") is not True or finished.get("sealed") is not True
            or finished.get("request_id") != prepared["request_id"]
            or finished.get("snapshot_sha256") != prepared["snapshot_sha256"]
            or type(finished.get("was_running")) is not bool
            or finished["was_running"] != prepared["was_running"]):
        raise VerificationFailure("Sealed custody result differs from the reviewed request.")
    receipt = finished.get("receipt")
    if not isinstance(receipt, dict) or any(receipt.get(key) != value for key, value in finished["head"].items()):
        raise VerificationFailure("Public receipt differs from the accepted checkpoint.")
    backup = finished.get("backup")
    if (not isinstance(backup, dict) or set(backup) != {"name", "bytes", "sha256"}
            or not isinstance(backup["name"], str) or not re.fullmatch(r"[A-Za-z0-9._-]+\.zip", backup["name"])
            or type(backup["bytes"]) is not int or not 0 < backup["bytes"] <= MAX_BACKUP_BYTES
            or not isinstance(backup["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", backup["sha256"])):
        raise VerificationFailure("Backup export metadata is malformed or exceeds its limit.")


def export_backup(folder, metadata):
    """Bound binary output; publish only after exit, size, and digest agree."""
    temporary, destination = folder / ".backup-download", folder / "evidence-backup.zip"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    process = None
    try:
        with os.fdopen(descriptor, "wb") as target:
            process = subprocess.Popen(command("export"), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            process.stdin.write((json.dumps({"backup": metadata}, sort_keys=True) + "\n").encode())
            process.stdin.close()
            digest, size, diagnostic = hashlib.sha256(), 0, bytearray()
            deadline = time.monotonic() + EXPORT_TIMEOUT
            with selectors.DefaultSelector() as selected:
                for stream, label in ((process.stdout, "bytes"), (process.stderr, "diagnostic")):
                    os.set_blocking(stream.fileno(), False)
                    selected.register(stream, selectors.EVENT_READ, label)
                while selected.get_map():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Backup export exceeded its time limit.")
                    for key, _ in selected.select(timeout=1):
                        chunk = os.read(key.fileobj.fileno(), 1024 * 1024)
                        if not chunk:
                            selected.unregister(key.fileobj)
                            continue
                        if key.data == "diagnostic":
                            diagnostic.extend(chunk[:max(0, 65_536 - len(diagnostic))])
                            continue
                        size += len(chunk)
                        if size > min(MAX_BACKUP_BYTES, metadata["bytes"]):
                            raise VerificationFailure("Backup export exceeds its declared size.")
                        target.write(chunk)
                        digest.update(chunk)
            code = process.wait(timeout=10)
            if code or size != metadata["bytes"] or digest.hexdigest() != metadata["sha256"]:
                detail = diagnostic.decode("utf-8", errors="replace").strip()
                raise VerificationFailure("Backup export failed its exit/size/fingerprint checks. " + detail)
            target.flush()
            os.fsync(target.fileno())
        os.link(temporary, destination)
        temporary.unlink()
        return destination
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    process.kill()
                    process.wait(timeout=10)
                except (OSError, subprocess.SubprocessError):
                    pass
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        if temporary.exists():
            temporary.unlink()


def restore_and_verify(folder, backup, receipt, expected_head):
    sys.path.insert(0, str(ROOT))
    from heltemes.core import Repository, restore_backup
    from heltemes.protection import default_key_dir
    restored = folder / "restored-verifier"
    restore_backup(backup, restored, trust_receipt=receipt)
    result = Repository(restored).verify_integrity()
    protection = result.get("protection", {})
    if (result.get("ok") is not True or protection.get("status") != "sealed"
            or any(protection.get(key) != value for key, value in expected_head.items())
            or default_key_dir(restored).exists()):
        raise VerificationFailure("Restored verifier failed to match the accepted public receipt.")
    write_private(folder / "restore-verification.json", json.dumps(result, indent=2) + "\n")
    return result


def resume_payload(state):
    return {"head": state["head"], "snapshot_sha256": state["snapshot_sha256"], "was_running": state["was_running"]}


def guarded_resume(state, emit, folder=None):
    emit("Requesting the prior dashboard state only if custody independently confirms unchanged evidence.")
    try:
        result, _ = native_json("resume", resume_payload(state), record_dir=folder)
        if type(result.get("resumed")) is not bool or result["resumed"] != state["was_running"]:
            raise VerificationFailure("Prior dashboard state was not confirmed.")
        emit("Prior dashboard state confirmed. This does not mark the recovery workflow complete.")
        return True
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        emit("Dashboard resume was not confirmed; it may remain stopped. " + str(error))
        return False


def main():
    try:
        folder = create_run_folder()
        write_private(folder / "workflow.log", b"")
    except (OSError, ValueError) as error:
        print("Stopped before authentication: " + str(error), file=sys.stderr)
        return 1
    prepared, seal_attempted, prepared_valid, accepted_result = None, False, False, None
    previous_signals = {}
    with (folder / "workflow.log").open("a", encoding="utf-8") as log:
        def emit(message):
            log.write(message + "\n")
            log.flush()
            os.fsync(log.fileno())
            try:
                print(message, flush=True)
            except OSError:
                pass
        def interrupted(signum, frame):
            raise InterruptedError("Received signal " + str(signum))
        try:
            for name in ("SIGHUP", "SIGTERM"):
                number = getattr(signal, name, None)
                if number is not None:
                    previous_signals[number] = signal.signal(number, interrupted)
            emit("HELTEMES Evidence — Review and backup workflow")
            emit("Status: INCOMPLETE until sealing, backup export, restored verification, and dashboard-state checks all pass.")
            emit("Private recovery folder: " + str(folder))
            emit("Administrator authentication uses Terminal directly and is never captured.")
            authenticate()
            prepared, raw = native_json("prepare", record_dir=folder)
            check_prepare(prepared)
            prepared_valid = True
            write_private(folder / "review-request.json", raw)
            emit("The dashboard is stopped while the exact custody snapshot is reviewed.")
            emit("Review request saved: " + str(folder / "review-request.json"))
            emit("Waiting up to 20 minutes for matching approval.json in this folder. No checkpoint has been signed by this workflow yet.")
            approval = wait_for_approval(folder, prepared)
            emit("Matching review approval received. Refreshing administrator authentication before custody signing.")
            authenticate()
            seal_attempted = True
            finished, raw = native_json("finish", approval, record_dir=folder)
            if finished.get("sealed") is True:
                accepted_result = finished
            write_private(folder / "custody-result.json", raw)
            check_finish(finished, prepared)
            receipt = write_private(folder / "public-receipt.json", json.dumps(finished["receipt"], indent=2) + "\n")
            emit("Accepted checkpoint and separate public receipt saved. Exporting and checking the evidence backup.")
            backup = export_backup(folder, finished["backup"])
            emit("Backup size and fingerprint verified. Restoring into a new verifier-only directory.")
            restored = restore_and_verify(folder, backup, receipt, finished["head"])
            emit("Restored evidence verified against the separate receipt; no signing key was exported.")
            resumed, raw = native_json("resume", resume_payload(finished), record_dir=folder)
            if type(resumed.get("resumed")) is not bool or resumed["resumed"] != finished["was_running"]:
                raise VerificationFailure("The prior dashboard state was not confirmed.")
            report = {"ok": True, "head": finished["head"], "backup": str(backup), "receipt": str(receipt),
                      "restored_verifier": str(folder / "restored-verifier"), "verified_objects": restored.get("checked"),
                      "dashboard_resumed": resumed["resumed"], "off_device_copy_verified": False, "aws_deployed": False}
            write_private(folder / "workflow-result.json", json.dumps(report, indent=2) + "\n")
            emit("Status: COMPLETE locally. The backup and separate receipt still need an independently verified off-device copy.")
            return 0
        except (KeyboardInterrupt, InterruptedError):
            emit("Status: INTERRUPTED. Completion was not confirmed; custody may already have accepted a checkpoint if signing began.")
            if prepared_valid and not seal_attempted:
                guarded_resume(prepared, emit, folder)
            return 130
        except (AuthenticationFailure, TimeoutError) as error:
            emit("Status: INCOMPLETE. " + str(error))
            if prepared_valid and not seal_attempted:
                guarded_resume(prepared, emit, folder)
            return 1
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            response = getattr(error, "native_response", None) or accepted_result
            # A local output-write failure can happen after a successful prepare.
            # Recover the validated in-memory pin solely for guarded cancellation.
            if getattr(error, "native_action", None) == "prepare" and isinstance(response, dict) and response.get("ok") is True:
                try:
                    check_prepare(response)
                    prepared, prepared_valid = response, True
                except (ValueError, KeyError, TypeError):
                    pass
            emit("Status: INCOMPLETE. " + str(error))
            if isinstance(response, dict) and response.get("sealed") is True:
                try:
                    head = checked_head(response.get("head"))
                    receipt = response.get("receipt")
                    if isinstance(receipt, dict) and all(receipt.get(key) == value for key, value in head.items()):
                        if not (folder / "public-receipt.json").exists():
                            write_private(folder / "public-receipt.json", json.dumps(receipt, indent=2) + "\n")
                        emit("Custody reports checkpoint " + str(head["sequence"]) + " already accepted; its public receipt is retained.")
                except (OSError, ValueError, TypeError, KeyError):
                    emit("Custody reports an accepted checkpoint; inspect the retained native result before retrying.")
            if prepared_valid and not seal_attempted:
                guarded_resume(prepared, emit, folder)
            elif isinstance(response, dict) and response.get("sealed") is True:
                emit("The checkpoint is accepted, but recovery and dashboard restart are not confirmed. Inspect the saved result before retrying.")
            else:
                emit("The dashboard may remain stopped. Inspect this result before retrying; a checkpoint may already have been accepted.")
            return 1
        finally:
            for number, handler in previous_signals.items():
                signal.signal(number, handler)
            emit("Private recovery folder: " + str(folder))


if __name__ == "__main__":
    raise SystemExit(main())
