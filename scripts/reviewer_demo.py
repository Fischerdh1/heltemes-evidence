"""Offline reviewer demonstration using fresh synthetic evidence and throwaway keys.

The public interface accepts only a new report directory, never evidence, key,
trust, or approval inputs. Every phase runs in an isolated fresh Python process.
This is a behavior demonstration, not native account-isolation or power-loss proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[1]
PHASES = (
    ("baseline", 0), ("tamper", 0), ("verify-tamper", 0),
    ("restore", 0), ("prepare", 0), ("crash", 71),
    ("verify-crash", 0), ("blocked-seal", 1), ("resume", 0),
    ("restart", 0), ("ordinary-sign", 0), ("final-check", 0),
)
BOOTSTRAP = (
    "import sys; sys.path.insert(0, sys.argv[1]); "
    "from scripts.reviewer_demo import _worker; "
    "raise SystemExit(_worker(sys.argv[2], sys.argv[3]))"
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(content):
    return hashlib.sha256(content).hexdigest()


def source_hashes():
    paths = sorted((ROOT / "heltemes").rglob("*.py"))
    paths += sorted((ROOT / "heltemes" / "fixtures").glob("*.json"))
    paths += [ROOT / "scripts/reviewer_demo.py"]
    return {str(path.relative_to(ROOT)): sha(path.read_bytes()) for path in paths}


def new_report_directory(output):
    path = Path(output).expanduser().absolute()
    if ".." in path.parts:
        raise ValueError("Use a direct report path without parent traversal.")
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError("Report paths must not contain symbolic links.")
    reserved = {".heltemes-keys", ".heltemes-trust", "custody", "data", "backups"}
    folded = str(path).casefold()
    managed = "/library/heltemes evidence"
    if (reserved.intersection(part.casefold() for part in path.parts)
            or folded == managed or folded.startswith(managed + "/")):
        raise ValueError("Reports cannot be written into evidence or protected storage.")
    # Exclusive creation: never adopt, erase, or overwrite an existing directory.
    path.mkdir(mode=0o700)
    return path.resolve()


def _worker(scratch_path, phase):
    """Private subprocess entrypoint; only the parent supplies its scratch path."""
    from contextlib import closing
    import shutil
    import sqlite3

    scratch = Path(scratch_path).resolve()
    require(scratch.name.startswith("heltemes-reviewer-demo-"), "Not demo scratch storage")
    require((scratch / "synthetic-only.marker").read_text() == "synthetic-only\n", "Missing demo marker")
    os.chdir(scratch)
    tempfile.tempdir = str(scratch / "temporary")

    def audit(event, args):
        if event in {"socket.connect", "socket.connect_ex", "socket.getaddrinfo", "socket.bind"}:
            raise RuntimeError("Network use is disabled for the reviewer demo")
        if event == "open" and isinstance(args[0], (str, bytes)):
            path = Path(os.fsdecode(args[0])).absolute()
            if path == Path("/Library/HELTEMES Evidence") or path.is_relative_to(Path("/Library/HELTEMES Evidence")):
                raise RuntimeError("The reviewer demo cannot open the managed installation")

    sys.addaudithook(audit)
    from heltemes import protection as p, key_recovery as r
    from heltemes.core import Repository, utc_now, _json
    from heltemes.sec import select_recent_filings

    data = scratch / "synthetic-evidence"
    trust = p.default_trust_dir(data)
    keys = p.default_key_dir(data)
    require(trust.is_relative_to(scratch) and keys.is_relative_to(scratch), "Escaped scratch storage")

    def read_state():
        anchor = json.loads((trust / "anchor.json").read_text())
        checkpoints = {f.name: sha(f.read_bytes()) for f in sorted((trust / "checkpoints").glob("*.json"))}
        completions = {str(f.relative_to(scratch)): sha(f.read_bytes()) for f in r.recovery_dir(trust).glob("*/completion.json")}
        return {"sequence": anchor["sequence"], "anchor_sha256": sha((trust / "anchor.json").read_bytes()),
                "checkpoints": checkpoints, "completions": completions}

    def print_result(value):
        print(json.dumps(value, sort_keys=True), flush=True)

    if phase == "baseline":
        repo = Repository(data)
        repo.seed_demo()
        repo.make_evidence_readonly()
        p.initialize_protection(data)
        result = repo.verify_integrity()
        require(result["ok"] and result["protection"]["sequence"] == 1, "Baseline verification failed")
        rows = repo.list_filings()
        require(len(rows) == 3 and all(row["mode"] == "demo" for row in rows), "Non-synthetic data in demo")
        selected = rows[0]
        (scratch / "selected.json").write_text(json.dumps(selected))
        (scratch / "original-document.bin").write_bytes((data / selected["document_path"]).read_bytes())
        shutil.copyfile(repo.db_path, scratch / "original-database.sqlite3")
        (scratch / "original-state.json").write_text(json.dumps(read_state()))
        print_result({"verification": result, "synthetic_filings": len(rows), "state": read_state()})
    elif phase == "tamper":
        repo = Repository(data)
        selected = json.loads((scratch / "selected.json").read_text())
        original_path = selected["document_path"]
        changed = (scratch / "original-document.bin").read_bytes() + b"\nSYNTHETIC TAMPER: invented result.\n"
        digest = sha(changed)
        source_rows = select_recent_filings(
            json.loads((ROOT / "heltemes/fixtures/demo_submissions.json").read_bytes()),
            ["10-Q", "10-Q/A", "8-K"], limit=3,
        )
        metadata = next(row for row in source_rows if row["accession"] == selected["accession"])
        metadata["source_url"] = f"demo://synthetic-training/{selected['accession']}"
        require(sha(_json({**metadata, "document_sha256": selected["document_sha256"]}).encode()) == selected["fingerprint"],
                "Fixture metadata does not reproduce the original filing fingerprint")
        fingerprint = sha(_json({**metadata, "document_sha256": digest}).encode())
        replacement = f"documents/{digest[:2]}/{digest}.bin"
        destination = data / replacement
        destination.parent.mkdir(exist_ok=True)
        destination.write_bytes(changed)
        destination.chmod(0o400)
        with closing(sqlite3.connect(repo.db_path)) as db, db:
            db.execute("UPDATE assets SET path=?, sha256=?, bytes=? WHERE path=?", (replacement, digest, len(changed), original_path))
            db.execute("UPDATE filings SET document_path=?,document_sha256=?,fingerprint=? WHERE document_path=?", (replacement, digest, fingerprint, original_path))
            db.execute("UPDATE observations SET document_path=?,document_sha256=? WHERE document_path=?", (replacement, digest, original_path))
        (data / original_path).unlink()
        (scratch / "tampered-path.txt").write_text(replacement)
        require(read_state() == json.loads((scratch / "original-state.json").read_text()), "Tamper changed trusted reference")
        print_result({"changed": "synthetic document plus mutable file references, hash, size and metadata-derived fingerprint",
                      "document_sha256": digest, "filing_fingerprint": fingerprint,
                      "fingerprint_uses_production_formula": True, "trusted_history_unchanged": True})
    elif phase == "verify-tamper":
        repo = Repository(data)
        ordinary = repo.verify_integrity(check_protection=False)
        signed = repo.verify_integrity()
        require(ordinary["ok"], "Tamper did not reconcile the mutable references")
        metadata_fields = set(select_recent_filings(
            json.loads((ROOT / "heltemes/fixtures/demo_submissions.json").read_bytes()),
            ["10-Q", "10-Q/A", "8-K"], limit=3,
        )[0])
        for row in repo.list_filings():
            metadata = {field: row[field] for field in metadata_fields}
            require(row["fingerprint"] == sha(_json({**metadata, "document_sha256": row["document_sha256"]}).encode()),
                    "A filing fingerprint was not recomputed using the production formula")
        require(not signed["ok"] and signed["evidence_ok"], "Signed checkpoint accepted tamper")
        errors = json.dumps(signed["issues"])
        require("Sealed " in errors and ("record was changed" in errors or "record was removed" in errors), "Unexpected tamper rejection")
        print_result({"ordinary_checks": ordinary, "signed_checks": signed, "metadata_fingerprints_match": True})
    elif phase == "restore":
        repo = Repository(data)
        selected = json.loads((scratch / "selected.json").read_text())
        changed_path = data / (scratch / "tampered-path.txt").read_text()
        changed_path.unlink()
        original = data / selected["document_path"]
        original.write_bytes((scratch / "original-document.bin").read_bytes())
        original.chmod(0o400)
        shutil.copyfile(scratch / "original-database.sqlite3", repo.db_path)
        require(sha(repo.db_path.read_bytes()) == sha((scratch / "original-database.sqlite3").read_bytes()), "Database restore differs")
        result = Repository(data).verify_integrity()
        require(result["ok"], "Trusted synthetic restoration failed")
        require(read_state() == json.loads((scratch / "original-state.json").read_text()), "Restoration repeated signing")
        print_result({"exact_synthetic_original_restored": True, "verification": result})
    elif phase == "prepare":
        candidate = scratch / "throwaway-candidate.key"
        p._crypto(["-q", "-t", "ed25519", "-N", "", "-f", str(candidate)], input_bytes=b"")
        candidate.chmod(0o400)
        receipt = p.export_receipt(data, scratch / "practice-receipt.json")
        approval = scratch / "practice-approval.json"
        planned = r.plan_recovery(data, candidate, receipt, approval)
        # Explicit same-user fixture approval, not the managed administrator workflow.
        prepared = r.prepare_recovery(data, candidate, approval, planned["authorization_sha256"])
        (scratch / "transition-id.txt").write_text(planned["transition_id"])
        status = r.recovery_status(data)
        require(not status["signing_allowed"] and "unfinished" in status["error"], "Prepare did not block signing")
        print_result({"authorization_scope": "same-user synthetic practice fixture", "prepared": prepared, "status": status})
    elif phase == "crash":
        def crash_at_boundary(name):
            if name == "before_completion.json":
                print_result({"crash_boundary": name, "intentional_exit": 71})
                os._exit(71)
        r._boundary = crash_at_boundary
        r.resume_recovery(data)
        raise RuntimeError("Crash boundary was not reached")
    elif phase == "verify-crash":
        transition = (scratch / "transition-id.txt").read_text()
        folder = r.recovery_dir(trust) / transition
        result = Repository(data).verify_integrity()
        status = r.recovery_status(data)
        require((folder / ".completion.tmp").is_file() and not (folder / "completion.json").exists(), "Incorrect interrupted boundary")
        require(result["ok"] and result["protection"]["sequence"] == 2, "Interrupted public history did not verify")
        require(not status["signing_allowed"] and "completion.json" in status["error"], "Missing completion did not block signing")
        (scratch / "interrupted-state.json").write_text(json.dumps(read_state()))
        print_result({"verification": result, "status": status, "temporary_completion_exists": True, "final_completion_exists": False})
    elif phase == "blocked-seal":
        before = read_state()
        try:
            p.seal_checkpoint(data)
        except (OSError, ValueError) as error:
            require("completion.json" in str(error), "Signing failed for an unexpected reason")
            require(before == read_state(), "Blocked signing changed trusted history")
            print_result({"signing_allowed": False, "error": str(error), "history_unchanged": True})
            return 1
        raise RuntimeError("Ordinary signing bypassed incomplete recovery")
    elif phase == "resume":
        result = r.resume_recovery(data)
        require(result["signing_allowed"] and not result["already_completed"], "Explicit completion failed")
        require(read_state()["sequence"] == 2, "Resume added an extra checkpoint")
        state = read_state()
        require(len(state["completions"]) == 1, "Durable completion absent")
        (scratch / "committed-state.json").write_text(json.dumps(state))
        print_result({"resume": result, "state": state})
    elif phase == "restart":
        before = read_state()
        status = r.recovery_status(data)
        result = r.resume_recovery(data)
        require(status["signing_allowed"] and result["already_completed"], "Completed restart did not revalidate")
        require(before == read_state() == json.loads((scratch / "committed-state.json").read_text()), "Restart repeated recovery")
        print_result({"status": status, "resume": result, "history_unchanged": True, "state": before})
    elif phase == "ordinary-sign":
        repo = Repository(data)
        now = utc_now()
        with closing(sqlite3.connect(repo.db_path)) as db, db:
            db.execute("INSERT INTO runs(id,started_at,finished_at,status,mode,cik,filings_added) VALUES(?,?,?,?,?,?,?)",
                       ("REVIEWER-DEMO-SIGNING-PROBE", now, now, "success", "demo", "0000000001", 0))
        pending = p.verify_protection(data)
        require(pending["pending_records"] == 1, "Missing ordinary signing probe")
        result = p.seal_checkpoint(data)
        require(result["sequence"] == 3 and result["ok"], "Ordinary signing did not resume")
        checkpoint = json.loads((trust / "checkpoints/00000003.json").read_text())
        require(checkpoint["payload"]["version"] == 1 and "key_transition" not in checkpoint["payload"], "Ordinary checkpoint repeated recovery")
        print_result({"signing": result, "probe": "REVIEWER-DEMO-SIGNING-PROBE", "new_filings": 0, "key_transition": False})
    elif phase == "final-check":
        result = Repository(data).verify_integrity()
        before = read_state()
        resumed = r.resume_recovery(data)
        committed = json.loads((scratch / "committed-state.json").read_text())
        require(result["ok"] and result["protection"]["sequence"] == 3, "Final archive failed")
        require(resumed["already_completed"] and before == read_state(), "Final restart repeated recovery")
        require(before["completions"] == committed["completions"], "Completion changed during ordinary signing")
        require(all(before["checkpoints"][name] == digest for name, digest in committed["checkpoints"].items()), "Earlier history changed")
        print_result({"verification": result, "resume": resumed, "old_history_and_completion_preserved": True, "state": before})
    else:
        raise ValueError("Unknown reviewer phase")
    return 0


def run_demo(output):
    report = new_report_directory(output)
    (report / "phases").mkdir(mode=0o700)
    started = datetime.now(timezone.utc).isoformat()
    result = {
        "format": "heltemes-reviewer-demo", "version": 1, "ok": False,
        "started_at_utc": started, "python_version": platform.python_version(),
        "platform": sys.platform, "source_sha256": source_hashes(), "phases": [],
        "scope": {"synthetic_only": True, "aws_used": False, "network_disabled": True,
                  "same_user_practice_authorization": True, "native_account_isolation_tested": False,
                  "physical_power_loss_tested": False, "real_archive_or_private_key_inputs": False},
        "scratch_removed": False,
    }
    scratch_name = None
    try:
        with tempfile.TemporaryDirectory(prefix="heltemes-reviewer-demo-") as directory:
            scratch = Path(directory).resolve()
            scratch_name = scratch
            (scratch / "synthetic-only.marker").write_text("synthetic-only\n")
            (scratch / "temporary").mkdir()
            responses = {}
            for index, (phase, expected) in enumerate(PHASES, 1):
                process = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", "-c", BOOTSTRAP, str(ROOT), str(scratch), phase],
                    capture_output=True, text=True, cwd=scratch, timeout=90,
                )
                def normalize(value):
                    return value.replace(str(scratch), "<scratch>").replace(str(ROOT), "<source>")
                stdout, stderr = normalize(process.stdout), normalize(process.stderr)
                require("PRIVATE KEY-----" not in stdout + stderr, "Private key material in worker output")
                filename = f"phases/{index:02d}-{phase}.json"
                payload = {"phase": phase, "expected_exit": expected, "returncode": process.returncode,
                           "stdout": stdout, "stderr": stderr}
                (report / filename).write_text(json.dumps(payload, indent=2) + "\n")
                passed = process.returncode == expected
                result["phases"].append({"name": phase, "expected_exit": expected,
                                         "observed_exit": process.returncode, "passed": passed, "report": filename})
                require(passed, f"Phase {phase} failed: expected exit {expected}, observed {process.returncode}; inspect {filename}")
                responses[phase] = json.loads(stdout)
                if phase == "crash":
                    require(responses[phase] == {"crash_boundary": "before_completion.json", "intentional_exit": 71}, "Unexpected crash result")
                print(f"PASS {phase}", flush=True)
            require(source_hashes() == result["source_sha256"], "Demonstrated source changed during the run")
            final = responses["final-check"]["verification"]
            result["summary"] = {"baseline_checkpoint": 1, "recovery_checkpoint": 2, "final_checkpoint": 3,
                                 "verified_objects": final["checked"], "synthetic_filings": final["protection"]["sealed_filings"]}
            result["checks"] = {name: True for name in (
                "mutable_hashes_pass_but_signed_tamper_fails", "exact_synthetic_original_restored",
                "crash_before_final_completion", "fresh_verification_passes_while_signing_blocked",
                "ordinary_signing_blocked_until_explicit_resume", "restart_does_not_repeat_recovery",
                "ordinary_signing_resumes", "earlier_history_and_completion_preserved")}
            result["ok"] = True
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        result["error"] = str(error).replace(str(ROOT), "<source>")
        if scratch_name:
            result["error"] = result["error"].replace(str(scratch_name), "<scratch>")
    finally:
        result["scratch_removed"] = scratch_name is not None and not scratch_name.exists()
        result["ok"] = result["ok"] and result["scratch_removed"]
        result["completed_at_utc"] = datetime.now(timezone.utc).isoformat()
        (report / "results.json").write_text(json.dumps(result, indent=2) + "\n")
        walkthrough = [
            "HELTEMES Evidence — synthetic reviewer demonstration",
            "PASS" if result["ok"] else "FAILED — inspect results.json and the phase reports",
            "",
            "Exercise sequence (only the observed PASS phases below establish results):",
            "1. Enroll three synthetic filings under a new throwaway identity (checkpoint 1).",
            "2. Change a document plus its mutable hash, size, path and database references.",
            "   Ordinary consistency checks pass; the unchanged signed snapshot rejects the change.",
            "3. Restore the exact saved synthetic original, then approve a throwaway replacement key.",
            "   Approval here is a same-user practice fixture, not a managed administrator approval.",
            "4. End the recovery process abruptly before publishing completion.json (exit 71).",
            "   Checkpoint 2 verifies, but a fresh process refuses ordinary signing.",
            "5. Explicitly resume: verify the authorization, key, history and durable completion.",
            "   A further restart reports already_completed and changes no checkpoint or completion.",
            "6. Add one synthetic operational record and sign ordinary checkpoint 3.",
            "   No new filing or key transition is created; earlier checkpoints remain unchanged.",
            "",
            "Observed phase results:",
        ]
        walkthrough += [f"  {p['name']}: {'PASS' if p['passed'] else 'FAIL'} (exit {p['observed_exit']}, expected {p['expected_exit']})" for p in result["phases"]]
        walkthrough += ["", "Temporary evidence and throwaway private keys removed: " + str(result["scratch_removed"]),
                        "No real archive or signing key was supplied. No SEC collection or AWS deployment was performed.",
                        "This tests process interruption, not physical power loss or native account separation.",
                        "Phase output paths are normalized; source hashes bind this report to the tested code.",
                        "Results are a local demonstration record, not an independent audit or certified timestamp."]
        (report / "WALKTHROUGH.txt").write_text("\n".join(walkthrough) + "\n")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="New report directory; its parent must already exist")
    args = parser.parse_args(argv)
    try:
        result = run_demo(args.output)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Demo stopped: {error}\n")
    print("Reviewer demo passed." if result["ok"] else "Reviewer demo failed; inspect the saved report.")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
