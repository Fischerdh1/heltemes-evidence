"""Restore synthetic Evidence backups taken before and after signing-key recovery."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from heltemes import key_recovery as recovery, protection
from heltemes.core import Repository
from scripts.ci_reviewer import git_identity, github_context
from scripts.clean_restore_fixture import _collect
from scripts.clean_restore_guest import (
    BOOTSTRAP, absent, backup_members, check_signed_refusal, inventory, no_private_material,
    pinned, require, sha, trust_hashes,
)
from scripts.reviewer_demo import new_report_directory

CHECKPOINT_MISMATCH = "Restored evidence does not match the supplied trusted checkpoint."
MISSING_JOURNAL = "Recovery is unfinished or its committed journal is missing; signing remains blocked."


def cli(data, *args, refusal=None):
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-B", "-c", BOOTSTRAP, str(ROOT),
         "--data-dir", str(data), *map(str, args)],
        cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=45,
    )
    if refusal is not None:
        require(result.returncode == 1 and not result.stdout
                and result.stderr == f"Error: {refusal}\n",
                f"Expected refusal from {' '.join(map(str, args[:2]))}: {result.stderr.strip()}")
        return
    require(result.returncode == 0 and not result.stderr,
            f"Command failed: {' '.join(map(str, args[:2]))}: {result.stderr.strip()}")
    return json.loads(result.stdout)


def export_point(data, work, name):
    backup = work / "backups" / f"{name}.zip"
    receipt = work / "receipts" / f"{name}.json"
    cli(data, "protect", "receipt", receipt)
    cli(data, "backup", backup)
    return backup, receipt


def verify_restore(target, pair, expected_inventory):
    backup, receipt_path = pair
    anchor, _ = protection._anchor(receipt_path)
    require(cli(target, "restore", backup, target, "--trust-receipt", receipt_path)
            == {"restored": str(target)}, "Restore did not activate the requested destination.")
    state = cli(target, "verify")
    require(state["ok"] and state["evidence_ok"] and state["protection"]["status"] == "sealed"
            and pinned(state["protection"], anchor)
            and state["protection"]["key_fingerprint"] == anchor["key_fingerprint"]
            and inventory(target) == expected_inventory, "Restored evidence differs from the accepted archive.")
    expected_trust = {"anchor.json": sha(receipt_path.read_bytes())}
    expected_trust.update({name.removeprefix("protection/"): sha(raw)
                           for name, raw in backup_members(backup).items()
                           if name.startswith("protection/checkpoints/")})
    require(trust_hashes(target) == expected_trust, "Restore changed public receipt or checkpoint bytes.")
    no_private_material(target)
    require(absent(recovery.recovery_dir(protection.default_trust_dir(target))),
            "Restore installed a private recovery journal.")
    return {"sequence": anchor["sequence"], "archive_id": anchor["archive_id"],
            "checkpoint_sha256": anchor["checkpoint_sha256"], "filings": len(expected_inventory[0]),
            "evidence_objects": len(expected_inventory[1]), "verified": True, "public_only": True}


def reject_pair(target, backup, receipt):
    check_signed_refusal(
        target.parent, backup, receipt,
        "Checkpoint inventory differs from the pinned head; missing, extra, or rolled-back checkpoints detected.")
    cli(target, "restore", backup, target, "--trust-receipt", receipt, refusal=CHECKPOINT_MISMATCH)
    require(absent(target) and absent(protection.default_trust_dir(target)),
            "Rejected restore installed a destination or public trust.")
    return {"rejected": True, "reason": "checkpoint_inventory_differs_from_receipt",
            "destination_absent": True, "trust_absent": True}


def refuse_signing(target):
    before = trust_hashes(target)
    _collect(Repository(target), 3)
    pending = cli(target, "verify")
    state = pending["protection"]
    require(pending["ok"] and state["status"] == "pending" and state["pending_filings"] == 1
            and state["sequence"] == 3, "The verifier copy did not have an actual filing pending.")
    before_database = sha((target / "data.sqlite3").read_bytes())
    cli(target, "protect", "seal", refusal=MISSING_JOURNAL)
    after = cli(target, "verify")
    require(trust_hashes(target) == before and after["ok"] and after["checked"] == pending["checked"]
            and after["protection"] == state
            and sha((target / "data.sqlite3").read_bytes()) == before_database,
            "Refused signing changed the accepted history or pending data.")
    no_private_material(target)
    require(absent(recovery.recovery_dir(protection.default_trust_dir(target))),
            "Refused signing unexpectedly created a recovery journal.")
    return {"rejected": True, "reason": "missing_recovery_journal", "private_key_absent": True,
            "head_unchanged": True, "pending_filing_retained": True}


def exercise(work):
    source = work / "source"
    for directory in (source, work / "backups", work / "receipts"):
        directory.mkdir(mode=0o700)
    repo = Repository(source / "evidence")
    data = repo.data_dir
    trust = protection.default_trust_dir(data)
    _collect(repo, 1)
    original = cli(data, "protect", "init")
    before = export_point(data, work, "before-rotation")
    before_inventory = inventory(data)
    require(original["sequence"] == 1 and original["sealed_filings"] == 1,
            "The practice archive did not start with one signed filing.")
    original_path = trust / "checkpoints/00000001.json"
    original_checkpoint = original_path.read_bytes()
    original_key = protection.default_key_dir(data) / "signing_key"
    original_key.unlink()
    require(absent(original_key) and cli(data, "verify")["ok"],
            "Loss of the disposable key did not leave public verification available.")
    cli(data, "protect", "seal", refusal="Matching private signing key is unavailable. "
        "Existing checkpoints remain verifiable; no new seal was made.")

    candidate, approval = source / "replacement", source / "practice-approval.json"
    protection._crypto(["-q", "-t", "ed25519", "-N", "", "-C", protection.SIGNER,
                        "-f", str(candidate)], input_bytes=b"")
    plan = cli(data, "protect", "recover", "plan", "--candidate-key", candidate,
               "--trust-receipt", before[1], "--output", approval)
    # In this single-user drill the script performs the review. Bind it to the
    # saved receipt and freshly generated public identity before approving bytes.
    approval_bytes = approval.read_bytes()
    request = json.loads(approval_bytes)
    candidate_public = protection._public_key(candidate.with_suffix(".pub").read_text().strip())
    approved_sha = sha(approval_bytes)
    require(plan["state"] == "review_required" and plan["authorization_sha256"] == approved_sha
            and request["action"] == "replace_signing_key"
            and request["old_receipt"] == json.loads(before[1].read_bytes())
            and request["old_receipt_sha256"] == sha(before[1].read_bytes())
            and request["candidate_public_key"] == candidate_public
            and request["candidate_key_fingerprint"] == protection._fingerprint(candidate_public)
            and request["candidate_key_fingerprint"] != original["key_fingerprint"],
            "Practice authorization did not bind the old head to the new key.")

    prepared = cli(data, "protect", "recover", "prepare", "--candidate-key", candidate,
                   "--authorization", approval, "--authorization-sha256", approved_sha)
    require(prepared["state"] == "prepared" and prepared["signing_allowed"] is False,
            "Preparation did not block signing.")
    committed = cli(data, "protect", "recover", "resume")
    transition = cli(data, "protect", "status")
    require(committed["state"] == "committed" and committed["signing_allowed"] is True
            and transition["sequence"] == 2 and transition["sealed_filings"] == 1
            and transition["status"] == "sealed" and inventory(data) == before_inventory
            and transition["key_fingerprint"] == request["candidate_key_fingerprint"],
            "Committed recovery did not preserve the accepted evidence under the new key.")

    _collect(repo, 2)
    latest = cli(data, "protect", "seal")
    after = export_point(data, work, "after-rotation")
    after_inventory = inventory(data)
    anchor, _ = protection._anchor(after[1])
    require(latest["sequence"] == 3 and latest["sealed_filings"] == 2
            and latest["key_fingerprint"] == transition["key_fingerprint"]
            and original_path.read_bytes() == original_checkpoint and absent(original_key)
            and [epoch["start_sequence"] for epoch in anchor["key_epochs"]] == [1, 2],
            "Post-rotation sealing did not preserve the original history.")
    require(backup_members(before[0])["protection/checkpoints/00000001.json"]
            == backup_members(after[0])["protection/checkpoints/00000001.json"]
            == original_checkpoint, "Checkpoint 1 changed between exports.")

    # Remove the practice signing source before any destination is restored.
    shutil.rmtree(source)
    require(absent(source), "The practice signing source still exists.")
    current = work / "restored-current"
    cases = {
        "original_pair": verify_restore(work / "restored-original", before, before_inventory),
        "current_pair": verify_restore(current, after, after_inventory),
        "rollback_with_current_receipt": reject_pair(work / "rollback", before[0], after[1]),
        "current_backup_with_original_receipt": reject_pair(work / "stale-receipt", after[0], before[1]),
        "signing_from_public_restore": refuse_signing(current),
    }
    return {
        "checkpoints": [
            {"sequence": state["sequence"], "sha256": state["checkpoint_sha256"],
             "key_fingerprint": state["key_fingerprint"], "sealed_filings": state["sealed_filings"]}
            for state in (original, transition, latest)
        ],
        "authorization_sha256": approved_sha,
        "checkpoint_1_bytes_preserved": True,
        "lost_original_key_public_verification_passed": True,
        "lost_original_key_signing_refused": True,
        "cases": cases,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source = git_identity(ROOT)
    commit = source["commit"]
    workflow = github_context(commit, os.environ)
    script = Path(__file__).resolve()
    committed_script = subprocess.check_output(
        ["git", "show", f"{commit}:{script.relative_to(ROOT).as_posix()}"], cwd=ROOT, timeout=10)
    require(script.read_bytes() == committed_script
            and not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"],
                                            cwd=ROOT, timeout=10),
            "Use a checkout with all tracked source changes committed.")
    output = new_report_directory(args.output)
    with tempfile.TemporaryDirectory(prefix=".practice-", dir=output) as temporary:
        report = exercise(Path(temporary))
    require(not any(output.iterdir()), "Practice material remained after cleanup.")
    report.update(ok=True, completed_at_utc=datetime.now(timezone.utc).isoformat(),
                  scratch_removed=True, approval_model="standalone_synthetic_operator",
                  source_commit=commit, source_tree=source["tree"], github=workflow,
                  synthetic_only=True, aws_deployed=False, external_storage_tested=False)
    raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    with (output / "REPORT.json").open("xb") as handle:
        handle.write(raw)
    with (output / "MANIFEST.json").open("x") as handle:
        json.dump({"REPORT.json": sha(raw)}, handle, indent=2)
        handle.write("\n")
    print(f"Verified {len(report['cases'])} key-rotation restore cases. Report: {output / 'REPORT.json'}")


if __name__ == "__main__":
    main()
