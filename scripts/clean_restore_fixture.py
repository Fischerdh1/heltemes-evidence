"""Build disposable synthetic inputs for the clean-machine restore drill."""

import hashlib
import json
import os
import sqlite3
import tempfile
import zipfile
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from heltemes.core import Repository, restore_backup
from heltemes.local_accounts import PREFIX
from heltemes.protection import (
    default_trust_dir,
    export_receipt,
    initialize_protection,
    repository_lock,
    seal_checkpoint,
    validate_backup_protection,
)


CIK = "9999999901"
COMPANY = "SYNTHETIC CLEAN RESTORE FIXTURE — NO REAL ISSUER"


def _hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class SyntheticSec:
    def __init__(self, number: int):
        self.accession = f"{CIK}-26-{number:06}"
        self.filename = f"synthetic-restore-{number}.htm"
        date = f"2026-01-{10 + number}"
        self.payload = {
            "cik": CIK,
            "name": COMPANY,
            "filings": {"recent": {
                "accessionNumber": [self.accession],
                "filingDate": [date],
                "acceptanceDateTime": [f"{date}T16:00:00Z"],
                "form": ["8-K"],
                "reportDate": [date],
                "primaryDocument": [self.filename],
            }},
        }

    def submissions(self, cik: str) -> tuple[dict, bytes]:
        if cik != CIK:
            raise ValueError("Unexpected fixture CIK.")
        return self.payload, json.dumps(self.payload, sort_keys=True).encode()

    def primary_document(self, cik: str, accession: str, filename: str) -> bytes:
        if (cik, accession, filename) != (CIK, self.accession, self.filename):
            raise ValueError("Unexpected fixture document.")
        return f"{COMPANY}\nInvented 8-K accession {accession}.\n".encode()


def _collect(repo: Repository, number: int) -> None:
    with patch("heltemes.core.SecClient", return_value=SyntheticSec(number)):
        run = repo.collect(CIK, "Synthetic Clean Restore Fixture", forms=["8-K"], limit=1)
    if run["status"] != "success" or run["filings_added"] != 1:
        raise RuntimeError(f"Synthetic collection failed: {run['error']}")


def _expectations(repo: Repository, state: dict, sequence: int) -> dict:
    integrity = repo.verify_integrity()
    if (not integrity["ok"] or state["status"] != "sealed"
            or state["sequence"] != sequence or state["sealed_filings"] != sequence):
        raise RuntimeError("Unexpected synthetic checkpoint state.")
    objects = []
    for folder in ("documents", "raw"):
        for path in sorted((repo.data_dir / folder).glob("*/*")):
            content = path.read_bytes()
            objects.append({"path": path.relative_to(repo.data_dir).as_posix(),
                            "sha256": _hash(content), "size": len(content)})
    by_path = {item["path"]: item for item in objects}
    filings = []
    for row in sorted(repo.list_filings(), key=lambda item: item["accession"]):
        document = by_path[row["document_path"]]
        filings.append({"accession": row["accession"], "sha256": document["sha256"],
                        "size": document["size"]})
    if len(filings) != sequence or len(objects) != integrity["checked"] or len(objects) != 2 * sequence:
        raise RuntimeError("Unexpected synthetic evidence inventory.")
    return {"archive_id": state["archive_id"], "sequence": sequence,
            "head": state["checkpoint_sha256"], "filing_count": len(filings),
            "object_count": len(objects), "filings": filings, "objects": objects}


def _corrupt(backup: Path, receipt: Path, output: Path, staging: Path, filing: dict) -> dict:
    staging.mkdir(mode=0o700)
    with zipfile.ZipFile(backup) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        for member in manifest["files"]:
            relative_member = Path(member)
            if relative_member.is_absolute() or ".." in relative_member.parts:
                raise RuntimeError("Unexpected fixture archive path.")
            member_target = staging / relative_member
            member_target.parent.mkdir(parents=True, exist_ok=True)
            member_target.write_bytes(archive.read(member))
    old_path = filing["document_path"]
    content = (staging / old_path).read_bytes() + b"Unauthorized synthetic filing replacement.\n"
    digest = _hash(content)
    relative = f"documents/{digest[:2]}/{digest}.bin"
    target = staging / relative
    target.parent.mkdir(exist_ok=True)
    target.write_bytes(content)

    database = staging / "data.sqlite3"
    with closing(sqlite3.connect(database)) as db, db:
        # Retain the original asset. Redirecting the sealed filing must fail even
        # though the original blob, new blob, and unsigned references all agree.
        db.execute("INSERT INTO assets SELECT ?, ?, ?, kind, created_at FROM assets WHERE path=?",
                   (relative, digest, len(content), old_path))
        db.execute("UPDATE filings SET document_path=?, document_sha256=? WHERE id=?",
                   (relative, digest, filing["id"]))
        db.execute("UPDATE observations SET document_path=?, document_sha256=? WHERE filing_id=?",
                   (relative, digest, filing["id"]))
    for member in ("data.sqlite3", relative):
        data = (staging / member).read_bytes()
        manifest["files"][member] = {"sha256": _hash(data), "bytes": len(data)}
    with output.open("xb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        with zipfile.ZipFile(handle, "w", zipfile.ZIP_DEFLATED) as archive:
            for member in manifest["files"]:
                archive.write(staging / member, member)
            archive.writestr("manifest.json", json.dumps(manifest, sort_keys=True))

    unsigned = Repository(staging).verify_integrity(check_protection=False)
    signed = validate_backup_protection(staging, receipt)
    signed_issue = "Sealed filings record was changed."
    if not unsigned["ok"] or signed["status"] != "failed" or signed["issues"] != [
        {"path": "protection", "error": signed_issue}
    ]:
        raise RuntimeError("Corrupt fixture did not isolate the signed filing check.")
    refused = staging.parent / "must-not-activate"
    try:
        restore_backup(output, refused, trust_receipt=receipt)
    except ValueError as error:
        if str(error) != "Restored evidence does not match the supplied trusted checkpoint.":
            raise RuntimeError("Corrupt fixture failed before signed restore validation.") from error
    else:
        raise RuntimeError("Corrupt fixture was restored.")
    if refused.exists() or default_trust_dir(refused).exists():
        raise RuntimeError("Corrupt fixture activated repository or trust state.")
    return {"unsigned_consistent": True, "signed_issue": signed_issue,
            "accession": filing["accession"], "original_sha256": filing["document_sha256"],
            "replacement_sha256": digest}


def build(scratch: Path) -> dict:
    """Use a new or empty caller-owned directory, leaving only backups and receipts."""
    scratch = Path(scratch).expanduser()
    if scratch.is_symlink():
        raise ValueError("Fixture directory cannot be a symbolic link.")
    scratch = scratch.resolve()
    if scratch.is_relative_to(PREFIX.resolve()):
        raise ValueError("Fixture directory cannot be inside the installed application.")
    scratch.mkdir(mode=0o700, exist_ok=True)
    if scratch.stat().st_uid != os.getuid() or any(scratch.iterdir()):
        raise ValueError("Fixture directory must be empty and owned by the caller.")
    backups = scratch / "backups"
    receipts = scratch / "receipts"
    backups.mkdir(mode=0o700)
    receipts.mkdir(mode=0o700)
    older_backup, latest_backup, corrupt_backup = (backups / name for name in ("older.zip", "latest.zip", "corrupt.zip"))
    older_receipt, receipt = receipts / "older.json", receipts / "latest.json"

    with tempfile.TemporaryDirectory(prefix="synthetic-source-", dir=scratch) as temp:
        source = Path(temp)
        repo = Repository(source / "repository")
        _collect(repo, 1)
        if not repo.verify_integrity()["ok"]:
            raise RuntimeError("Synthetic evidence failed before initial signing.")
        with repository_lock(repo.data_dir):
            state = initialize_protection(repo.data_dir)
        older = _expectations(repo, state, 1)
        export_receipt(repo.data_dir, older_receipt)
        repo.backup(older_backup)

        _collect(repo, 2)
        with repository_lock(repo.data_dir):
            state = seal_checkpoint(repo.data_dir)
        expected = _expectations(repo, state, 2)
        if expected["archive_id"] != older["archive_id"] or expected["head"] == older["head"]:
            raise RuntimeError("Synthetic checkpoints did not advance within one archive.")
        export_receipt(repo.data_dir, receipt)
        repo.backup(latest_backup)

        filing = repo.list_filings(q=f"{CIK}-26-000002")[0]
        expected["corruption"] = _corrupt(latest_backup, receipt, corrupt_backup, source / "corruption", filing)
    expected.update({f"older_{key}": value for key, value in older.items() if key != "archive_id"})
    return {"older_backup": older_backup, "latest_backup": latest_backup,
            "corrupt_backup": corrupt_backup, "older_receipt": older_receipt,
            "receipt": receipt, "expected": expected}
