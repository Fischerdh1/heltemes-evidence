"""Local evidence repository with immutable blobs, observations, and backups."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from contextlib import contextmanager, closing
from pathlib import Path, PurePosixPath
from functools import wraps

from .config import configured
from .local_accounts import policy_for, require_role
from .sec import SecClient, select_recent_filings, submissions_url, validate_cik
from .protection import (verify_protection, repository_lock, default_trust_dir,
                         backup_files, validate_backup_protection, install_restored_trust)

SCHEMA_VERSION = 1
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
MAX_ARCHIVE_FILES = 20000


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _safe_relative(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if not name or "\\" in name or "\x00" in name or path.is_absolute() or any(p in {".", "..", ""} for p in name.split("/")) or ":" in name:
        raise ValueError("Unsafe archive or evidence path.")
    return path


def _inside(root: Path, relative: str) -> Path:
    path = _safe_relative(relative)
    candidate = root.joinpath(*path.parts)
    # Do not let a replaced local blob or directory turn a read into a symlink traversal.
    for part in [candidate, *candidate.parents]:
        if part == root:
            break
        if part.is_symlink():
            raise ValueError("Evidence paths must not contain symbolic links.")
    if not candidate.resolve().is_relative_to(root.resolve()):
        raise ValueError("Evidence path escapes the repository.")
    return candidate


def _serialized(operation):
    """Share a process-level lock with checkpoint signing and other collectors."""
    @wraps(operation)
    def wrapped(self, *args, **kwargs):
        require_role(self.data_dir, "collector")
        with repository_lock(self.data_dir):
            protection = verify_protection(self.data_dir)
            if not protection["ok"]:
                raise ValueError("Signed checkpoint verification failed; investigate before changing the archive.")
            return operation(self, *args, **kwargs)
    return wrapped


class Repository:
    def __init__(self, data_dir: str | Path):
        supplied = Path(data_dir).expanduser()
        self.policy = policy_for(supplied)
        if supplied.is_symlink():
            raise ValueError("Repository root must not be a symbolic link.")
        self.data_dir = supplied.resolve()
        self.root = self.data_dir
        if not self.policy:
            self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db_path = self.data_dir / "data.sqlite3"
        if self.db_path.is_symlink():
            raise ValueError("Repository database must not be a symbolic link.")
        new_database = not self.db_path.exists()
        if new_database and ((self.data_dir / "protection.json").exists() or default_trust_dir(self.data_dir).exists()):
            raise ValueError("Protected database is missing. Restore into a separate directory; do not initialize over it.")
        for name in ("raw", "documents"):
            path = self.data_dir / name
            if path.is_symlink():
                raise ValueError("Repository storage must not be a symbolic link.")
            if self.policy:
                if not path.is_dir():
                    raise ValueError("Managed evidence storage is missing; do not recreate it during verification.")
            else:
                path.mkdir(exist_ok=True, mode=0o700)
        with self._connect(readonly=not new_database) as db:
            current = db.execute("PRAGMA user_version").fetchone()[0]
            if current != SCHEMA_VERSION and not (new_database and current == 0):
                raise ValueError("Unsupported repository schema version.")
            if new_database:
                db.executescript("""
                CREATE TABLE IF NOT EXISTS runs (
                    id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT,
                    status TEXT NOT NULL, mode TEXT NOT NULL, cik TEXT NOT NULL,
                    filings_added INTEGER NOT NULL DEFAULT 0, error TEXT);
                CREATE TABLE IF NOT EXISTS assets (
                    path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, bytes INTEGER NOT NULL,
                    kind TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS filings (
                    id INTEGER PRIMARY KEY, company TEXT NOT NULL, cik TEXT NOT NULL,
                    form TEXT NOT NULL, accession TEXT NOT NULL, filed_at TEXT NOT NULL,
                    accepted_at TEXT NOT NULL, retrieved_at TEXT NOT NULL, source_url TEXT NOT NULL,
                    sha256 TEXT NOT NULL, document_sha256 TEXT, document_path TEXT,
                    raw_path TEXT NOT NULL, status TEXT NOT NULL, mode TEXT NOT NULL,
                    report_date TEXT NOT NULL, primary_document TEXT NOT NULL,
                    fingerprint TEXT NOT NULL, run_id TEXT NOT NULL REFERENCES runs(id),
                    UNIQUE(mode,cik,accession,fingerprint));
                CREATE TABLE IF NOT EXISTS observations (
                    id INTEGER PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id),
                    filing_id INTEGER REFERENCES filings(id), observed_at TEXT NOT NULL,
                    raw_path TEXT NOT NULL, raw_sha256 TEXT NOT NULL,
                    document_path TEXT, document_sha256 TEXT, error TEXT);
                CREATE INDEX IF NOT EXISTS filing_lookup ON filings(mode,cik,accession);
            """)
                db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        if not self.policy:
            os.chmod(self.db_path, 0o600)

    @contextmanager
    def _connect(self, readonly=False):
        if not readonly and self.policy:
            self.policy.require("collector")
        db = sqlite3.connect(self.db_path.as_uri() + "?mode=ro", uri=True, timeout=15) if readonly else sqlite3.connect(self.db_path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        # DELETE mode keeps idle backups simple and avoids hidden WAL retention.
        if not readonly:
            db.execute("PRAGMA journal_mode=DELETE")
        try:
            with db:
                yield db
        finally:
            db.close()

    def _blob(self, data: bytes, kind: str) -> tuple[str, str]:
        sha = _digest(data)
        suffix = ".json" if kind == "raw" else ".bin"
        relative = f"{kind}/{sha[:2]}/{sha}{suffix}"
        path = _inside(self.data_dir, relative)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o750 if self.policy else 0o700)
        if self.policy:
            os.chmod(path.parent, 0o750)
            os.chown(path.parent, -1, self.policy.shared_gid)
        try:
            with path.open("xb") as handle:
                os.chmod(path, 0o600)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
                if self.policy:
                    os.fchown(handle.fileno(), -1, self.policy.shared_gid)
                os.fchmod(handle.fileno(), 0o440 if self.policy else 0o400)
        except FileExistsError:
            if _digest(path.read_bytes()) != sha:
                raise ValueError(f"Existing evidence blob is corrupt: {relative}")
        with self._connect() as db:
            db.execute("INSERT OR IGNORE INTO assets VALUES (?,?,?,?,?)", (relative, sha, len(data), kind, utc_now()))
        return relative, sha

    def _start_run(self, mode: str, cik: str) -> str:
        run_id = uuid.uuid4().hex
        with self._connect() as db:
            db.execute("INSERT INTO runs (id,started_at,status,mode,cik) VALUES (?,?,?,?,?)", (run_id, utc_now(), "running", mode, cik[:40]))
        return run_id

    def _finish_run(self, run_id: str, status: str, count: int, error: str | None = None) -> dict:
        with self._connect() as db:
            db.execute("UPDATE runs SET finished_at=?,status=?,filings_added=?,error=? WHERE id=?", (utc_now(), status, count, error, run_id))
            return dict(db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone())

    def _record(self, row: dict, run_id: str, mode: str, raw_path: str, raw_sha: str, doc_path: str | None, doc_sha: str | None, error: str | None = None) -> bool:
        observed = utc_now()
        # The response snapshot may change because of unrelated filings. A revision
        # means this selected filing's metadata/document changed, not merely its packet.
        fingerprint = _digest(_json({**row, "document_sha256": doc_sha}).encode())
        values = {**row, "retrieved_at": observed, "sha256": raw_sha,
                  "document_sha256": doc_sha, "document_path": doc_path, "raw_path": raw_path,
                  "status": "preserved" if doc_sha else "metadata_only", "mode": mode,
                  "fingerprint": fingerprint, "run_id": run_id}
        keys = list(values)
        with self._connect() as db:
            result = db.execute(f"INSERT OR IGNORE INTO filings ({','.join(keys)}) VALUES ({','.join('?' for _ in keys)})", [values[k] for k in keys])
            added = result.rowcount == 1
            filing_id = db.execute("SELECT id FROM filings WHERE mode=? AND cik=? AND accession=? AND fingerprint=?", (mode, row["cik"], row["accession"], fingerprint)).fetchone()[0]
            db.execute("INSERT INTO observations (run_id,filing_id,observed_at,raw_path,raw_sha256,document_path,document_sha256,error) VALUES (?,?,?,?,?,?,?,?)", (run_id, filing_id, observed, raw_path, raw_sha, doc_path, doc_sha, error))
        return added

    @_serialized
    def seed_demo(self) -> dict:
        """Create deterministic SYNTHETIC training records once; no network calls."""
        with self._connect() as db:
            prior = db.execute("SELECT * FROM runs WHERE mode='demo' AND status='success' ORDER BY started_at DESC LIMIT 1").fetchone()
        if prior:
            return dict(prior)
        fixture = Path(__file__).resolve().parent / "fixtures" / "demo_submissions.json"
        raw = fixture.read_bytes()
        payload = json.loads(raw)
        rows = select_recent_filings(payload, ["10-Q", "10-Q/A", "8-K"], limit=3)
        run_id = self._start_run("demo", "0000000001")
        added = 0
        try:
            raw_path, raw_sha = self._blob(raw, "raw")
            for row in rows:
                row["source_url"] = f"demo://synthetic-training/{row['accession']}"
                document = ("SYNTHETIC TRAINING DOCUMENT — NOT A REAL COMPANY OR SEC FILING\n"
                            f"Company: {row['company']}\nForm: {row['form']}\nAccession: {row['accession']}\n"
                            "This fixture teaches evidence storage and amendment handling.\n"
                            "It contains no financial results, forecasts, QES score, or trade recommendation.\n").encode()
                doc_path, doc_sha = self._blob(document, "documents")
                added += self._record(row, run_id, "demo", raw_path, raw_sha, doc_path, doc_sha)
            return self._finish_run(run_id, "success", added)
        except Exception as error:
            self._finish_run(run_id, "failed", added, f"{type(error).__name__}: {error}"[:1000])
            raise

    @_serialized
    def collect(self, cik: str, user_agent: str, forms: list[str] | None = None, limit: int = 3) -> dict:
        """Collect a bounded recent-filings subset; return a persisted run status.

        Failure is explicit in ``status`` and ``error``. A partial document failure
        retains the successfully retrieved metadata and other documents. A run is
        not proof of historical coverage, SEC filing authenticity, or market timing.
        """
        run_id = self._start_run("live", str(cik))
        added, failures = 0, []
        try:
            normalized = validate_cik(cik)
            # Validate limits/forms before any external network access.
            if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 20:
                raise ValueError("Collection limit must be from 1 to 20.")
            if forms is not None:
                import re
                if not isinstance(forms, list) or not 1 <= len(forms) <= 10 or any(not isinstance(f, str) or not re.fullmatch(r"[A-Z0-9][A-Z0-9 /.-]{0,19}", f) for f in forms):
                    raise ValueError("Provide 1 to 10 valid exact SEC form types.")
            client = SecClient(user_agent)
            payload, raw = client.submissions(normalized)
            raw_path, raw_sha = self._blob(raw, "raw")
            with self._connect() as db:
                db.execute("INSERT INTO observations (run_id,observed_at,raw_path,raw_sha256) VALUES (?,?,?,?)", (run_id, utc_now(), raw_path, raw_sha))
            rows = select_recent_filings(payload, forms, limit)
            for row in rows:
                doc_path = doc_sha = problem = None
                try:
                    document = client.primary_document(normalized, row["accession"], row["primary_document"])
                    doc_path, doc_sha = self._blob(document, "documents")
                except Exception as error:
                    problem = f"{row['accession']}: {type(error).__name__}: {error}"[:700]
                    failures.append(problem)
                added += self._record(row, run_id, "live", raw_path, raw_sha, doc_path, doc_sha, problem)
            return self._finish_run(run_id, "partial" if failures else "success", added, " | ".join(failures)[:4000] if failures else None)
        except Exception as error:
            return self._finish_run(run_id, "failed", added, f"{type(error).__name__}: {error}"[:1000])

    def list_filings(self, q: str = "", form: str = "", mode: str = "all") -> list[dict]:
        if mode not in {"all", "demo", "live"}:
            raise ValueError("Mode must be all, demo, or live.")
        conditions, values = [], []
        if q:
            conditions.append("(company LIKE ? ESCAPE '\\' OR cik LIKE ? ESCAPE '\\' OR accession LIKE ? ESCAPE '\\')")
            escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            values += [f"%{escaped}%"] * 3
        if form:
            conditions.append("form=?")
            values.append(form)
        if mode != "all":
            conditions.append("mode=?")
            values.append(mode)
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        with self._connect(readonly=True) as db:
            rows = db.execute("SELECT * FROM filings" + where + " ORDER BY filed_at DESC,id DESC", values).fetchall()
        return [dict(row) for row in rows]

    def get_filing(self, id: int | str) -> dict | None:
        with self._connect(readonly=True) as db:
            row = db.execute("SELECT * FROM filings WHERE id=?", (id,)).fetchone()
            if row is None:
                return None
            result = dict(row)
            result["observations"] = [dict(o) for o in db.execute("SELECT * FROM observations WHERE filing_id=? ORDER BY id", (id,))]
        return result

    def dashboard(self) -> dict:
        with self._connect(readonly=True) as db:
            runs = [dict(row) for row in db.execute("SELECT * FROM runs ORDER BY started_at DESC,rowid DESC LIMIT 100")]
            total_runs = db.execute("SELECT count(*) FROM runs").fetchone()[0]
            observations = db.execute("SELECT count(*) FROM observations").fetchone()[0]
            latest = db.execute("SELECT finished_at FROM runs WHERE status='success' AND mode='live' ORDER BY finished_at DESC LIMIT 1").fetchone()
        filings = self.list_filings()
        return {"filings": filings, "runs": runs, "protection": verify_protection(self.data_dir),
                "stats": {"filings": len(filings), "live_filings": sum(f["mode"] == "live" for f in filings),
                          "demo_filings": sum(f["mode"] == "demo" for f in filings), "runs": total_runs,
                          "observations": observations, "latest_success": latest[0] if latest else None},
                "config": {"data_dir": str(self.data_dir), "schema_version": SCHEMA_VERSION,
                           "scope": "SEC submissions recent arrays only; selected primary documents; no historical pagination",
                           "live_contact_configured": configured(self.data_dir),
                           "demo_is_synthetic": True}}

    def verify_integrity(self, *, check_protection=True) -> dict:
        issues, checked = [], 0
        try:
            with self._connect(readonly=True) as db:
                db.execute("BEGIN")
                checks = [row[0] for row in db.execute("PRAGMA integrity_check")]
                if checks != ["ok"]:
                    issues.append({"path": "data.sqlite3", "error": "SQLite integrity check failed", "details": checks})
                if db.execute("PRAGMA foreign_key_check").fetchall():
                    issues.append({"path": "data.sqlite3", "error": "Database references are inconsistent"})
                assets = {row["path"]: dict(row) for row in db.execute("SELECT * FROM assets")}
                for table, pairs in (("filings", (("raw_path", "sha256"), ("document_path", "document_sha256"))), ("observations", (("raw_path", "raw_sha256"), ("document_path", "document_sha256")))):
                    for row in db.execute(f"SELECT * FROM {table}"):
                        for path_key, hash_key in pairs:
                            path, sha = row[path_key], row[hash_key]
                            if (path is None) != (sha is None) or (path is not None and (path not in assets or assets[path]["sha256"] != sha)):
                                issues.append({"path": path or table, "error": f"{table} record {row['id']} has an inconsistent evidence reference"})
            for relative, asset in assets.items():
                checked += 1
                try:
                    sha = asset["sha256"]
                    kind = asset["kind"]
                    if kind not in {"raw", "documents"} or not isinstance(sha, str) or not re.fullmatch(r"[a-f0-9]{64}", sha):
                        raise ValueError("Invalid evidence type or SHA-256 reference")
                    suffix = ".json" if kind == "raw" else ".bin"
                    if relative != f"{kind}/{sha[:2]}/{sha}{suffix}":
                        raise ValueError("Evidence path does not match its content address")
                    path = _inside(self.data_dir, relative)
                    if not path.is_file() or path.stat().st_nlink != 1:
                        raise ValueError("Evidence file is missing")
                    if path.stat().st_size != asset["bytes"] or _digest(path.read_bytes()) != asset["sha256"]:
                        raise ValueError("Evidence checksum or size mismatch")
                except (OSError, ValueError) as error:
                    issues.append({"path": relative, "error": str(error)})
        except (sqlite3.Error, ValueError, OSError) as error:
            issues.append({"path": "data.sqlite3", "error": str(error)})
        evidence_ok = not issues
        protection = verify_protection(self.data_dir) if check_protection else None
        if protection and not protection["ok"]:
            issues.extend(protection["issues"])
        return {"ok": not issues, "evidence_ok": evidence_ok, "checked": checked, "issues": issues,
                "protection": protection, "checked_at": utc_now(),
                "meaning": "Checks bytes and references; configured signed checkpoints additionally detect changes to sealed records. New rows remain pending. The operating-system account and external trust vault remain trusted; timestamps are not independently certified."}

    def make_evidence_readonly(self):
        """Reduce accidental edits, after validation; this is not an OS identity boundary."""
        if self.policy:
            self.policy.require("collector")
        with self._connect(readonly=True) as db:
            paths = [row[0] for row in db.execute("SELECT path FROM assets")]
        os.chmod(self.data_dir, 0o750 if self.policy else 0o700)
        for relative in paths:
            path = _inside(self.data_dir, relative)
            if not path.is_file() or path.stat().st_nlink != 1:
                raise ValueError("Evidence must be an ordinary, unlinked file.")
            os.chmod(path, 0o440 if self.policy else 0o400)
            for parent in path.parents:
                if parent == self.data_dir:
                    break
                os.chmod(parent, 0o750 if self.policy else 0o700)

    @_serialized
    def backup(self, destination_path: str | Path) -> str:
        destination = Path(destination_path).expanduser().absolute()
        if destination.exists() or destination.is_symlink():
            raise FileExistsError("Backup destination already exists; choose a new filename.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_relative_to(self.data_dir):
            raise ValueError("Store backups outside the active repository directory.")
        verified = self.verify_integrity()
        if not verified["ok"]:
            raise ValueError("Integrity verification failed; investigate before backup.")
        if verified["protection"]["status"] == "pending":
            raise ValueError("New records are not checkpointed. Run protect seal before a protected backup.")
        protected = verified["protection"]["status"] == "sealed"
        with tempfile.TemporaryDirectory(prefix="heltemes-backup-") as temp:
            staging = Path(temp).resolve()
            snapshot = staging / "data.sqlite3"
            with self._connect(readonly=True) as source, closing(sqlite3.connect(snapshot)) as target:
                source.backup(target)
            with closing(sqlite3.connect(snapshot)) as db:
                assets = db.execute("SELECT path,sha256,bytes FROM assets ORDER BY path").fetchall()
            public_files = backup_files(self.data_dir) if protected else {}
            if len(assets) + len(public_files) + 2 > MAX_ARCHIVE_FILES:
                raise ValueError("Repository exceeds the local backup file-count limit.")
            declared_size = snapshot.stat().st_size + sum(row[2] for row in assets) + sum(len(b) for b in public_files.values())
            if declared_size > MAX_ARCHIVE_BYTES:
                raise ValueError("Repository exceeds the local backup size limit.")
            records = {"data.sqlite3": {"sha256": _digest(snapshot.read_bytes()), "bytes": snapshot.stat().st_size}}
            for relative, sha, size in assets:
                data = _inside(self.data_dir, relative).read_bytes()
                if _digest(data) != sha or len(data) != size:
                    raise ValueError("Evidence changed during backup; archive was not created.")
                target = _inside(staging, relative)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_bytes(data)
                records[relative] = {"sha256": sha, "bytes": size}
            for relative, data in public_files.items():
                target = _inside(staging, relative)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_bytes(data)
                records[relative] = {"sha256": _digest(data), "bytes": len(data)}
            # Check what will actually be archived, not just the earlier live state.
            copied = Repository(staging).verify_integrity(check_protection=False)
            if not copied["ok"]:
                raise ValueError("Copied backup evidence failed integrity verification.")
            if protected:
                result = validate_backup_protection(staging, default_trust_dir(self.data_dir) / "anchor.json")
                if not result["ok"] or result["status"] != "sealed":
                    raise ValueError("Copied backup does not match its independently pinned checkpoint.")
            manifest = {"format": "heltemes-evidence-backup", "version": 2,
                        "protection": "signed-checkpoint" if protected else "unsigned",
                        "created_at": utc_now(), "files": records}
            created = False
            try:
                with destination.open("xb") as handle:
                    created = True
                    os.chmod(destination, 0o600)
                    with zipfile.ZipFile(handle, "w", zipfile.ZIP_DEFLATED) as archive:
                        for relative, record in records.items():
                            data = _inside(staging, relative).read_bytes()
                            if _digest(data) != record["sha256"] or len(data) != record["bytes"]:
                                raise ValueError("Staged evidence changed while writing backup.")
                            archive.writestr(relative, data)
                        archive.writestr("manifest.json", _json(manifest).encode())
                    handle.flush()
                    os.fsync(handle.fileno())
            except Exception:
                if created and destination.exists():
                    destination.unlink()
                raise
        return str(destination)


def restore_backup(archive_path: str | Path, destination_dir: str | Path, *, trust_receipt: str | Path | None = None) -> str:
    """Validate every member, checksum, DB relation, and path before activation.

    Protected archives require an independently retained receipt. The archive's
    own manifest or key is never adopted as trusted verification material.
    """
    destination = Path(destination_dir).expanduser().absolute()
    if destination.is_symlink() or (destination.exists() and (not destination.is_dir() or any(destination.iterdir()))):
        raise ValueError("Restore destination must be absent or an empty directory, without symlinks.")
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if default_trust_dir(destination).exists():
        raise ValueError("Restore destination already has a trust vault; choose a new location.")
    with zipfile.ZipFile(archive_path, "r") as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(infos) > MAX_ARCHIVE_FILES or len(set(names)) != len(names):
            raise ValueError("Archive contains too many or duplicate members.")
        if sum(info.file_size for info in infos) > MAX_ARCHIVE_BYTES:
            raise ValueError("Archive exceeds the 200 MiB expanded size limit.")
        for info in infos:
            _safe_relative(info.filename)
            if info.is_dir() or stat.S_ISLNK(info.external_attr >> 16) or info.flag_bits & 1:
                raise ValueError("Archive directories, symbolic links, and encryption are unsupported.")
            public_checkpoint = re.fullmatch(r"protection/checkpoints/[0-9]+\.json", info.filename)
            if info.filename not in {"manifest.json", "data.sqlite3", "protection.json"} and not public_checkpoint and not info.filename.startswith(("raw/", "documents/")):
                raise ValueError("Archive contains an unexpected file type.")
        if "manifest.json" not in names or "data.sqlite3" not in names:
            raise ValueError("Archive is missing its manifest or database.")
        if archive.getinfo("manifest.json").file_size > 4 * 1024 * 1024:
            raise ValueError("Archive manifest is too large.")
        try:
            manifest = json.loads(archive.read("manifest.json"))
        except (ValueError, UnicodeDecodeError) as error:
            raise ValueError("Invalid archive manifest.") from error
        if not isinstance(manifest, dict) or manifest.get("format") != "heltemes-evidence-backup" or manifest.get("version") not in (1, 2) or not isinstance(manifest.get("files"), dict):
            raise ValueError("Unsupported archive format.")
        protected = "protection.json" in names or any(n.startswith("protection/") for n in names) or manifest.get("protection") == "signed-checkpoint"
        if protected and trust_receipt is None:
            raise ValueError("A protected backup requires an independently saved --trust-receipt.")
        if trust_receipt is not None and not protected:
            raise ValueError("Expected protected evidence, but this archive has no signed checkpoint.")
        if manifest.get("version") == 2 and manifest.get("protection") not in {"signed-checkpoint", "unsigned"}:
            raise ValueError("Unsupported backup protection mode.")
        if protected and manifest.get("version") == 2 and manifest.get("protection") != "signed-checkpoint":
            raise ValueError("Backup protection metadata is inconsistent.")
        records = manifest["files"]
        if set(records) != set(names) - {"manifest.json"}:
            raise ValueError("Archive members do not match the manifest.")
        with tempfile.TemporaryDirectory(prefix=".heltemes-restore-", dir=destination.parent) as temp:
            staging = Path(temp).resolve() / "repository"
            staging.mkdir(mode=0o700)
            for relative, record in records.items():
                if not isinstance(record, dict) or not isinstance(record.get("bytes"), int) or not isinstance(record.get("sha256"), str):
                    raise ValueError("Malformed manifest file record.")
                content = archive.read(relative)
                if len(content) != record["bytes"] or _digest(content) != record["sha256"]:
                    raise ValueError(f"Archive checksum mismatch: {relative}")
                target = _inside(staging, relative)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.write_bytes(content)
                os.chmod(target, 0o600)
            # Inspect the exact schema and inventory before constructing a repository.
            with closing(sqlite3.connect(f"file:{staging / 'data.sqlite3'}?mode=ro", uri=True)) as db:
                db.execute("PRAGMA trusted_schema=OFF")
                if db.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                    raise ValueError("Backup database has an unsupported schema.")
                schema = db.execute("SELECT name,type FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
                expected_tables = {"runs", "assets", "filings", "observations"}
                if {name for name, kind in schema if kind == "table"} != expected_tables or any(kind not in {"table", "index"} for _, kind in schema):
                    raise ValueError("Backup database has an unexpected schema.")
                asset_paths = {row[0] for row in db.execute("SELECT path FROM assets")}
                evidence_names = {n for n in records if n.startswith(("raw/", "documents/"))}
                if asset_paths != evidence_names:
                    raise ValueError("Backup file inventory does not match the database.")
            repo = Repository(staging)
            if not repo.verify_integrity(check_protection=False)["ok"]:
                raise ValueError("Restored evidence failed integrity verification.")
            if protected:
                result = validate_backup_protection(staging, Path(trust_receipt))
                if not result["ok"] or result["status"] != "sealed":
                    raise ValueError("Restored evidence does not match the supplied trusted checkpoint.")
            repo.make_evidence_readonly()
            if destination.exists():
                if any(destination.iterdir()):
                    raise ValueError("Restore destination became nonempty; stopped.")
                destination.rmdir()
            # The independently validated public vault is installed before activation.
            # If activation fails, its presence intentionally prevents a silent retry/reset.
            if protected:
                install_restored_trust(staging, destination, Path(trust_receipt))
            staging.rename(destination)
    return str(destination)
