"""Signed local checkpoints, with trust kept outside the evidence directory.

The external public vault pins an Ed25519 key, archive identity, and latest
checkpoint. It detects evidence/database tampering and rollback relative to that
pin. It does NOT defend against an administrator or the same operating-system
user rewriting the signing key and trust vault. Seal times are local clock times,
not trusted timestamps. Signing is an explicit CLI operation, never a web action.
"""
from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import subprocess
import tempfile
import uuid
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .local_accounts import policy_for, public_trust_mode

SSH_KEYGEN = "/usr/bin/ssh-keygen"
NAMESPACE = "heltemes-evidence"
SIGNER = "heltemes-evidence"
VERSION = 1
MAX_JSON_BYTES = 32 * 1024 * 1024
MAX_CHAIN_BYTES = 128 * 1024 * 1024
MAX_CHECKPOINTS = 1000
MAX_KEY_EPOCHS = 32
MAX_ROWS = 200_000
_TABLES = ("runs", "assets", "filings", "observations")
_KEYS = {"runs": "id", "assets": "path", "filings": "id", "observations": "id"}
_REQUIRED_COLUMNS = {
    "runs": {"id", "started_at", "finished_at", "status", "mode", "cik", "filings_added", "error"},
    "assets": {"path", "sha256", "bytes", "kind", "created_at"},
    "filings": {"id", "company", "cik", "form", "accession", "filed_at", "accepted_at", "retrieved_at", "source_url", "sha256", "document_sha256", "document_path", "raw_path", "status", "mode", "report_date", "primary_document", "fingerprint", "run_id"},
    "observations": {"id", "run_id", "filing_id", "observed_at", "raw_path", "raw_sha256", "document_path", "document_sha256", "error"},
}
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_LIMIT_NOTE = "Local signature and rollback checks depend on this external trust vault. They do not defeat same-user/administrator compromise or establish a trusted timestamp."


def _canonical(value) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _sha(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _safe_path(path: str | Path) -> Path:
    candidate = Path(path).expanduser().absolute()
    if ".." in candidate.parts:
        raise ValueError("Protection paths must not contain parent traversal.")
    for part in (candidate, *candidate.parents):
        if part.is_symlink():
            raise ValueError("Protection paths must not contain symbolic links.")
    return candidate.resolve()


def _data_path(data_dir) -> Path:
    path = _safe_path(data_dir)
    if not path.is_dir():
        raise ValueError("Evidence directory does not exist.")
    return path


def _identity(data_dir) -> str:
    return _sha(str(_safe_path(data_dir)).encode())[:16]


def default_trust_dir(data_dir) -> Path:
    policy = policy_for(data_dir)
    if policy:
        return policy.trust_dir
    data = _safe_path(data_dir)
    return data.parent / ".heltemes-trust" / _identity(data)


def default_key_dir(data_dir) -> Path:
    policy = policy_for(data_dir)
    if policy:
        return policy.key_dir
    data = _safe_path(data_dir)
    return data.parent / ".heltemes-keys" / _identity(data)


def _external(data: Path, selected, default) -> Path:
    path = _safe_path(default if selected is None else selected)
    if path == data or path.is_relative_to(data):
        raise ValueError("Trust and signing keys must be outside the evidence directory.")
    return path


def _read(path, maximum=MAX_JSON_BYTES) -> bytes:
    target = _safe_path(path)
    if not target.is_file() or target.stat().st_nlink != 1 or target.stat().st_size > maximum:
        raise ValueError("Missing, linked, or oversized protection file: " + target.name)
    with target.open("rb") as handle:
        content = handle.read(maximum + 1)
    if len(content) > maximum:
        raise ValueError("Protection file exceeds its size limit.")
    return content


def _json(content: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate JSON key in protection material.")
            result[key] = value
        return result
    try:
        value = json.loads(content, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON value.")))
        if not isinstance(value, dict):
            raise ValueError("Protection document must be a JSON object.")
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("Malformed protection JSON.") from error


def _sync_directory(path):
    directory = _safe_path(path)
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    except OSError as error:
        raise ValueError("The filesystem could not durably commit the protection directory; stopped.") from error
    finally:
        os.close(fd)


def _exclusive(path, content: bytes):
    target = _safe_path(path)
    if len(content) > MAX_JSON_BYTES:
        raise ValueError("Protection document exceeds its size limit.")
    mode = 0o440 if public_trust_mode(target) else 0o400
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(fd, "wb") as handle:
        if mode == 0o440:
            os.fchown(handle.fileno(), -1, target.parent.stat().st_gid)
        handle.write(content)
        handle.flush()
        os.fchmod(handle.fileno(), mode)
        os.fsync(handle.fileno())
    _sync_directory(target.parent)


def _mkdir(path):
    path = _safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _safe_path(path.parent)
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    _sync_directory(path)
    _sync_directory(path.parent)


@contextmanager
def repository_lock(data_dir):
    """Nonblocking advisory lock shared by repository mutation entry points."""
    data = _data_path(data_dir)
    policy = policy_for(data_dir)
    lock_path = _safe_path(data / ".operation.lock")
    flags = os.O_RDONLY if policy and os.geteuid() != policy.collector_uid else os.O_RDWR | os.O_CREAT
    fd = os.open(lock_path, flags | getattr(os, "O_NOFOLLOW", 0), 0o640 if policy else 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Repository lock must be a regular file.")
        if policy and os.geteuid() == policy.collector_uid:
            os.fchmod(fd, 0o640)
            os.fchown(fd, -1, policy.shared_gid)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("Another repository operation is running. Try again when it finishes.") from error
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _crypto(args, *, input_bytes=None) -> bytes:
    if not Path(SSH_KEYGEN).is_file() or not os.access(SSH_KEYGEN, os.X_OK):
        raise ValueError("Ed25519 protection requires /usr/bin/ssh-keygen with SSH signature support; it is unavailable.")
    try:
        process = subprocess.run([SSH_KEYGEN, *args], input=input_bytes,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("The Ed25519 signing/verification tool could not run safely.") from error
    if process.returncode != 0:
        raise ValueError("Ed25519 signing/verification failed. Check the signature, matching key, and SSH signature support.")
    if len(process.stdout) > 16_384:
        raise ValueError("Unexpectedly large cryptographic tool output.")
    return process.stdout


def _public_key(text: str) -> str:
    if not isinstance(text, str) or len(text) > 1024 or "\n" in text or "\r" in text:
        raise ValueError("Invalid pinned public key.")
    parts = text.split()
    if len(parts) not in {2, 3} or parts[0] != "ssh-ed25519":
        raise ValueError("Only an Ed25519 public key can anchor this archive.")
    try:
        decoded = base64.b64decode(parts[1], validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("Invalid Ed25519 public key encoding.") from error
    if len(decoded) != 51 or not decoded.startswith(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"):
        raise ValueError("Invalid Ed25519 public key structure.")
    return " ".join(parts[:2])


def _fingerprint(public_key: str) -> str:
    normalized = _public_key(public_key)
    raw = base64.b64decode(normalized.split()[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def _private_key(key_path: Path) -> Path:
    key_path = _safe_path(key_path)
    if not key_path.is_file():
        raise ValueError("Matching private signing key is unavailable. Existing checkpoints remain verifiable; no new seal was made.")
    metadata = key_path.stat()
    if metadata.st_nlink != 1 or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise ValueError("Private signing key must be an ordinary unlinked file with owner-only permissions.")
    return key_path


def _signature(payload: dict, key_path: Path) -> str:
    key_path = _private_key(key_path)
    with tempfile.TemporaryDirectory(prefix="heltemes-sign-") as temporary:
        folder = Path(temporary).resolve()
        message = folder / "checkpoint.json"
        _exclusive(message, _canonical(payload))
        _crypto(["-Y", "sign", "-q", "-f", str(key_path), "-n", NAMESPACE, str(message)])
        try:
            return _read(folder / "checkpoint.json.sig", 16_384).decode("ascii")
        except UnicodeError as error:
            raise ValueError("Invalid SSH signature output.") from error


def _verify_signature(payload: dict, signature: str, public_key: str):
    if not isinstance(signature, str) or len(signature) > 16_384 or not signature.startswith("-----BEGIN SSH SIGNATURE-----\n"):
        raise ValueError("Invalid checkpoint signature envelope.")
    with tempfile.TemporaryDirectory(prefix="heltemes-verify-") as temporary:
        folder = Path(temporary).resolve()
        signers = folder / "allowed_signers"
        sig_path = folder / "checkpoint.sig"
        _exclusive(signers, f'{SIGNER} namespaces="{NAMESPACE}" {_public_key(public_key)}\n'.encode("ascii"))
        _exclusive(sig_path, signature.encode("ascii"))
        _crypto(["-Y", "verify", "-q", "-f", str(signers), "-I", SIGNER,
                 "-n", NAMESPACE, "-s", str(sig_path)], input_bytes=_canonical(payload))


def _value(value):
    if isinstance(value, bytes):
        return {"base64": base64.b64encode(value).decode("ascii")}
    if value is None or isinstance(value, (str, int, float)):
        # Canonical JSON rejects NaN/Infinity. SQL text and blobs stay distinct.
        _canonical(value)
        return value
    raise ValueError("Unsupported SQLite value in checkpoint snapshot.")


def _snapshot(data: Path, *, require_finished=False) -> dict:
    database = _safe_path(data / "data.sqlite3")
    if not database.is_file():
        raise ValueError("Evidence database is missing; protection cannot initialize or verify it.")
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=10)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("BEGIN")
        if [row[0] for row in db.execute("PRAGMA integrity_check")] != ["ok"] or db.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError("The evidence database failed its structural/reference checks.")
        objects = [dict(zip(("name", "type", "table", "sql"), row)) for row in db.execute("SELECT name,type,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name,type")]
        if {obj["name"] for obj in objects if obj["type"] == "table"} != set(_TABLES) or any(obj["type"] not in {"table", "index"} for obj in objects):
            raise ValueError("Unexpected evidence schema; protection cannot silently establish a new baseline.")
        tables, columns, total = {}, {}, 0
        for table in _TABLES:
            columns[table] = [list(row) for row in db.execute(f'PRAGMA table_info("{table}")')]
            cursor = db.execute(f'SELECT * FROM "{table}"')
            names = [item[0] for item in cursor.description]
            if not _REQUIRED_COLUMNS[table].issubset(names):
                raise ValueError("Evidence table is missing required identity or integrity columns.")
            records = []
            for row in cursor:
                total += 1
                if total > MAX_ROWS:
                    raise ValueError("Repository exceeds the checkpoint record limit.")
                records.append([_value(item) for item in row])
            index = names.index(_KEYS[table])
            records.sort(key=lambda row: _canonical(row[index]))
            tables[table] = {"columns": names, "rows": records}
        if require_finished:
            run_columns = tables["runs"]["columns"]
            if "status" not in run_columns or "finished_at" not in run_columns:
                raise ValueError("Run state columns are missing.")
            status_i, finish_i = run_columns.index("status"), run_columns.index("finished_at")
            if any(row[status_i] == "running" or row[finish_i] is None for row in tables["runs"]["rows"]):
                raise ValueError("A running or unfinished collection cannot be sealed.")
        snapshot = {"schema": {"user_version": db.execute("PRAGMA user_version").fetchone()[0],
                                "application_id": db.execute("PRAGMA application_id").fetchone()[0],
                                "objects": objects, "columns": columns}, "tables": tables}
        if len(_canonical(snapshot)) > MAX_JSON_BYTES - 32_768:
            raise ValueError("Repository snapshot exceeds the checkpoint size limit.")
        return snapshot


def _row_map(snapshot, table):
    if not isinstance(snapshot, dict) or set(snapshot) != {"schema", "tables"} or not isinstance(snapshot["tables"], dict) or set(snapshot["tables"]) != set(_TABLES):
        raise ValueError("Malformed checkpoint snapshot.")
    content = snapshot["tables"][table]
    if not isinstance(content, dict) or set(content) != {"columns", "rows"}:
        raise ValueError("Malformed checkpoint table.")
    columns, rows = content["columns"], content["rows"]
    if not isinstance(columns, list) or not all(isinstance(c, str) for c in columns) or len(set(columns)) != len(columns) or _KEYS[table] not in columns or not isinstance(rows, list) or len(rows) > MAX_ROWS:
        raise ValueError("Malformed checkpoint columns or records.")
    key_index = columns.index(_KEYS[table])
    result = {}
    for row in rows:
        if not isinstance(row, list) or len(row) != len(columns):
            raise ValueError("Malformed checkpoint row.")
        key = _canonical(row[key_index])
        if key in result:
            raise ValueError("Duplicate stable identity in checkpoint records.")
        result[key] = row
    return result


def _compare(sealed: dict, current: dict) -> dict:
    if _canonical(sealed.get("schema")) != _canonical(current.get("schema")):
        raise ValueError("The sealed database schema was changed.")
    pending, pending_filings = 0, 0
    for table in _TABLES:
        old, new = _row_map(sealed, table), _row_map(current, table)
        if sealed["tables"][table]["columns"] != current["tables"][table]["columns"]:
            raise ValueError("The sealed database columns were changed.")
        for identity, row in old.items():
            if identity not in new:
                raise ValueError(f"Sealed {table} record was removed; rollback or deletion detected.")
            if _canonical(row) != _canonical(new[identity]):
                raise ValueError(f"Sealed {table} record was changed.")
        additions = len(new) - len(old)
        pending += additions
        if table == "filings":
            pending_filings = additions
    return {"pending_records": pending, "pending_filings": pending_filings,
            "sealed_filings": len(_row_map(sealed, "filings"))}


def _check_evidence(data: Path, snapshot: dict):
    """Independently refuse to seal inconsistently indexed or changed bytes."""
    def records(table):
        columns = snapshot["tables"][table]["columns"]
        return [dict(zip(columns, row)) for row in snapshot["tables"][table]["rows"]]
    assets = {row["path"]: row for row in records("assets")}
    for table, pairs in (("filings", (("raw_path", "sha256"), ("document_path", "document_sha256"))), ("observations", (("raw_path", "raw_sha256"), ("document_path", "document_sha256")))):
        for row in records(table):
            for path_key, sha_key in pairs:
                relative, digest = row[path_key], row[sha_key]
                if (relative is None) != (digest is None) or (relative is not None and (relative not in assets or assets[relative]["sha256"] != digest)):
                    raise ValueError("Evidence hash references are inconsistent; sealing refused.")
    for relative, record in assets.items():
        if not isinstance(relative, str) or "\\" in relative or ":" in relative or "\x00" in relative or Path(relative).is_absolute() or any(part in {"", ".", ".."} for part in relative.split("/")):
            raise ValueError("Unsafe evidence path; sealing refused.")
        digest_value, kind = record["sha256"], record["kind"]
        if kind not in {"raw", "documents"} or not isinstance(digest_value, str) or not _HASH.fullmatch(digest_value):
            raise ValueError("Invalid evidence type or digest; sealing refused.")
        suffix = ".json" if kind == "raw" else ".bin"
        if relative != f"{kind}/{digest_value[:2]}/{digest_value}{suffix}":
            raise ValueError("Evidence path differs from its content address; sealing refused.")
        file = _safe_path(data / relative)
        if not file.is_relative_to(data) or not file.is_file() or file.stat().st_nlink != 1 or type(record["bytes"]) is not int or record["bytes"] < 0:
            raise ValueError("Missing, linked, or malformed evidence asset; sealing refused.")
        digest = hashlib.sha256()
        size = 0
        with file.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
        if size != record["bytes"] or digest.hexdigest() != record["sha256"]:
            raise ValueError("Preserved evidence bytes do not match the recorded hash; sealing refused.")


def _marker(path: Path) -> dict:
    marker = _json(_read(path, 4096))
    if set(marker) != {"format", "version", "archive_id"} or marker.get("format") != "heltemes-protection" or type(marker.get("version")) is not int or marker.get("version") != VERSION:
        raise ValueError("Invalid or unsupported protection marker.")
    _archive_id(marker.get("archive_id"))
    return marker


def _archive_id(value):
    try:
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError("Invalid archive identity.")
    except (ValueError, AttributeError) as error:
        raise ValueError("Invalid archive identity.") from error


def _anchor(path: Path) -> tuple[dict, bytes]:
    raw = _read(path, 16_384)
    anchor = _json(raw)
    _validate_anchor(anchor)
    return anchor, raw


def _validate_anchor(anchor: dict):
    """Validate the independently trusted receipt, including its key schedule."""
    expected = {"format", "version", "archive_id", "public_key", "key_fingerprint", "sequence", "checkpoint_sha256", "checkpoint_at"}
    if isinstance(anchor, dict) and anchor.get("version") == 2:
        expected.add("key_epochs")
    if not isinstance(anchor, dict) or set(anchor) != expected or anchor.get("format") != "heltemes-trust-anchor" or type(anchor.get("version")) is not int or anchor["version"] not in {1, 2}:
        raise ValueError("Invalid external trust receipt.")
    _archive_id(anchor["archive_id"])
    if type(anchor["sequence"]) is not int or not 1 <= anchor["sequence"] <= MAX_CHECKPOINTS or not isinstance(anchor["checkpoint_sha256"], str) or not _HASH.fullmatch(anchor["checkpoint_sha256"]):
        raise ValueError("Invalid pinned checkpoint head.")
    if anchor["key_fingerprint"] != _fingerprint(anchor["public_key"]):
        raise ValueError("Pinned public key fingerprint mismatch.")
    if not isinstance(anchor["checkpoint_at"], str) or len(anchor["checkpoint_at"]) > 40:
        raise ValueError("Invalid checkpoint time in external receipt.")
    if anchor["version"] == 1:
        return
    epochs = anchor["key_epochs"]
    if not isinstance(epochs, list) or not 2 <= len(epochs) <= MAX_KEY_EPOCHS:
        raise ValueError("Invalid public-key epoch schedule in external receipt.")
    fields = {"start_sequence", "public_key", "key_fingerprint", "transition_id", "approval_sha256", "previous_checkpoint_sha256"}
    previous_start, identities, transitions = 0, set(), set()
    for index, epoch in enumerate(epochs):
        if not isinstance(epoch, dict) or set(epoch) != fields:
            raise ValueError("Malformed public-key epoch in external receipt.")
        start = epoch["start_sequence"]
        if type(start) is not int or not previous_start < start <= anchor["sequence"] or (index == 0 and start != 1):
            raise ValueError("Public-key epochs must begin at one and advance in order.")
        public_key = _public_key(epoch["public_key"])
        if public_key != epoch["public_key"] or epoch["key_fingerprint"] != _fingerprint(public_key) or public_key in identities:
            raise ValueError("Invalid, repeated, or noncanonical public-key epoch identity.")
        if index == 0:
            if any(epoch[name] is not None for name in ("transition_id", "approval_sha256", "previous_checkpoint_sha256")):
                raise ValueError("The original key epoch cannot claim a recovery authorization.")
        else:
            _archive_id(epoch["transition_id"])
            if epoch["transition_id"] in transitions:
                raise ValueError("Repeated key-transition identity in external receipt.")
            transitions.add(epoch["transition_id"])
            for name in ("approval_sha256", "previous_checkpoint_sha256"):
                if not isinstance(epoch[name], str) or not _HASH.fullmatch(epoch[name]):
                    raise ValueError("Malformed key-transition digest in external receipt.")
        identities.add(public_key)
        previous_start = start
    if anchor["public_key"] != epochs[-1]["public_key"] or anchor["key_fingerprint"] != epochs[-1]["key_fingerprint"]:
        raise ValueError("Active public key differs from the independently pinned epoch schedule.")
    if len(_canonical(anchor)) > 16_384:
        raise ValueError("External trust receipt exceeds its size limit.")


def _key_epochs(anchor: dict) -> list[dict]:
    _validate_anchor(anchor)
    if anchor["version"] == 2:
        return [dict(epoch) for epoch in anchor["key_epochs"]]
    return [{"start_sequence": 1, "public_key": _public_key(anchor["public_key"]),
             "key_fingerprint": anchor["key_fingerprint"], "transition_id": None,
             "approval_sha256": None, "previous_checkpoint_sha256": None}]


def active_key_path(keys: Path, anchor: dict) -> Path:
    """Select only the identity pinned by the trusted receipt; never replace key one."""
    _validate_anchor(anchor)
    keys = _safe_path(keys)
    if anchor["version"] == 1:
        return _safe_path(keys / "signing_key")
    identity = _sha(_public_key(anchor["public_key"]).encode("utf-8"))
    return _safe_path(keys / "identities" / (identity + ".key"))


def _checkpoint_name(sequence) -> str:
    return f"{sequence:08d}.json"


def _load_chain(folder: Path, anchor: dict) -> tuple[dict, dict[str, bytes]]:
    epochs = _key_epochs(anchor)
    epoch_index = 0
    folder = _safe_path(folder)
    if not folder.is_dir():
        raise ValueError("Required public checkpoint directory is missing.")
    expected = {_checkpoint_name(i) for i in range(1, anchor["sequence"] + 1)}
    if {item.name for item in folder.iterdir()} != expected:
        raise ValueError("Checkpoint inventory differs from the pinned head; missing, extra, or rolled-back checkpoints detected.")
    previous_sha, previous_snapshot, files, total = None, None, {}, 0
    latest = None
    for sequence in range(1, anchor["sequence"] + 1):
        name = _checkpoint_name(sequence)
        raw = _read(folder / name)
        total += len(raw)
        if total > MAX_CHAIN_BYTES:
            raise ValueError("Checkpoint chain exceeds its total size limit.")
        envelope = _json(raw)
        if set(envelope) != {"payload", "signature"} or not isinstance(envelope["payload"], dict):
            raise ValueError("Malformed checkpoint envelope.")
        payload = envelope["payload"]
        fields = {"version", "archive_id", "sequence", "previous_checkpoint_sha256", "sealed_at", "snapshot"}
        at_transition = epoch_index + 1 < len(epochs) and epochs[epoch_index + 1]["start_sequence"] == sequence
        if at_transition:
            fields.add("key_transition")
        if set(payload) != fields or type(payload.get("version")) is not int or payload["version"] != (2 if at_transition else 1) or type(payload.get("sequence")) is not int or payload["sequence"] != sequence or payload.get("archive_id") != anchor["archive_id"] or payload.get("previous_checkpoint_sha256") != previous_sha:
            raise ValueError("Checkpoint identity, sequence, or previous link does not match the pinned chain.")
        if not isinstance(payload["sealed_at"], str) or len(payload["sealed_at"]) > 40:
            raise ValueError("Malformed checkpoint seal time.")
        if at_transition:
            old_epoch, new_epoch = epochs[epoch_index], epochs[epoch_index + 1]
            expected_transition = {"transition_id": new_epoch["transition_id"],
                                   "approval_sha256": new_epoch["approval_sha256"],
                                   "from_key_fingerprint": old_epoch["key_fingerprint"],
                                   "to_key_fingerprint": new_epoch["key_fingerprint"]}
            if payload["key_transition"] != expected_transition or new_epoch["previous_checkpoint_sha256"] != previous_sha:
                raise ValueError("Key transition differs from its independently pinned authorization.")
            if _canonical(payload["snapshot"]) != _canonical(previous_snapshot):
                raise ValueError("Key recovery cannot seal additions or change the last accepted snapshot.")
            epoch_index += 1
        _verify_signature(payload, envelope["signature"], epochs[epoch_index]["public_key"])
        for table in _TABLES:
            _row_map(payload["snapshot"], table)
        if previous_snapshot is not None:
            _compare(previous_snapshot, payload["snapshot"])
        previous_snapshot = payload["snapshot"]
        previous_sha = _sha(raw)
        latest = payload
        files[name] = raw
    if previous_sha != anchor["checkpoint_sha256"] or latest["sealed_at"] != anchor["checkpoint_at"]:
        raise ValueError("Checkpoint head does not match the external pin; rollback or substitution detected.")
    return latest, files


def _status(status, **extra):
    return {"status": status, "ok": status != "failed", "issues": [], "sealed_filings": 0,
            "pending_filings": 0, "pending_records": 0, "checkpoint_at": None,
            "sequence": None, "checkpoint_sha256": None, "key_fingerprint": None,
            "meaning": _LIMIT_NOTE, **extra}


def _verified(data: Path, anchor: dict, folder: Path, *, include_filing_hashes=False) -> tuple[dict, dict, dict[str, bytes]]:
    marker = _marker(data / "protection.json")
    if marker["archive_id"] != anchor["archive_id"]:
        raise ValueError("Evidence archive identity does not match the external trust receipt.")
    latest, files = _load_chain(folder, anchor)
    current = _snapshot(data)
    counts = _compare(latest["snapshot"], current)
    status = _status("pending" if counts["pending_records"] else "sealed", **counts,
                     checkpoint_at=anchor["checkpoint_at"], sequence=anchor["sequence"],
                     checkpoint_sha256=anchor["checkpoint_sha256"], key_fingerprint=anchor["key_fingerprint"],
                     archive_id=anchor["archive_id"])
    if include_filing_hashes:
        table = latest["snapshot"]["tables"]["filings"]
        status["sealed_filing_hashes"] = {
            str(dict(zip(table["columns"], row))["id"]): _sha(json.dumps(dict(zip(table["columns"], row)), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8"))
            for row in table["rows"]
        }
    return status, current, files


def verify_protection(data_dir, trust_dir=None, *, include_filing_hashes=False) -> dict:
    """Read-only verification; never initializes, repairs, re-pins, or re-signs."""
    try:
        policy = policy_for(data_dir)
        data = _data_path(data_dir)
        trust = _external(data, trust_dir, default_trust_dir(data))
        if policy and trust != policy.trust_dir:
            raise ValueError("Managed verification cannot override the administrator-installed trust vault.")
        marker_path = _safe_path(data / "protection.json")
        staged = _safe_path(data / "protection")
        if not marker_path.exists() and not trust.exists() and not staged.exists():
            return _status("unconfigured")
        if not marker_path.is_file() or not trust.is_dir():
            raise ValueError("Required protection marker or external trust vault is missing; refusing an unsigned downgrade.")
        if {item.name for item in trust.iterdir()} != {"anchor.json", "checkpoints"}:
            raise ValueError("Unexpected trust-vault inventory.")
        anchor, _ = _anchor(trust / "anchor.json")
        status, _, _ = _verified(data, anchor, trust / "checkpoints", include_filing_hashes=include_filing_hashes)
        status["account_isolation"] = "separate-local-accounts" if policy else "same-account"
        if policy:
            status["meaning"] = "The collector and custodian have separate operating-system accounts. Verification depends on protected custodian trust, administrator-installed code, and the operating system; timestamps are not independently certified."
        return status
    except (ValueError, OSError, sqlite3.Error, TypeError, KeyError, UnicodeError, OverflowError, RecursionError) as error:
        return _status("failed", issues=[{"path": "protection", "error": str(error)[:700]}])


def _new_anchor(public_key, payload, checkpoint, previous_anchor=None):
    anchor = {"format": "heltemes-trust-anchor", "version": VERSION,
              "archive_id": payload["archive_id"], "public_key": _public_key(public_key),
              "key_fingerprint": _fingerprint(public_key), "sequence": payload["sequence"],
              "checkpoint_sha256": _sha(checkpoint), "checkpoint_at": payload["sealed_at"]}
    if previous_anchor is not None:
        _validate_anchor(previous_anchor)
        if anchor["public_key"] != _public_key(previous_anchor["public_key"]) or anchor["archive_id"] != previous_anchor["archive_id"] or anchor["sequence"] != previous_anchor["sequence"] + 1 or payload["previous_checkpoint_sha256"] != previous_anchor["checkpoint_sha256"]:
            raise ValueError("A normal checkpoint cannot change the accepted signing identity or history.")
        if previous_anchor["version"] == 2:
            anchor.update(version=2, key_epochs=_key_epochs(previous_anchor))
    _validate_anchor(anchor)
    return anchor


def transition_anchor(old_anchor, payload, checkpoint, new_public_key, transition_id, approval_sha256):
    """Build a public receipt AFTER caller independently authorizes key recovery.

    This validates cryptographic bindings, not the authority to change identity.
    The protected recovery workflow must validate and durably commit approval.
    Historical checkpoints and the original key are never rewritten here.
    """
    _validate_anchor(old_anchor)
    _archive_id(transition_id)
    if not isinstance(approval_sha256, str) or not _HASH.fullmatch(approval_sha256):
        raise ValueError("Malformed recovery approval digest.")
    new_public_key = _public_key(new_public_key)
    fields = {"version", "archive_id", "sequence", "previous_checkpoint_sha256", "sealed_at", "snapshot", "key_transition"}
    transition = {"transition_id": transition_id, "approval_sha256": approval_sha256,
                  "from_key_fingerprint": old_anchor["key_fingerprint"],
                  "to_key_fingerprint": _fingerprint(new_public_key)}
    if not isinstance(payload, dict) or set(payload) != fields or type(payload.get("version")) is not int or payload["version"] != 2 or payload["archive_id"] != old_anchor["archive_id"] or type(payload["sequence"]) is not int or payload["sequence"] != old_anchor["sequence"] + 1 or payload["previous_checkpoint_sha256"] != old_anchor["checkpoint_sha256"] or payload["key_transition"] != transition:
        raise ValueError("Key transition does not match the approved prior head and identities.")
    envelope = _json(checkpoint)
    if set(envelope) != {"payload", "signature"} or _canonical(envelope["payload"]) != _canonical(payload):
        raise ValueError("Key-transition envelope does not match its proposed payload.")
    _verify_signature(payload, envelope["signature"], new_public_key)
    epochs = _key_epochs(old_anchor)
    epochs.append({"start_sequence": payload["sequence"], "public_key": new_public_key,
                   "key_fingerprint": _fingerprint(new_public_key), "transition_id": transition_id,
                   "approval_sha256": approval_sha256,
                   "previous_checkpoint_sha256": old_anchor["checkpoint_sha256"]})
    anchor = {"format": "heltemes-trust-anchor", "version": 2,
              "archive_id": old_anchor["archive_id"], "public_key": new_public_key,
              "key_fingerprint": _fingerprint(new_public_key), "sequence": payload["sequence"],
              "checkpoint_sha256": _sha(checkpoint), "checkpoint_at": payload["sealed_at"],
              "key_epochs": epochs}
    _validate_anchor(anchor)
    return anchor


def _new_payload(archive_id, sequence, previous, snapshot):
    return {"version": VERSION, "archive_id": archive_id, "sequence": sequence,
            "previous_checkpoint_sha256": previous, "sealed_at": _now(), "snapshot": snapshot}


def initialize_protection(data_dir, trust_dir=None, key_dir=None) -> dict:
    """Explicitly pin a NEW archive and sign its first complete snapshot.

    Caller must hold repository_lock and perform its normal full integrity check.
    Existing marker, vault, or key directory is never overwritten or reset.
    """
    if policy_for(data_dir):
        raise ValueError("Managed archives cannot initialize or reset trust; import existing verified protection through the administrator installer.")
    data = _data_path(data_dir)
    trust = _external(data, trust_dir, default_trust_dir(data))
    keys = _external(data, key_dir, default_key_dir(data))
    if trust == keys or trust.is_relative_to(keys) or keys.is_relative_to(trust):
        raise ValueError("Public trust and private signing key directories must be separate.")
    if any(_safe_path(path).exists() for path in (data / "protection.json", data / "protection", trust, keys)):
        raise ValueError("Protection material already exists. Initialization never overwrites or re-baselines an archive.")
    snapshot = _snapshot(data, require_finished=True)
    _check_evidence(data, snapshot)
    # Check executable availability before creating the first persistent directory.
    if not Path(SSH_KEYGEN).is_file() or not os.access(SSH_KEYGEN, os.X_OK):
        raise ValueError("Ed25519 protection requires /usr/bin/ssh-keygen; it is unavailable.")
    _mkdir(keys)
    key_path = keys / "signing_key"
    _crypto(["-q", "-t", "ed25519", "-N", "", "-C", SIGNER, "-f", str(key_path)], input_bytes=b"")
    for path in (key_path, keys / "signing_key.pub"):
        _safe_path(path)
        os.chmod(path, 0o400)
    public_key = _public_key(_read(keys / "signing_key.pub", 4096).decode("ascii").strip())
    archive_id = str(uuid.uuid4())
    payload = _new_payload(archive_id, 1, None, snapshot)
    checkpoint = _canonical({"payload": payload, "signature": _signature(payload, key_path)})
    _verify_signature(payload, _json(checkpoint)["signature"], public_key)
    _mkdir(trust)
    _mkdir(trust / "checkpoints")
    _exclusive(trust / "checkpoints" / _checkpoint_name(1), checkpoint)
    _exclusive(trust / "anchor.json", _canonical(_new_anchor(public_key, payload, checkpoint)))
    _exclusive(data / "protection.json", _canonical({"format": "heltemes-protection", "version": VERSION, "archive_id": archive_id}))
    result = verify_protection(data, trust)
    if result["status"] != "sealed":
        raise ValueError("Initial checkpoint did not verify; protection material was retained for investigation.")
    return result


def seal_checkpoint(data_dir, trust_dir=None, key_dir=None) -> dict:
    """Seal additions only; existing signed rows must match the pinned history."""
    policy = policy_for(data_dir)
    if policy:
        if trust_dir is not None and Path(trust_dir) != policy.trust_dir or key_dir is not None and Path(key_dir) != policy.key_dir:
            raise ValueError("Managed signing cannot override the administrator-installed trust or key directories.")
        from .local_accounts import seal_managed
        return seal_managed(policy)
    data = _data_path(data_dir)
    trust = _external(data, trust_dir, default_trust_dir(data))
    keys = _external(data, key_dir, default_key_dir(data))
    from .key_recovery import recovery_lock
    with recovery_lock(trust):
        return _seal_checkpoint_locked(data, trust, keys)


def _seal_checkpoint_locked(data, trust, keys):
    from .key_recovery import gate_signing
    existing = verify_protection(data, trust)
    if existing["status"] not in {"sealed", "pending"}:
        raise ValueError("Protection is missing or failed. Refusing to initialize or re-sign an untrusted baseline.")
    anchor, old_anchor_bytes = _anchor(trust / "anchor.json")
    key_path = gate_signing(data, trust, keys, anchor)
    latest, _ = _load_chain(trust / "checkpoints", anchor)
    snapshot = _snapshot(data, require_finished=True)
    counts = _compare(latest["snapshot"], snapshot)
    _check_evidence(data, snapshot)
    if not counts["pending_records"]:
        return existing
    if anchor["sequence"] >= MAX_CHECKPOINTS:
        raise ValueError("Checkpoint sequence limit reached; no checkpoint was changed.")
    key_path = _private_key(key_path)
    public_key = _public_key(_crypto(["-y", "-f", str(key_path)], input_bytes=b"").decode("ascii").strip())
    if public_key != _public_key(anchor["public_key"]):
        raise ValueError("Private signing key does not match the pinned public key.")
    payload = _new_payload(anchor["archive_id"], anchor["sequence"] + 1, anchor["checkpoint_sha256"], snapshot)
    checkpoint = _canonical({"payload": payload, "signature": _signature(payload, key_path)})
    _verify_signature(payload, _json(checkpoint)["signature"], anchor["public_key"])
    total = sum(path.stat().st_size for path in (trust / "checkpoints").iterdir())
    if total + len(checkpoint) > MAX_CHAIN_BYTES:
        raise ValueError("Checkpoint chain size limit reached; no checkpoint was changed.")
    if _read(trust / "anchor.json", 16_384) != old_anchor_bytes:
        raise ValueError("External trust head changed during sealing; stopped.")
    _exclusive(trust / "checkpoints" / _checkpoint_name(payload["sequence"]), checkpoint)
    # The old head is replaced atomically only after the new immutable envelope exists.
    # An interruption between these writes deliberately produces a failed inventory
    # check instead of silently forgetting or accepting an unpinned checkpoint.
    replacement = trust / (".anchor-" + uuid.uuid4().hex + ".tmp")
    try:
        _exclusive(replacement, _canonical(_new_anchor(anchor["public_key"], payload, checkpoint, previous_anchor=anchor)))
        if _read(trust / "anchor.json", 16_384) != old_anchor_bytes:
            raise ValueError("External trust head changed before commit; stopped.")
        os.replace(replacement, _safe_path(trust / "anchor.json"))
        _sync_directory(trust)
    finally:
        if replacement.exists():
            replacement.unlink()
    result = verify_protection(data, trust)
    if result["status"] != "sealed":
        raise ValueError("New checkpoint failed verification; investigate without resetting the trust vault.")
    return result


def export_receipt(data_dir, destination, trust_dir=None) -> str:
    data = _data_path(data_dir)
    trust = _external(data, trust_dir, default_trust_dir(data))
    state = verify_protection(data, trust)
    if state["status"] not in {"sealed", "pending"}:
        raise ValueError("Receipt export requires a verified pinned checkpoint. Pending rows are not included in the receipt.")
    target = _safe_path(destination)
    if target == data or target.is_relative_to(data):
        raise ValueError("Keep the public trust receipt outside the evidence directory.")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _exclusive(target, _read(trust / "anchor.json", 16_384))
    return str(target)


def backup_files(data_dir, trust_dir=None) -> dict[str, bytes]:
    data = _data_path(data_dir)
    trust = _external(data, trust_dir, default_trust_dir(data))
    state = verify_protection(data, trust)
    if state["status"] == "unconfigured":
        return {}
    if state["status"] != "sealed":
        raise ValueError("Protected backups require a fully sealed, verified archive; pending changes cannot be silently sealed.")
    anchor, _ = _anchor(trust / "anchor.json")
    _, _, files = _verified(data, anchor, trust / "checkpoints")
    return {"protection.json": _read(data / "protection.json", 4096),
            **{f"protection/checkpoints/{name}": raw for name, raw in files.items()}}


def validate_backup_protection(staging, receipt_path=None) -> dict:
    """Verify staged public evidence against an explicitly external pinned receipt.

    An archive-contained anchor is never accepted as trust. No vault is installed,
    key generated, or database changed by this function.
    """
    try:
        data = _data_path(staging)
        marker = _safe_path(data / "protection.json")
        folder = _safe_path(data / "protection")
        if not marker.exists() and not folder.exists():
            if receipt_path is not None:
                raise ValueError("Receipt supplied but protection material is missing; unsigned downgrade refused.")
            return _status("unconfigured")
        if not marker.is_file() or not folder.is_dir() or receipt_path is None:
            raise ValueError("Protected restore requires complete public checkpoints and an external trusted receipt.")
        receipt = _safe_path(receipt_path)
        if receipt.is_relative_to(data):
            raise ValueError("An archive-contained receipt cannot establish trust.")
        if {item.name for item in folder.iterdir()} != {"checkpoints"}:
            raise ValueError("Unexpected protected-backup material; archive-provided trust anchors are forbidden.")
        anchor, _ = _anchor(receipt)
        status, snapshot, _ = _verified(data, anchor, folder / "checkpoints")
        if status["status"] != "sealed":
            raise ValueError("Protected backup contains unsealed additions.")
        _check_evidence(data, snapshot)
        return status
    except (ValueError, OSError, sqlite3.Error, TypeError, KeyError, UnicodeError, OverflowError, RecursionError) as error:
        return _status("failed", issues=[{"path": "protection", "error": str(error)[:700]}])


def install_restored_trust(staging, destination, receipt_path) -> str:
    """Exclusively install PUBLIC trust for a validated restore; never copy a key.

    Caller activates staging only after this succeeds. Existing destination trust
    is never replaced, even if it appears to describe the same archive.
    """
    data = _data_path(staging)
    destination = _safe_path(destination)
    if destination.exists() and (not destination.is_dir() or any(destination.iterdir())):
        raise ValueError("Restore destination must be absent or empty before trust installation.")
    state = validate_backup_protection(data, receipt_path)
    if state["status"] != "sealed":
        raise ValueError("Cannot install trust for an unverified protected restore.")
    trust = _external(destination, None, default_trust_dir(destination))
    if trust.exists():
        raise ValueError("Destination trust already exists; refusing to replace its pinned head.")
    anchor, anchor_bytes = _anchor(_safe_path(receipt_path))
    _, _, files = _verified(data, anchor, data / "protection" / "checkpoints")
    _mkdir(trust)
    _mkdir(trust / "checkpoints")
    for name, raw in files.items():
        _exclusive(trust / "checkpoints" / name, raw)
    _exclusive(trust / "anchor.json", anchor_bytes)
    return str(trust)
