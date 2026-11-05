"""Atomic, replay-verified storage for the disposable network monitor.

Private filesystem permissions and a single-writer lock protect local operation.
The journal is not an independent anti-rollback or hostile-administrator anchor.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import uuid

from scripts import network_monitor as monitor

FORMAT = "heltemes-monitor-journal"
VERSION = 1
MAX_ROWS = 256
MAX_BYTES = 64 * 1024 * 1024
MAX_REQUEST = 512 * 1024
ZERO = "0" * 64
REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\Z")
OBSERVATION_KEYS = {"phase", "observed_at_utc", "ruleset", "collection_error", "probes"}
SCHEMA_SQL = {
    "config": "CREATE TABLE config (id INTEGER PRIMARY KEY CHECK(id=1), identity TEXT NOT NULL, approved TEXT NOT NULL, head_sequence INTEGER NOT NULL, head_digest TEXT NOT NULL)",
    "observations": "CREATE TABLE observations (sequence INTEGER PRIMARY KEY, request_id TEXT UNIQUE NOT NULL, request TEXT NOT NULL, sample TEXT NOT NULL, evaluation TEXT NOT NULL, events TEXT NOT NULL, previous_digest TEXT NOT NULL, row_digest TEXT NOT NULL)",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(encoded(value).encode()).hexdigest()


def parse(value):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            require(key not in result, "Duplicate JSON object key.")
            result[key] = item
        return result
    return json.loads(value, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("Nonfinite JSON value.")))


def engine_hash():
    return hashlib.sha256(Path(monitor.__file__).read_bytes()).hexdigest()


def state_path(value, *, existing=True):
    path = Path(value).absolute()
    require(".." not in path.parts, "State path cannot traverse parent components.")
    for ancestor in (path, *path.parents):
        require(not ancestor.is_symlink(), "State path cannot traverse symbolic links.")
    if existing:
        info = path.stat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o700, "State directory must be private and owned by this account.")
    return path


def ordinary(path, *, limit=MAX_BYTES):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= limit,
            "State file must be bounded, private, singly linked, and owned by this account.")
    return info


def read_private(path, *, limit=MAX_BYTES):
    before = ordinary(path, limit=limit)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), "State file changed during open.")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            value = handle.read(limit + 1)
        require(len(value) <= limit, "State file exceeds size limit.")
        return value
    finally:
        os.close(fd)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(value)
            handle.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def configure(connection):
    connection.execute("PRAGMA trusted_schema=OFF")
    require(connection.execute("PRAGMA trusted_schema").fetchone() == (0,), "Untrusted schema mode is required.")
    require(connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0] == "delete", "Rollback journaling is required.")
    # DELETE mode also needs the containing directory synchronized after the
    # rollback journal is removed. EXTRA includes that final commit boundary.
    connection.execute("PRAGMA synchronous=EXTRA")
    connection.execute("PRAGMA foreign_keys=ON")
    require(connection.execute("PRAGMA synchronous").fetchone()[0] == 3, "Extra commit synchronization is required.")


def initialize(value, approved):
    """Explicitly initialize a new directory. Partial/existing state is never reset."""
    monitor.Monitor(approved)
    require(len(encoded(approved).encode()) <= MAX_REQUEST, "Approved ruleset exceeds size limit.")
    path = state_path(value, existing=False)
    require(path.parent.is_dir() and not path.exists(), "Initialization requires a new state directory.")
    path.mkdir(mode=0o700)
    sync_directory(path.parent)
    identity = {"format": FORMAT, "version": VERSION, "database_id": uuid.uuid4().hex,
                "approved_policy_sha256": monitor.policy_fingerprint(approved), "engine_sha256": engine_hash()}
    write_new(path / "service.lock", b"")
    write_new(path / "monitor.sqlite3", b"")
    connection = sqlite3.connect((path / "monitor.sqlite3").as_uri() + "?mode=rw", uri=True, isolation_level=None)
    try:
        configure(connection)
        connection.execute("BEGIN IMMEDIATE")
        for statement in SCHEMA_SQL.values():
            connection.execute(statement)
        connection.execute("INSERT INTO config VALUES(1,?,?,0,?)", (encoded(identity), encoded(approved), ZERO))
        connection.execute("COMMIT")
    finally:
        connection.close()
    # This is the initialization completion marker. Its absence blocks service startup.
    write_new(path / "identity.json", (encoded(identity) + "\n").encode())
    sync_directory(path)
    return identity


class Journal:
    def __init__(self, value):
        self.path = state_path(value)
        self.connection, self.lock_fd = None, None
        try:
            ordinary(self.path / "service.lock", limit=0)
            self.lock_fd = os.open(self.path / "service.lock", os.O_RDWR | os.O_NOFOLLOW)
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.identity = parse(read_private(self.path / "identity.json", limit=4096))
            require(set(self.identity) == {"format", "version", "database_id", "approved_policy_sha256", "engine_sha256"}
                    and self.identity["format"] == FORMAT and self.identity["version"] == VERSION
                    and re.fullmatch(r"[0-9a-f]{32}", self.identity["database_id"])
                    and self.identity["engine_sha256"] == engine_hash(), "Journal identity or engine version is incompatible.")
            ordinary(self.path / "monitor.sqlite3")
            for suffix in ("-journal", "-wal", "-shm"):
                sidecar = self.path / ("monitor.sqlite3" + suffix)
                if sidecar.exists() or sidecar.is_symlink():
                    ordinary(sidecar)
                    require(suffix == "-journal", "Unexpected SQLite journal mode.")
            self.connection = sqlite3.connect((self.path / "monitor.sqlite3").as_uri() + "?mode=rw", uri=True,
                                              isolation_level=None, timeout=2)
            configure(self.connection)
            self._load()
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.close()

    def _load(self):
        require(self.connection.execute("PRAGMA quick_check").fetchone() == ("ok",), "Journal database integrity check failed.")
        objects = self.connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' ORDER BY name").fetchall()
        require(objects == [("table", name, name, statement) for name, statement in sorted(SCHEMA_SQL.items())],
                "Journal schema is incompatible.")
        config = self.connection.execute("SELECT identity,approved,head_sequence,head_digest FROM config WHERE id=1").fetchone()
        require(config is not None and self.connection.execute("SELECT count(*) FROM config").fetchone()[0] == 1,
                "Journal configuration is missing or duplicated.")
        require(parse(config[0]) == self.identity, "Pinned identity differs from database identity.")
        approved = parse(config[1])
        require(monitor.policy_fingerprint(approved) == self.identity["approved_policy_sha256"], "Pinned approved policy differs.")
        engine = monitor.Monitor(approved)
        records = self.connection.execute("SELECT sequence,request_id,request,sample,evaluation,events,previous_digest,row_digest FROM observations ORDER BY sequence").fetchall()
        require(len(records) <= MAX_ROWS, "Journal history exceeds bound.")
        rows, last_digest = [], ZERO
        for position, raw in enumerate(records, 1):
            sequence, request_id, request_raw, sample_raw, evaluation_raw, events_raw, previous, row_digest = raw
            request, sample, evaluation, events = map(parse, (request_raw, sample_raw, evaluation_raw, events_raw))
            require(sequence == position and sample.get("sequence") == sequence and previous == last_digest,
                    "Journal sequence or chain is incomplete.")
            require(isinstance(request, dict) and set(request) == {"kind", "observation"}
                    and request["kind"] in {"restart", "observation"}, "Journal request kind is invalid.")
            self._validate_observation(request["observation"])
            require(all(sample.get(key) == request["observation"][key] for key in OBSERVATION_KEYS)
                    and set(sample) == OBSERVATION_KEYS | {"sequence", "elapsed_seconds"}, "Journal sample differs from its request.")
            require((request["kind"] == "restart" and re.fullmatch(r"_restart_[0-9a-f]{32}", request_id)
                     and sample["phase"] == "monitor_restart" and sample["ruleset"] is None
                     and sample["collection_error"] == "monitor_restarted" and sample["probes"] == [])
                    or (request["kind"] == "observation" and REQUEST_ID.fullmatch(request_id)), "Journal request identity is invalid.")
            before = len(engine.events)
            actual = engine.observe(sample)
            require(actual == evaluation and engine.events[before:] == events, "Saved monitoring result does not match deterministic replay.")
            payload = {"sequence": sequence, "request_id": request_id, "request": request, "sample": sample,
                       "evaluation": evaluation, "events": events, "previous_digest": previous}
            require(digest(payload) == row_digest, "Journal row digest differs.")
            rows.append({**payload, "row_digest": row_digest})
            last_digest = row_digest
        require((config[2], config[3]) == (len(rows), last_digest), "Journal head differs from committed history.")
        self.approved, self.engine, self.rows, self.head_digest = approved, engine, rows, last_digest

    @staticmethod
    def _validate_observation(observation):
        require(isinstance(observation, dict) and set(observation) == OBSERVATION_KEYS,
                "Observation fields differ from the service contract.")
        require(len(encoded(observation).encode()) <= MAX_REQUEST, "Observation exceeds size limit.")

    def append(self, request_id, observation, elapsed_seconds, *, restart=False, fault=None):
        self._validate_observation(observation)
        require(isinstance(request_id, str) and ((restart and re.fullmatch(r"_restart_[0-9a-f]{32}", request_id))
                or (not restart and REQUEST_ID.fullmatch(request_id))), "Request ID is invalid.")
        request = {"kind": "restart" if restart else "observation", "observation": copy.deepcopy(observation)}
        existing = next((row for row in self.rows if row["request_id"] == request_id), None)
        if existing is not None:
            require(encoded(existing["request"]) == encoded(request), "Request ID conflicts with already committed content.")
            return {"duplicate": True, "committed_sequence": existing["sequence"],
                    "evaluation": copy.deepcopy(existing["evaluation"]), "events": copy.deepcopy(existing["events"])}
        require(len(self.rows) < MAX_ROWS, "Journal history limit reached.")
        # Build the candidate in a separate replayed engine. A failed transaction
        # cannot advance the process's accepted in-memory view.
        candidate = monitor.Monitor(self.approved)
        for row in self.rows:
            candidate.observe(row["sample"])
        sequence = len(self.rows) + 1
        sample = {**copy.deepcopy(observation), "sequence": sequence, "elapsed_seconds": elapsed_seconds}
        event_start = len(candidate.events)
        evaluation = candidate.observe(sample)
        events = candidate.events[event_start:]
        payload = {"sequence": sequence, "request_id": request_id, "request": request, "sample": sample,
                   "evaluation": evaluation, "events": events, "previous_digest": self.head_digest}
        checksum = digest(payload)
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute("INSERT INTO observations VALUES(?,?,?,?,?,?,?,?)",
                (sequence, request_id, encoded(request), encoded(sample), encoded(evaluation), encoded(events), self.head_digest, checksum))
            self.connection.execute("UPDATE config SET head_sequence=?,head_digest=? WHERE id=1", (sequence, checksum))
            size = self.connection.execute("PRAGMA page_count").fetchone()[0] * self.connection.execute("PRAGMA page_size").fetchone()[0]
            require(size <= MAX_BYTES, "Journal database exceeds size limit.")
            if fault:
                fault("before_commit")
            self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise
        if fault:
            fault("after_commit_before_ack")
        self.rows.append({**payload, "row_digest": checksum})
        self.head_digest, self.engine = checksum, candidate
        return {"duplicate": False, "committed_sequence": sequence,
                "evaluation": copy.deepcopy(evaluation), "events": copy.deepcopy(events)}

    def status(self):
        return {"committed_count": len(self.rows), "head_digest": self.head_digest,
                "current_evaluation": copy.deepcopy(self.engine.evaluations[-1]) if self.engine.evaluations else None,
                "alerts": copy.deepcopy(self.engine.alerts)}

    def export(self):
        return {"identity": copy.deepcopy(self.identity), "approved_policy": copy.deepcopy(self.approved),
                "rows": copy.deepcopy(self.rows), "evaluations": copy.deepcopy(self.engine.evaluations),
                "events": copy.deepcopy(self.engine.events), "alerts": copy.deepcopy(self.engine.alerts)}
