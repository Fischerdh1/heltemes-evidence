"""Opt-in, bounded history segments for the disposable network monitor.

The original journal format and engine remain unchanged. Sealed segments are
verified local history, not an independent anti-rollback or administrator anchor.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor as monitor
from scripts import network_monitor_store as store

FORMAT = "heltemes-monitor-archive-journal"
VERSION = 1
MAX_ROWS = 4096
MAX_SEGMENTS = 16
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
EVENT_REFERENCES = 16
RESOLVED_SUMMARIES = 16
ROW_KEYS = {"sequence", "request_id", "request", "sample", "evaluation", "events", "previous_digest", "row_digest"}
SCHEMA_SQL = {
    "config": "CREATE TABLE config (id INTEGER PRIMARY KEY CHECK(id=1), identity TEXT NOT NULL, approved TEXT NOT NULL, head_sequence INTEGER NOT NULL, head_digest TEXT NOT NULL, archived_sequence INTEGER NOT NULL, archived_digest TEXT NOT NULL)",
    "observations": store.SCHEMA_SQL["observations"],
    "segments": "CREATE TABLE segments (segment_index INTEGER PRIMARY KEY, first_sequence INTEGER NOT NULL, last_sequence INTEGER NOT NULL, row_count INTEGER NOT NULL, byte_count INTEGER NOT NULL, file_digest TEXT NOT NULL, last_digest TEXT NOT NULL)",
}


def implementation_hash():
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


class StreamingMonitor(monitor.Monitor):
    """Keep current state bounded; complete observation/event history lives on disk."""
    def __init__(self, approved):
        super().__init__(approved)
        self.event_count = 0
        self.resolved_count = 0

    def observe(self, sample):
        self.events, self.evaluations = [], []
        result = super().observe(sample)
        resolved = sorted((alert for alert in self.alerts if alert["state"] == "resolved"),
                          key=lambda alert: (alert["resolved_sequence"], alert["last_seen_sequence"]))
        retained = {alert["id"] for alert in resolved[-RESOLVED_SUMMARIES:]}
        self.alerts = [alert for alert in self.alerts if alert["state"] == "open" or alert["id"] in retained]
        return result

    def _signal(self, code, scope, severity, active, evidence, sample):
        key = code + ":" + scope
        incident = self._active.get(key)
        if not active and incident is None:
            return
        action = "updated" if active and incident is not None else "opened" if active else "resolved"
        if action == "opened":
            occurrence = self._occurrences.get(key, 0) + 1
            self._occurrences[key] = occurrence
            incident = {"id": key + "#" + str(occurrence), "key": key, "code": code, "scope": scope,
                        "severity": severity, "state": "open", "occurrence": occurrence,
                        "opened_sequence": sample.get("sequence"), "resolved_sequence": None,
                        "observations": 0, "event_ids": [], "event_count": 0, "event_ids_truncated": False}
            self.alerts.append(incident)
            self._active[key] = incident
        self.event_count += 1
        event = {"id": f"event-{self.event_count:04d}", "alert_id": incident["id"], "key": key,
                 "code": code, "severity": severity, "action": action,
                 "sequence": sample.get("sequence"), "phase": sample.get("phase"),
                 "observed_at_utc": sample.get("observed_at_utc"), "evidence": copy.deepcopy(evidence)}
        self.events.append(event)
        incident["event_ids"].append(event["id"])
        incident["event_count"] += 1
        incident["event_ids"] = incident["event_ids"][-EVENT_REFERENCES:]
        incident["event_ids_truncated"] = incident["event_count"] > len(incident["event_ids"])
        incident["last_seen_sequence"] = sample.get("sequence")
        incident["last_evidence"] = copy.deepcopy(evidence)
        if active:
            incident["observations"] += 1
        else:
            incident["state"] = "resolved"
            incident["resolved_sequence"] = sample.get("sequence")
            self.resolved_count += 1
            del self._active[key]


def initialize(value, approved, *, segment_rows=256, max_rows=MAX_ROWS, max_archive_bytes=MAX_ARCHIVE_BYTES):
    """Create a new opt-in identity; never migrate/reset an existing journal."""
    StreamingMonitor(approved)
    store.require(type(segment_rows) is int and 32 <= segment_rows <= store.MAX_ROWS,
                  "Segment row bound must be from 32 to 256.")
    store.require(type(max_rows) is int and segment_rows <= max_rows <= min(MAX_ROWS, segment_rows * MAX_SEGMENTS),
                  "Total row bound must fit the configured segment size and 16 segment budget.")
    store.require(type(max_archive_bytes) is int and 1024 <= max_archive_bytes <= MAX_ARCHIVE_BYTES,
                  "Archive byte budget must be from 1024 bytes to 128 MiB.")
    store.require(len(store.encoded(approved).encode()) <= store.MAX_REQUEST, "Approved ruleset exceeds size limit.")
    path = store.state_path(value, existing=False)
    store.require(path.parent.is_dir() and not path.exists(), "Initialization requires a new state directory.")
    path.mkdir(mode=0o700)
    store.sync_directory(path.parent)
    archives = path / "archives"
    archives.mkdir(mode=0o700)
    identity = {"format": FORMAT, "version": VERSION, "database_id": uuid.uuid4().hex,
                "approved_policy_sha256": monitor.policy_fingerprint(approved), "engine_sha256": store.engine_hash(),
                "archive_engine_sha256": implementation_hash(), "segment_rows": segment_rows,
                "max_rows": max_rows, "max_segments": MAX_SEGMENTS, "max_archive_bytes": max_archive_bytes}
    store.write_new(path / "service.lock", b"")
    store.write_new(path / "monitor.sqlite3", b"")
    connection = sqlite3.connect((path / "monitor.sqlite3").as_uri() + "?mode=rw", uri=True, isolation_level=None)
    try:
        store.configure(connection)
        connection.execute("BEGIN IMMEDIATE")
        for statement in SCHEMA_SQL.values():
            connection.execute(statement)
        connection.execute("INSERT INTO config VALUES(1,?,?,0,?,0,?)",
                           (store.encoded(identity), store.encoded(approved), store.ZERO, store.ZERO))
        connection.execute("COMMIT")
    finally:
        connection.close()
    store.sync_directory(archives)
    store.write_new(path / "identity.json", (store.encoded(identity) + "\n").encode())
    store.sync_directory(path)
    return identity


class ArchiveJournal:
    _validate_observation = staticmethod(store.Journal._validate_observation)

    def __init__(self, value):
        self.path = store.state_path(value)
        self.connection, self.lock_fd = None, None
        self.failure = None
        self.recovery_actions = []
        try:
            store.ordinary(self.path / "service.lock", limit=0)
            self.lock_fd = os.open(self.path / "service.lock", os.O_RDWR | os.O_NOFOLLOW)
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.identity = store.parse(store.read_private(self.path / "identity.json", limit=4096))
            self._validate_identity()
            self.archive_path = store.state_path(self.path / "archives")
            store.ordinary(self.path / "monitor.sqlite3")
            for suffix in ("-journal", "-wal", "-shm"):
                sidecar = self.path / ("monitor.sqlite3" + suffix)
                if sidecar.exists() or sidecar.is_symlink():
                    store.ordinary(sidecar)
                    store.require(suffix == "-journal", "Unexpected SQLite journal mode.")
            self.connection = sqlite3.connect((self.path / "monitor.sqlite3").as_uri() + "?mode=rw", uri=True,
                                             isolation_level=None, timeout=2)
            store.configure(self.connection)
            self._load()
        except BaseException:
            self.close()
            raise

    def _validate_identity(self):
        identity = self.identity
        store.require(isinstance(identity, dict) and set(identity) == {"format", "version", "database_id",
            "approved_policy_sha256", "engine_sha256", "archive_engine_sha256", "segment_rows", "max_rows",
            "max_segments", "max_archive_bytes"}, "Archive identity fields differ.")
        store.require(identity["format"] == FORMAT and identity["version"] == VERSION
            and isinstance(identity["database_id"], str) and re.fullmatch(r"[0-9a-f]{32}", identity["database_id"])
            and identity["engine_sha256"] == store.engine_hash()
            and identity["archive_engine_sha256"] == implementation_hash(), "Archive identity or engine version is incompatible.")
        store.require(type(identity["segment_rows"]) is int and 32 <= identity["segment_rows"] <= store.MAX_ROWS
            and type(identity["max_rows"]) is int
            and identity["segment_rows"] <= identity["max_rows"] <= min(MAX_ROWS, identity["segment_rows"] * MAX_SEGMENTS)
            and type(identity["max_segments"]) is int and identity["max_segments"] == MAX_SEGMENTS
            and type(identity["max_archive_bytes"]) is int and 1024 <= identity["max_archive_bytes"] <= MAX_ARCHIVE_BYTES,
            "Archive storage budget is incompatible.")

    close = store.Journal.close
    __enter__ = store.Journal.__enter__
    __exit__ = store.Journal.__exit__

    @staticmethod
    def _filename(index):
        return f"segment-{index:06d}.json"

    def _segment(self, index, rows):
        return {"format": FORMAT + "-segment", "version": VERSION, "database_id": self.identity["database_id"],
                "segment_index": index, "first_sequence": rows[0]["sequence"], "last_sequence": rows[-1]["sequence"],
                "previous_digest": rows[0]["previous_digest"], "last_digest": rows[-1]["row_digest"], "rows": rows}

    def _segment_bytes(self, index, rows):
        return (store.encoded(self._segment(index, rows)) + "\n").encode()

    def _read_segment(self, descriptor):
        index, first, last, count, size, expected, last_digest = descriptor
        raw = store.read_private(self.archive_path / self._filename(index))
        store.require(len(raw) == size and hashlib.sha256(raw).hexdigest() == expected, "Archive segment bytes differ.")
        value = store.parse(raw)
        store.require(isinstance(value, dict) and isinstance(value.get("rows"), list)
                      and len(value["rows"]) == count and count == self.identity["segment_rows"],
                      "Archive segment row count differs.")
        rows = value["rows"]
        store.require(rows and value == self._segment(index, rows) and self._segment_bytes(index, rows) == raw
                      and (rows[0]["sequence"], rows[-1]["sequence"], rows[-1]["row_digest"]) == (first, last, last_digest),
                      "Archive segment envelope differs.")
        return rows

    @staticmethod
    def _database_row(raw):
        sequence, request_id, request, sample, evaluation, events, previous, row_digest = raw
        return {"sequence": sequence, "request_id": request_id, "request": store.parse(request),
                "sample": store.parse(sample), "evaluation": store.parse(evaluation), "events": store.parse(events),
                "previous_digest": previous, "row_digest": row_digest}

    def _replay_row(self, row, location):
        store.require(isinstance(row, dict) and set(row) == ROW_KEYS, "Journal row fields differ.")
        sequence, request_id, request, sample = (row[key] for key in ("sequence", "request_id", "request", "sample"))
        store.require(type(sequence) is int and sequence == self.total_count + 1 and isinstance(sample, dict)
                      and sample.get("sequence") == sequence and row["previous_digest"] == self.head_digest,
                      "Journal sequence or chain is incomplete.")
        store.require(isinstance(request, dict) and set(request) == {"kind", "observation"}
                      and request["kind"] in {"restart", "observation"}, "Journal request kind is invalid.")
        self._validate_observation(request["observation"])
        store.require(set(sample) == store.OBSERVATION_KEYS | {"sequence", "elapsed_seconds"}
                      and all(sample.get(key) == request["observation"][key] for key in store.OBSERVATION_KEYS),
                      "Journal sample differs from its request.")
        store.require(isinstance(request_id, str) and ((request["kind"] == "restart"
                      and re.fullmatch(r"_restart_[0-9a-f]{32}", request_id) and sample["phase"] == "monitor_restart"
                      and sample["ruleset"] is None and sample["collection_error"] == "monitor_restarted"
                      and sample["probes"] == []) or (request["kind"] == "observation" and store.REQUEST_ID.fullmatch(request_id))),
                      "Journal request identity is invalid.")
        store.require(request_id not in self._requests, "Journal request identity is duplicated.")
        evaluation = self.engine.observe(sample)
        store.require(evaluation == row["evaluation"] and self.engine.events == row["events"],
                      "Saved monitoring result does not match deterministic replay.")
        store.require(store.digest({key: row[key] for key in ROW_KEYS - {"row_digest"}}) == row["row_digest"],
                      "Journal row digest differs.")
        self.total_count, self.head_digest, self.last_row = sequence, row["row_digest"], row
        self._requests[request_id] = (location, sequence)

    def _load(self):
        store.require(self.connection.execute("PRAGMA quick_check").fetchone() == ("ok",), "Journal database integrity check failed.")
        objects = self.connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT GLOB 'sqlite_*' ORDER BY name").fetchall()
        store.require(objects == [("table", name, name, statement) for name, statement in sorted(SCHEMA_SQL.items())],
                      "Journal schema is incompatible.")
        config = self.connection.execute("SELECT identity,approved,head_sequence,head_digest,archived_sequence,archived_digest FROM config WHERE id=1").fetchone()
        store.require(config is not None and self.connection.execute("SELECT count(*) FROM config").fetchone()[0] == 1,
                      "Journal configuration is missing or duplicated.")
        store.require(store.parse(config[0]) == self.identity, "Pinned identity differs from database identity.")
        self.approved = store.parse(config[1])
        store.require(len(config[1].encode()) <= store.MAX_REQUEST
                      and monitor.policy_fingerprint(self.approved) == self.identity["approved_policy_sha256"], "Pinned approved policy differs.")
        self.engine, self.rows, self._requests = StreamingMonitor(self.approved), [], {}
        self.total_count, self.head_digest, self.last_row = 0, store.ZERO, None
        self.segments = self.connection.execute("SELECT segment_index,first_sequence,last_sequence,row_count,byte_count,file_digest,last_digest FROM segments ORDER BY segment_index").fetchall()
        store.require(len(self.segments) <= MAX_SEGMENTS, "Archive segment budget exceeded.")
        self.archive_bytes = 0
        for position, descriptor in enumerate(self.segments, 1):
            index, first, last, count, size, file_digest, last_digest = descriptor
            store.require(all(type(number) is int for number in (index, first, last, count, size))
                          and index == position and first == self.total_count + 1 and last == first + count - 1
                          and count == self.identity["segment_rows"] and 0 < size <= store.MAX_BYTES,
                          "Archive descriptor sequence or size differs.")
            self.archive_bytes += size
            store.require(self.archive_bytes <= self.identity["max_archive_bytes"], "Archive byte budget exceeded.")
            for row in self._read_segment(descriptor):
                self._replay_row(row, index)
        store.require((config[4], config[5]) == (self.total_count, self.head_digest), "Archived boundary differs from verified segments.")
        records = self.connection.execute("SELECT sequence,request_id,request,sample,evaluation,events,previous_digest,row_digest FROM observations ORDER BY sequence").fetchall()
        store.require(len(records) <= self.identity["segment_rows"], "Active journal history exceeds bound.")
        for raw in records:
            row = self._database_row(raw)
            self._replay_row(row, None)
            self.rows.append(row)
        store.require(self.total_count <= self.identity["max_rows"]
                      and (config[2], config[3]) == (self.total_count, self.head_digest), "Journal head differs from committed history.")
        referenced = {self._filename(descriptor[0]) for descriptor in self.segments}
        names = {path.name for path in self.archive_path.iterdir()}
        orphan = self._filename(len(self.segments) + 1)
        pending = orphan + ".pending"
        store.require(names == referenced or (names in (referenced | {orphan}, referenced | {pending})
                      and len(self.rows) == self.identity["segment_rows"]), "Unexpected archive file inventory.")
        # A pre-metadata crash leaves the exact full prefix in SQLite. The file
        # is adopted only after full replay and byte-for-byte comparison below.
        if len(self.rows) == self.identity["segment_rows"]:
            self._rotate()

    @property
    def head_sequence(self):
        return self.total_count

    @property
    def capacity_remaining(self):
        return max(0, self.identity["max_rows"] - self.total_count)

    def has_request(self, request_id):
        return isinstance(request_id, str) and request_id in self._requests

    def _find_request(self, request_id):
        location = self._requests.get(request_id) if isinstance(request_id, str) else None
        if location is None:
            return None
        segment, sequence = location
        rows = self.rows if segment is None else self._read_segment(self.segments[segment - 1])
        row = next((item for item in rows if item["sequence"] == sequence), None)
        store.require(row is not None and row["request_id"] == request_id, "Duplicate request location differs.")
        return row

    def _rotation_payload(self, rows):
        store.require(len(self.segments) < MAX_SEGMENTS, "Archive segment budget exhausted.")
        index = len(self.segments) + 1
        raw = self._segment_bytes(index, rows)
        store.require(len(raw) <= store.MAX_BYTES and self.archive_bytes + len(raw) <= self.identity["max_archive_bytes"],
                      "Archive byte budget exhausted.")
        descriptor = (index, rows[0]["sequence"], rows[-1]["sequence"], len(rows), len(raw),
                      hashlib.sha256(raw).hexdigest(), rows[-1]["row_digest"])
        return raw, descriptor

    def _rotate(self, fault=None):
        store.require(len(self.rows) == self.identity["segment_rows"], "Only a full active segment can be archived.")
        raw, descriptor = self._rotation_payload(self.rows)
        destination = self.archive_path / self._filename(descriptor[0])
        staging = destination.with_name(destination.name + ".pending")
        if destination.exists() or destination.is_symlink():
            store.require(not staging.exists() and not staging.is_symlink(), "Conflicting archive staging file.")
            store.require(store.read_private(destination) == raw, "Uncommitted archive differs from the exact active prefix.")
            self.recovery_actions.append({"action": "accepted_exact_uncommitted_segment", "segment_index": descriptor[0]})
        else:
            if staging.exists() or staging.is_symlink():
                partial = store.read_private(staging)
                # Staging is never accepted history. Rebuild only a known
                # private prefix of the exact segment replayed from SQLite.
                store.require(raw.startswith(partial), "Archive staging bytes differ from the exact active prefix.")
                staging.unlink()
                store.sync_directory(self.archive_path)
                self.recovery_actions.append({"action": "rebuilt_verified_staging_prefix", "segment_index": descriptor[0],
                                              "staged_bytes": len(partial)})
            store.write_new(staging, raw)
            if fault:
                fault("archive_staging_durable")
            # The lifetime writer lock and private directory exclude competing
            # legitimate publishers. Never replace an observed final segment.
            store.require(not destination.exists() and not destination.is_symlink(), "Archive destination unexpectedly exists.")
            os.rename(staging, destination)
        store.sync_directory(self.archive_path)
        if fault:
            fault("archive_file_durable")
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            self.connection.execute("INSERT INTO segments VALUES(?,?,?,?,?,?,?)", descriptor)
            removed = self.connection.execute("DELETE FROM observations WHERE sequence>=? AND sequence<=?", descriptor[1:3]).rowcount
            store.require(removed == len(self.rows), "Archive handoff did not remove the exact committed prefix.")
            self.connection.execute("UPDATE config SET archived_sequence=?,archived_digest=? WHERE id=1", (descriptor[2], descriptor[6]))
            self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise
        self.segments.append(descriptor)
        self.archive_bytes += len(raw)
        for row in self.rows:
            self._requests[row["request_id"]] = (descriptor[0], row["sequence"])
        self.rows = []
        if fault:
            fault("archive_metadata_committed")

    def append(self, request_id, observation, elapsed_seconds, *, restart=False, fault=None):
        self._validate_observation(observation)
        store.require(isinstance(request_id, str) and ((restart and re.fullmatch(r"_restart_[0-9a-f]{32}", request_id))
                      or (not restart and store.REQUEST_ID.fullmatch(request_id))), "Request ID is invalid.")
        request = {"kind": "restart" if restart else "observation", "observation": copy.deepcopy(observation)}
        existing = self._find_request(request_id)
        if existing is not None:
            store.require(store.encoded(existing["request"]) == store.encoded(request), "Request ID conflicts with already committed content.")
            return {"duplicate": True, "committed_sequence": existing["sequence"],
                    "evaluation": copy.deepcopy(existing["evaluation"]), "events": copy.deepcopy(existing["events"])}
        store.require(self.failure is None, "Journal persistence is unavailable; verified restart is required.")
        store.require(self.capacity_remaining > 0, "Journal total row budget exhausted.")
        store.require(len(self.rows) < self.identity["segment_rows"], "Archive handoff is pending; verified restart is required.")
        candidate = copy.deepcopy(self.engine)
        sequence = self.total_count + 1
        sample = {**copy.deepcopy(observation), "sequence": sequence, "elapsed_seconds": elapsed_seconds}
        evaluation = candidate.observe(sample)
        payload = {"sequence": sequence, "request_id": request_id, "request": request, "sample": sample,
                   "evaluation": evaluation, "events": copy.deepcopy(candidate.events), "previous_digest": self.head_digest}
        row = {**payload, "row_digest": store.digest(payload)}
        try:
            if len(self.rows) + 1 == self.identity["segment_rows"]:
                self._rotation_payload([*self.rows, row])  # Budget check before committing the boundary row.
            self.connection.execute("BEGIN IMMEDIATE")
            self.connection.execute("INSERT INTO observations VALUES(?,?,?,?,?,?,?,?)", (sequence, request_id,
                store.encoded(request), store.encoded(sample), store.encoded(evaluation), store.encoded(candidate.events),
                self.head_digest, row["row_digest"]))
            self.connection.execute("UPDATE config SET head_sequence=?,head_digest=? WHERE id=1", (sequence, row["row_digest"]))
            pages = self.connection.execute("PRAGMA page_count").fetchone()[0]
            page_size = self.connection.execute("PRAGMA page_size").fetchone()[0]
            store.require(pages * page_size <= store.MAX_BYTES, "Active journal byte budget exceeded.")
            if fault:
                fault("before_commit")
            self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            self.failure = "journal_write_failed"
            raise
        self.rows.append(row)
        self.total_count, self.head_digest, self.last_row, self.engine = sequence, row["row_digest"], row, candidate
        self._requests[request_id] = (None, sequence)
        try:
            if len(self.rows) == self.identity["segment_rows"]:
                self._rotate(fault)
            if fault:
                fault("after_commit_before_ack")
        except BaseException:
            self.failure = "archive_handoff_failed"
            raise
        return {"duplicate": False, "committed_sequence": sequence,
                "evaluation": copy.deepcopy(evaluation), "events": copy.deepcopy(candidate.events)}

    def status(self):
        current = copy.deepcopy(self.engine.evaluations[-1]) if self.engine.evaluations else None
        reason = self.failure or ("journal_capacity_exhausted" if self.capacity_remaining == 0 else None)
        if current is not None and reason:
            current["status"], current["telemetry_valid"] = "unknown", False
            current["diagnostics"].append(reason)
        return {"committed_count": self.total_count, "head_digest": self.head_digest,
                "current_evaluation": current, "alerts": copy.deepcopy(self.engine.alerts),
                "history_summary": {"complete": False, "resolved_alerts_total": self.engine.resolved_count,
                    "resolved_alerts_retained": sum(item["state"] == "resolved" for item in self.engine.alerts),
                    "event_ids_per_alert_limit": EVENT_REFERENCES, "full_history_available_in_offline_export": True,
                    "socket_export_byte_limit": 16 * 1024 * 1024},
                "archives": {"enabled": True, "segment_rows": self.identity["segment_rows"],
                    "active_rows": len(self.rows), "sealed_segments": len(self.segments),
                    "archived_rows": sum(item[3] for item in self.segments), "archive_bytes": self.archive_bytes,
                    "max_rows": self.identity["max_rows"], "max_segments": MAX_SEGMENTS,
                    "max_archive_bytes": self.identity["max_archive_bytes"], "capacity_remaining": self.capacity_remaining,
                    "persistence_error": reason, "recovery_actions": copy.deepcopy(self.recovery_actions)}}

    def iter_rows(self):
        """Stream bounded segments; explicit exports may materialize the finite history."""
        for descriptor in self.segments:
            yield from self._read_segment(descriptor)
        yield from copy.deepcopy(self.rows)

    def export(self):
        rows = list(self.iter_rows())
        events = [copy.deepcopy(event) for row in rows for event in row["events"]]
        alerts = {}
        for event in events:
            if event["action"] == "opened":
                alerts[event["alert_id"]] = {"id": event["alert_id"], "key": event["key"], "code": event["code"],
                    "scope": event["key"].split(":", 1)[1], "severity": event["severity"], "state": "open",
                    "occurrence": int(event["alert_id"].rsplit("#", 1)[1]), "opened_sequence": event["sequence"],
                    "resolved_sequence": None, "observations": 0, "event_ids": []}
            incident = alerts[event["alert_id"]]
            incident["event_ids"].append(event["id"])
            incident["last_seen_sequence"], incident["last_evidence"] = event["sequence"], copy.deepcopy(event["evidence"])
            if event["action"] == "resolved":
                incident["state"], incident["resolved_sequence"] = "resolved", event["sequence"]
            else:
                incident["observations"] += 1
        return {"identity": copy.deepcopy(self.identity), "approved_policy": copy.deepcopy(self.approved), "rows": rows,
                "evaluations": [copy.deepcopy(row["evaluation"]) for row in rows], "events": events,
                "alerts": list(alerts.values()), "history_complete": True,
                "archive_descriptors": [dict(zip(("segment_index", "first_sequence", "last_sequence", "row_count",
                    "byte_count", "file_digest", "last_digest"), item)) for item in self.segments]}


def export_offline(state, output):
    """Stream complete rows to a new private file while holding the writer lock."""
    destination = store.state_path(output, existing=False)
    store.require(destination.parent.is_dir() and not destination.exists(), "Offline export requires a new output file.")
    with ArchiveJournal(state) as journal:
        fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as handle:
                header = {"identity": journal.identity, "approved_policy": journal.approved}
                handle.write((store.encoded(header)[:-1] + ',"rows":[').encode())
                count = 0
                for row in journal.iter_rows():
                    if count:
                        handle.write(b",")
                    handle.write(store.encoded(row).encode())
                    count += 1
                handle.write(b'],"history_complete":true}\n')
                handle.flush()
                os.fsync(fd)
        finally:
            os.close(fd)
        store.sync_directory(destination.parent)
        return {"committed_count": count, "head_digest": journal.head_digest,
                "output_bytes": destination.stat().st_size}


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Stream full disposable monitoring history; stop the writer first.")
    parser.add_argument("--state", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = export_offline(args.state, args.output)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, sqlite3.Error):
        parser.exit(1, "Archive export stopped: history or new output could not be verified.\n")
    print(store.encoded({"ok": True, **result}))


if __name__ == "__main__":
    main()
