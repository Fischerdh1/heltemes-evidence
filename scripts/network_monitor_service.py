"""Foreground, restart-safe AF_UNIX service for the disposable monitor lab."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import math
import os
from pathlib import Path
import signal
import socket
import stat
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor_store as store

SOCKET_NAME = "monitor.sock"
CRASH_CODES = {"before_commit": 71, "after_commit_before_ack": 72}
MAX_RESPONSE = 16 * 1024 * 1024
IO_SECONDS = 3.0
TICK_SECONDS = 0.2


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def socket_path(state):
    path = store.state_path(state) / SOCKET_NAME
    store.require(len(os.fsencode(path)) <= 100, "State path is too long for the private Unix socket.")
    return path


def receive(connection, limit, *, deadline=None, tick=None):
    value = bytearray()
    while not value.endswith(b"\n"):
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Complete request deadline exceeded.")
            connection.settimeout(min(TICK_SECONDS, remaining))
            if tick is not None:
                tick()
        try:
            part = connection.recv(min(65536, limit + 1 - len(value)))
        except socket.timeout:
            if deadline is None:
                raise
            continue
        if not part:
            raise ValueError("Connection closed before a complete response.")
        # Every earlier chunk was already checked. Scanning only the new bytes
        # avoids repeatedly copying and scanning a growing response buffer.
        newline = part.find(b"\n")
        store.require(newline in (-1, len(part) - 1), "One request per connection is required.")
        value.extend(part)
        store.require(len(value) <= limit, "Socket message exceeds size limit.")
    return store.parse(value)


def request(state, payload, timeout=10):
    path = socket_path(state)
    info = path.lstat()
    store.require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid()
                  and stat.S_IMODE(info.st_mode) == 0o600, "Private monitor socket identity is invalid.")
    data = (store.encoded(payload) + "\n").encode()
    store.require(len(data) <= store.MAX_REQUEST, "Request exceeds size limit.")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect(str(path))
        connection.sendall(data)
        return receive(connection, MAX_RESPONSE)


class Service:
    def __init__(self, journal, allow_test_crashes=False, test_pause=None, *, freshness_seconds=None):
        store.require(freshness_seconds is None or (type(freshness_seconds) in (int, float)
                      and math.isfinite(freshness_seconds) and 1 <= freshness_seconds <= 30),
                      "Freshness threshold must be a finite number from 1 to 30 seconds.")
        self.journal, self.allow_test_crashes = journal, allow_test_crashes
        # Only the separately guarded disposable VM worker installs this hook.
        # The ordinary service CLI never enables a transaction pause.
        self.test_pause = test_pause
        self.instance_id = uuid.uuid4().hex
        self.started = time.monotonic()
        self.started_at_utc = utc_now()
        self.freshness_seconds = freshness_seconds
        self.last_accepted = None
        self.gap_attempted = False
        self.gap_sequence = None
        self.gap_committed_at_utc = None
        self.persistence_error = None
        self.outage_number = 0
        last_row = self._last_row()
        self.base_elapsed = last_row["sample"]["elapsed_seconds"] if last_row else 0.0
        # An accepted restart boundary is required before serving any request.
        journal.append("_restart_" + self.instance_id,
            {"phase": "monitor_restart", "observed_at_utc": utc_now(), "ruleset": None,
             "collection_error": "monitor_restarted", "probes": []}, self.base_elapsed, restart=True)

    def _last_row(self):
        if hasattr(self.journal, "last_row"):
            return self.journal.last_row
        return self.journal.rows[-1] if self.journal.rows else None

    def _capacity_remaining(self):
        if hasattr(self.journal, "capacity_remaining"):
            return self.journal.capacity_remaining
        return max(0, store.MAX_ROWS - len(self.journal.rows))

    def _has_request(self, request_id):
        if hasattr(self.journal, "has_request"):
            return self.journal.has_request(request_id)
        return any(row["request_id"] == request_id for row in self.journal.rows)

    def _age(self):
        if self.last_accepted is None:
            return time.monotonic() - self.started
        return (time.monotonic() - self.last_accepted["monotonic"]
                + self.last_accepted["source_age_seconds"])

    def tick(self):
        """Commit a missing-data boundary even while no caller asks for status."""
        if self.freshness_seconds is None:
            return
        if self._capacity_remaining() == 0:
            self.persistence_error = self.persistence_error or "journal_capacity_exhausted"
        if self.persistence_error or self.gap_attempted or self._age() < self.freshness_seconds:
            return
        self.gap_attempted = True
        self.outage_number += 1
        observed = utc_now()
        try:
            result = self.journal.append(f"freshness-gap-{self.instance_id}-{self.outage_number}",
                {"phase": "collector_missing", "observed_at_utc": observed, "ruleset": None,
                 "collection_error": "freshness_deadline_exceeded", "probes": []},
                self.base_elapsed + time.monotonic() - self.started)
        except (OSError, ValueError, store.sqlite3.Error):
            self.persistence_error = "journal_write_failed"
            return
        self.gap_sequence = result["committed_sequence"]
        self.gap_committed_at_utc = utc_now()
        if self._capacity_remaining() == 0:
            self.persistence_error = "journal_capacity_exhausted"

    def status(self):
        self.tick()
        result = {"process_id": os.getpid(), "instance_id": self.instance_id, **self.journal.status()}
        if self.freshness_seconds is None:
            return result
        age = max(0.0, self._age())
        accepted = self.last_accepted or {}
        expired = age >= self.freshness_seconds
        result["freshness"] = {
            "enabled": True, "threshold_seconds": self.freshness_seconds,
            "last_accepted_request_id": accepted.get("request_id"),
            "last_accepted_source_at_utc": accepted.get("source_at_utc"),
            "last_accepted_at_utc": accepted.get("received_at_utc"),
            "age_seconds": age if self.last_accepted else None,
            "waiting_seconds": age if self.last_accepted is None else 0.0,
            "remaining_seconds": max(0.0, self.freshness_seconds - age),
            "deadline_at_utc": datetime.fromtimestamp((accepted.get("source_timestamp")
                if self.last_accepted else store.monitor.utc(self.started_at_utc))
                + self.freshness_seconds, timezone.utc).isoformat(),
            "expired": expired, "gap_recorded": self.gap_sequence is not None,
            "gap_sequence": self.gap_sequence, "gap_committed_at_utc": self.gap_committed_at_utc,
            "capacity_remaining": self._capacity_remaining(),
            "persistence_error": self.persistence_error,
        }
        if self.last_accepted is None or expired or self.persistence_error:
            evaluation = result["current_evaluation"]
            evaluation["status"] = "unknown"
            evaluation["telemetry_valid"] = False
            reason = self.persistence_error or ("freshness_deadline_exceeded" if expired else "awaiting_fresh_telemetry")
            evaluation["diagnostics"].append(reason)
        return result

    def dispatch(self, payload):
        self.tick()
        store.require(isinstance(payload, dict), "Request must be an object.")
        command = payload.get("command")
        if command == "status":
            store.require(set(payload) == {"command"}, "Unexpected status fields.")
            return {"ok": True, **self.status()}
        if command == "export":
            store.require(set(payload) == {"command"}, "Unexpected export fields.")
            if getattr(self.journal, "offline_export_required", False):
                return {"ok": False, "error": "offline_export_required",
                        "message": "Stop the monitor and use the offline archive export command."}
            status = self.status()
            return {"ok": True, **self.journal.export(), "current_status": status}
        store.require(command == "observe" and set(payload) in (
            {"command", "request_id", "observation"}, {"command", "request_id", "observation", "test_crash"},
            {"command", "request_id", "observation", "test_pause"}),
            "Observation request fields are invalid.")
        point = payload.get("test_crash")
        store.require(point is None or (self.allow_test_crashes and point in CRASH_CODES), "Test crash is disabled or invalid.")
        pause = payload.get("test_pause")
        store.require("test_pause" not in payload or (self.test_pause is not None and pause in CRASH_CODES),
                      "Test pause is disabled or invalid.")
        source_time, source_age, received, received_monotonic = None, None, None, None
        duplicate = self._has_request(payload["request_id"])
        if self.freshness_seconds is not None and not duplicate:
            self.journal._validate_observation(payload["observation"])
            store.require(isinstance(payload["request_id"], str)
                          and store.REQUEST_ID.fullmatch(payload["request_id"]), "Request ID is invalid.")
            store.require(self.persistence_error is None, "Journal persistence is unavailable.")
            source_time = store.monitor.utc(payload["observation"]["observed_at_utc"])
            received = utc_now()
            received_monotonic = time.monotonic()
            source_age = store.monitor.utc(received) - source_time
            store.require(0 <= source_age < self.freshness_seconds, "Source timestamp is stale or in the future.")
            store.require(self.last_accepted is None or source_time > self.last_accepted["source_timestamp"],
                          "Source timestamp does not advance the last accepted fresh observation.")
            store.require(source_time >= store.monitor.utc(self._last_row()["sample"]["observed_at_utc"]),
                          "Source timestamp precedes the latest committed observation boundary.")
        def fault(current):
            if current == point:
                os._exit(CRASH_CODES[current])
            if current == pause:
                self.test_pause(self, current, payload)
                raise RuntimeError("A test pause must not return to normal service.")
        try:
            result = self.journal.append(payload["request_id"], payload["observation"],
                        self.base_elapsed + time.monotonic() - self.started, fault=fault if point or pause else None)
        except (OSError, ValueError, store.sqlite3.Error):
            if self.freshness_seconds is not None and not duplicate:
                self.persistence_error = "journal_write_failed"
            raise
        if self.freshness_seconds is not None and not result["duplicate"] and result["evaluation"]["telemetry_valid"]:
            self.last_accepted = {"request_id": payload["request_id"], "source_timestamp": source_time,
                "source_at_utc": payload["observation"]["observed_at_utc"], "received_at_utc": received,
                "monotonic": received_monotonic, "source_age_seconds": source_age}
            self.gap_attempted = False
            self.gap_sequence = None
            self.gap_committed_at_utc = None
        return {"ok": True, **result, "result_is_historical": result["duplicate"], "current_status": self.status()}


def serve(state, *, allow_test_crashes=False, test_pause=None, freshness_seconds=None,
          archive_history=False, journal_factory=None):
    path = socket_path(state)
    if journal_factory is None:
        if archive_history:
            from scripts.network_monitor_archive import ArchiveJournal
            journal_factory = ArchiveJournal
        else:
            journal_factory = store.Journal
    with journal_factory(state) as journal:
        # The lifetime lock permits removing only our owned stale socket.
        if path.exists() or path.is_symlink():
            info = path.lstat()
            store.require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid()
                          and stat.S_IMODE(info.st_mode) == 0o600, "Unexpected object occupies the monitor socket path.")
            path.unlink()
        service = Service(journal, allow_test_crashes, test_pause=test_pause, freshness_seconds=freshness_seconds)
        stopping = False
        def stop(signum, frame):
            nonlocal stopping
            stopping = True
        handlers = {signum: signal.signal(signum, stop) for signum in (signal.SIGTERM, signal.SIGINT)}
        bound_identity = None
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
                server.bind(str(path))
                path.chmod(0o600)
                info = path.lstat()
                bound_identity = (info.st_dev, info.st_ino)
                server.listen(8)
                server.settimeout(TICK_SECONDS)
                while not stopping:
                    service.tick()
                    try:
                        connection, _ = server.accept()
                    except socket.timeout:
                        continue
                    with connection:
                        connection.settimeout(IO_SECONDS)
                        deadline = time.monotonic() + IO_SECONDS if freshness_seconds is not None else None
                        try:
                            response = service.dispatch(receive(connection, store.MAX_REQUEST,
                                deadline=deadline, tick=service.tick if deadline is not None else None))
                            data = (store.encoded(response) + "\n").encode()
                            store.require(len(data) <= MAX_RESPONSE, "Response exceeds size limit.")
                        except (ValueError, TypeError, KeyError, OSError, OverflowError, store.sqlite3.Error):
                            data = b'{"ok":false,"error":"request_rejected"}\n'
                        try:
                            if deadline is not None:
                                connection.settimeout(max(0.001, deadline - time.monotonic()))
                            connection.sendall(data)
                        except OSError:
                            pass  # A committed observation survives a disconnected client.
        finally:
            for signum, handler in handlers.items():
                signal.signal(signum, handler)
            if bound_identity is not None and path.exists():
                info = path.lstat()
                if stat.S_ISSOCK(info.st_mode) and (info.st_dev, info.st_ino) == bound_identity:
                    path.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("init", help="Explicitly initialize new disposable state")
    create.add_argument("--state", required=True)
    create.add_argument("--approved", required=True)
    create.add_argument("--archive-history", action="store_true", help="Explicit new archive journal format")
    create.add_argument("--segment-rows", type=int, default=256)
    create.add_argument("--max-history-rows", type=int, default=4096)
    run = commands.add_parser("serve", help="Serve existing verified state only")
    run.add_argument("--state", required=True)
    run.add_argument("--allow-test-crashes", action="store_true")
    run.add_argument("--freshness-seconds", type=float, help="Opt-in missing-data deadline (1 to 30 seconds)")
    run.add_argument("--archive-history", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "init":
            raw = Path(args.approved).read_bytes()
            store.require(len(raw) <= store.MAX_REQUEST, "Approved input exceeds size limit.")
            if args.archive_history:
                from scripts.network_monitor_archive import initialize
                result = initialize(args.state, store.parse(raw), segment_rows=args.segment_rows,
                                    max_rows=args.max_history_rows)
            else:
                store.require(args.segment_rows == 256 and args.max_history_rows == 4096,
                              "Archive budget options require explicit archive history mode.")
                result = store.initialize(args.state, store.parse(raw))
            print(store.encoded({"ok": True, "identity": result}))
        else:
            serve(args.state, allow_test_crashes=args.allow_test_crashes, freshness_seconds=args.freshness_seconds,
                  archive_history=args.archive_history)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, store.sqlite3.Error):
        parser.exit(1, "Monitor service stopped: existing state or request could not be verified.\n")


if __name__ == "__main__":
    main()
