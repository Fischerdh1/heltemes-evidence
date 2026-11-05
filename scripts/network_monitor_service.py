"""Foreground, restart-safe AF_UNIX service for the disposable monitor lab."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
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


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def socket_path(state):
    path = store.state_path(state) / SOCKET_NAME
    store.require(len(os.fsencode(path)) <= 100, "State path is too long for the private Unix socket.")
    return path


def receive(connection, limit):
    value = bytearray()
    while not value.endswith(b"\n"):
        part = connection.recv(min(65536, limit + 1 - len(value)))
        if not part:
            raise ValueError("Connection closed before a complete response.")
        value.extend(part)
        store.require(len(value) <= limit, "Socket message exceeds size limit.")
        store.require(b"\n" not in value[:-1], "One request per connection is required.")
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
    def __init__(self, journal, allow_test_crashes=False):
        self.journal, self.allow_test_crashes = journal, allow_test_crashes
        self.instance_id = uuid.uuid4().hex
        self.started = time.monotonic()
        self.base_elapsed = journal.rows[-1]["sample"]["elapsed_seconds"] if journal.rows else 0.0
        # An accepted restart boundary is required before serving any request.
        journal.append("_restart_" + self.instance_id,
            {"phase": "monitor_restart", "observed_at_utc": utc_now(), "ruleset": None,
             "collection_error": "monitor_restarted", "probes": []}, self.base_elapsed, restart=True)

    def status(self):
        return {"process_id": os.getpid(), "instance_id": self.instance_id, **self.journal.status()}

    def dispatch(self, payload):
        store.require(isinstance(payload, dict), "Request must be an object.")
        command = payload.get("command")
        if command == "status":
            store.require(set(payload) == {"command"}, "Unexpected status fields.")
            return {"ok": True, **self.status()}
        if command == "export":
            store.require(set(payload) == {"command"}, "Unexpected export fields.")
            return {"ok": True, **self.journal.export(), "current_status": self.status()}
        store.require(command == "observe" and set(payload) in (
            {"command", "request_id", "observation"}, {"command", "request_id", "observation", "test_crash"}),
            "Observation request fields are invalid.")
        point = payload.get("test_crash")
        store.require(point is None or (self.allow_test_crashes and point in CRASH_CODES), "Test crash is disabled or invalid.")
        def fault(current):
            if current == point:
                os._exit(CRASH_CODES[current])
        result = self.journal.append(payload["request_id"], payload["observation"],
                    self.base_elapsed + time.monotonic() - self.started, fault=fault if point else None)
        return {"ok": True, **result, "result_is_historical": result["duplicate"], "current_status": self.status()}


def serve(state, *, allow_test_crashes=False):
    path = socket_path(state)
    with store.Journal(state) as journal:
        # The lifetime lock permits removing only our owned stale socket.
        if path.exists() or path.is_symlink():
            info = path.lstat()
            store.require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid()
                          and stat.S_IMODE(info.st_mode) == 0o600, "Unexpected object occupies the monitor socket path.")
            path.unlink()
        service = Service(journal, allow_test_crashes)
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
                server.settimeout(0.2)
                while not stopping:
                    try:
                        connection, _ = server.accept()
                    except socket.timeout:
                        continue
                    with connection:
                        connection.settimeout(3)
                        try:
                            response = service.dispatch(receive(connection, store.MAX_REQUEST))
                            data = (store.encoded(response) + "\n").encode()
                            store.require(len(data) <= MAX_RESPONSE, "Response exceeds size limit.")
                        except (ValueError, TypeError, KeyError, OSError, OverflowError):
                            data = b'{"ok":false,"error":"request_rejected"}\n'
                        try:
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
    run = commands.add_parser("serve", help="Serve existing verified state only")
    run.add_argument("--state", required=True)
    run.add_argument("--allow-test-crashes", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "init":
            raw = Path(args.approved).read_bytes()
            store.require(len(raw) <= store.MAX_REQUEST, "Approved input exceeds size limit.")
            result = store.initialize(args.state, store.parse(raw))
            print(store.encoded({"ok": True, "identity": result}))
        else:
            serve(args.state, allow_test_crashes=args.allow_test_crashes)
    except (OSError, ValueError, TypeError, KeyError, OverflowError, store.sqlite3.Error):
        parser.exit(1, "Monitor service stopped: existing state or request could not be verified.\n")


if __name__ == "__main__":
    main()
