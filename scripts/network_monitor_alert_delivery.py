"""Deliver committed synthetic firewall alerts to an authenticated loopback receiver."""
from __future__ import annotations

import argparse
from contextlib import closing, contextmanager
import fcntl
import hashlib
import hmac
from http.client import HTTPConnection, HTTPException, RemoteDisconnected
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import os
import re
import sqlite3
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store

HOST, PORT, ENDPOINT = "127.0.0.1", 18766, "/alerts"
AUTH_HEADER = "X-Heltemes-Signature"
MAX_BODY, MAX_DELIVERIES, MAX_ATTEMPTS = 4096, 512, 4096
TIMEOUT, RETRY_INTERVAL = 2, 0.5
FAULT_MARKER = b"drop-next-ack\n"
CODE = "forbidden_path_open"
ACTIONS = {"opened", "resolved"}
MSG_FIELDS = {"version", "id", "journal_id", "event_id", "incident_id", "sequence",
              "action", "code", "severity", "observed_at_utc"}
SHA256 = re.compile(r"[0-9a-f]{64}")
JOURNAL_ID = re.compile(r"[0-9a-f]{32}")
EVENT_ID = re.compile(r"event-[0-9]{4,8}")
INCIDENT_ID = re.compile(
    r"forbidden_path_open:(user|app|management)->(user|app|management):(8080|9090)#[1-9][0-9]{0,5}"
)
UTC_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)")
require = store.require


def canonical(value):
    return store.encoded(value).encode()


def payload_digest(body):
    return hashlib.sha256(body).hexdigest()


def signature(secret, purpose, body):
    require(purpose in {"request", "ack"}, "Unknown alert authentication purpose.")
    prefix = ("heltemes-alert-v1/" + purpose + "\n").encode("ascii")
    return hmac.new(secret, prefix + body, hashlib.sha256).hexdigest()


def authenticated(secret, purpose, body, headers):
    values = headers.get_all(AUTH_HEADER, [])
    return (len(values) == 1 and SHA256.fullmatch(values[0]) is not None
            and hmac.compare_digest(values[0], signature(secret, purpose, body)))


def message_id(journal_id, event_id):
    return payload_digest(canonical([journal_id, event_id]))


def validate_message(message):
    require(isinstance(message, dict) and set(message) == MSG_FIELDS,
            "Alert message fields differ from the allowed projection.")
    require(type(message["version"]) is int and message["version"] == 1
            and message["action"] in ACTIONS and message["code"] == CODE
            and message["severity"] == "critical" and type(message["sequence"]) is int
            and 1 <= message["sequence"] <= store.MAX_ROWS, "Alert classification is invalid.")
    require(all(isinstance(message[field], str) and pattern.fullmatch(message[field])
                for field, pattern in (("id", SHA256), ("journal_id", JOURNAL_ID),
                ("event_id", EVENT_ID), ("incident_id", INCIDENT_ID), ("observed_at_utc", UTC_TIME))),
            "Alert identity or UTC timestamp is invalid.")
    store.monitor.utc(message["observed_at_utc"])
    require(hmac.compare_digest(message["id"], message_id(message["journal_id"], message["event_id"])),
            "Alert identity does not match its source event.")
    return message


def project(journal_id, event):
    if event["code"] != CODE or event["severity"] != "critical" or event["action"] not in ACTIONS:
        return None
    return validate_message({
        "version": 1, "id": message_id(journal_id, event["id"]), "journal_id": journal_id,
        "event_id": event["id"], "incident_id": event["alert_id"], "sequence": event["sequence"],
        "action": event["action"], "code": event["code"], "severity": event["severity"],
        "observed_at_utc": event["observed_at_utc"],
    })


def private_bytes(path, byte_limit):
    return store.read_private(store.state_path(path, existing=False), limit=byte_limit)


def read_key(path):
    key = private_bytes(path, 32)
    require(len(key) == 32, "The disposable alert key must be exactly 32 bytes.")
    return key


def initialize(state, role):
    require(role in {"sender", "receiver"}, "Unknown delivery state role.")
    state = store.state_path(state, existing=False)
    state.mkdir(mode=0o700)
    store.sync_directory(state.parent)
    store.write_new(state / "delivery.sqlite3", b"")
    if role == "sender":
        store.write_new(state / "sender.lock", b"")
    with database(state, initializing=True) as db, db:
        db.execute("CREATE TABLE meta (slot INTEGER PRIMARY KEY CHECK(slot=1), role TEXT NOT NULL, "
                   "journal_id TEXT, imported_rows INTEGER NOT NULL, imported_head TEXT NOT NULL)")
        db.execute("INSERT INTO meta VALUES(1, ?, NULL, 0, ?)", (role, store.ZERO))
        if role == "sender":
            db.execute("CREATE TABLE deliveries (ordinal INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL, "
                       "body BLOB NOT NULL, digest TEXT NOT NULL, ack BLOB)")
            db.execute("CREATE TABLE attempts (number INTEGER PRIMARY KEY, id TEXT NOT NULL REFERENCES deliveries(id), "
                       "result TEXT NOT NULL)")
        else:
            db.execute("CREATE TABLE deliveries (ordinal INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL, "
                       "body BLOB NOT NULL, digest TEXT NOT NULL, duplicates INTEGER NOT NULL, dropped INTEGER NOT NULL)")
    store.write_new(state / "role", (role + "\n").encode("ascii"))
    store.sync_directory(state)
    return {"ok": True, "role": role}


@contextmanager
def database(state, role=None, *, initializing=False, readonly=False):
    path = store.state_path(state)
    require(initializing or store.read_private(path / "role", limit=32) == (role + "\n").encode("ascii"),
            "Delivery state is incomplete or belongs to another role.")
    file = path / "delivery.sqlite3"
    store.ordinary(file)
    mode = "ro" if readonly else "rw"
    with closing(sqlite3.connect(f"{file.as_uri()}?mode={mode}", uri=True, timeout=10)) as db:
        if readonly:
            db.execute("PRAGMA query_only=ON")
            db.execute("PRAGMA trusted_schema=OFF")
        else:
            store.configure(db)
        require(initializing or db.execute("SELECT role FROM meta WHERE slot=1").fetchone() == (role,),
                "Database role does not match the delivery directory.")
        yield db


def committed_snapshot(monitor_state):
    """Read the journal's committed IPC export and check its row chain."""
    export = service.request(monitor_state, {"command": "export"}, timeout=TIMEOUT)
    identity, rows = export["identity"], export["rows"]
    journal_id = identity["database_id"]
    require(export.get("ok") is True and identity["format"] == store.FORMAT
            and identity["version"] == store.VERSION and JOURNAL_ID.fullmatch(journal_id)
            and isinstance(rows, list) and len(rows) <= store.MAX_ROWS,
            "Invalid committed monitor snapshot.")
    previous = store.ZERO
    for sequence, row in enumerate(rows, 1):
        content = {key: value for key, value in row.items() if key != "row_digest"}
        require(row["sequence"] == sequence and row["previous_digest"] == previous
                and row["row_digest"] == store.digest(content)
                and row["sample"]["sequence"] == sequence
                and all(event["sequence"] == sequence
                        and event["observed_at_utc"] == row["sample"]["observed_at_utc"] for event in row["events"]),
                "Committed monitor history does not match its row chain.")
        previous = row["row_digest"]
    require(export["current_status"]["committed_count"] == len(rows)
            and export["current_status"]["head_digest"] == previous,
            "Exported monitor history disagrees with its head.")
    return journal_id, rows


def import_pending(db, journal_id, rows):
    with db:
        pinned, imported, head = db.execute(
            "SELECT journal_id, imported_rows, imported_head FROM meta WHERE slot=1").fetchone()
        require(pinned in (None, journal_id) and 0 <= imported <= len(rows)
                and head == (rows[imported - 1]["row_digest"] if imported else store.ZERO),
                "Committed monitor history was replaced or rolled back.")
        for row in rows[imported:]:
            for event in row["events"]:
                message = project(journal_id, event)
                if message is not None:
                    body = canonical(message)
                    require(len(body) <= MAX_BODY, "Projected alert exceeds its bound.")
                    db.execute("INSERT INTO deliveries(id,body,digest) VALUES(?,?,?)",
                               (message["id"], body, payload_digest(body)))
        require(db.execute("SELECT count(*) FROM deliveries").fetchone()[0] <= MAX_DELIVERIES,
                "The bounded alert outbox is full.")
        db.execute("UPDATE meta SET journal_id=?, imported_rows=?, imported_head=? WHERE slot=1",
                   (journal_id, len(rows), rows[-1]["row_digest"] if rows else store.ZERO))


def post(secret, body, identity, digest):
    with closing(HTTPConnection(HOST, PORT, timeout=TIMEOUT)) as connection:
        try:
            connection.request("POST", ENDPOINT, body=body, headers={
                "Content-Type": "application/json", AUTH_HEADER: signature(secret, "request", body),
                "Connection": "close",
            })
        except (OSError, HTTPException):
            return "transport_error", None
        try:
            with connection.getresponse() as response:
                if response.status != 200:
                    return "invalid_ack", None
                length = response.headers.get_all("Content-Length", [])
                if (len(length) != 1 or not re.fullmatch(r"[1-9][0-9]{0,3}", length[0])
                        or int(length[0]) > MAX_BODY or response.getheader("Transfer-Encoding") is not None):
                    return "invalid_ack", None
                raw = response.read(int(length[0]))
                if len(raw) != int(length[0]):
                    return "ack_missing", None
                if not authenticated(secret, "ack", raw, response.headers):
                    return "invalid_ack", None
            ack = store.parse(raw)
            if (not isinstance(ack, dict) or set(ack) != {"id", "payload_sha256", "duplicate"}
                    or ack["id"] != identity or ack["payload_sha256"] != digest
                    or type(ack["duplicate"]) is not bool or canonical(ack) != raw):
                return "invalid_ack", None
        except (OSError, RemoteDisconnected):
            return "ack_missing", None
        except (HTTPException, ValueError):
            return "invalid_ack", None
    return ("duplicate" if ack["duplicate"] else "accepted"), raw


@contextmanager
def sender_lock(state):
    path = store.state_path(state) / "sender.lock"
    store.ordinary(path, limit=0)
    fd = os.open(path, os.O_NOFOLLOW | os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def deliver_once(state, monitor_state, key_path):
    secret = read_key(key_path)
    with sender_lock(state), database(state, "sender") as db:
        import_pending(db, *committed_snapshot(monitor_state))
        pending = db.execute("SELECT id,body,digest FROM deliveries WHERE ack IS NULL ORDER BY ordinal LIMIT 1").fetchone()
        if pending is None:
            return None
        identity, body, digest = pending
        require(payload_digest(body) == digest and validate_message(store.parse(body))["id"] == identity,
                "Pending outbox content does not match its saved identity.")
        with db:
            require(db.execute("SELECT count(*) FROM attempts").fetchone()[0] < MAX_ATTEMPTS,
                    "The bounded delivery attempt log is full.")
            number = db.execute("INSERT INTO attempts(id,result) VALUES(?,'started')", (identity,)).lastrowid
        result, ack = post(secret, body, identity, digest)
        with db:
            db.execute("UPDATE attempts SET result=? WHERE number=?", (result, number))
            if ack is not None:
                db.execute("UPDATE deliveries SET ack=? WHERE id=?", (ack, identity))
        return {"number": number, "id": identity, "result": result}


def serve_sender(state, monitor_state, key_path):
    while True:
        try:
            deliver_once(state, monitor_state, key_path)
        except (FileNotFoundError, ConnectionRefusedError, TimeoutError):
            # The monitor may come up after this disposable worker.
            pass
        time.sleep(RETRY_INTERVAL)


def receive_alert(state, message, body, drop_ack):
    identity, digest = message["id"], payload_digest(body)
    with database(state, "receiver") as db, db:
        # Scope the event and one-shot lost response flag to a single commit.
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT digest,body FROM deliveries WHERE id=?", (identity,)).fetchone()
        if row is not None:
            if row != (digest, body):
                return "conflict"
            db.execute("UPDATE deliveries SET duplicates=duplicates+1 WHERE id=?", (identity,))
            return "duplicate"
        require(db.execute("SELECT count(*) FROM deliveries").fetchone()[0] < MAX_DELIVERIES,
                "The bounded receiver ledger is full.")
        drop = drop_ack and db.execute("SELECT 1 FROM deliveries WHERE dropped=1 LIMIT 1").fetchone() is None
        db.execute("INSERT INTO deliveries(id,body,digest,duplicates,dropped) VALUES(?,?,?,0,?)",
                   (identity, body, digest, int(drop)))
        return "drop_ack" if drop else "accepted"


def serve_receiver(state, key_path, *, drop_ack=None):
    secret = read_key(key_path)
    drop = drop_ack is not None
    require(not drop or private_bytes(drop_ack, len(FAULT_MARKER)) == FAULT_MARKER,
            "Unexpected one-shot dropped acknowledgement marker.")
    # Open once before listening so malformed local state cannot appear ready.
    with database(state, "receiver", readonly=True):
        pass

    class AlertHandler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # No headers, secrets, raw bodies, or host paths in logs.

        def answer(self, code, body=b"", signed=False):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            if signed:
                self.send_header(AUTH_HEADER, signature(secret, "ack", body))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            self.close_connection = True
            if self.path != ENDPOINT:
                self.answer(404)
                return
            length = self.headers.get_all("Content-Length", [])
            if (len(length) != 1 or not re.fullmatch(r"[1-9][0-9]{0,3}", length[0])
                    or int(length[0]) > MAX_BODY or self.headers.get("Transfer-Encoding") is not None
                    or self.headers.get("Content-Type") != "application/json"):
                self.answer(400)
                return
            body = self.rfile.read(int(length[0]))
            if len(body) != int(length[0]) or not authenticated(secret, "request", body, self.headers):
                self.answer(401)
                return
            try:
                message = validate_message(store.parse(body))
                require(canonical(message) == body, "Alert body is not canonical.")
            except (ValueError, TypeError, OverflowError):
                self.answer(400)
                return
            try:
                result = receive_alert(state, message, body, drop)
            except (OSError, sqlite3.Error, ValueError):
                self.answer(503)
                return
            if result == "drop_ack":
                return  # Commit already completed; close before writing a response.
            if result == "conflict":
                self.answer(409)
                return
            acknowledgement = {"id": message["id"], "payload_sha256": payload_digest(body),
                               "duplicate": result == "duplicate"}
            self.answer(200, canonical(acknowledgement), signed=True)

    class LoopbackServer(HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(TIMEOUT)
            return connection, address

        def handle_error(self, _request, _address):
            pass  # A closed or timed-out client is a delivery failure.

    with LoopbackServer((HOST, PORT), AlertHandler) as server:
        server.serve_forever(poll_interval=RETRY_INTERVAL)


def status(state, role):
    with database(state, role, readonly=True) as db:
        db.execute("BEGIN")
        result = {"ok": True, "role": role, "deliveries": []}
        if role == "sender":
            for identity, body, digest, ack in db.execute("SELECT id,body,digest,ack FROM deliveries ORDER BY ordinal"):
                result["deliveries"].append({
                    "id": identity, "payload_sha256": digest, "message": store.parse(body),
                    "state": "delivered" if ack is not None else "pending",
                    "acknowledgement": store.parse(ack) if ack is not None else None,
                })
            result["attempts"] = [{"number": number, "id": identity, "result": outcome}
                                  for number, identity, outcome in db.execute(
                                      "SELECT number,id,result FROM attempts ORDER BY number")]
        else:
            for identity, body, digest, count, dropped in db.execute(
                    "SELECT id,body,digest,duplicates,dropped FROM deliveries ORDER BY ordinal"):
                result["deliveries"].append({
                    "id": identity, "payload_sha256": digest, "message": store.parse(body),
                    "duplicate_requests": count, "ack_dropped": bool(dropped),
                })
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("init", "status", "send", "receive"):
        command = commands.add_parser(name)
        command.add_argument("--state", required=True)
        if name in {"init", "status"}:
            command.add_argument("role", choices=("sender", "receiver"))
        else:
            command.add_argument("--key", required=True)
        if name == "send":
            command.add_argument("--monitor-state", required=True)
            command.add_argument("--once", action="store_true")
        if name == "receive":
            command.add_argument("--drop-ack")
    args = parser.parse_args()
    try:
        if args.command == "init":
            value = initialize(args.state, args.role)
        elif args.command == "status":
            value = status(args.state, args.role)
        elif args.command == "receive":
            serve_receiver(args.state, args.key, drop_ack=args.drop_ack)
            return
        elif args.once:
            value = deliver_once(args.state, args.monitor_state, args.key)
        else:
            serve_sender(args.state, args.monitor_state, args.key)
            return
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as error:
        parser.exit(1, "Alert delivery stopped: " + type(error).__name__ + "\n")
    print(store.encoded(value))


if __name__ == "__main__":
    main()
