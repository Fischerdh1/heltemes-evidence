"""Exercise durable alert delivery and the bounded loopback protocol."""
from contextlib import closing
from email.message import Message
from http.client import HTTPConnection
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from scripts import network_monitor_alert_delivery as delivery
from scripts import network_monitor_store as store

ROOT = Path(__file__).resolve().parents[1]
JOURNAL = "d" * 32
NOW = "2026-11-14T09:31:50.123456+00:00"


def event(action, sequence):
    return {
        "id": f"event-{sequence:04d}", "alert_id": "forbidden_path_open:user->app:9090#1",
        "sequence": sequence, "observed_at_utc": NOW, "evidence": {"excluded": True},
        "phase": "synthetic", "action": action, "severity": "critical", "code": "forbidden_path_open",
    }


def row(action, sequence, previous=store.ZERO):
    value = {"sequence": sequence, "previous_digest": previous,
             "sample": {"sequence": sequence, "observed_at_utc": NOW}, "events": [event(action, sequence)]}
    return {**value, "row_digest": store.digest(value)}


class AlertDeliveryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="he-alert-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.sender, self.receiver = self.base / "sender", self.base / "receiver"
        self.key, self.marker = self.base / "key", self.base / "drop-next"
        self.secret = os.urandom(32)
        store.write_new(self.key, self.secret)
        store.write_new(self.marker, delivery.FAULT_MARKER)
        delivery.initialize(self.sender, "sender")
        delivery.initialize(self.receiver, "receiver")

    def request(self, body, mac):
        with closing(HTTPConnection(delivery.HOST, delivery.PORT, timeout=2)) as connection:
            connection.request("POST", delivery.ENDPOINT, body=body, headers={
                "Content-Type": "application/json", delivery.AUTH_HEADER: mac,
            })
            with connection.getresponse() as response:
                return response.status

    def start_receiver(self):
        command = [sys.executable, "-I", "-S", "-B", "-c",
                   "import sys; sys.path.insert(0,sys.argv[1]); "
                   "from scripts import network_monitor_alert_delivery as core; "
                   "core.PORT=int(sys.argv[2]); core.serve_receiver(sys.argv[3],sys.argv[4],drop_ack=sys.argv[5])",
                   str(ROOT), str(delivery.PORT), str(self.receiver), str(self.key), str(self.marker)]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_receiver, process)
        limit = time.monotonic() + 5
        while time.monotonic() < limit:
            self.assertIsNone(process.poll(), "Receiver exited during startup.")
            try:
                with socket.create_connection((delivery.HOST, delivery.PORT), timeout=0.2):
                    return process
            except OSError:
                time.sleep(0.02)
        self.fail("Receiver readiness was not observed.")

    @staticmethod
    def stop_receiver(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    def test_offline_then_lost_ack_retry_and_resolution(self):
        opened = row("opened", 1)
        resolved = row("resolved", 2, opened["row_digest"])
        message = delivery.project(JOURNAL, event("opened", 1))
        self.assertNotIn("evidence", message)
        self.assertEqual(message["id"], delivery.message_id(JOURNAL, event("opened", 1)["id"]))
        body = delivery.canonical(message)
        with socket.socket() as reservation:
            reservation.bind((delivery.HOST, 0))
            port = reservation.getsockname()[1]
        with patch.object(delivery, "PORT", port), patch.object(
                delivery, "committed_snapshot", return_value=(JOURNAL, [opened])) as snapshot:
            self.assertEqual(delivery.deliver_once(self.sender, self.base, self.key)["result"], "transport_error")
            self.assertEqual(delivery.status(self.sender, "sender")["deliveries"][0]["state"], "pending")
            self.assertEqual(delivery.status(self.receiver, "receiver")["deliveries"], [])

            receiver_process = self.start_receiver()
            self.assertEqual(self.request(body, "0" * 64), 401)
            changed = {**message, "observed_at_utc": "2026-11-14T09:32:00Z"}
            changed_body = delivery.canonical(changed)
            mac = delivery.signature(self.secret, "request", body)
            self.assertEqual(self.request(changed_body, mac), 401)
            self.assertEqual(delivery.deliver_once(self.sender, self.base, self.key)["result"], "ack_missing")
            lost = delivery.status(self.receiver, "receiver")["deliveries"]
            self.assertEqual((len(lost), lost[0]["ack_dropped"], lost[0]["duplicate_requests"]), (1, True, 0))
            self.assertEqual(delivery.status(self.sender, "sender")["deliveries"][0]["state"], "pending")

            self.stop_receiver(receiver_process)
            self.start_receiver()
            self.assertEqual(self.request(changed_body, delivery.signature(self.secret, "request", changed_body)), 409)
            self.assertEqual(delivery.deliver_once(self.sender, self.base, self.key)["result"], "duplicate")
            self.assertIsNone(delivery.deliver_once(self.sender, self.base, self.key))
            snapshot.return_value = JOURNAL, [opened, resolved]
            self.assertEqual(delivery.deliver_once(self.sender, self.base, self.key)["result"], "accepted")
            sender = delivery.status(self.sender, "sender")
            receiver = delivery.status(self.receiver, "receiver")
        self.assertEqual([item["result"] for item in sender["attempts"]],
                         ["transport_error", "ack_missing", "duplicate", "accepted"])
        self.assertEqual([item["id"] for item in sender["attempts"][:3]], [message["id"]] * 3)
        self.assertEqual([item["message"]["action"] for item in receiver["deliveries"]], ["opened", "resolved"])
        self.assertEqual([item["duplicate_requests"] for item in receiver["deliveries"]], [1, 0])
        self.assertEqual([item["ack_dropped"] for item in receiver["deliveries"]], [True, False])
        self.assertTrue(all(item["state"] == "delivered" for item in sender["deliveries"]))
        self.assertEqual(sender["deliveries"][0]["acknowledgement"], {
            "id": message["id"], "payload_sha256": delivery.payload_digest(body), "duplicate": True})

    def test_import_refuses_changed_prefix_or_identity_and_keeps_pending(self):
        opened = row("opened", 1)
        with delivery.database(self.sender, "sender") as db:
            delivery.import_pending(db, JOURNAL, [opened])
            delivery.import_pending(db, JOURNAL, [opened])
            for new_id, rows in (("0" * 32, [opened]), (JOURNAL, []),
                                 (JOURNAL, [{"row_digest": "9" * 64}])):
                with self.subTest(journal=new_id, row_count=len(rows)), self.assertRaisesRegex(ValueError, "rolled back"):
                    delivery.import_pending(db, new_id, rows)
        state = delivery.status(self.sender, "sender")
        self.assertEqual(len(state["deliveries"]), 1)
        self.assertEqual(state["deliveries"][0]["state"], "pending")
        self.assertIsNone(delivery.project(JOURNAL, {**event("opened", 1), "severity": "high"}))
        self.assertIsNone(delivery.project(JOURNAL, event("updated", 1)))

    def test_committed_export_rejects_tampered_rows(self):
        sample = row("opened", 1)
        data = {"ok": True, "identity": {"database_id": JOURNAL, "format": store.FORMAT, "version": store.VERSION},
                "rows": [sample], "current_status": {"committed_count": 1, "head_digest": sample["row_digest"]}}
        with patch.object(delivery.service, "request", return_value=data) as request:
            self.assertEqual(delivery.committed_snapshot(self.base), (JOURNAL, [sample]))
            request.assert_called_once_with(self.base, {"command": "export"}, timeout=delivery.TIMEOUT)
            sample["events"][0]["action"] = "resolved"
            with self.assertRaisesRegex(ValueError, "row chain"):
                delivery.committed_snapshot(self.base)

    def test_sender_rejects_unsigned_or_mismatched_acknowledgements(self):
        message = delivery.project(JOURNAL, event("opened", 1))
        body = delivery.canonical(message)
        digest = delivery.payload_digest(body)
        legitimate = {"id": message["id"], "payload_sha256": digest, "duplicate": False}
        for code, ack, purpose in (
                (409, legitimate, "ack"), (200, legitimate, "request"),
                (200, {**legitimate, "id": "f" * 64}, "ack"),
                (200, {**legitimate, "payload_sha256": "f" * 64}, "ack")):
            with self.subTest(code=code, ack=ack, purpose=purpose):
                raw = delivery.canonical(ack)
                response = Mock()
                response.status, response.headers = code, Message()
                response.headers["Content-Length"] = str(len(raw))
                response.headers[delivery.AUTH_HEADER] = delivery.signature(self.secret, purpose, raw)
                response.read.return_value = raw
                connection = Mock()
                connection.getresponse.return_value.__enter__ = Mock(return_value=response)
                connection.getresponse.return_value.__exit__ = Mock(return_value=False)
                with patch.object(delivery, "HTTPConnection", return_value=connection):
                    self.assertEqual(delivery.post(self.secret, body, message["id"], digest), ("invalid_ack", None))


if __name__ == "__main__":
    unittest.main()
