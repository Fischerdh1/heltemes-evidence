"""Opt-in missing-data deadlines; no real Evidence identity or host networking."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts import network_monitor as monitor
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store
from test_network_monitor import Fixture, ruleset

ROOT = Path(__file__).resolve().parents[1]


class FreshnessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hmf-")
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name).resolve() / "s"
        store.initialize(self.state, ruleset())
        self.journal = store.Journal(self.state)
        self.addCleanup(self.journal.close)
        self.fixture = Fixture()
        self.elapsed = 0.0
        self.wall = self.fixture.time
        for target, replacement in (("time.monotonic", lambda: self.elapsed),
                                    ("utc_now", lambda: self.wall.isoformat())):
            mocked = patch("scripts.network_monitor_service." + target, replacement)
            mocked.start()
            self.addCleanup(mocked.stop)
        self.subject = service.Service(self.journal, freshness_seconds=20)

    def advance(self, seconds):
        self.elapsed += seconds
        self.wall += timedelta(seconds=seconds)
        self.fixture.time = self.wall

    def payload(self, request_id, rows=(), **options):
        sample = self.fixture.sample(rows, **options)
        self.advance(2)
        return {"command": "observe", "request_id": request_id,
                "observation": {key: sample[key] for key in store.OBSERVATION_KEYS}}

    def observe(self, request_id, rows=(), **options):
        return self.subject.dispatch(self.payload(request_id, rows, **options))

    def healthy(self):
        self.observe("baseline")
        result = self.observe("covered", monitor.CANARIES)
        self.assertEqual(result["current_status"]["current_evaluation"]["status"], "healthy")
        return result

    def test_startup_is_unknown_and_deadline_emits_one_gap_without_dispatch(self):
        initial = self.subject.status()
        self.assertEqual(initial["current_evaluation"]["status"], "unknown")
        self.assertIsNone(initial["freshness"]["last_accepted_request_id"])
        self.advance(19.9)
        self.subject.tick()
        self.assertEqual(len(self.journal.rows), 1)
        self.advance(0.1)
        self.subject.tick()
        self.assertEqual(len(self.journal.rows), 2)
        self.assertEqual(self.journal.rows[-1]["sample"]["phase"], "collector_missing")
        self.advance(100)
        self.subject.tick()
        self.assertEqual(len(self.journal.rows), 2)
        status = self.subject.status()
        self.assertTrue(status["freshness"]["expired"])
        self.assertTrue(status["freshness"]["gap_recorded"])
        self.assertEqual(status["freshness"]["gap_sequence"], 2)

    def test_duplicate_and_status_requests_cannot_renew_healthy_coverage(self):
        self.observe("baseline")
        payload = self.payload("covered", monitor.CANARIES)
        first = self.subject.dispatch(payload)
        self.advance(19)
        retry = self.subject.dispatch(payload)
        self.assertTrue(retry["duplicate"])
        self.assertEqual(retry["current_status"]["freshness"]["age_seconds"], 19)
        self.assertEqual(self.subject.dispatch({"command": "status"})["freshness"]["remaining_seconds"], 1)
        self.advance(1)
        retry = self.subject.dispatch(payload)
        self.assertEqual(retry["evaluation"]["status"], "healthy")
        self.assertTrue(retry["result_is_historical"])
        self.assertEqual(retry["current_status"]["current_evaluation"]["status"], "unknown")
        self.assertEqual(len(self.journal.rows), first["committed_sequence"] + 1)

    def test_rejected_invalid_and_stale_telemetry_do_not_refresh_deadline(self):
        self.healthy()
        accepted = self.subject.status()["freshness"]["last_accepted_at_utc"]
        invalid = self.payload("invalid")
        invalid["observation"]["ruleset"] = {"malformed": True}
        result = self.subject.dispatch(invalid)
        self.assertFalse(result["evaluation"]["telemetry_valid"])
        self.assertEqual(result["current_status"]["freshness"]["last_accepted_at_utc"], accepted)
        for name, timestamp in (("stale", self.wall - timedelta(seconds=21)),
                                ("future", self.wall + timedelta(seconds=1)),
                                ("same-source", datetime.fromisoformat(accepted))):
            value = copy.deepcopy(invalid)
            value["request_id"] = name
            value["observation"]["observed_at_utc"] = timestamp.isoformat()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.subject.dispatch(value)
        with self.assertRaises(ValueError):
            self.subject.dispatch({"command": "status", "extra": True})
        self.assertIsNone(self.subject.persistence_error)
        self.advance(18)
        self.subject.tick()
        self.assertTrue(self.subject.status()["freshness"]["expired"])

    def test_future_timestamp_is_accepted_only_after_clock_catches_up(self):
        self.healthy()
        payload = self.payload("clock-step")
        payload["observation"]["observed_at_utc"] = (self.wall + timedelta(seconds=1)).isoformat()
        original = store.encoded(payload)
        before = self.subject.status()
        with self.assertRaises(service.ObservationTimeRejected) as rejected:
            self.subject.dispatch(payload)
        self.assertEqual(rejected.exception.reason, "source_timestamp_in_future")
        self.assertEqual(self.subject.status()["head_digest"], before["head_digest"])
        self.assertEqual(self.subject.status()["freshness"]["last_accepted_at_utc"],
                         before["freshness"]["last_accepted_at_utc"])

        self.advance(1)
        receipt = self.subject.dispatch(payload)
        self.assertFalse(receipt["duplicate"])
        self.assertEqual(receipt["committed_sequence"], before["committed_count"] + 1)
        self.assertEqual(store.encoded(payload), original)

    def test_delayed_source_gets_only_remaining_source_freshness(self):
        self.observe("baseline")
        delayed = self.payload("delayed", monitor.CANARIES)
        self.advance(7)
        result = self.subject.dispatch(delayed)
        self.assertEqual(result["current_status"]["freshness"]["age_seconds"], 7)
        self.assertEqual(result["current_status"]["freshness"]["remaining_seconds"], 13)
        self.advance(13)
        self.subject.tick()
        self.assertTrue(self.subject.status()["freshness"]["expired"])

    def test_invalid_and_rejected_requests_do_not_latch_a_storage_failure(self):
        self.healthy()
        invalid = self.payload("invalid-phase")
        invalid["observation"]["phase"] = 42
        self.assertFalse(self.subject.dispatch(invalid)["evaluation"]["telemetry_valid"])
        invalid = self.payload("collection-failed")
        invalid["observation"]["collection_error"] = "source_unavailable"
        self.assertFalse(self.subject.dispatch(invalid)["evaluation"]["telemetry_valid"])
        backwards = copy.deepcopy(invalid)
        backwards["request_id"] = "backward-source"
        backwards["observation"]["observed_at_utc"] = (self.wall - timedelta(seconds=1)).isoformat()
        before = len(self.journal.rows)
        with self.assertRaises(ValueError):
            self.subject.dispatch(backwards)
        self.assertEqual(len(self.journal.rows), before)
        self.assertIsNone(self.subject.persistence_error)
        self.observe("recovery-baseline")
        result = self.observe("recovery-canaries", monitor.CANARIES)
        self.assertEqual(result["current_status"]["current_evaluation"]["status"], "healthy")
        self.assertIsNone(result["current_status"]["freshness"]["persistence_error"])

    def test_monotonic_deadline_survives_wall_clock_moving_backwards(self):
        self.healthy()
        self.elapsed += 20
        self.wall -= timedelta(hours=1)
        self.subject.tick()
        self.assertTrue(self.subject.status()["freshness"]["expired"])
        self.assertEqual(self.subject.status()["current_evaluation"]["status"], "unknown")

    def test_gap_preserves_incident_and_recovery_requires_fresh_baseline_and_canaries(self):
        self.observe("baseline")
        incident = self.observe("forbidden-open", (("user", "app", 9090),), bad=True)
        incident_id = next(a["id"] for a in incident["current_status"]["alerts"]
                           if a["code"] == "forbidden_path_open" and a["state"] == "open")
        self.advance(20)
        self.subject.tick()
        stale = self.subject.status()
        self.assertEqual(stale["current_evaluation"]["status"], "unknown")
        self.assertTrue(any(a["id"] == incident_id and a["state"] == "open" for a in stale["alerts"]))
        baseline = self.observe("restored-baseline")
        self.assertNotEqual(baseline["current_status"]["current_evaluation"]["status"], "healthy")
        self.assertTrue(any(a["id"] == incident_id and a["state"] == "open"
                            for a in baseline["current_status"]["alerts"]))
        healthy = self.observe("fresh-canaries", monitor.CANARIES)
        self.assertEqual(healthy["current_status"]["current_evaluation"]["status"], "healthy")
        self.assertTrue(any(a["id"] == incident_id and a["state"] == "resolved"
                            for a in healthy["current_status"]["alerts"]))
        self.advance(20)
        self.subject.tick()
        self.assertEqual(sum(row["sample"]["phase"] == "collector_missing" for row in self.journal.rows), 2)

    def test_restart_does_not_inherit_freshness_or_accept_duplicate_as_heartbeat(self):
        self.observe("baseline")
        old = self.payload("covered", monitor.CANARIES)
        self.subject.dispatch(old)
        self.advance(1)
        replacement = service.Service(self.journal, freshness_seconds=20)
        self.assertIsNone(replacement.status()["freshness"]["last_accepted_request_id"])
        retried = replacement.dispatch(old)
        self.assertTrue(retried["duplicate"])
        self.assertEqual(retried["current_status"]["current_evaluation"]["status"], "unknown")
        self.advance(20)
        replacement.tick()
        self.assertEqual(self.journal.rows[-1]["sample"]["phase"], "collector_missing")

    def test_capacity_failure_forces_unknown_without_rotation_or_extra_writes(self):
        self.assertEqual(store.MAX_ROWS, 256)
        self.healthy()
        before = self.journal.export()
        with patch.object(store, "MAX_ROWS", len(self.journal.rows)):
            status = self.subject.status()
            self.assertEqual(status["freshness"]["capacity_remaining"], 0)
            self.assertEqual(status["freshness"]["persistence_error"], "journal_capacity_exhausted")
            self.assertEqual(status["current_evaluation"]["status"], "unknown")
            self.advance(20)
            self.subject.tick()
            self.assertEqual(self.journal.export(), before)

    def test_gap_write_failure_is_latched_unknown_and_preserves_last_healthy_row(self):
        self.healthy()
        head = self.journal.head_digest
        self.advance(20)
        with patch.object(self.journal, "append", side_effect=sqlite3.OperationalError("disk full")) as append:
            self.subject.tick()
            self.subject.tick()
            status = self.subject.status()
            self.assertEqual(append.call_count, 1)
        self.assertEqual(status["freshness"]["persistence_error"], "journal_write_failed")
        self.assertFalse(status["freshness"]["gap_recorded"])
        self.assertEqual(status["current_evaluation"]["status"], "unknown")
        self.assertEqual(self.journal.head_digest, head)
        self.assertEqual(self.journal.rows[-1]["evaluation"]["status"], "healthy")
        with self.assertRaises(ValueError):
            self.observe("cannot-clear-write-failure")

    def test_new_observation_write_failure_does_not_refresh_freshness(self):
        self.healthy()
        last = self.subject.status()["freshness"]["last_accepted_request_id"]
        value = self.payload("write-failed")
        with patch.object(self.journal, "append", side_effect=sqlite3.OperationalError("disk full")):
            with self.assertRaises(sqlite3.OperationalError):
                self.subject.dispatch(value)
        status = self.subject.status()
        self.assertEqual(status["freshness"]["last_accepted_request_id"], last)
        self.assertEqual(status["current_evaluation"]["status"], "unknown")

    def test_invalid_thresholds_do_not_append_restart(self):
        count = len(self.journal.rows)
        for value in (True, False, 0, -1, 31, "20", float("nan"), float("inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                service.Service(self.journal, freshness_seconds=value)
        self.assertEqual(len(self.journal.rows), count)

    def test_default_mode_keeps_fixed_row_behavior_and_status_contract(self):
        legacy = service.Service(self.journal)
        count = len(self.journal.rows)
        self.advance(100)
        legacy.tick()
        self.assertNotIn("freshness", legacy.status())
        self.assertEqual(len(self.journal.rows), count)


class IdleProcessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hmi-")
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name).resolve() / "s"
        store.initialize(self.state, ruleset())
        self.process = subprocess.Popen([sys.executable, "-I", "-S", "-B",
            str(ROOT / "scripts/network_monitor_service.py"), "serve", "--state", str(self.state),
            "--freshness-seconds", "1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            self.assertIsNone(self.process.poll(), "Freshness service exited before readiness")
            if (self.state / service.SOCKET_NAME).exists():
                return
            time.sleep(0.01)
        self.fail("Freshness service did not start")

    def stop(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def test_no_rpc_silence_commits_gap_before_any_inspection(self):
        # No monitor request has been sent, including readiness polling.
        time.sleep(1.6)
        first_inspection = datetime.now(timezone.utc).timestamp()
        exported = service.request(self.state, {"command": "export"})
        gap = exported["rows"][-1]
        metadata = exported["current_status"]["freshness"]
        self.assertEqual(gap["sample"]["phase"], "collector_missing")
        self.assertEqual(len(exported["rows"]), 2)
        self.assertLess(store.monitor.utc(metadata["gap_committed_at_utc"]), first_inspection - 0.2)
        self.assertEqual(exported["current_status"]["current_evaluation"]["status"], "unknown")
        self.stop()
        with store.Journal(self.state) as reopened:
            self.assertEqual(reopened.rows[-1]["row_digest"], gap["row_digest"])

    def test_slow_client_cannot_defer_idle_gap_or_hold_service_forever(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(4)
            connection.connect(str(self.state / service.SOCKET_NAME))
            connection.sendall(b'{"command":')
            time.sleep(1.5)
            # SQLite read only inspection proves the gap was committed while
            # this incomplete request still occupied the connection.
            with sqlite3.connect(f"file:{self.state / 'monitor.sqlite3'}?mode=ro", uri=True) as reader:
                row = reader.execute("SELECT sample FROM observations ORDER BY sequence DESC LIMIT 1").fetchone()
            self.assertEqual(json.loads(row[0])["phase"], "collector_missing")
            start = time.monotonic()
            rejected = service.receive(connection, service.MAX_RESPONSE)
            self.assertEqual(rejected, {"ok": False, "error": "request_rejected"})
            self.assertLess(time.monotonic() - start, 2.2)
        self.assertTrue(service.request(self.state, {"command": "status"})["freshness"]["gap_recorded"])


if __name__ == "__main__":
    unittest.main()
