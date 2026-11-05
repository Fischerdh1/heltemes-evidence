"""Actual foreground process crashes and private-socket recovery tests."""
import copy
from datetime import datetime, timezone
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from scripts import network_monitor as monitor
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store
from test_network_monitor import ruleset, count, response

ROOT = Path(__file__).resolve().parents[1]


def now():
    return datetime.now(timezone.utc).isoformat()


class MonitorServiceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hmu-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.state = self.base / "s"
        self.approved = ruleset()
        self.raw = copy.deepcopy(self.approved)
        self.port = 40000
        self.processes = []
        self.addCleanup(self.stop_all)
        store.initialize(self.state, self.approved)

    def stop_all(self):
        for process in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=5)

    def start(self, enabled=True):
        arguments = [sys.executable, "-I", "-S", "-B", str(ROOT / "scripts/network_monitor_service.py"),
                     "serve", "--state", str(self.state)]
        if enabled:
            arguments.append("--allow-test-crashes")
        process = subprocess.Popen(arguments, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.processes.append(process)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            self.assertIsNone(process.poll(), "Service exited before readiness")
            try:
                status = service.request(self.state, {"command": "status"}, timeout=0.2)
                if status.get("process_id") == process.pid:
                    return process, status
            except (OSError, ValueError):
                pass
            time.sleep(0.01)
        self.fail("Service did not become ready")

    def observation(self, phase, rows=(), *, denied=True):
        probes = []
        for source, target, port in rows:
            self.port += 1
            start = now()
            probe = {"from": source, "to": target, "destination": monitor.ZONES[target], "port": port,
                     "source_port": self.port, "phase": phase, "started_at_utc": start, "destination_health": None}
            if (source, target, port) not in monitor.ALLOWED and denied:
                count(self.raw, f"drop_{source}_{target}_{port}", 2)
                probe.update({"outcome": "connect_timeout", "completed_at_utc": now()})
                self.port += 1
                probe["destination_health"] = {"from": target, "to": target, "destination": monitor.ZONES[target],
                    "port": port, "source_port": self.port, "phase": phase, "started_at_utc": now(),
                    "completed_at_utc": now(), **response(target, port)}
            else:
                probe.update({**response(target, port), "completed_at_utc": now()})
            probes.append(probe)
        return {"phase": phase, "observed_at_utc": now(), "ruleset": copy.deepcopy(self.raw),
                "collection_error": None, "probes": probes}

    def observe(self, request_id, rows=(), **options):
        value = self.observation(request_id, rows, **options)
        return service.request(self.state, {"command": "observe", "request_id": request_id, "observation": value})

    def establish_critical(self):
        for item in self.raw["nftables"]:
            rule = item.get("rule", {})
            if {"counter": "drop_user_app_9090"} in rule.get("expr", []):
                rule["expr"][-1] = {"accept": None}
        self.observe("bad-rules")
        result = self.observe("forbidden-open", (("user", "app", 9090),), denied=False)
        alerts = [a for a in result["current_status"]["alerts"] if a["code"] == "forbidden_path_open" and a["state"] == "open"]
        self.assertEqual(len(alerts), 1)
        return alerts[0]["id"]

    def test_startup_gap_is_accepted_before_status_and_private_socket_is_bounded(self):
        process, status = self.start()
        self.assertEqual(status["committed_count"], 1)
        self.assertEqual(status["current_evaluation"]["phase"], "monitor_restart")
        self.assertEqual(status["current_evaluation"]["status"], "unknown")
        self.assertEqual((self.state / service.SOCKET_NAME).stat().st_mode & 0o777, 0o600)
        export = service.request(self.state, {"command": "export"})
        self.assertEqual(export["rows"][0]["request_id"], "_restart_" + status["instance_id"])
        self.assertEqual(export["current_status"]["process_id"], process.pid)

    def test_before_commit_crash_does_not_lose_existing_alert_or_accept_uncommitted_recovery(self):
        process, _ = self.start()
        incident = self.establish_critical()
        self.raw = copy.deepcopy(self.approved)
        self.observe("repaired-rules")
        before = service.request(self.state, {"command": "status"})
        value = self.observation("uncommitted-recovery", monitor.CANARIES)
        with self.assertRaises((OSError, ValueError)):
            service.request(self.state, {"command": "observe", "request_id": "uncommitted-recovery",
                "observation": value, "test_crash": "before_commit"})
        self.assertEqual(process.wait(timeout=5), 71)
        replacement, status = self.start()
        self.assertNotEqual(process.pid, replacement.pid)
        self.assertEqual(status["committed_count"], before["committed_count"] + 1)
        self.assertEqual(status["current_evaluation"]["status"], "unknown")
        self.assertTrue(any(a["id"] == incident and a["state"] == "open" for a in status["alerts"]))
        exported = service.request(self.state, {"command": "export"})
        self.assertNotIn("uncommitted-recovery", [row["request_id"] for row in exported["rows"]])
        self.observe("fresh-interval")
        repaired = self.observe("fresh-recovery", monitor.CANARIES)
        self.assertEqual(repaired["current_status"]["current_evaluation"]["status"], "healthy")
        self.assertTrue(any(a["id"] == incident and a["state"] == "resolved" for a in repaired["current_status"]["alerts"]))

    def test_after_commit_lost_ack_retry_deduplicates_and_keeps_current_restart_unknown(self):
        process, _ = self.start()
        incident = self.establish_critical()
        before = service.request(self.state, {"command": "status"})
        value = self.observation("committed-without-ack", (("user", "app", 9090),), denied=False)
        payload = {"command": "observe", "request_id": "committed-without-ack", "observation": value}
        with self.assertRaises((OSError, ValueError)):
            service.request(self.state, {**payload, "test_crash": "after_commit_before_ack"})
        self.assertEqual(process.wait(timeout=5), 72)
        _, restarted = self.start()
        self.assertEqual(restarted["committed_count"], before["committed_count"] + 2)
        replayed = service.request(self.state, payload)
        self.assertTrue(replayed["ok"] and replayed["duplicate"] and replayed["result_is_historical"])
        self.assertEqual(replayed["committed_sequence"], before["committed_count"] + 1)
        self.assertEqual(replayed["current_status"]["committed_count"], restarted["committed_count"])
        self.assertEqual(replayed["current_status"]["current_evaluation"]["status"], "unknown")
        self.assertEqual(replayed["evaluation"]["phase"], "committed-without-ack")
        self.assertTrue(any(a["id"] == incident and a["state"] == "open" for a in replayed["current_status"]["alerts"]))
        changed = copy.deepcopy(payload); changed["observation"]["phase"] = "conflicting-content"
        rejected = service.request(self.state, changed)
        self.assertEqual(rejected, {"ok": False, "error": "request_rejected"})
        self.assertEqual(service.request(self.state, {"command": "status"})["committed_count"], restarted["committed_count"])

    def test_crash_control_is_disabled_without_explicit_test_option(self):
        process, before = self.start(enabled=False)
        result = service.request(self.state, {"command": "observe", "request_id": "not-permitted",
            "observation": self.observation("not-permitted"), "test_crash": "before_commit"})
        self.assertFalse(result["ok"])
        self.assertIsNone(process.poll())
        self.assertEqual(service.request(self.state, {"command": "status"})["committed_count"], before["committed_count"])

    def test_second_service_cannot_write_or_remove_live_socket(self):
        process, before = self.start()
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(ROOT / "scripts/network_monitor_service.py"),
                                 "serve", "--state", str(self.state)], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        after = service.request(self.state, {"command": "status"})
        self.assertEqual(after, before)
        self.assertIsNone(process.poll())

    def test_stale_pre_restart_probe_cannot_recover_current_coverage(self):
        process, _ = self.start()
        self.observe("first-baseline")
        old = self.observation("stale", monitor.CANARIES)
        process.terminate(); self.assertEqual(process.wait(timeout=5), 0)
        _, status = self.start()
        result = service.request(self.state, {"command": "observe", "request_id": "stale", "observation": old})
        self.assertEqual(result["evaluation"]["status"], "unknown")
        self.assertFalse(result["evaluation"]["telemetry_valid"])
        self.assertIn("telemetry_gap:collector", result["evaluation"]["active_alert_keys"])

    def test_unexpected_socket_object_and_missing_database_refuse_without_replacement(self):
        occupied = self.state / service.SOCKET_NAME
        store.write_new(occupied, b"keep this file")
        command = [sys.executable, "-I", "-S", "-B", str(ROOT / "scripts/network_monitor_service.py"), "serve", "--state", str(self.state)]
        result = subprocess.run(command, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(occupied.read_bytes(), b"keep this file")
        occupied.unlink()
        database = self.state / "monitor.sqlite3"
        database.unlink()
        result = subprocess.run(command, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertFalse(database.exists())
        self.assertFalse(occupied.exists())

    def test_request_framing_and_socket_path_length_are_bounded(self):
        _, before = self.start()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(2); connection.connect(str(self.state / service.SOCKET_NAME))
            connection.sendall(b'{"command":"status","command":"export"}\n')
            self.assertFalse(service.receive(connection, service.MAX_RESPONSE)["ok"])
        with self.assertRaises(ValueError):
            service.request(self.state, {"command": "x" * store.MAX_REQUEST})
        long = self.base / ("x" * 100)
        long.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            service.socket_path(long)
        self.assertEqual(service.request(self.state, {"command": "status"})["committed_count"], before["committed_count"])


if __name__ == "__main__":
    unittest.main()
