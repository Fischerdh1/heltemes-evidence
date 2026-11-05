"""Portable orchestration tests; real systemd/packet evidence comes from Linux CI."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import network_monitor_restart_lab as lab
from scripts import network_monitor_store as store

spec = importlib.util.spec_from_file_location("restart_observation_fixture", Path(__file__).with_name("test_network_monitoring_lab.py"))
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
TOOLS = {name: "/tools/" + name for name in ("ip", "nft", "tcpdump", "sysctl", "git", "systemctl", "systemd-run")}


class NetworkFixture(fixtures.ScenarioFixture):
    def stop_captures(self):
        return {"ok": True, "routed_flows_verified": 12}


class InjectedExit(BaseException):
    pass


class StoreSupervisorFixture:
    """Real durable store/service dispatch, mocked supervisor and no network packets."""
    def __init__(self, state):
        self.state = state
        self.worker = self.journal = None
        self.manager_records, self.observed_processes = [], set()
        self.restarts = -1

    def initialize(self, approved):
        store.initialize(self.state, approved)

    def start(self):
        self.journal = store.Journal(self.state)
        self.worker = lab.service.Service(self.journal, allow_test_crashes=True)
        self.restarts += 1
        self.pid = 1000 + self.restarts
        self.observed_processes.add(self.pid)
        return self.request({"command": "status"})

    def request(self, payload):
        try:
            response = self.worker.dispatch(payload)
        except ValueError:
            return {"ok": False, "error": "request_rejected"}
        if payload["command"] == "status":
            response["process_id"] = self.pid
        elif "current_status" in response:
            response["current_status"]["process_id"] = self.pid
        return response

    def crash(self, payload, expected_exit):
        previous = self.request({"command": "status"})
        def exit_process(code):
            if code != expected_exit:
                raise AssertionError("Unexpected crash boundary")
            raise InjectedExit()
        with patch.object(lab.service.os, "_exit", side_effect=exit_process):
            try:
                self.request(payload)
            except InjectedExit:
                pass
            else:
                raise AssertionError("Missing injected exit")
        self.journal.close()
        restarted = self.start()
        record = {"phase": payload["observation"]["phase"], "request_id": payload["request_id"],
                  "test_crash": payload["test_crash"], "expected_exit": expected_exit,
                  "acknowledgement_received": False, "previous_process_id": previous["process_id"],
                  "restarted_process_id": restarted["process_id"],
                  "previous_instance_id": previous["instance_id"], "restarted_instance_id": restarted["instance_id"],
                  "committed_count_before": previous["committed_count"],
                  "committed_count_after_restart": restarted["committed_count"],
                  "restart_status": restarted["current_evaluation"]["status"]}
        self.manager_records.append(record)
        return restarted, record

    def close(self):
        if self.journal:
            self.journal.close()


def manager(pid=0, restarts=0, active="inactive", loaded="loaded", exit_code=0):
    return {"LoadState": loaded, "ActiveState": active, "SubState": "running" if pid else "dead",
            "MainPID": pid, "NRestarts": restarts, "ExecMainCode": 1, "ExecMainStatus": exit_code}


class RestartLabTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="restart-driver-tests-")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve()

    def scenario(self):
        network = NetworkFixture()
        supervisor = StoreSupervisorFixture(self.directory / "state")
        self.addCleanup(supervisor.close)
        return network, supervisor

    def test_complete_scenario_replays_real_committed_history_and_keeps_lost_probe(self):
        network, supervisor = self.scenario()
        result = lab.run_exercise(network, supervisor)
        self.assertEqual(result["results"]["committed_journal_rows"], 13)
        self.assertEqual(result["results"]["startup_gap_rows"], 3)
        self.assertEqual(result["results"]["final_evaluation"]["status"], "healthy")
        self.assertEqual([row["observation"]["phase"] for row in result["observations"]], list(lab.PHASES))
        rows = result["journal"]["rows"]
        self.assertNotIn("uncommitted_recovery", [row["request_id"] for row in rows])
        self.assertEqual(sum(row["request_id"] == "committed_before_crash" for row in rows), 1)
        self.assertEqual(len([p for p in network.probes if p["phase"] == "uncommitted_recovery"]), 4)
        critical = [event for event in result["journal"]["events"] if event["key"] == lab.CRITICAL_KEY]
        self.assertEqual([(event["action"], event["phase"]) for event in critical],
                         [("opened", "forbidden_open"), ("updated", "committed_before_crash"),
                          ("updated", "still_forbidden"), ("resolved", "final_canaries")])
        self.assertTrue(result["service"]["retry"]["result_is_historical"])
        self.assertEqual(result["service"]["retry"]["current_status"], "unknown")
        self.assertEqual(result["service"]["retry"]["head_before"], result["service"]["retry"]["head_after"])
        self.assertTrue(result["service"]["conflicting_retry"]["rejected"])
        self.assertEqual(result["approved"], result["journal"]["approved_policy"])

    def test_missing_uncommitted_capture_flow_fails(self):
        network, supervisor = self.scenario()
        network.stop_captures = lambda: {"ok": True, "routed_flows_verified": 11}
        with self.assertRaisesRegex(RuntimeError, "Capture evidence omits"):
            lab.run_exercise(network, supervisor)

    def test_missing_historical_label_fails_retry(self):
        network, supervisor = self.scenario()
        original = supervisor.request
        def request(payload):
            result = original(payload)
            if result.get("duplicate"):
                result["result_is_historical"] = False
            return result
        supervisor.request = request
        with self.assertRaisesRegex(RuntimeError, "acknowledgement-loss retry"):
            lab.run_exercise(network, supervisor)

    def test_changed_request_id_content_must_be_rejected(self):
        network, supervisor = self.scenario()
        original = supervisor.request
        def request(payload):
            result = original(payload)
            if payload.get("observation", {}).get("phase") == "conflicting_retry":
                return {"ok": True}
            return result
        supervisor.request = request
        with self.assertRaisesRegex(RuntimeError, "Conflicting request content"):
            lab.run_exercise(network, supervisor)

    def test_inventoried_candidate_and_unique_ports_are_required(self):
        network, supervisor = self.scenario()
        result = lab.run_exercise(network, supervisor)
        observations = copy.deepcopy(result["observations"])
        observations[8]["observation"]["probes"].pop()
        with self.assertRaises(RuntimeError):
            lab.require_inventory(network, observations)
        network.probes[-1]["source_port"] = network.probes[0]["source_port"]
        with self.assertRaisesRegex(RuntimeError, "reuses a port"):
            lab.require_inventory(network, result["observations"])

    def test_mac_guard_refuses_before_source_read_or_output(self):
        output = self.directory / "no-output"
        with patch.object(lab.base.sys, "platform", "darwin"), patch.object(lab, "source_identity") as identity:
            with self.assertRaisesRegex(RuntimeError, "disposable Linux"):
                lab.run(output)
        identity.assert_not_called()
        self.assertFalse(output.exists())

    def test_preflight_requires_running_system_manager(self):
        with patch.object(lab.base, "preflight", return_value=dict(TOOLS)), \
             patch.object(lab.shutil, "which", side_effect=lambda name: TOOLS[name]), \
             patch.object(lab.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "")):
            with self.assertRaisesRegex(RuntimeError, "running systemd"):
                lab.preflight()

    def test_start_hardens_scoped_transient_worker_and_does_not_use_shell(self):
        worker = lab.SystemdMonitor(TOOLS, self.directory)
        worker.state_root, worker.state = Path("/run/he-rst-owned"), Path("/run/he-rst-owned/state")
        status = {"process_id": 123, "instance_id": "first", "committed_count": 1,
                  "current_evaluation": {"status": "unknown"}}
        with patch.object(worker, "show", side_effect=[manager(loaded="not-found"), manager(123, active="active")]), \
             patch.object(worker, "command", return_value=subprocess.CompletedProcess([], 0, "", "")) as command, \
             patch.object(worker, "wait_ready", return_value=(status, manager(123, active="active"))):
            worker.start()
        arguments = command.call_args.args[0]
        self.assertEqual(arguments[0], TOOLS["systemd-run"])
        for flag in ("--collect", "--unit=" + worker.unit, "--service-type=exec", "--property=Restart=on-failure",
                     "--property=RestartSec=1.5s", "--property=UMask=0077", "--property=NoNewPrivileges=yes",
                     "--property=PrivateTmp=yes", "--property=ProtectSystem=strict",
                     "--property=ReadWritePaths=/run/he-rst-owned", "--property=RestrictAddressFamilies=AF_UNIX"):
            self.assertIn(flag, arguments)
        self.assertNotIn("shell", command.call_args.kwargs)
        self.assertTrue(worker.created and worker.start_attempted)

    def test_existing_unit_is_never_adopted_or_stopped(self):
        worker = lab.SystemdMonitor(TOOLS, self.directory)
        worker.state = Path("/run/he-rst-unused/state")
        with patch.object(worker, "show", return_value=manager(99, active="active")), patch.object(worker, "command") as command:
            with self.assertRaisesRegex(RuntimeError, "already in use"):
                worker.start()
            worker.cleanup()
        command.assert_not_called()
        self.assertFalse(worker.start_attempted)

    def test_timed_out_start_still_stops_owned_unit_before_state_cleanup(self):
        worker = lab.SystemdMonitor(TOOLS, self.directory)
        worker.state = Path("/run/he-rst-unused/state")
        with patch.object(worker, "show", return_value=manager(loaded="not-found")), \
             patch.object(worker, "command", side_effect=subprocess.TimeoutExpired("systemd-run", 10)):
            with self.assertRaises(subprocess.TimeoutExpired):
                worker.start()
        self.assertTrue(worker.start_attempted)
        with patch.object(worker, "show", side_effect=[manager(99, active="active"), manager(loaded="not-found")]), \
             patch.object(worker, "command", return_value=subprocess.CompletedProcess([], 0, "", "")) as command:
            result = worker.cleanup()
        self.assertTrue(result["transient_unit_unloaded"])
        self.assertEqual([call.args[0] for call in command.call_args_list],
                         [[TOOLS["systemctl"], "stop", worker.unit], [TOOLS["systemctl"], "reset-failed", worker.unit]])

    def test_foreign_description_blocks_cleanup(self):
        worker = lab.SystemdMonitor(TOOLS, self.directory)
        worker.start_attempted = True
        reply = subprocess.CompletedProcess([], 0, "LoadState=loaded\nDescription=unrelated\nMainPID=123\n", "")
        with patch.object(worker, "command", return_value=reply) as command:
            with self.assertRaisesRegex(RuntimeError, "identity differs"):
                worker.cleanup()
        self.assertEqual(command.call_count, 1)

    def test_ready_requires_matching_pid_and_new_process_instance(self):
        worker = lab.SystemdMonitor(TOOLS, self.directory)
        old = {"ok": True, "process_id": 100, "instance_id": "old"}
        fresh = {"ok": True, "process_id": 101, "instance_id": "new"}
        with patch.object(worker, "show", return_value=manager(101, 1, "active")), \
             patch.object(worker, "request", side_effect=[old, fresh]), patch.object(lab.time, "sleep"):
            result, props = worker.wait_ready(old, 1)
        self.assertEqual(result, fresh)
        self.assertEqual(worker.observed_processes, {101})
        self.assertEqual(props["NRestarts"], 1)

    def test_crash_requires_observed_exit_and_exactly_one_restart(self):
        worker = lab.SystemdMonitor(TOOLS, self.directory)
        old = {"process_id": 100, "instance_id": "old", "committed_count": 4}
        fresh = {"process_id": 101, "instance_id": "new", "committed_count": 6,
                 "current_evaluation": {"status": "unknown"}}
        payload = {"request_id": "crash", "observation": {"phase": "crash"}, "test_crash": "after_commit_before_ack"}
        with patch.object(worker, "request", side_effect=[old, EOFError("crashed")]), \
             patch.object(worker, "show", side_effect=[manager(100, 0, "active"), manager(exit_code=72)]), \
             patch.object(worker, "wait_ready", return_value=(fresh, manager(101, 1, "active"))):
            result, evidence = worker.crash(payload, 72)
        self.assertEqual(result, fresh)
        self.assertEqual(evidence["exit"]["ExecMainStatus"], 72)
        self.assertEqual(evidence["after"]["NRestarts"], 1)
        with patch.object(worker, "request", side_effect=[old, EOFError("crashed")]), \
             patch.object(worker, "show", side_effect=[manager(100, 0, "active"), manager(exit_code=72)]), \
             patch.object(worker, "wait_ready", return_value=(fresh, manager(101, 2, "active"))):
            with self.assertRaisesRegex(RuntimeError, "more than once"):
                worker.crash(payload, 72)

    def test_manager_evidence_filters_description_and_private_properties(self):
        worker = lab.SystemdMonitor(TOOLS, self.directory)
        text = "LoadState=loaded\nDescription=" + worker.description + "\nMainPID=100\nNRestarts=2\nExecMainCode=1\nExecMainStatus=72\nExecStart=/private/secret\n"
        with patch.object(worker, "command", return_value=subprocess.CompletedProcess([], 0, text, "")):
            result = worker.show(require_owner=True)
        self.assertEqual(set(result), set(lab.MANAGER_PROPERTIES))
        self.assertNotIn("/private/secret", json.dumps(result))

    def publication_fixture(self, output):
        network, supervisor = self.scenario()
        scenario = lab.run_exercise(network, supervisor)
        instance = Mock(names={}, cleanup=Mock(return_value={"ok": True, "owned_namespaces_removed": 4,
                        "owned_virtual_links_removed": 6, "tracked_processes_stopped": 6}))
        managed = Mock(cleanup=Mock(return_value={"ok": True, "transient_unit_unloaded": True,
                       "private_state_removed": True, "verified_process_instances": 3, "active_main_pid": 0}))
        def exercise(unused_network, unused_service):
            for zone in lab.segmentation.ZONES:
                (output / "staging" / (zone + ".pcap")).write_bytes(b"portable test fixture, not packet evidence")
                (output / "staging" / (zone + "-packets.txt")).write_text("fixture\n")
            return scenario
        return instance, managed, exercise

    def test_publication_has_exact_16_file_allowlist_and_matching_15_hashes(self):
        output = self.directory / "published"
        network, managed, exercise = self.publication_fixture(output)
        with patch.object(lab, "preflight", return_value=TOOLS), patch.object(lab, "source_identity", return_value={"commit": "a" * 40}), \
             patch.object(lab.monitoring, "MonitoringLab", return_value=network), patch.object(lab, "SystemdMonitor", return_value=managed), \
             patch.object(lab, "run_exercise", side_effect=exercise):
            report = lab.run(output)
        self.assertTrue(report["ok"])
        publish = output / "publish"
        self.assertEqual({path.name for path in publish.iterdir()}, set(lab.PUBLIC_FILES) | {"MANIFEST.json"})
        manifest = json.loads((publish / "MANIFEST.json").read_text())
        self.assertEqual(len(manifest), 15)
        self.assertEqual(len(list(publish.iterdir())), 16)
        for name, expected in manifest.items():
            self.assertEqual(hashlib.sha256((publish / name).read_bytes()).hexdigest(), expected)
            self.assertEqual((publish / name).stat().st_mode & 0o777, 0o644)
        self.assertIn("Final monitored state: **healthy**", (publish / "SUMMARY.md").read_text())

    def test_failure_cleans_both_resources_and_never_publishes(self):
        output = self.directory / "failure"
        network = Mock(names={}, cleanup=Mock(return_value={"ok": True}))
        managed = Mock(cleanup=Mock(side_effect=RuntimeError("owned service remains")))
        with patch.object(lab, "preflight", return_value=TOOLS), patch.object(lab, "source_identity", return_value={"commit": "a" * 40}), \
             patch.object(lab.monitoring, "MonitoringLab", return_value=network), patch.object(lab, "SystemdMonitor", return_value=managed), \
             patch.object(lab, "run_exercise", side_effect=RuntimeError("scenario failed")):
            with self.assertRaisesRegex(RuntimeError, "scenario failed"):
                lab.run(output)
        network.cleanup.assert_called_once()
        managed.cleanup.assert_called_once()
        self.assertFalse((output / "publish").exists())
        report = json.loads((output / "staging/REPORT.json").read_text())
        self.assertFalse(report["ok"])
        self.assertFalse(report["cleanup"]["service"]["ok"])

    def test_cleanup_failure_after_success_prevents_publication(self):
        output = self.directory / "cleanup-failure"
        network, managed, exercise = self.publication_fixture(output)
        managed.cleanup.side_effect = RuntimeError("unit remains")
        with patch.object(lab, "preflight", return_value=TOOLS), patch.object(lab, "source_identity", return_value={"commit": "a" * 40}), \
             patch.object(lab.monitoring, "MonitoringLab", return_value=network), patch.object(lab, "SystemdMonitor", return_value=managed), \
             patch.object(lab, "run_exercise", side_effect=exercise):
            with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                lab.run(output)
        self.assertFalse((output / "publish").exists())

    def test_source_change_after_success_prevents_publication(self):
        output = self.directory / "changed-source"
        network, managed, exercise = self.publication_fixture(output)
        with patch.object(lab, "preflight", return_value=TOOLS), \
             patch.object(lab, "source_identity", side_effect=[{"commit": "a" * 40}, {"commit": "b" * 40}]), \
             patch.object(lab.monitoring, "MonitoringLab", return_value=network), patch.object(lab, "SystemdMonitor", return_value=managed), \
             patch.object(lab, "run_exercise", side_effect=exercise):
            with self.assertRaisesRegex(RuntimeError, "source changed"):
                lab.run(output)
        self.assertFalse((output / "publish").exists())

    def test_new_source_hashes_require_exact_committed_bytes(self):
        for name in lab.SOURCE_FILES[len(lab.monitoring.SOURCE_FILES):]:
            file = self.directory / name
            file.parent.mkdir(exist_ok=True)
            file.write_bytes(b"expected")
        identity = {"commit": "a" * 40, "source_sha256": {}}
        with patch.object(lab.monitoring, "source_identity", return_value=copy.deepcopy(identity)), \
             patch.object(lab.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"expected", b"")):
            result = lab.source_identity(self.directory)
        self.assertEqual(len(result["source_sha256"]), 3)
        self.assertEqual(len(lab.SOURCE_FILES), 12)
        with patch.object(lab.monitoring, "source_identity", return_value=copy.deepcopy(identity)), \
             patch.object(lab.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"changed", b"")):
            with self.assertRaisesRegex(RuntimeError, "committed version"):
                lab.source_identity(self.directory)


if __name__ == "__main__":
    unittest.main()
