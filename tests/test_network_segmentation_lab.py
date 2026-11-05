"""Portable segmentation orchestration tests; privileged networking is mocked."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import network_segmentation_lab as lab

TOOLS = {name: "/tools/" + name for name in ("ip", "nft", "tcpdump", "sysctl", "git")}


def response(destination, port):
    return {"outcome": "response", "status": 200,
            "payload": {"synthetic": True, "zone": destination, "service_port": port}}


class ExerciseFixture:
    """Deterministic evaluator fixture; it does not simulate Linux packet behavior."""
    def __init__(self):
        self.probes, self.phase, self.mode = [], "readiness", "baseline"
        self.apply_policy()

    def setup(self):
        pass

    start_services = setup
    start_captures = setup

    def apply_policy(self, mode="restricted"):
        self.mode = mode
        self.counts = {lab.row_counter(row, verdict): 0 for row in lab.MATRIX for verdict in ("allow", "drop")}
        self.counts["injected_user_app_9090"] = 0

    def counters(self):
        return self.counts.copy()

    def probe(self, source, destination, port):
        probe = {"from": source, "to": destination, "port": port, "destination": lab.ZONES[destination],
                 "source_port": 40000 + len(self.probes), "phase": self.phase}
        key = (source, destination, port)
        if source == destination:
            probe.update(response(destination, port))
        elif self.mode == "misconfigured" and key == lab.EXCEPTION:
            probe.update(response(destination, port))
            self.counts["injected_user_app_9090"] += 3
        elif self.mode == "baseline" or key in lab.ALLOWED:
            probe.update(response(destination, port))
            self.counts[lab.row_counter(probe, "allow")] += 3
        else:
            probe["outcome"] = "connect_timeout"
            self.counts[lab.row_counter(probe, "drop")] += 2
        self.probes.append(probe)
        return probe

    def stop_captures(self):
        return {"ok": True, "routed_flows_verified": 37}


class NetworkSegmentationLabTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="network-segmentation-tests-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()

    def make_lab(self):
        return lab.SegmentationLab(TOOLS, self.base)

    def test_complete_matrix_has_three_allows_and_nine_directional_denials(self):
        self.assertEqual(len(lab.MATRIX), 12)
        allows = {(row["from"], row["to"], row["port"]) for row in lab.MATRIX if row["expected"] == "allow"}
        self.assertEqual(allows, {("user", "app", 8080), ("management", "app", 8080), ("management", "app", 9090)})
        expected = {(row["from"], row["to"], row["port"]): row["expected"] for row in lab.MATRIX}
        self.assertEqual(expected[("app", "management", 8080)], "deny")
        self.assertEqual(expected[("app", "user", 8080)], "deny")

    def test_policy_has_exact_interfaces_addresses_and_reply_direction(self):
        restricted, baseline = lab.policy_text(), lab.policy_text("baseline")
        self.assertEqual(restricted.count("ct direction reply accept"), 3)
        self.assertEqual(baseline.count("ct direction reply accept"), 12)
        self.assertNotIn("ct state established,related accept", restricted)
        for source, destination, port in lab.ALLOWED:
            self.assertIn(f'{lab.tuple_match(destination, source)} tcp sport {port} ct state established ct direction reply accept', restricted)
            self.assertIn(f'{lab.tuple_match(source, destination)} tcp dport {port} ct state new,established ct direction original', restricted)
        self.assertEqual(restricted.count(" drop\n"), 9)
        for line in restricted.splitlines():
            if line.rstrip().endswith(" drop"):
                self.assertIn("ct direction original", line)
        self.assertNotIn("counter name drop_", baseline)
        bad = lab.policy_text("misconfigured")
        self.assertLess(bad.index("counter name injected_user_app_9090 accept"), bad.index("counter name drop_user_app_9090 drop"))
        self.assertEqual(bad.count("ct direction reply accept"), 4)

    def test_all_phases_validate_37_routed_probes_and_18_health_controls(self):
        fixture = ExerciseFixture()
        result = lab.run_exercise(fixture)
        self.assertEqual(len(fixture.probes), 55)
        self.assertEqual(result["summary"]["routed_probes"], 37)
        self.assertEqual(result["summary"]["denied_connections"], 18)
        for phase in ("restricted", "repaired"):
            self.assertEqual(sum(row["observed"] == "allowed" for row in result[phase]), 3)
            self.assertEqual(sum(row["observed"] == "blocked" for row in result[phase]), 9)
            self.assertTrue(all(row["counter"]["delta"] > 0 for row in result[phase]))
        self.assertTrue(result["injected_misconfiguration"]["expected_policy_violation"])
        self.assertTrue(result["injected_misconfiguration"]["observed_policy_violation"])

    def test_skipped_duplicate_wrong_phase_or_wrong_outcome_inventory_fails(self):
        fixture = ExerciseFixture()
        lab.run_exercise(fixture)
        variants = []
        missing = copy.deepcopy(fixture.probes)
        missing.pop()
        variants.append(missing)
        for field, value in (("phase", "unexpected"), ("outcome", "read_timeout"), ("port", 12345), ("source_port", 40001)):
            altered = copy.deepcopy(fixture.probes)
            altered[0][field] = value
            variants.append(altered)
        for values in variants:
            with self.subTest(count=len(values)), self.assertRaises(RuntimeError):
                lab.require_complete_inventory(values)

    def test_denial_needs_connect_timeout_exact_destination_health_and_own_counter(self):
        lab.require_denial({"outcome": "connect_timeout"}, response("user", 8080), "user", 8080, 1, 3)
        invalid = (({"outcome": "read_timeout"}, response("user", 8080), 1, 3),
                   ({"outcome": "socket_error"}, response("user", 8080), 1, 3),
                   ({"outcome": "connect_timeout"}, response("app", 8080), 1, 3),
                   ({"outcome": "connect_timeout"}, response("user", 9090), 1, 3),
                   ({"outcome": "connect_timeout"}, response("user", 8080), 1, 1))
        for probe, health, before, after in invalid:
            with self.subTest(probe=probe, health=health), self.assertRaises(RuntimeError):
                lab.require_denial(probe, health, "user", 8080, before, after)

    def test_allowed_response_without_its_counter_increment_fails(self):
        fixture = ExerciseFixture()
        fixture.counters = lambda: dict.fromkeys(fixture.counts, 0)
        with self.assertRaisesRegex(RuntimeError, "allowed matrix row's own counter"):
            lab.exercise_matrix(fixture, baseline=True)

    def test_setup_creates_only_owned_four_namespaces_and_six_endpoints(self):
        instance = self.make_lab()
        calls = []
        def command(arguments, **options):
            calls.append(arguments)
            return subprocess.CompletedProcess(arguments, 0, "", "")
        with patch.object(instance, "command", side_effect=command):
            instance.setup()
        self.assertEqual(len(instance.created_names), 4)
        self.assertEqual(len(instance.created_links), 6)
        self.assertEqual(instance.host_links, [])
        forwarding = [arguments for arguments in calls if "net.ipv4.ip_forward=1" in arguments]
        self.assertEqual(forwarding, [[TOOLS["ip"], "netns", "exec", instance.names["router"], TOOLS["sysctl"], "-w", "net.ipv4.ip_forward=1"]])
        for zone in lab.ZONES:
            self.assertIn([TOOLS["ip"], "netns", "exec", instance.names[zone], TOOLS["ip"], "route", "add", "default", "via", lab.GATEWAYS[zone]], calls)

    def test_failed_namespace_creation_never_adopts_existing_name(self):
        instance = self.make_lab()
        existing = instance.names["user"]
        calls = []
        def command(arguments, **options):
            calls.append(arguments)
            if arguments[1:3] == ["netns", "add"]:
                raise RuntimeError("already exists")
            return subprocess.CompletedProcess(arguments, 0, existing + "\n", "")
        with patch.object(instance, "command", side_effect=command):
            with self.assertRaises(RuntimeError):
                instance.setup()
            self.assertEqual(instance.cleanup()["owned_namespaces_removed"], 0)
        self.assertFalse(any("delete" in arguments for arguments in calls))

    def test_probe_ports_and_exact_addresses_are_bound_and_recorded(self):
        instance = self.make_lab()
        def result(role, arguments):
            return subprocess.CompletedProcess(arguments, 0, json.dumps({"source_port": int(arguments[-1]), "outcome": "connect_timeout"}), "")
        with patch.object(instance, "run_in", side_effect=result) as run:
            first = instance.probe("user", "app", 9090)
            second = instance.probe("app", "user", 8080)
            with self.assertRaises(RuntimeError):
                instance.probe("outside", "app", 8080)
        self.assertEqual((first["source_port"], second["source_port"]), (40000, 40001))
        self.assertEqual(run.call_args.args[1][-4:], [lab.ZONES["user"], "8080", lab.ZONES["app"], "40001"])
        self.assertIn("started_at_utc", first)
        self.assertIn("completed_at_utc", first)

    def test_policy_application_requires_owned_router_and_atomic_stdin(self):
        instance = self.make_lab()
        with self.assertRaisesRegex(RuntimeError, "exclusively created"):
            instance.apply_policy()
        instance.created_names.append(instance.names["router"])
        with patch.object(instance, "command") as command:
            instance.apply_policy("misconfigured")
        self.assertEqual(command.call_args.args[0], [TOOLS["ip"], "netns", "exec", instance.names["router"], TOOLS["nft"], "-f", "-"])
        self.assertEqual(command.call_args.kwargs["input"], lab.policy_text("misconfigured"))

    def test_three_captures_use_only_owned_router_interfaces_and_exact_filters(self):
        instance = self.make_lab()
        instance.created_names = [instance.names["router"]]
        process = Mock()
        process.poll.return_value = None
        def spawn(arguments, **options):
            options["stderr"].write(b"listening on scoped interface\n")
            return process
        try:
            with patch.object(lab.subprocess, "Popen", side_effect=spawn) as popen:
                instance.start_captures()
            self.assertEqual(len(instance.captures), 3)
            self.assertEqual(len(instance.processes), 3)
            for zone, call in zip(lab.ZONES, popen.call_args_list):
                arguments = call.args[0]
                self.assertEqual(arguments[:4], [TOOLS["ip"], "netns", "exec", instance.names["router"]])
                self.assertEqual(arguments[arguments.index("-i") + 1], lab.INTERFACES[zone])
                self.assertEqual(arguments[-1], lab.capture.capture_filter(zone))
                self.assertIn("--immediate-mode", arguments)
        finally:
            for handle in instance.handles:
                handle.close()

    def prepare_capture_stop(self):
        instance = self.make_lab()
        for zone in lab.ZONES:
            (self.base / (zone + ".pcap")).write_bytes(b"inert capture fixture")
            (self.base / (zone + "-capture.stderr")).write_text("1 packets captured\n0 packets dropped by kernel\n")
            process = Mock()
            process.poll.return_value = None
            process.wait.return_value = 0
            instance.captures[zone] = process
        verification = {"ok": True, "routed_flows_verified": 37, "capture_packet_counts": dict.fromkeys(lab.ZONES, 1)}
        return instance, verification

    def test_capture_wait_is_bounded_without_premature_stop(self):
        instance, verification = self.prepare_capture_stop()
        with patch.object(lab.capture, "validate_captures", side_effect=lab.base.CaptureIncomplete("missing final flow")), \
                patch.object(lab.time, "monotonic", side_effect=[0, 6]):
            with self.assertRaisesRegex(RuntimeError, "deadline expired"):
                instance.stop_captures()
        for process in instance.captures.values():
            process.send_signal.assert_not_called()

    def test_all_captures_close_before_final_validation_and_zero_loss_check(self):
        instance, verification = self.prepare_capture_stop()
        calls = 0
        def validate(raw, probes):
            nonlocal calls
            calls += 1
            if calls == 2:
                for process in instance.captures.values():
                    process.wait.assert_called_once_with(timeout=10)
            return copy.deepcopy(verification)
        with patch.object(lab.capture, "validate_captures", side_effect=validate), \
                patch.object(instance, "command", return_value=subprocess.CompletedProcess([], 0, "synthetic packet fixture", "")):
            result = instance.stop_captures()
        self.assertEqual(calls, 2)
        self.assertTrue(all(value["kernel_dropped_packets"] == 0 for value in result["capture_statistics"].values()))
        self.assertTrue(all((self.base / (zone + "-packets.txt")).exists() for zone in lab.ZONES))

    def test_poststop_missing_flow_or_missing_nonzero_kernel_drop_statistics_fails(self):
        instance, verification = self.prepare_capture_stop()
        with patch.object(lab.capture, "validate_captures", side_effect=[verification, lab.base.CaptureIncomplete("missing closed flow")]):
            with self.assertRaises(lab.base.CaptureIncomplete):
                instance.stop_captures()
        for contents in ("", "1 packets captured\n1 packets dropped by kernel\n", "2 packets captured\n0 packets dropped by kernel\n"):
            instance, verification = self.prepare_capture_stop()
            (self.base / "user-capture.stderr").write_text(contents)
            with patch.object(lab.capture, "validate_captures", return_value=verification):
                with self.assertRaises(RuntimeError):
                    instance.stop_captures()

    def test_cleanup_stops_six_children_before_deleting_owned_namespaces(self):
        instance = self.make_lab()
        instance.created_names = list(instance.names.values())
        instance.created_links = list(instance.link_names)
        events = []
        for _ in range(6):
            process = Mock()
            process.poll.return_value = None
            process.terminate.side_effect = lambda: events.append("stop")
            process.wait.side_effect = lambda **kwargs: events.append("wait")
            instance.processes.append(process)
        def command(arguments, **options):
            events.append(arguments)
            return subprocess.CompletedProcess(arguments, 0, "unrelated-existing\n", "")
        with patch.object(instance, "command", side_effect=command):
            result = instance.cleanup()
        self.assertEqual(events[:12], ["stop", "wait"] * 6)
        self.assertEqual(result, {"ok": True, "owned_namespaces_removed": 4, "tracked_processes_stopped": 6, "owned_virtual_links_removed": 6})
        self.assertFalse(any("unrelated-existing" in event for event in events))

    def test_source_provenance_covers_capture_module_and_rejects_modification(self):
        root = self.base / "source"
        root.mkdir()
        for name in lab.SOURCE_FILES:
            path = root / name
            path.parent.mkdir(exist_ok=True)
            path.write_text("# synthetic source fixture\n")
        def git(*arguments):
            return subprocess.check_output(["git", "-C", str(root), *arguments], stderr=subprocess.PIPE)
        git("init", "--quiet")
        git("add", ".")
        git("-c", "user.name=Lab Test", "-c", "user.email=test@example.invalid", "commit", "--quiet", "-m", "Synthetic fixture")
        self.assertEqual(set(lab.source_identity(root, {})["source_sha256"]), set(lab.SOURCE_FILES))
        (root / "scripts/network_segmentation_capture.py").write_text("# changed\n")
        with self.assertRaisesRegex(RuntimeError, "differs"):
            lab.source_identity(root, {})

    def test_mac_preflight_stops_before_output_or_git_checks(self):
        output = self.base / "must-not-exist"
        with patch.object(lab.base.sys, "platform", "darwin"), patch.object(lab, "source_identity") as identity:
            with self.assertRaisesRegex(RuntimeError, "Linux"):
                lab.run(output)
        identity.assert_not_called()
        self.assertFalse(output.exists())

    def test_cleanup_failure_prevents_publication(self):
        output = self.base / "failed"
        with patch.object(lab.base, "preflight", return_value=TOOLS), patch.object(lab, "source_identity", return_value={"commit": "a" * 40}), \
                patch.object(lab, "run_exercise", return_value={}), \
                patch.object(lab.SegmentationLab, "cleanup", side_effect=RuntimeError("owned namespace remains")):
            with self.assertRaisesRegex(RuntimeError, "owned namespace remains"):
                lab.run(output)
        self.assertFalse((output / "publish").exists())
        self.assertFalse(json.loads((output / "staging/REPORT.json").read_text())["ok"])

    def test_success_publishes_twelve_fixed_files_with_matching_manifest(self):
        output = self.base / "success"
        def exercise(instance):
            for zone in lab.ZONES:
                (instance.staging / (zone + ".pcap")).write_bytes(b"inert unit-test capture")
                (instance.staging / (zone + "-packets.txt")).write_text("inert unit-test capture")
            (instance.staging / "user-service.stderr").write_text("not a public file")
            return {"baseline": [], "restricted": [], "repaired": [], "injected_misconfiguration": {}}
        with patch.object(lab.base, "preflight", return_value=TOOLS), patch.object(lab, "source_identity", return_value={"commit": "a" * 40}), \
                patch.object(lab, "run_exercise", side_effect=exercise), patch.object(lab.SegmentationLab, "cleanup", return_value={"ok": True}):
            self.assertTrue(lab.run(output)["ok"])
        publish = output / "publish"
        self.assertEqual(len(list(publish.iterdir())), 12)
        self.assertEqual({path.name for path in publish.iterdir()}, {*lab.PUBLIC_FILES, "MANIFEST.json"})
        manifest = json.loads((publish / "MANIFEST.json").read_text())
        for name, digest in manifest.items():
            self.assertEqual(hashlib.sha256((publish / name).read_bytes()).hexdigest(), digest)
            self.assertEqual((publish / name).stat().st_mode & 0o777, 0o644)


if __name__ == "__main__":
    unittest.main()
