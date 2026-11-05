"""Portable safety/regression tests; no network namespaces or root commands run."""
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import network_lab as lab


TOOLS = {name: "/tools/" + name for name in ("ip", "nft", "tcpdump", "sysctl", "git")}


def response(port):
    return {"outcome": "response", "status": 200,
            "payload": {"synthetic": True, "service_port": port}}


def packet(source_port, service_port, *, incoming=False, flags=0x02, payload=b"", source_ip=None):
    """Construct inert Ethernet/IPv4/TCP bytes; never opens a network socket."""
    source, destination = (lab.SERVER, lab.CLIENT) if incoming else (lab.CLIENT, lab.SERVER)
    ports = (service_port, source_port) if incoming else (source_port, service_port)
    tcp = struct.pack("!HHIIBBHHH", *ports, 0, 0, 0x50, flags, 65535, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                     socket.inet_aton(source_ip or source), socket.inet_aton(destination))
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp


def pcap(frames):
    return (b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, 512, 1)
            + b"".join(struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame for frame in frames))


def capture_fixture():
    specs = (("baseline", 8080, "response"), ("baseline", 9090, "response"),
             ("protected", 8080, "response"), ("protected", 9090, "timeout"),
             ("misconfigured", 9090, "response"), ("repaired", 9090, "timeout"),
             ("repaired", 8080, "response"))
    probes, frames = [], []
    for index, (phase, port, outcome) in enumerate(specs):
        source_port = 40000 + index
        probes.append({"from": "client", "phase": phase, "port": port,
                       "source_port": source_port, "outcome": outcome})
        frames.append(packet(source_port, port))
        if outcome == "response":
            frames.append(packet(source_port, port, incoming=True, flags=0x12))
            frames.append(packet(source_port, port, incoming=True, flags=0x18, payload=b"synthetic HTTP response"))
    return probes, frames


class ExerciseFixture:
    """Model outcomes to test the evaluator, not actual Linux networking."""
    def __init__(self):
        self.phase = "baseline"
        self.counts = {"allowed": 0, "denied_9090": 0, "unexpected_allow": 0}
        self.stopped = False

    def setup(self):
        pass

    start_services = setup
    start_capture = setup

    def apply_policy(self, misconfigured=False):
        self.counts = dict.fromkeys(self.counts, 0)

    def counters(self):
        return self.counts.copy()

    def probe(self, role, port):
        if role == "client" and port == 9090 and self.phase in ("protected", "repaired"):
            self.counts["denied_9090"] += 2
            return {"outcome": "timeout"}
        if role == "client" and port == 9090 and self.phase == "misconfigured":
            self.counts["unexpected_allow"] += 1
        return response(port)

    def stop_capture(self):
        self.stopped = True


class NetworkLabTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="network-lab-tests-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()

    def make_lab(self):
        return lab.NamespaceLab(TOOLS, self.base)

    def test_preflight_rejects_mac_before_inspecting_privileges_or_tools(self):
        with patch.object(lab.sys, "platform", "darwin"), patch.object(lab.os, "geteuid") as uid, \
                patch.object(lab.shutil, "which") as which:
            with self.assertRaisesRegex(RuntimeError, "Linux"):
                lab.preflight()
            uid.assert_not_called()
            which.assert_not_called()

    def test_preflight_rejects_nonroot_and_missing_tools(self):
        with patch.object(lab.sys, "platform", "linux"), patch.object(lab.os, "geteuid", return_value=501):
            with self.assertRaisesRegex(RuntimeError, "administrator"):
                lab.preflight()
        with patch.object(lab.sys, "platform", "linux"), patch.object(lab.os, "geteuid", return_value=0), \
                patch.object(lab.shutil, "which", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "Install"):
                lab.preflight()

    def test_output_refuses_existing_symlink_and_evidence_paths(self):
        existing = self.base / "existing"
        existing.mkdir()
        (existing / "keep").write_text("untouched")
        linked = self.base / "link"
        linked.symlink_to(existing, target_is_directory=True)
        for value in (existing, linked / "child", self.base / "data" / "new",
                      self.base / ".." / "traversal", "/Library/HELTEMES Evidence/new"):
            with self.subTest(value=value), self.assertRaises((RuntimeError, FileExistsError)):
                lab.new_output(value)
        self.assertEqual((existing / "keep").read_text(), "untouched")
        self.assertEqual(lab.new_output(self.base / "new").stat().st_mode & 0o777, 0o700)

    def test_protected_drop_precedes_established_and_injected_allow(self):
        good = lab.policy_text()
        bad = lab.policy_text(True)
        self.assertLess(good.index("counter name denied_9090 drop"), good.index("ct state established"))
        self.assertLess(bad.index("counter name unexpected_allow accept"), bad.index("counter name denied_9090 drop"))
        self.assertIn("policy drop;", good)
        instance = self.make_lab()
        with self.assertRaisesRegex(RuntimeError, "exclusively created"):
            instance.apply_policy()
        instance.created_names.append(instance.names["router"])
        with patch.object(instance, "command") as command:
            instance.apply_policy()
        self.assertEqual(command.call_args.args[0], [TOOLS["ip"], "netns", "exec", instance.names["router"], TOOLS["nft"], "-f", "-"])
        self.assertEqual(command.call_args.kwargs["input"], good)

    def test_denial_needs_timeout_healthy_control_and_increased_drop_counter(self):
        healthy = response(9090)
        lab.require_denied({"outcome": "timeout"}, healthy, 2, 7)
        invalid = (({"outcome": "socket_error", "errno": 111}, healthy, 2, 7),
                   ({"outcome": "timeout"}, {"outcome": "timeout"}, 2, 7),
                   ({"outcome": "timeout"}, healthy, 2, 2),
                   ({"outcome": "timeout"}, healthy, 2, 1))
        for values in invalid:
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                lab.require_denied(*values)

    def test_expected_misconfiguration_is_detected_then_repaired(self):
        fixture = ExerciseFixture()
        result = lab.run_exercise(fixture)
        self.assertTrue(result["injected_misconfiguration"]["expected_policy_violation"])
        self.assertTrue(result["injected_misconfiguration"]["observed_policy_violation"])
        self.assertEqual(result["repaired"]["denied"]["outcome"], "timeout")
        self.assertTrue(fixture.stopped)

    def test_missing_misconfiguration_detection_fails_exercise(self):
        fixture = ExerciseFixture()
        original = fixture.probe
        fixture.probe = lambda role, port: ({"outcome": "timeout"} if fixture.phase == "misconfigured" else original(role, port))
        with self.assertRaisesRegex(RuntimeError, "permissive rule"):
            lab.run_exercise(fixture)
        self.assertFalse(fixture.stopped)

    def test_timed_out_probes_record_unique_explicit_source_ports(self):
        instance = self.make_lab()
        def result(role, arguments):
            return subprocess.CompletedProcess(arguments, 0, json.dumps({"outcome": "timeout", "source_port": int(arguments[-1])}), "")
        with patch.object(instance, "run_in", side_effect=result) as run:
            first = instance.probe("client", 9090)
            second = instance.probe("client", 9090)
            with self.assertRaisesRegex(RuntimeError, "outside"):
                instance.probe("router", 443)
        self.assertEqual((first["source_port"], second["source_port"]), (40000, 40001))
        self.assertIn("source_address", run.call_args.args[1][-3])
        self.assertIn("started_at_utc", first)
        self.assertIn("completed_at_utc", first)

    def test_cleanup_never_adopts_a_namespace_that_failed_creation(self):
        instance = self.make_lab()
        existing = instance.names["client"]
        calls = []
        def command(arguments, **options):
            calls.append(arguments)
            if arguments[1:3] == ["netns", "add"]:
                raise RuntimeError("already exists")
            return subprocess.CompletedProcess(arguments, 0, existing + "\n", "")
        with patch.object(instance, "command", side_effect=command):
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                instance.setup()
            result = instance.cleanup()
        self.assertEqual(instance.created_names, [])
        self.assertEqual(result["owned_namespaces_removed"], 0)
        self.assertFalse(any("delete" in arguments for arguments in calls))

    def test_cleanup_waits_for_children_then_deletes_only_owned_resources(self):
        instance = self.make_lab()
        owned = instance.names["client"]
        instance.created_names = [owned]
        instance.created_links = ["moved-endpoint", "unfinished-endpoint"]
        instance.host_links = ["unfinished-endpoint"]
        events = []
        process = Mock()
        process.poll.return_value = None
        process.terminate.side_effect = lambda: events.append("terminate")
        process.wait.side_effect = lambda **kwargs: events.append("wait")
        instance.processes = [process]
        def command(arguments, **options):
            events.append(arguments)
            return subprocess.CompletedProcess(arguments, 0, "unrelated-existing\n", "")
        with patch.object(instance, "command", side_effect=command):
            self.assertTrue(instance.cleanup()["ok"])
        self.assertEqual(events[:2], ["terminate", "wait"])
        self.assertIn([TOOLS["ip"], "netns", "delete", owned], events)
        self.assertIn([TOOLS["ip"], "link", "delete", "unfinished-endpoint"], events)
        self.assertFalse(any("moved-endpoint" in event or "unrelated-existing" in event for event in events))

    def test_remaining_owned_namespace_fails_cleanup(self):
        instance = self.make_lab()
        instance.created_names = [instance.names["router"]]
        with patch.object(instance, "command", return_value=subprocess.CompletedProcess([], 0, instance.names["router"] + "\n", "")):
            with self.assertRaisesRegex(RuntimeError, "remain"):
                instance.cleanup()

    def test_capture_is_scoped_and_waited_before_reading(self):
        instance = self.make_lab()
        instance.created_names = [instance.names["router"]]
        process = Mock()
        process.poll.return_value = None
        process.wait.return_value = 0
        instance.probes, frames = capture_fixture()
        def spawn(arguments, **options):
            options["stderr"].write(b"listening on lan0\n")
            options["stdout"].write(pcap(frames))
            return process
        try:
            with patch.object(lab.subprocess, "Popen", side_effect=spawn) as popen:
                instance.start_capture()
            arguments = popen.call_args.args[0]
            self.assertEqual(arguments[:4], [TOOLS["ip"], "netns", "exec", instance.names["router"]])
            self.assertEqual(arguments[-1], lab.CAPTURE_FILTER)
            self.assertIn("--immediate-mode", arguments)
            self.assertEqual(arguments[arguments.index("-i") + 1], "lan0")
            self.assertEqual(arguments[arguments.index("-w") + 1], "-")
            def decode(arguments, **options):
                process.wait.assert_called_once_with(timeout=10)
                return subprocess.CompletedProcess(arguments, 0, f"{lab.CLIENT}.40001 > {lab.SERVER}.8080\n{lab.CLIENT}.40002 > {lab.SERVER}.9090\n", "")
            with patch.object(instance, "command", side_effect=decode):
                verification = instance.stop_capture()
            self.assertEqual(verification["client_flows_verified"], 7)
            self.assertTrue((self.base / "packet-capture.txt").is_file())
        finally:
            for handle in instance.handles:
                handle.close()

    def test_early_capture_exit_is_failure(self):
        instance = self.make_lab()
        instance.capture = Mock()
        instance.capture.poll.return_value = 0
        with self.assertRaisesRegex(RuntimeError, "unexpectedly"):
            instance.stop_capture()

    def test_capture_validation_requires_every_flow_including_final_repair(self):
        probes, frames = capture_fixture()
        verification = lab.validate_capture(pcap(frames), probes)
        self.assertEqual(verification["client_flows_verified"], 7)
        self.assertEqual(verification["flows"][-1]["phase"], "repaired")
        self.assertEqual(verification["flows"][-1]["source_port"], 40006)
        with self.assertRaisesRegex(lab.CaptureIncomplete, "repaired TCP8080 source 40006"):
            lab.validate_capture(pcap(frames[:-3]), probes)
        with self.assertRaisesRegex(lab.CaptureIncomplete, "handshake or payload"):
            lab.validate_capture(pcap(frames[:-1]), probes)
        denied_index = next(i for i, frame in enumerate(frames) if struct.unpack("!HH", frame[34:38]) == (40005, 9090))
        with self.assertRaisesRegex(lab.CaptureIncomplete, "repaired TCP9090 source 40005"):
            lab.validate_capture(pcap(frames[:denied_index] + frames[denied_index + 1:]), probes)

    def test_capture_wait_is_bounded_and_does_not_stop_before_final_flow(self):
        instance = self.make_lab()
        instance.probes, frames = capture_fixture()
        (self.base / "packet-capture.pcap").write_bytes(pcap(frames[:-3]))
        instance.capture = Mock()
        instance.capture.poll.return_value = None
        with patch.object(lab.time, "monotonic", side_effect=[0, 6]):
            with self.assertRaisesRegex(RuntimeError, "delivery deadline.*repaired TCP8080"):
                instance.stop_capture()
        instance.capture.send_signal.assert_not_called()

    def test_capture_wait_observes_late_records_then_revalidates_closed_file(self):
        instance = self.make_lab()
        instance.probes, frames = capture_fixture()
        capture = self.base / "packet-capture.pcap"
        capture.write_bytes(pcap(frames[:-3]))
        instance.capture = Mock()
        instance.capture.poll.return_value = None
        def finish(**options):
            capture.write_bytes(pcap(frames[:-3]))
            return 0
        instance.capture.wait.side_effect = finish
        with patch.object(lab.time, "sleep", side_effect=lambda duration: capture.write_bytes(pcap(frames))):
            with self.assertRaisesRegex(lab.CaptureIncomplete, "repaired TCP8080"):
                instance.stop_capture()
        instance.capture.send_signal.assert_called_once()
        instance.capture.wait.assert_called_once_with(timeout=10)

    def test_capture_rejects_out_of_scope_malformed_and_denied_return_packets(self):
        probes, frames = capture_fixture()
        invalid = (pcap(frames + [packet(40000, 8080, source_ip="192.0.2.1")]),
                   pcap(frames + [packet(40000, 443)]),
                   pcap(frames + [packet(49999, 8080)]),
                   pcap(frames + [packet(40005, 9090, incoming=True, flags=0x14)]),
                   b"INVALID" + pcap(frames)[7:], pcap(frames)[:-1],
                   pcap(frames) + b"\x00", pcap([b"\x00" * 54]))
        for value in invalid:
            with self.subTest(length=len(value)), self.assertRaises(RuntimeError):
                lab.validate_capture(value, probes)

    def test_source_identity_rejects_modified_code_and_wrong_ci_commit(self):
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
        identity = lab.source_identity(root, {})
        self.assertEqual(identity["source_sha256"][lab.SOURCE_FILES[0]], hashlib.sha256((root / lab.SOURCE_FILES[0]).read_bytes()).hexdigest())
        environment = {"GITHUB_ACTIONS": "true", "GITHUB_SHA": "0" * 40, "SECRET": "must-not-export"}
        with self.assertRaises((RuntimeError, ValueError)):
            lab.source_identity(root, environment)
        (root / lab.SOURCE_FILES[0]).write_text("# altered\n")
        with self.assertRaisesRegex(RuntimeError, "differs"):
            lab.source_identity(root, {})

    def test_failed_cleanup_prevents_publication_and_keeps_diagnostic(self):
        output = self.base / "output"
        source = {"commit": "a" * 40}
        with patch.object(lab, "preflight", return_value=TOOLS), patch.object(lab, "source_identity", return_value=source), \
                patch.object(lab, "run_exercise", return_value={}), \
                patch.object(lab.NamespaceLab, "cleanup", side_effect=RuntimeError("owned namespace remains")):
            with self.assertRaisesRegex(RuntimeError, "owned namespace remains"):
                lab.run(output)
        self.assertFalse((output / "publish").exists())
        report = json.loads((output / "staging" / "REPORT.json").read_text())
        self.assertFalse(report["ok"])
        self.assertFalse(report["cleanup"]["ok"])

    def test_success_publishes_only_fixed_files_with_matching_manifest(self):
        output = self.base / "output"
        def exercise(instance):
            (instance.staging / "packet-capture.pcap").write_bytes(b"synthetic unit-test fixture")
            (instance.staging / "packet-capture.txt").write_text("synthetic unit-test fixture\n")
            (instance.staging / "service.stderr").write_text("not a public artifact")
            return {"unit_test_fixture": True}
        with patch.object(lab, "preflight", return_value=TOOLS), \
                patch.object(lab, "source_identity", return_value={"commit": "a" * 40}), \
                patch.object(lab, "run_exercise", side_effect=exercise), \
                patch.object(lab.NamespaceLab, "cleanup", return_value={"ok": True}):
            self.assertTrue(lab.run(output)["ok"])
        publish = output / "publish"
        expected = {"REPORT.json", "MANIFEST.json", "packet-capture.pcap", "packet-capture.txt", "policy.nft", "misconfigured-policy.nft", "SUMMARY.md"}
        self.assertEqual({path.name for path in publish.iterdir()}, expected)
        manifest = json.loads((publish / "MANIFEST.json").read_text())
        self.assertEqual(set(manifest), expected - {"MANIFEST.json"})
        for name, digest in manifest.items():
            self.assertEqual(hashlib.sha256((publish / name).read_bytes()).hexdigest(), digest)
            self.assertEqual((publish / name).stat().st_mode & 0o777, 0o644)
        self.assertEqual(output.stat().st_mode & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main()
