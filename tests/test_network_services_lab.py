"""Portable DNS/TLS orchestration safeguards; no privileged networking commands."""
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import network_services_lab as lab

TOOLS = {name: "/tools/" + name for name in ("ip", "nft", "tcpdump", "sysctl", "git", "openssl")}
FINGERPRINT = "a" * 64


def metadata():
    return {"synthetic_only": True, "server_hostname": lab.HOSTNAME, "configured_validity_days": 2,
            "trusted_ca_sha256": "b" * 64, "untrusted_ca_sha256": "c" * 64,
            "server_certificate_sha256": FINGERPRINT,
            "public_certificates_pem": dict.fromkeys(("ca", "untrusted-ca", "server"), "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----"),
            "server_certificate_details": ["synthetic public certificate fixture"]}


def tls_response():
    return {"outcome": "response", "status": 200, "payload": lab.protocol.TLS_PAYLOAD,
            "peer_certificate_sha256": FINGERPRINT}


class ExerciseFixture:
    def __init__(self):
        self.phase, self.probes, self.blocked = "readiness", [], False
        self.certificates = metadata()
        self.counts = dict.fromkeys(("dns_allowed", "tls_allowed", "tls_denied"), 0)

    def setup(self):
        pass

    create_certificates = setup
    start_services = setup
    start_capture = setup

    def apply_policy(self, blocked=False):
        self.blocked = blocked
        self.counts = dict.fromkeys(self.counts, 0)

    def counters(self):
        return self.counts.copy()

    def probe_service(self, role, kind, **options):
        source = 40000 + len(self.probes)
        result = {"from": role, "phase": self.phase, "source_port": source,
                  "transport": "udp" if kind == "dns" else "tcp", "port": lab.DNS_PORT if kind == "dns" else lab.TLS_PORT}
        if kind == "dns":
            name = options.get("name", lab.HOSTNAME)
            result.update(name=name, transaction_id=source)
            if name == "unknown.test":
                result.update(outcome="nxdomain", rcode=3)
            else:
                result.update(outcome="response", rcode=0, address=lab.SERVER)
        elif role == "client" and self.blocked:
            result["outcome"] = "connect_timeout"
            self.counts["tls_denied"] += 2
        elif options.get("hostname") == "wrong.test":
            result.update(outcome="certificate_error", verify_code=62)
        elif options.get("trust") == "untrusted":
            result.update(outcome="certificate_error", verify_code=20)
        else:
            result.update(tls_response())
        self.probes.append(result)
        return result

    def stop_capture(self):
        return {"ok": True, "client_flows_verified": sum(probe["from"] == "client" for probe in self.probes)}


def frame(transport, source_port, service_port, *, incoming=False, flags=0x02, payload=b"", source_ip=None):
    source, destination = (lab.SERVER, lab.CLIENT) if incoming else (lab.CLIENT, lab.SERVER)
    ports = (service_port, source_port) if incoming else (source_port, service_port)
    if transport == "udp":
        segment = struct.pack("!HHHH", *ports, 8 + len(payload), 0) + payload
    else:
        segment = struct.pack("!HHIIBBHHH", *ports, 0, 0, 0x50, flags, 65535, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0, 0, 64, 17 if transport == "udp" else 6, 0,
                     socket.inet_aton(source_ip or source), socket.inet_aton(destination))
    return b"\x00" * 12 + b"\x08\x00" + ip + segment


def pcap(frames):
    return (b"\xd4\xc3\xb2\xa1" + struct.pack("<HHiIII", 2, 4, 0, 0, lab.SNAPLEN, 1)
            + b"".join(struct.pack("<IIII", 1, 0, len(value), len(value)) + value for value in frames))


def capture_fixture():
    exercise = ExerciseFixture()
    lab.run_exercise(exercise)
    frames = []
    for probe in exercise.probes:
        if probe["from"] != "client":
            continue
        args = (probe["transport"], probe["source_port"], probe["port"])
        if probe["transport"] == "udp":
            query = lab.protocol.make_dns_query(probe["name"], probe["transaction_id"])
            frames.extend((frame(*args, payload=query), frame(*args, incoming=True, payload=lab.protocol.make_dns_response(query))))
        else:
            frames.append(frame(*args))
            if probe["outcome"] != "connect_timeout":
                frames.extend((frame(*args, incoming=True, flags=0x12), frame(*args, flags=0x18, payload=b"synthetic client TLS bytes"),
                               frame(*args, incoming=True, flags=0x18, payload=b"synthetic server TLS bytes")))
    return exercise.probes, frames


class NetworkServicesLabTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="network-services-tests-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()

    def make_lab(self):
        return lab.ServicesLab(TOOLS, self.base)

    def test_all_cases_keep_dns_transport_and_identity_failures_distinct(self):
        fixture = ExerciseFixture()
        result = lab.run_exercise(fixture)
        self.assertEqual(result["capture_verification"]["client_flows_verified"], 9)
        self.assertFalse(result["unknown_dns"]["tls_attempted"])
        self.assertEqual(result["wrong_hostname"]["verify_code"], 62)
        self.assertEqual(result["untrusted_ca"]["verify_code"], 20)
        self.assertEqual(result["firewall_blocked"]["dns"]["outcome"], "response")
        self.assertEqual(result["firewall_blocked"]["denied"]["outcome"], "connect_timeout")
        self.assertEqual(result["repaired"]["tls"]["peer_certificate_sha256"], FINGERPRINT)

    def test_nxdomain_stops_before_any_tls_probe(self):
        fixture = Mock()
        fixture.probe_service.return_value = {"outcome": "nxdomain", "rcode": 3}
        self.assertFalse(lab.resolve_then_tls(fixture, "unknown.test")["tls_attempted"])
        fixture.probe_service.assert_called_once_with("client", "dns", name="unknown.test")

    def test_wrong_certificate_failure_cause_or_peer_fingerprint_fails(self):
        for cause, code in (("hostname", 20), ("hostname", 10), ("untrusted_ca", 62), ("untrusted_ca", 10)):
            with self.subTest(cause=cause, code=code), self.assertRaises(RuntimeError):
                lab.require_certificate_rejection({"outcome": "certificate_error", "verify_code": code}, cause)
        with self.assertRaisesRegex(RuntimeError, "leaf certificate"):
            lab.require_tls(tls_response(), "d" * 64)

    def test_firewall_proof_rejects_read_timeout_or_missing_drop_delta(self):
        fixture = ExerciseFixture()
        original = fixture.probe_service
        def wrong_timeout(role, kind, **options):
            value = original(role, kind, **options)
            if value["outcome"] == "connect_timeout":
                value["outcome"] = "read_timeout"
            return value
        fixture.probe_service = wrong_timeout
        with self.assertRaisesRegex(RuntimeError, "during TCP connection"):
            lab.run_exercise(fixture)
        fixture = ExerciseFixture()
        fixture.counters = lambda: dict.fromkeys(fixture.counts, 0)
        with self.assertRaisesRegex(RuntimeError, "drop counter"):
            lab.run_exercise(fixture)

    def test_policy_uses_dns53_and_denies_tls_before_established_state(self):
        policy = lab.policy_text(True)
        self.assertIn("udp dport 53", policy)
        self.assertLess(policy.index("counter name tls_denied drop"), policy.index("ct state established"))
        instance = self.make_lab()
        with self.assertRaisesRegex(RuntimeError, "exclusively created"):
            instance.apply_policy(True)
        instance.created_names = [instance.names["router"]]
        with patch.object(instance, "command") as command:
            instance.apply_policy(True)
        self.assertEqual(command.call_args.args[0][:4], [TOOLS["ip"], "netns", "exec", instance.names["router"]])
        self.assertEqual(command.call_args.kwargs["input"], policy)

    def test_fresh_probe_ports_are_explicit_and_recorded_on_timeout(self):
        instance = self.make_lab()
        def probe(role, arguments):
            return subprocess.CompletedProcess(arguments, 0, json.dumps({"source_port": int(arguments[-1]), "outcome": "connect_timeout"}), "")
        with patch.object(instance, "run_in", side_effect=probe) as run:
            first = instance.probe_service("client", "tls")
            second = instance.probe_service("client", "tls")
        self.assertEqual((first["source_port"], second["source_port"]), (40000, 40001))
        self.assertIn("--source-port", run.call_args.args[1])
        self.assertIn("started_at_utc", first)
        self.assertIn("completed_at_utc", first)

    def test_public_certificate_metadata_excludes_extra_private_fields(self):
        value = metadata()
        value["private_key"] = "DO NOT PUBLISH"
        self.assertNotIn("private_key", lab.public_certificates(value))
        value["public_certificates_pem"]["server"] += "-----BEGIN PRIVATE KEY-----"
        with self.assertRaisesRegex(RuntimeError, "key material"):
            lab.public_certificates(value)

    def test_partial_pki_generation_is_owned_and_removed_after_child_cleanup(self):
        instance = self.make_lab()
        events = []
        def partial(path, openssl):
            path.mkdir()
            (path / "server.key").write_text("synthetic unit-test private fixture")
            raise ValueError("generation failed")
        with patch.object(lab.protocol, "create_pki", side_effect=partial):
            with self.assertRaises(ValueError):
                instance.create_certificates()
        self.assertTrue(instance.pki_owned)
        def parent_cleanup():
            self.assertTrue(instance.private_root.exists())
            events.append("children stopped")
            return {"ok": True}
        with patch.object(lab.base.NamespaceLab, "cleanup", side_effect=parent_cleanup):
            self.assertTrue(instance.cleanup()["private_pki_deleted"])
        self.assertEqual(events, ["children stopped"])
        self.assertFalse(instance.private_root.exists())

    def test_existing_pki_is_never_adopted_and_running_child_blocks_deletion(self):
        instance = self.make_lab()
        instance.private_root.mkdir()
        (instance.private_root / "keep").write_text("untouched")
        with self.assertRaises(FileExistsError):
            instance.create_certificates()
        self.assertFalse(instance.pki_owned)
        with patch.object(lab.base.NamespaceLab, "cleanup", return_value={"ok": True}):
            instance.cleanup()
        self.assertEqual((instance.private_root / "keep").read_text(), "untouched")
        instance.pki_owned = True
        instance.processes = [Mock()]
        instance.processes[0].poll.return_value = None
        with patch.object(lab.base.NamespaceLab, "cleanup", return_value={"ok": True}):
            with self.assertRaisesRegex(RuntimeError, "child is running"):
                instance.cleanup()
        self.assertTrue(instance.private_root.exists())

    def test_capture_matches_nine_dns_and_tls_flows(self):
        probes, frames = capture_fixture()
        result = lab.validate_capture(pcap(frames), probes)
        self.assertTrue(result["ok"])
        self.assertEqual(result["client_flows_verified"], 9)
        self.assertEqual(sum(flow["transport"] == "udp" for flow in result["flows"]), 4)
        self.assertIn("strict TLS client", result["tls_identity_decision_source"])

    def test_capture_rejects_missing_final_flow_or_tls_handshake_bytes(self):
        probes, frames = capture_fixture()
        with self.assertRaisesRegex(lab.CaptureIncomplete, "repaired"):
            lab.validate_capture(pcap(frames[:-4]), probes)
        with self.assertRaisesRegex(lab.CaptureIncomplete, "bidirectional TLS bytes"):
            lab.validate_capture(pcap(frames[:-1]), probes)

    def test_capture_rejects_dns_id_question_rcode_and_answer_tampering(self):
        probes, frames = capture_fixture()
        baseline = probes[0]
        query = lab.protocol.make_dns_query(lab.HOSTNAME, baseline["transaction_id"])
        good = lab.protocol.make_dns_response(query)
        altered = (struct.pack("!H", baseline["transaction_id"] + 1) + good[2:],
                   good[:3] + b"\x03" + good[4:], good[:-4] + socket.inet_aton("192.0.2.1"),
                   lab.protocol.make_dns_response(lab.protocol.make_dns_query("unknown.test", baseline["transaction_id"])))
        for response in altered:
            replacement = frame("udp", baseline["source_port"], lab.DNS_PORT, incoming=True, payload=response)
            with self.subTest(response=response[:12]), self.assertRaises((ValueError, RuntimeError)):
                lab.validate_capture(pcap([frames[0], replacement, *frames[2:]]), probes)

    def test_capture_rejects_unrecorded_out_of_scope_and_denied_return_traffic(self):
        probes, frames = capture_fixture()
        denied = next(probe for probe in probes if probe["outcome"] == "connect_timeout")
        extra = (frame("tcp", 49999, lab.TLS_PORT), frame("udp", 49999, 5353),
                 frame("tcp", denied["source_port"], lab.TLS_PORT, incoming=True, flags=0x14),
                 frame("tcp", 49999, lab.TLS_PORT, source_ip="192.0.2.1"))
        for value in extra:
            with self.subTest(value=value[-12:]), self.assertRaises(RuntimeError):
                lab.validate_capture(pcap([*frames, value]), probes)
        with self.assertRaises(lab.CaptureIncomplete):
            lab.validate_capture(pcap(frames)[:-1], probes)

    def test_capture_wait_is_bounded_and_closed_file_is_revalidated(self):
        instance = self.make_lab()
        instance.probes, frames = capture_fixture()
        path = self.base / "packet-capture.pcap"
        path.write_bytes(pcap(frames[:-4]))
        instance.capture = Mock()
        instance.capture.poll.return_value = None
        with patch.object(lab.time, "monotonic", side_effect=[0, 6]):
            with self.assertRaisesRegex(RuntimeError, "deadline expired"):
                instance.stop_capture()
        instance.capture.send_signal.assert_not_called()
        path.write_bytes(pcap(frames))
        def close_capture(**options):
            path.write_bytes(pcap(frames[:-4]))
            return 0
        instance.capture.wait.side_effect = close_capture
        with self.assertRaisesRegex(lab.CaptureIncomplete, "repaired"):
            instance.stop_capture()
        instance.capture.wait.assert_called_once_with(timeout=10)

    def test_capture_start_uses_owned_router_exact_scope_and_immediate_mode(self):
        instance = self.make_lab()
        instance.created_names = [instance.names["router"]]
        process = Mock()
        process.poll.return_value = None
        def spawn(arguments, **options):
            options["stderr"].write(b"listening on lan0\n")
            return process
        try:
            with patch.object(lab.subprocess, "Popen", side_effect=spawn) as popen:
                instance.start_capture()
            arguments = popen.call_args.args[0]
            self.assertEqual(arguments[:4], [TOOLS["ip"], "netns", "exec", instance.names["router"]])
            self.assertIn("--immediate-mode", arguments)
            self.assertEqual(arguments[-1], lab.CAPTURE_FILTER)
            self.assertEqual(arguments[arguments.index("-i") + 1], "lan0")
            self.assertIn("udp port 53", arguments[-1])
        finally:
            for handle in instance.handles:
                handle.close()

    def test_source_provenance_rejects_modified_helper(self):
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
        self.assertEqual(set(identity["source_sha256"]), set(lab.SOURCE_FILES))
        (root / "scripts/network_services_protocol.py").write_text("# altered\n")
        with self.assertRaisesRegex(RuntimeError, "differs"):
            lab.source_identity(root, {})

    def test_cleanup_failure_prevents_publication(self):
        output = self.base / "failed"
        with patch.object(lab.base, "preflight", return_value=TOOLS.copy()), patch.object(lab.shutil, "which", return_value="/tools/openssl"), \
                patch.object(lab, "source_identity", return_value={"commit": "a" * 40}), \
                patch.object(lab, "run_exercise", return_value={}), \
                patch.object(lab.ServicesLab, "cleanup", side_effect=RuntimeError("private PKI remains")):
            with self.assertRaisesRegex(RuntimeError, "private PKI remains"):
                lab.run(output)
        self.assertFalse((output / "publish").exists())
        self.assertFalse(json.loads((output / "staging/REPORT.json").read_text())["ok"])

    def test_success_publishes_eight_fixed_files_with_no_private_fixture(self):
        output = self.base / "success"
        def exercise(instance):
            instance.certificates = metadata()
            (instance.staging / "packet-capture.pcap").write_bytes(b"unit-test fixture")
            (instance.staging / "packet-capture.txt").write_text("unit-test fixture")
            (instance.staging / "service.stderr").write_text("not for publication")
            return {"unit_test_fixture": True}
        with patch.object(lab.base, "preflight", return_value=TOOLS.copy()), patch.object(lab.shutil, "which", return_value="/tools/openssl"), \
                patch.object(lab, "source_identity", return_value={"commit": "a" * 40}), \
                patch.object(lab, "run_exercise", side_effect=exercise), \
                patch.object(lab.ServicesLab, "cleanup", return_value={"ok": True, "private_pki_deleted": True}):
            self.assertTrue(lab.run(output)["ok"])
        publish = output / "publish"
        self.assertEqual({path.name for path in publish.iterdir()}, {*lab.PUBLIC_FILES, "MANIFEST.json"})
        manifest = json.loads((publish / "MANIFEST.json").read_text())
        self.assertEqual(len(manifest), 7)
        for name, digest in manifest.items():
            self.assertEqual(hashlib.sha256((publish / name).read_bytes()).hexdigest(), digest)
            self.assertNotIn(b"PRIVATE KEY", (publish / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
