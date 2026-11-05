"""Inert packet-fixture regressions for multi-interface segmentation evidence."""
import copy
import socket
import struct
import unittest

from scripts import network_segmentation_capture as capture


def packet(probe, *, incoming=False, flags=0x02, payload=b"", source_ip=None):
    source, destination = capture.ZONES[probe["from"]], capture.ZONES[probe["to"]]
    source_port, destination_port = probe["source_port"], probe["port"]
    if incoming:
        source, destination = destination, source
        source_port, destination_port = destination_port, source_port
    tcp = struct.pack("!HHIIBBHHH", source_port, destination_port, 0, 0, 0x50, flags, 65535, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0,
                     socket.inet_aton(source_ip or source), socket.inet_aton(destination))
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp


def pcap(frames, *, endian="<", nano=False):
    magic = {(True, False): b"\xd4\xc3\xb2\xa1", (False, False): b"\xa1\xb2\xc3\xd4",
             (True, True): b"\x4d\x3c\xb2\xa1", (False, True): b"\xa1\xb2\x3c\x4d"}[(endian == "<", nano)]
    result = magic + struct.pack(endian + "HHiIII", 2, 4, 0, 0, 512, 1)
    for frame in frames:
        clipped = frame[:512]
        result += struct.pack(endian + "IIII", 1, 1, len(clipped), len(frame)) + clipped
    return result


def fixture():
    intended = {("user", "app", 8080), ("management", "app", 8080), ("management", "app", 9090)}
    matrix = [(source, destination, port) for source in capture.ZONES for destination in capture.ZONES
              if source != destination for port in (8080, 9090)]
    specifications = [("baseline", row, "response") for row in matrix]
    specifications += [("restricted", row, "response" if row in intended else "connect_timeout") for row in matrix]
    specifications += [("misconfigured", ("user", "app", 9090), "response")]
    specifications += [("repaired", row, "response" if row in intended else "connect_timeout") for row in matrix]
    probes, frames = [], {role: [] for role in capture.ZONES}
    for index, (phase, row, outcome) in enumerate(specifications):
        source, destination, port = row
        probe = {"phase": phase, "from": source, "to": destination,
                 "destination": capture.ZONES[destination], "port": port,
                 "source_port": 40000 + index, "outcome": outcome}
        probes.append(probe)
        if outcome == "response":
            flow = [packet(probe), packet(probe, incoming=True, flags=0x12),
                    packet(probe, flags=0x18, payload=b"GET /synthetic HTTP/1.1\r\n\r\n"),
                    packet(probe, incoming=True, flags=0x18, payload=b"HTTP/1.0 200 OK\r\n\r\nsynthetic")]
            frames[source].extend(flow)
            frames[destination].extend(flow)
        else:
            frames[source].extend([packet(probe), packet(probe)])
    return probes, frames


def raw_captures(frames):
    return {role: pcap(packets) for role, packets in frames.items()}


def omit_flow(frames, probe):
    return [frame for frame in frames if probe["source_port"] not in struct.unpack("!HH", frame[34:38])]


class SegmentationCaptureTests(unittest.TestCase):
    def setUp(self):
        self.probes, self.frames = fixture()

    def validate(self):
        return capture.validate_captures(raw_captures(self.frames), self.probes)

    def denied(self):
        return next(probe for probe in self.probes if probe["outcome"] == "connect_timeout")

    def test_filters_are_exact_for_each_router_zone_interface(self):
        self.assertEqual(capture.capture_filter("user"),
                         "host 10.204.10.2 and (host 10.204.20.2 or host 10.204.30.2) and tcp and (port 8080 or port 9090)")
        for role, address in capture.ZONES.items():
            value = capture.capture_filter(role)
            self.assertTrue(value.startswith("host " + address + " and ("))
            self.assertNotIn("any", value)
            for other in capture.ZONES.values():
                self.assertEqual(value.count("host " + other), 1)
        with self.assertRaisesRegex(RuntimeError, "Unknown"):
            capture.capture_filter("host")

    def test_all_37_flows_have_distinct_source_and_destination_observations(self):
        result = self.validate()
        self.assertTrue(result["ok"])
        self.assertEqual(result["routed_flows_verified"], 37)
        self.assertEqual(len([row for row in result["flows"] if row["destination_reached"]]), 19)
        self.assertEqual(len([row for row in result["flows"] if not row["destination_reached"]]), 18)
        self.assertEqual(result["capture_packet_counts"], {role: len(rows) for role, rows in self.frames.items()})
        self.assertEqual(result["packet_observations"], 19 * 8 + 18 * 2)
        self.assertIn("not deduplicated", result["packet_count_semantics"])
        for row in result["flows"]:
            self.assertEqual(row["source_interface"]["role"], row["from"])
            self.assertEqual(row["destination_interface"]["role"], row["to"])
            if row["outcome"] == "connect_timeout":
                self.assertEqual(row["source_interface"]["incoming_packets"], 0)
                self.assertEqual(row["destination_interface"]["outgoing_packets"], 0)
                self.assertEqual(row["destination_interface"]["incoming_packets"], 0)

    def test_missing_final_repaired_flow_is_incomplete(self):
        last = self.probes[-1]
        for role in (last["from"], last["to"]):
            self.frames[role] = omit_flow(self.frames[role], last)
        with self.assertRaisesRegex(capture.CaptureIncomplete, "repaired.*40036"):
            self.validate()

    def test_allowed_flow_needs_the_destination_observation(self):
        first = self.probes[0]
        self.frames[first["to"]] = omit_flow(self.frames[first["to"]], first)
        with self.assertRaisesRegex(capture.CaptureIncomplete, "on app.*baseline"):
            self.validate()

    def test_allowed_flow_needs_handshake_and_payload_on_each_interface(self):
        first = self.probes[0]
        for role in (first["from"], first["to"]):
            for replacement in ([packet(first)], [packet(first), packet(first, incoming=True, flags=0x12)]):
                with self.subTest(role=role, count=len(replacement)):
                    frames = copy.deepcopy(self.frames)
                    frames[role] = omit_flow(frames[role], first) + replacement
                    with self.assertRaises(capture.CaptureIncomplete):
                        capture.validate_captures(raw_captures(frames), self.probes)

    def test_denial_needs_its_source_syn(self):
        probe = self.denied()
        self.frames[probe["from"]] = omit_flow(self.frames[probe["from"]], probe)
        with self.assertRaisesRegex(capture.CaptureIncomplete, "source SYN"):
            self.validate()

    def test_denied_flow_reaching_destination_is_a_hard_failure(self):
        probe = self.denied()
        self.frames[probe["to"]].append(packet(probe))
        with self.assertRaisesRegex(RuntimeError, "reached the destination") as raised:
            self.validate()
        self.assertNotIsInstance(raised.exception, capture.CaptureIncomplete)

    def test_denied_reply_at_source_is_a_hard_failure(self):
        probe = self.denied()
        self.frames[probe["from"]].append(packet(probe, incoming=True, flags=0x14))
        with self.assertRaisesRegex(RuntimeError, "reply at its source"):
            self.validate()

    def test_third_zone_cannot_claim_another_pair_traffic(self):
        self.frames["management"].append(packet(self.probes[0]))
        with self.assertRaisesRegex(RuntimeError, "wrong zone interface"):
            self.validate()

    def test_missing_or_extra_capture_is_not_treated_as_an_empty_interface(self):
        raw = raw_captures(self.frames)
        for change in ({key: value for key, value in raw.items() if key != "app"}, {**raw, "host": pcap([])}):
            with self.assertRaisesRegex(RuntimeError, "exactly three"):
                capture.validate_captures(change, self.probes)
        with self.assertRaises(capture.CaptureIncomplete):
            capture.validate_captures({**raw, "app": pcap([])}, self.probes)

    def test_unrecorded_flow_and_unrelated_address_are_rejected(self):
        first = self.probes[0]
        for frame in (packet({**first, "source_port": 49999}), packet(first, source_ip="192.0.2.2")):
            with self.subTest(frame=frame.hex()):
                frames = copy.deepcopy(self.frames)
                frames["user"].append(frame)
                with self.assertRaisesRegex(RuntimeError, "unrecorded|out-of-scope"):
                    capture.validate_captures(raw_captures(frames), self.probes)

    def test_probe_metadata_and_source_port_reuse_are_rejected(self):
        invalid_updates = ({"source_port": self.probes[1]["source_port"]}, {"source_port": 8080},
                           {"source_port": True}, {"destination": "192.0.2.2"}, {"port": 22},
                           {"outcome": "read_timeout"}, {"from": "host"}, {"phase": ""})
        for updates in invalid_updates:
            probes = copy.deepcopy(self.probes)
            probes[0].update(updates)
            with self.subTest(updates=updates), self.assertRaises(RuntimeError):
                capture.validate_captures(raw_captures(self.frames), probes)

    def test_local_health_probes_are_excluded_from_routed_capture(self):
        self.probes.append({"from": "app", "to": "app", "outcome": "response"})
        self.assertEqual(self.validate()["routed_flows_verified"], 37)
        with self.assertRaisesRegex(RuntimeError, "requires routed probes"):
            capture.validate_captures({role: pcap([]) for role in capture.ZONES}, [self.probes[-1]])

    def test_incomplete_live_record_is_distinguished_from_invalid_format(self):
        raw = pcap([packet(self.probes[0])])
        for value in (b"", raw[:20], raw[:25], raw[:-1]):
            with self.subTest(size=len(value)), self.assertRaises(capture.CaptureIncomplete):
                capture.pcap_packets(value, "user")
        for value in (b"INVALID" + raw[7:], raw[:20] + struct.pack("<I", 113) + raw[24:],
                      raw[:16] + struct.pack("<I", 2048) + raw[20:]):
            with self.assertRaises(RuntimeError) as raised:
                capture.pcap_packets(value, "user")
            self.assertNotIsInstance(raised.exception, capture.CaptureIncomplete)

    def test_fragment_non_tcp_bad_lengths_and_bad_ports_are_rejected(self):
        original = packet(self.probes[0])
        changes = ((12, b"\x81\x00"), (14, b"\x65"), (16, b"\x00\x01"),
                   (20, b"\x20\x00"), (20, b"\x80\x00"), (23, b"\x11"),
                   (34, struct.pack("!HH", 8080, 9090)), (36, struct.pack("!H", 443)), (46, b"\xf0"))
        for offset, replacement in changes:
            frame = original[:offset] + replacement + original[offset + len(replacement):]
            with self.subTest(offset=offset, replacement=replacement.hex()), self.assertRaises(RuntimeError):
                capture.pcap_packets(pcap([frame]), "user")

    def test_endian_and_timestamp_precisions_preserve_flow_evidence(self):
        for endian in ("<", ">"):
            for nano in (False, True):
                with self.subTest(endian=endian, nano=nano):
                    raw = {role: pcap(frames, endian=endian, nano=nano) for role, frames in self.frames.items()}
                    self.assertEqual(capture.validate_captures(raw, self.probes)["routed_flows_verified"], 37)

    def test_snaplen_limited_payload_has_complete_headers_and_bounded_count(self):
        frame = packet(self.probes[0], incoming=True, flags=0x18, payload=b"x" * 1000)
        packets = capture.pcap_packets(pcap([frame]), "user")
        self.assertEqual(packets[0]["payload_bytes"], 512 - 14 - 20 - 20)
        self.assertLess(packets[0]["payload_bytes"], 1000)


if __name__ == "__main__":
    unittest.main()
