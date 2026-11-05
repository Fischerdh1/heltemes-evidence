"""Validate scoped packet evidence on both sides of a three-zone lab router."""
from __future__ import annotations

import socket
import struct

from scripts.network_lab import CaptureIncomplete, require

ZONES = {"user": "10.204.10.2", "app": "10.204.20.2", "management": "10.204.30.2"}
PORTS = (8080, 9090)
SNAPLEN = 512
MAX_CAPTURE_BYTES = 4 * 1024 * 1024


def capture_filter(role):
    require(role in ZONES, "Unknown segmentation capture interface role.")
    others = " or ".join("host " + address for other, address in ZONES.items() if other != role)
    return f"host {ZONES[role]} and ({others}) and tcp and (port 8080 or port 9090)"


def pcap_packets(raw, role):
    """Parse bounded Ethernet/IPv4/TCP records from one exact zone interface.

    Header and payload truncation while a capture is running is distinguished
    from invalid traffic. TCP payload may be snaplen-limited; this validates
    the recorded header and captured bytes, not TCP checksums or reassembly.
    """
    require(role in ZONES, "Unknown segmentation capture interface role.")
    require(isinstance(raw, bytes) and len(raw) < MAX_CAPTURE_BYTES,
            "Segmentation capture exceeds its bound or is not bytes.")
    if len(raw) < 24:
        raise CaptureIncomplete("Segmentation capture header is incomplete for " + role)
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
               b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000)}
    require(raw[:4] in formats, "Segmentation capture magic is unsupported.")
    endian, precision = formats[raw[:4]]
    major, minor, zone, accuracy, snaplen, link_type = struct.unpack(endian + "HHiIII", raw[4:24])
    require((major, minor, snaplen, link_type) == (2, 4, SNAPLEN, 1),
            "Segmentation capture format is unexpected.")
    position, packets = 24, []
    while position < len(raw):
        if len(raw) - position < 16:
            raise CaptureIncomplete("Segmentation packet record header is incomplete for " + role)
        seconds, fraction, size, original = struct.unpack(endian + "IIII", raw[position:position + 16])
        require(fraction < precision and 54 <= size <= SNAPLEN and size <= original <= 65549,
                "Segmentation capture record lengths or timestamp are malformed.")
        position += 16
        if len(raw) - position < size:
            raise CaptureIncomplete("Segmentation packet record body is incomplete for " + role)
        frame = raw[position:position + size]
        position += size
        require(frame[12:14] == b"\x08\x00", "Segmentation capture contains non-IPv4 traffic.")
        ip = frame[14:]
        header = (ip[0] & 15) * 4
        total = struct.unpack("!H", ip[2:4])[0]
        fragment = struct.unpack("!H", ip[6:8])[0]
        require(ip[0] >> 4 == 4 and header >= 20 and len(ip) >= header + 20
                and header + 20 <= total <= original - 14 and fragment & 0xbfff == 0 and ip[9] == 6,
                "Segmentation capture contains malformed, fragmented, or non-TCP IPv4 traffic.")
        source, destination = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        require(source != destination and source in ZONES.values() and destination in ZONES.values(),
                "Segmentation capture contains an out-of-scope address.")
        require(ZONES[role] in (source, destination),
                "Segmentation capture contains a flow on the wrong zone interface.")
        tcp = ip[header:min(total, len(ip))]
        source_port, destination_port = struct.unpack("!HH", tcp[:4])
        require((source_port in PORTS) != (destination_port in PORTS),
                "Segmentation capture contains an unexpected service/source port pair.")
        tcp_header = (tcp[12] >> 4) * 4
        require(20 <= tcp_header <= len(tcp) and header + tcp_header <= total,
                "Segmentation capture contains a malformed TCP header.")
        packets.append({"source": source, "destination": destination,
                        "source_port": source_port, "destination_port": destination_port,
                        "flags": tcp[13], "payload_bytes": len(tcp) - tcp_header})
    return packets


def validate_captures(captures, probes):
    """Require evidence at source and destination for every routed probe.

    A permitted request needs both observations. A blocked request needs its
    source SYN and must have neither a source reply nor destination traffic.
    Counts are interface observations, not deduplicated end-to-end packets.
    """
    require(isinstance(captures, dict) and set(captures) == set(ZONES),
            "Segmentation evidence requires exactly three zone captures.")
    packets_by_role = {role: pcap_packets(captures[role], role) for role in ZONES}
    require(isinstance(probes, list), "Segmentation probes must be a recorded list.")
    routed, ports, lookup = [], set(), {}
    for probe in probes:
        require(isinstance(probe, dict) and probe.get("from") in ZONES and probe.get("to") in ZONES,
                "Segmentation probe has an unknown zone.")
        if probe["from"] == probe["to"]:
            continue
        require(probe.get("destination") == ZONES[probe["to"]] and probe.get("port") in PORTS
                and isinstance(probe.get("source_port"), int) and not isinstance(probe["source_port"], bool)
                and 1024 <= probe["source_port"] <= 65535 and probe["source_port"] not in PORTS
                and isinstance(probe.get("phase"), str) and bool(probe["phase"])
                and probe.get("outcome") in ("response", "connect_timeout"),
                "Segmentation probe metadata is invalid or has an unsuccessful outcome.")
        require(probe["source_port"] not in ports, "Segmentation probe source ports must be globally unique.")
        ports.add(probe["source_port"])
        key = (ZONES[probe["from"]], probe["source_port"], ZONES[probe["to"]], probe["port"])
        reverse = (key[2], key[3], key[0], key[1])
        index = len(routed)
        lookup[key], lookup[reverse] = (index, "outgoing"), (index, "incoming")
        routed.append(probe)
    require(bool(routed), "Segmentation capture verification requires routed probes.")
    observations = [{role: {"outgoing": [], "incoming": []} for role in ZONES} for probe in routed]
    for role, packets in packets_by_role.items():
        for packet in packets:
            key = (packet["source"], packet["source_port"], packet["destination"], packet["destination_port"])
            require(key in lookup, "Segmentation capture contains an unrecorded flow.")
            index, direction = lookup[key]
            observations[index][role][direction].append(packet)
    summary = []
    for index, probe in enumerate(routed):
        source = observations[index][probe["from"]]
        destination = observations[index][probe["to"]]
        label = f"{probe['phase']} {probe['from']}->{probe['to']} TCP{probe['port']} source {probe['source_port']}"
        if probe["outcome"] == "connect_timeout":
            require(not source["incoming"], "A denied segmentation probe has a reply at its source: " + label)
            require(not destination["outgoing"] and not destination["incoming"],
                    "A denied segmentation probe reached the destination interface: " + label)
        if not any(packet["flags"] & 0x16 == 0x02 for packet in source["outgoing"]):
            raise CaptureIncomplete("Segmentation capture lacks the source SYN for " + label)
        if probe["outcome"] == "response":
            for role, observed in ((probe["from"], source), (probe["to"], destination)):
                if not (any(packet["flags"] & 0x16 == 0x02 for packet in observed["outgoing"])
                        and any(packet["flags"] & 0x16 == 0x12 for packet in observed["incoming"])
                        and any(packet["payload_bytes"] > 0 for packet in observed["incoming"])):
                    raise CaptureIncomplete("Segmentation capture lacks a handshake or server payload on " + role + " for " + label)
        def counts(role, observed):
            return {"role": role, "outgoing_packets": len(observed["outgoing"]),
                    "incoming_packets": len(observed["incoming"]),
                    "incoming_payload_bytes": sum(packet["payload_bytes"] for packet in observed["incoming"])}
        summary.append({"phase": probe["phase"], "from": probe["from"], "to": probe["to"],
                        "port": probe["port"], "source_port": probe["source_port"], "outcome": probe["outcome"],
                        "source_interface": counts(probe["from"], source),
                        "destination_interface": counts(probe["to"], destination),
                        "destination_reached": bool(destination["outgoing"] or destination["incoming"])})
    counts_by_role = {role: len(packets) for role, packets in packets_by_role.items()}
    return {"ok": True, "routed_flows_verified": len(routed), "capture_packet_counts": counts_by_role,
            "packet_observations": sum(counts_by_role.values()),
            "packet_count_semantics": "Separate interface observations; forwarded packets appear on two interfaces and are not deduplicated.",
            "flows": summary}
