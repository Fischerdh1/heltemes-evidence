"""Exercise synthetic DNS resolution and strict TLS identity checks in Linux namespaces."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_lab as base
from scripts import network_services_protocol as protocol

CLIENT, SERVER = base.CLIENT, base.SERVER
HOSTNAME, DNS_PORT, TLS_PORT = protocol.HOSTNAME, protocol.DNS_PORT, protocol.TLS_PORT
SNAPLEN = 2048
CAPTURE_FILTER = f"host {CLIENT} and host {SERVER} and ((udp port {DNS_PORT}) or (tcp port {TLS_PORT}))"
SOURCE_FILES = (*base.SOURCE_FILES, "scripts/network_services_lab.py", "scripts/network_services_protocol.py")
PUBLIC_FILES = ("REPORT.json", "packet-capture.pcap", "packet-capture.txt", "policy.nft",
                "blocked-policy.nft", "certificates.json", "SUMMARY.md")
PUBLIC_CERTIFICATE_FIELDS = ("synthetic_only", "server_hostname", "configured_validity_days", "trusted_ca_sha256",
                             "untrusted_ca_sha256", "server_certificate_sha256", "public_certificates_pem", "server_certificate_details")
require, timestamp, CaptureIncomplete = base.require, base.timestamp, base.CaptureIncomplete


def source_identity(root=ROOT, environment=None):
    root = Path(root).resolve()
    identity = base.source_identity(root, environment)
    for name in SOURCE_FILES[len(base.SOURCE_FILES):]:
        content = (root / name).read_bytes()
        result = subprocess.run(["git", "-c", f"safe.directory={root}", "-C", str(root),
                                 "show", f"{identity['commit']}:{name}"], capture_output=True, timeout=30)
        require(result.returncode == 0 and content == result.stdout,
                "DNS/TLS lab source differs from its committed version.")
        identity["source_sha256"][name] = hashlib.sha256(content).hexdigest()
    return identity


def policy_text(blocked=False):
    deny = f"ip saddr {CLIENT} ip daddr {SERVER} tcp dport {TLS_PORT} counter name tls_denied drop" if blocked else ""
    return f"""flush ruleset
table inet heltemes_services {{
    counter dns_allowed {{ }}
    counter tls_allowed {{ }}
    counter tls_denied {{ }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
        {deny}
        ct state established,related accept
        ip saddr {CLIENT} ip daddr {SERVER} udp dport {DNS_PORT} counter name dns_allowed accept
        ip saddr {CLIENT} ip daddr {SERVER} tcp dport {TLS_PORT} counter name tls_allowed accept
    }}
}}
"""


def require_dns(probe, *, missing=False):
    if missing:
        require(probe.get("outcome") == "nxdomain" and probe.get("rcode") == 3 and "address" not in probe,
                "The unknown synthetic DNS name did not return validated NXDOMAIN.")
    else:
        require(probe.get("outcome") == "response" and probe.get("rcode") == 0 and probe.get("address") == SERVER,
                "The synthetic DNS name did not resolve to the expected lab server.")


def require_tls(probe, fingerprint):
    require(probe.get("outcome") == "response" and probe.get("status") == 200
            and probe.get("payload") == {"synthetic": True, "service": "tls", "hostname": HOSTNAME}
            and probe.get("peer_certificate_sha256") == fingerprint,
            "Strict trusted TLS did not return the expected service and leaf certificate.")


def require_certificate_rejection(probe, cause):
    codes = {"hostname": {62}, "untrusted_ca": {20, 21}}
    require(probe.get("outcome") == "certificate_error" and probe.get("verify_code") in codes[cause],
            f"TLS did not reject the intended {cause} mismatch with the expected verification cause.")


def public_certificates(metadata):
    require(set(PUBLIC_CERTIFICATE_FIELDS).issubset(metadata), "Public certificate metadata is incomplete.")
    result = {name: metadata[name] for name in PUBLIC_CERTIFICATE_FIELDS}
    require(result["synthetic_only"] is True and result["server_hostname"] == HOSTNAME,
            "Certificate metadata is outside the synthetic fixture.")
    require(set(result["public_certificates_pem"]) == {"ca", "untrusted-ca", "server"}
            and all("-----BEGIN CERTIFICATE-----" in value for value in result["public_certificates_pem"].values())
            and "PRIVATE KEY" not in json.dumps(result), "Public certificate metadata contains unexpected key material.")
    require(result["trusted_ca_sha256"] != result["untrusted_ca_sha256"], "The unrelated trust anchor is not distinct.")
    return result


def pcap_packets(raw):
    """Parse only bounded Ethernet/IPv4 UDP-DNS or TCP-TLS capture records."""
    require(len(raw) < 8 * 1024 * 1024, "Service capture exceeds its bound.")
    if len(raw) < 24:
        raise CaptureIncomplete("Service capture header is incomplete.")
    formats = {b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
               b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000)}
    require(raw[:4] in formats, "Service capture magic is unsupported.")
    endian, precision = formats[raw[:4]]
    major, minor, zone, accuracy, snaplen, link_type = struct.unpack(endian + "HHiIII", raw[4:24])
    require((major, minor, snaplen, link_type) == (2, 4, SNAPLEN, 1), "Service capture format is unexpected.")
    position, packets = 24, []
    while position < len(raw):
        if len(raw) - position < 16:
            raise CaptureIncomplete("Service packet record header is incomplete.")
        seconds, fraction, size, original = struct.unpack(endian + "IIII", raw[position:position + 16])
        require(fraction < precision and 42 <= size <= SNAPLEN and size <= original <= 65549,
                "Service capture record is malformed.")
        position += 16
        if len(raw) - position < size:
            raise CaptureIncomplete("Service packet record body is incomplete.")
        frame = raw[position:position + size]
        position += size
        require(frame[12:14] == b"\x08\x00", "Service capture contains non-IPv4 traffic.")
        ip = frame[14:]
        header, total = (ip[0] & 15) * 4, struct.unpack("!H", ip[2:4])[0]
        fragment = struct.unpack("!H", ip[6:8])[0]
        require(ip[0] >> 4 == 4 and header >= 20 and header + 8 <= min(total, len(ip))
                and total <= original - 14 and fragment & 0x3fff == 0 and ip[9] in (6, 17),
                "Service capture contains malformed or unexpected IPv4 traffic.")
        source, destination = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        require({source, destination} == {CLIENT, SERVER}, "Service capture contains an out-of-scope address.")
        segment = ip[header:total]
        source_port, destination_port = struct.unpack("!HH", segment[:4])
        service_port = destination_port if source == CLIENT else source_port
        transport = "udp" if ip[9] == 17 else "tcp"
        packet = {"source": source, "source_port": source_port, "destination_port": destination_port,
                  "transport": transport}
        if transport == "udp":
            length = struct.unpack("!H", segment[4:6])[0]
            require(service_port == DNS_PORT and 8 <= length == total - header <= len(segment),
                    "Service capture contains malformed or out-of-scope UDP traffic.")
            packet["payload"] = segment[8:length]
        else:
            require(service_port == TLS_PORT and len(segment) >= 20, "Service capture contains out-of-scope or malformed TCP traffic.")
            tcp_header = (segment[12] >> 4) * 4
            require(20 <= tcp_header <= len(segment) and header + tcp_header <= total,
                    "Service capture contains a malformed TCP header.")
            packet.update(flags=segment[13], payload_bytes=len(segment) - tcp_header)
        packets.append(packet)
    return packets


def validate_capture(raw, probes):
    packets = pcap_packets(raw)
    clients = [probe for probe in probes if probe["from"] == "client"]
    expected = {(probe["transport"], probe["source_port"], probe["port"]): probe for probe in clients}
    require(bool(clients) and len(expected) == len(clients)
            and len({probe["source_port"] for probe in clients}) == len(clients),
            "Service capture requires unique client probe source ports.")
    flows = {key: {"outgoing": [], "incoming": []} for key in expected}
    for packet in packets:
        outgoing = packet["source"] == CLIENT
        key = (packet["transport"], packet["source_port"] if outgoing else packet["destination_port"],
               packet["destination_port"] if outgoing else packet["source_port"])
        require(key in expected, "Service capture contains an unrecorded client flow.")
        flows[key]["outgoing" if outgoing else "incoming"].append(packet)
    summary = []
    for key, probe in expected.items():
        outgoing, incoming = flows[key]["outgoing"], flows[key]["incoming"]
        label = f"{probe['phase']} {probe['transport']} source {probe['source_port']}"
        if probe["transport"] == "udp":
            if not outgoing or not incoming:
                raise CaptureIncomplete("Service capture lacks a DNS query or response for " + label)
            for packet in outgoing:
                query = protocol.parse_dns_query(packet["payload"])
                require(query["transaction_id"] == probe["transaction_id"] and query["name"] == probe["name"],
                        "Captured DNS query differs from the recorded probe.")
            for packet in incoming:
                response = protocol.parse_dns_response(packet["payload"], probe["transaction_id"], probe["name"])
                require(response["outcome"] == probe["outcome"] and response["rcode"] == probe["rcode"]
                        and response.get("address") == probe.get("address"), "Captured DNS response differs from the recorded probe.")
        else:
            if not any(packet["flags"] & 0x12 == 0x02 for packet in outgoing):
                raise CaptureIncomplete("Service capture lacks an outgoing TCP SYN for " + label)
            require(probe["outcome"] in ("response", "certificate_error", "connect_timeout"), "Unexpected captured TLS probe outcome.")
            if probe["outcome"] == "connect_timeout":
                require(not incoming, "A firewall-denied TLS probe has incoming server traffic.")
            elif not (any(packet["flags"] & 0x12 == 0x12 for packet in incoming)
                      and any(packet["payload_bytes"] > 0 for packet in outgoing)
                      and any(packet["payload_bytes"] > 0 for packet in incoming)):
                raise CaptureIncomplete("Service capture lacks a TCP handshake or bidirectional TLS bytes for " + label)
        summary.append({"phase": probe["phase"], "transport": probe["transport"], "port": probe["port"],
                        "source_port": probe["source_port"], "outcome": probe["outcome"],
                        "outgoing_packets": len(outgoing), "incoming_packets": len(incoming)})
    return {"ok": True, "packet_count": len(packets), "client_flows_verified": len(summary), "flows": summary,
            "tls_identity_decision_source": "strict TLS client; packet capture verifies connectivity, not certificate acceptance"}


class ServicesLab(base.NamespaceLab):
    def __init__(self, tools, staging):
        super().__init__(tools, staging)
        self.private_root = staging / "private-pki"
        self.pki = self.private_root / "certificates"
        self.pki_owned = False
        self.certificates = None

    def create_certificates(self):
        # Exclusive parent creation records ownership before any key generation;
        # partial generation can be cleaned without adopting an existing path.
        self.private_root.mkdir(mode=0o700)
        self.pki_owned = True
        self.certificates = public_certificates(protocol.create_pki(self.pki, self.tools["openssl"]))

    def probe_service(self, role, kind, *, name=HOSTNAME, hostname=HOSTNAME, trust="trusted", record=True):
        require(role in ("client", "server") and kind in ("dns", "tls") and trust in ("trusted", "untrusted"),
                "Service probe is outside the fixed lab scope.")
        source_port = self.next_source_port
        self.next_source_port += 1
        require(source_port < 50000, "Fresh service probe port range is exhausted.")
        arguments = [sys.executable, "-I", "-S", "-B", str(ROOT / "scripts/network_services_protocol.py"), kind]
        if kind == "dns":
            arguments.extend(["--name", name])
        else:
            ca = "ca.pem" if trust == "trusted" else "untrusted-ca.pem"
            arguments.extend(["--address", SERVER, "--hostname", hostname, "--ca", str(self.pki / ca)])
        arguments.extend(["--source-port", str(source_port)])
        started = timestamp()
        result = json.loads(self.run_in(role, arguments).stdout)
        require(result.get("source_port") == source_port, "Service probe source-port provenance differs.")
        result.update({"from": role, "destination": SERVER, "transport": "udp" if kind == "dns" else "tcp",
                       "port": DNS_PORT if kind == "dns" else TLS_PORT, "phase": self.phase,
                       "started_at_utc": started, "completed_at_utc": timestamp()})
        if kind == "tls":
            result.update(hostname=hostname, trust=trust)
        if record:
            self.probes.append(result)
        return result

    def start_services(self):
        errors = (self.staging / "service.stderr").open("wb")
        self.handles.append(errors)
        command = [sys.executable, "-I", "-S", "-B", str(ROOT / "scripts/network_services_protocol.py"),
                   "serve", "--pki", str(self.pki)]
        process = subprocess.Popen(self.namespace_command("server", command), stdout=subprocess.DEVNULL, stderr=errors)
        self.processes.append(process)
        for _ in range(40):
            require(process.poll() is None, "Synthetic DNS/TLS services exited before readiness.")
            dns = self.probe_service("server", "dns", record=False)
            tls = self.probe_service("server", "tls", record=False)
            if dns.get("outcome") == "response" and tls.get("outcome") == "response":
                require_dns(dns)
                require_tls(tls, self.certificates["server_certificate_sha256"])
                return
            time.sleep(0.1)
        raise RuntimeError("Synthetic DNS/TLS services did not become ready.")

    def apply_policy(self, blocked=False):
        self.run_in("router", [self.tools["nft"], "-f", "-"], input=policy_text(blocked))

    def counters(self):
        result = json.loads(self.run_in("router", [self.tools["nft"], "-j", "list", "table", "inet", "heltemes_services"]).stdout)
        counters = {entry["counter"]["name"]: entry["counter"]["packets"] for entry in result["nftables"] if "counter" in entry}
        require(set(counters) == {"dns_allowed", "tls_allowed", "tls_denied"}, "Named service firewall counters are missing.")
        return counters

    def start_capture(self):
        packets = (self.staging / "packet-capture.pcap").open("wb", buffering=0)
        errors = (self.staging / "capture.stderr").open("wb", buffering=0)
        self.handles.extend((packets, errors))
        command = [self.tools["tcpdump"], "-n", "-i", "lan0", "--immediate-mode", "-U", "-s", str(SNAPLEN),
                   "-c", "2000", "-w", "-", CAPTURE_FILTER]
        self.capture = subprocess.Popen(self.namespace_command("router", command), stdout=packets, stderr=errors)
        self.processes.append(self.capture)
        for _ in range(50):
            require(self.capture.poll() is None, "Service capture exited before readiness.")
            if b"listening on" in (self.staging / "capture.stderr").read_bytes():
                return
            time.sleep(0.1)
        raise RuntimeError("Service capture did not become ready.")

    def stop_capture(self):
        path = self.staging / "packet-capture.pcap"
        deadline = time.monotonic() + 5
        while True:
            require(self.capture is not None and self.capture.poll() is None, "Service capture ended unexpectedly.")
            try:
                validate_capture(path.read_bytes(), self.probes)
                break
            except CaptureIncomplete as error:
                require(time.monotonic() < deadline, "Service capture deadline expired: " + str(error))
                time.sleep(0.05)
        self.capture.send_signal(signal.SIGINT)
        require(self.capture.wait(timeout=10) == 0, "Service capture did not close successfully.")
        verification = validate_capture(path.read_bytes(), self.probes)
        decoded = self.command([self.tools["tcpdump"], "-nn", "-tt", "-r", str(path)]).stdout
        (self.staging / "packet-capture.txt").write_text(decoded)
        return verification

    def cleanup(self):
        errors, result = [], {}
        try:
            result = super().cleanup()
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            errors.append(str(error))
        try:
            require(all(process.poll() is not None for process in self.processes), "Private PKI cannot be removed while a lab child is running.")
            if self.pki_owned and self.private_root.exists():
                require(not self.private_root.is_symlink(), "Private PKI cleanup refuses a substituted symbolic link.")
                shutil.rmtree(self.private_root)
            require(not self.pki_owned or (not self.private_root.exists() and not self.private_root.is_symlink()), "Owned private PKI remains after cleanup.")
            result["private_pki_deleted"] = True
        except (OSError, RuntimeError) as error:
            errors.append(str(error))
        require(not errors, " ".join(errors))
        return result


def resolve_then_tls(lab, name=HOSTNAME):
    dns = lab.probe_service("client", "dns", name=name)
    if name == "unknown.test":
        require_dns(dns, missing=True)
        return {"dns": dns, "tls_attempted": False}
    require_dns(dns)
    tls = lab.probe_service("client", "tls")
    require_tls(tls, lab.certificates["server_certificate_sha256"])
    return {"dns": dns, "tls_attempted": True, "tls": tls}


def run_exercise(lab):
    lab.setup()
    lab.create_certificates()
    lab.start_services()
    lab.apply_policy()
    lab.start_capture()
    lab.phase = "trusted_baseline"
    baseline = resolve_then_tls(lab)
    lab.phase = "unknown_dns"
    unknown = resolve_then_tls(lab, "unknown.test")
    lab.phase = "wrong_hostname"
    hostname = lab.probe_service("client", "tls", hostname="wrong.test")
    require_certificate_rejection(hostname, "hostname")
    lab.phase = "untrusted_ca"
    authority = lab.probe_service("client", "tls", trust="untrusted")
    require_certificate_rejection(authority, "untrusted_ca")
    lab.apply_policy(blocked=True)
    lab.phase = "firewall_blocked"
    dns = lab.probe_service("client", "dns")
    require_dns(dns)
    before = lab.counters()
    denied = lab.probe_service("client", "tls")
    healthy = lab.probe_service("server", "tls")
    after = lab.counters()
    require(denied.get("outcome") == "connect_timeout", "Blocked TLS did not time out during TCP connection.")
    require_tls(healthy, lab.certificates["server_certificate_sha256"])
    require(after["tls_denied"] > before["tls_denied"], "The explicit TLS drop counter did not increase.")
    lab.apply_policy()
    lab.phase = "repaired"
    repaired = resolve_then_tls(lab)
    require(not any(probe["phase"] == "unknown_dns" and probe["transport"] == "tcp" for probe in lab.probes),
            "The NXDOMAIN scenario unexpectedly attempted TLS.")
    capture = lab.stop_capture()
    return {"trusted_baseline": baseline, "unknown_dns": unknown, "wrong_hostname": hostname,
            "untrusted_ca": authority, "firewall_blocked": {"dns": dns, "denied": denied, "server_health": healthy,
            "counters_before": before, "counters_after": after}, "repaired": repaired, "capture_verification": capture}


def run(output):
    tools = base.preflight()
    tools["openssl"] = shutil.which("openssl")
    require(tools["openssl"], "OpenSSL is required for fresh synthetic certificate generation.")
    source = source_identity()
    destination = base.new_output(output)
    staging = destination / "staging"
    staging.mkdir(mode=0o700)
    lab = ServicesLab(tools, staging)
    report = {"format": "heltemes-network-services-lab", "version": 1, "ok": False,
              "started_at_utc": timestamp(), "source": source,
              "topology": {"client": CLIENT, "server": SERVER, "namespaces": lab.names},
              "capture": {"namespace_role": "router", "interface": "lan0", "filter": CAPTURE_FILTER, "snaplen": SNAPLEN},
              "scope": {"synthetic_only": True, "aws_deployed": False, "real_evidence_inputs": False,
              "dns": "explicit unicast UDP53; no OS resolver or DNSSEC",
              "tls": "strict fresh private CA and hostname verification; no certificate expiry or revocation exercise",
              "packet_capture": "DNS datagrams and TLS connectivity; TLS identity decisions come from the strict client",
              "private_keys_published": False, "tls_session_keys_logged": False}}
    try:
        report["results"] = run_exercise(lab)
        require(source_identity() == source, "Service lab source changed during execution.")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = str(error).replace(str(ROOT), "<source>").replace(str(destination), "<report>")
    finally:
        try:
            report["cleanup"] = lab.cleanup()
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            report["cleanup"] = {"ok": False, "error": str(error)}
        report["completed_at_utc"] = timestamp()
    report["ok"] = "error" not in report and report["cleanup"]["ok"] and report["cleanup"]["private_pki_deleted"]
    (staging / "REPORT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if not report["ok"]:
        raise RuntimeError("Service exercise failed: " + " ".join(value for value in (report.get("error"), report["cleanup"].get("error")) if value))
    (staging / "policy.nft").write_text(policy_text())
    (staging / "blocked-policy.nft").write_text(policy_text(True))
    (staging / "certificates.json").write_text(json.dumps(lab.certificates, indent=2, sort_keys=True) + "\n")
    (staging / "SUMMARY.md").write_text(f"""# HELTEMES Evidence DNS and TLS exercise

Source commit `{source['commit']}`. Completed {report['completed_at_utc']}.

- Explicit DNS resolved evidence.test and strict HTTPS returned the expected synthetic service.
- An unknown name returned NXDOMAIN and prevented a TLS attempt.
- The client rejected the wrong hostname and an unrelated trusted CA for distinct certificate verification reasons.
- The firewall blocked a fresh TLS connection while DNS and a server-local trusted TLS health control remained healthy.
- Repair restored DNS plus strict HTTPS; all recorded client flows have matching packet evidence.
- Known child processes stopped, owned namespaces were removed, and all fresh private PKI files were deleted before publication.

REPORT.json records strict-client identity decisions, peer certificate fingerprints, DNS transactions, packet-flow checks, and cleanup.
The packet capture supports DNS and connectivity findings. It does not independently establish encrypted TLS certificate decisions.
certificates.json contains public certificates and fingerprints only. This exercise uses no real Evidence keys, archive, or AWS deployment.
""")
    manifest = {name: hashlib.sha256((staging / name).read_bytes()).hexdigest() for name in PUBLIC_FILES}
    (staging / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    publish = destination / "publish"
    publish.mkdir(mode=0o755)
    for name in (*PUBLIC_FILES, "MANIFEST.json"):
        (staging / name).rename(publish / name)
        (publish / name).chmod(0o644)
    destination.chmod(0o755)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="New report directory with an existing parent")
    args = parser.parse_args()
    try:
        result = run(args.output)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, "Network services lab stopped: " + str(error) + "\n")
    print(json.dumps({"ok": result["ok"], "source_commit": result["source"]["commit"], "cleanup": result["cleanup"]}, indent=2))


if __name__ == "__main__":
    main()
