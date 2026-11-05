"""Verify a synthetic three-zone segmentation matrix in disposable Linux namespaces."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_lab as base
from scripts import network_segmentation_capture as capture

ZONES, PORTS = capture.ZONES, capture.PORTS
INTERFACES = {zone: zone + "0" for zone in ZONES}
GATEWAYS = {zone: address.rsplit(".", 1)[0] + ".1" for zone, address in ZONES.items()}
ALLOWED = {("user", "app", 8080), ("management", "app", 8080), ("management", "app", 9090)}
EXCEPTION = ("user", "app", 9090)
MATRIX = tuple({"from": source, "to": destination, "port": port,
                "expected": "allow" if (source, destination, port) in ALLOWED else "deny"}
               for source in ZONES for destination in ZONES if source != destination for port in PORTS)
SOURCE_FILES = (*base.SOURCE_FILES, "scripts/network_segmentation_lab.py", "scripts/network_segmentation_capture.py")
PUBLIC_FILES = ("REPORT.json", "policy.nft", "misconfigured-policy.nft", "MATRIX.json", "SUMMARY.md",
                *(name for zone in ZONES for name in (zone + ".pcap", zone + "-packets.txt")))
require, timestamp = base.require, base.timestamp

PROBE_CODE = r'''
import http.client, json, socket, sys
destination, port, source, source_port = sys.argv[1], int(sys.argv[2]), sys.argv[3], int(sys.argv[4])
connection = http.client.HTTPConnection(destination, port, timeout=1.2, source_address=(source, source_port))
stage = "connect"
try:
    connection.connect()
    stage = "read"
    connection.request("GET", "/synthetic", headers={"Connection": "close"})
    response = connection.getresponse()
    body = response.read(4097)
    result = {"outcome": "response", "status": response.status,
              "payload": json.loads(body) if len(body) <= 4096 else None}
except (TimeoutError, socket.timeout):
    result = {"outcome": "connect_timeout" if stage == "connect" else "read_timeout"}
except OSError as error:
    result = {"outcome": "socket_error", "errno": error.errno}
except (http.client.HTTPException, ValueError):
    result = {"outcome": "protocol_error"}
finally:
    connection.close()
result["source_port"] = source_port
print(json.dumps(result))
'''
SERVICE_CODE = r'''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json, sys, threading, time
address, zone = sys.argv[1:]
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"synthetic": True, "zone": zone, "service_port": self.server.server_port}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
servers = [ThreadingHTTPServer((address, port), Handler) for port in (8080, 9090)]
for server in servers:
    threading.Thread(target=server.serve_forever, daemon=True).start()
while True:
    time.sleep(1)
'''


def source_identity(root=ROOT, environment=None):
    root = Path(root).resolve()
    identity = base.source_identity(root, environment)
    for name in SOURCE_FILES[len(base.SOURCE_FILES):]:
        content = (root / name).read_bytes()
        result = subprocess.run(["git", "-c", f"safe.directory={root}", "-C", str(root),
                                 "show", f"{identity['commit']}:{name}"], capture_output=True, timeout=30)
        require(result.returncode == 0 and content == result.stdout, "Segmentation source differs from its committed version.")
        identity["source_sha256"][name] = hashlib.sha256(content).hexdigest()
    return identity


def row_counter(row, verdict):
    return f"{verdict}_{row['from']}_{row['to']}_{row['port']}"


def tuple_match(source, destination):
    return (f'iifname "{INTERFACES[source]}" oifname "{INTERFACES[destination]}" '
            f"ip saddr {ZONES[source]} ip daddr {ZONES[destination]}")


def policy_text(mode="restricted"):
    require(mode in ("baseline", "restricted", "misconfigured"), "Unknown segmentation policy mode.")
    declarations = [f"    counter {row_counter(row, verdict)} {{ }}" for row in MATRIX for verdict in ("allow", "drop")]
    declarations.append("    counter injected_user_app_9090 { }")
    rules = []
    accepted = {(row["from"], row["to"], row["port"]) for row in MATRIX} if mode == "baseline" else set(ALLOWED)
    if mode == "misconfigured":
        source, destination, port = EXCEPTION
        rules.append(f"{tuple_match(source, destination)} tcp dport {port} ct state new,established ct direction original counter name injected_user_app_9090 accept")
        accepted.add(EXCEPTION)
    # Explicit row drops precede any reply rules. There is no blanket established
    # accept: reverse new connections must independently satisfy the matrix.
    if mode != "baseline":
        for row in MATRIX:
            if row["expected"] == "deny":
                rules.append(f"{tuple_match(row['from'], row['to'])} tcp dport {row['port']} ct direction original counter name {row_counter(row, 'drop')} drop")
    for source, destination, port in sorted(accepted):
        rules.append(f"{tuple_match(destination, source)} tcp sport {port} ct state established ct direction reply accept")
        if mode == "misconfigured" and (source, destination, port) == EXCEPTION:
            continue
        row = {"from": source, "to": destination, "port": port}
        rules.append(f"{tuple_match(source, destination)} tcp dport {port} ct state new,established ct direction original counter name {row_counter(row, 'allow')} accept")
    return ("flush ruleset\ntable inet heltemes_segmentation {\n" + "\n".join(declarations)
            + "\n    chain forward {\n        type filter hook forward priority 0; policy drop;\n"
            + "\n".join("        " + rule for rule in rules) + "\n    }\n}\n")


def require_response(probe, destination, port):
    require(probe.get("outcome") == "response" and probe.get("status") == 200
            and probe.get("payload") == {"synthetic": True, "zone": destination, "service_port": port},
            "The expected synthetic destination service did not respond correctly.")


def require_denial(probe, healthy, destination, port, before, after):
    require(probe.get("outcome") == "connect_timeout", "A denied matrix row did not time out during TCP connect.")
    require_response(healthy, destination, port)
    require(after > before, "The denied matrix row's own drop counter did not increase.")


class SegmentationLab(base.NamespaceLab):
    def __init__(self, tools, staging):
        super().__init__(tools, staging)
        suffix = secrets.token_hex(5)
        self.names = {role: f"he-seg-{suffix}-{role}" for role in (*ZONES, "router")}
        self.link_names = [f"hs{suffix}{letter}" for letter in "abcdef"]
        self.captures = {}

    def setup(self):
        for name in self.names.values():
            self.command([self.tools["ip"], "netns", "add", name])
            self.created_names.append(name)
        for role in self.names:
            self.run_in(role, [self.tools["ip"], "link", "set", "lo", "up"])
        for index, zone in enumerate(ZONES):
            first, second = self.link_names[index * 2:index * 2 + 2]
            self.command([self.tools["ip"], "link", "add", first, "type", "veth", "peer", "name", second])
            self.created_links.extend((first, second))
            self.host_links.extend((first, second))
            endpoints = ((first, zone, "eth0", ZONES[zone]), (second, "router", INTERFACES[zone], GATEWAYS[zone]))
            for interface, role, local, address in endpoints:
                self.command([self.tools["ip"], "link", "set", interface, "netns", self.names[role]])
                self.host_links.remove(interface)
                self.run_in(role, [self.tools["ip"], "link", "set", interface, "name", local])
                self.run_in(role, [self.tools["ip"], "addr", "add", address + "/24", "dev", local])
                self.run_in(role, [self.tools["ip"], "link", "set", local, "up"])
            self.run_in(zone, [self.tools["ip"], "route", "add", "default", "via", GATEWAYS[zone]])
        self.run_in("router", [self.tools["sysctl"], "-w", "net.ipv4.ip_forward=1"])

    def probe(self, source, destination, port, *, record=True):
        require(source in ZONES and destination in ZONES and port in PORTS, "Probe is outside the synthetic zone matrix.")
        source_port = self.next_source_port
        self.next_source_port += 1
        require(source_port < 50000, "Fresh segmentation probe port range is exhausted.")
        started = timestamp()
        arguments = [sys.executable, "-I", "-S", "-B", "-c", PROBE_CODE, ZONES[destination], str(port), ZONES[source], str(source_port)]
        result = json.loads(self.run_in(source, arguments).stdout)
        require(result.get("source_port") == source_port, "Segmentation probe source-port provenance differs.")
        result.update({"from": source, "to": destination, "destination": ZONES[destination], "port": port,
                       "phase": self.phase, "started_at_utc": started, "completed_at_utc": timestamp()})
        if record:
            self.probes.append(result)
        return result

    def start_services(self):
        services = []
        for zone, address in ZONES.items():
            errors = (self.staging / (zone + "-service.stderr")).open("wb")
            self.handles.append(errors)
            command = [sys.executable, "-I", "-S", "-B", "-c", SERVICE_CODE, address, zone]
            process = subprocess.Popen(self.namespace_command(zone, command), stdout=subprocess.DEVNULL, stderr=errors)
            services.append(process)
            self.processes.append(process)
        for _ in range(40):
            require(all(process.poll() is None for process in services), "A synthetic zone service exited before readiness.")
            healthy = True
            for zone in ZONES:
                for port in PORTS:
                    probe = self.probe(zone, zone, port, record=False)
                    if probe.get("outcome") != "response":
                        healthy = False
                    else:
                        require_response(probe, zone, port)
            if healthy:
                return
            time.sleep(0.1)
        raise RuntimeError("The six synthetic zone services did not become healthy.")

    def apply_policy(self, mode="restricted"):
        self.run_in("router", [self.tools["nft"], "-f", "-"], input=policy_text(mode))

    def counters(self):
        result = json.loads(self.run_in("router", [self.tools["nft"], "-j", "list", "table", "inet", "heltemes_segmentation"]).stdout)
        counters = {entry["counter"]["name"]: entry["counter"]["packets"] for entry in result["nftables"] if "counter" in entry}
        expected = {row_counter(row, verdict) for row in MATRIX for verdict in ("allow", "drop")} | {"injected_user_app_9090"}
        require(set(counters) == expected, "A named segmentation matrix counter is missing.")
        return counters

    def start_captures(self):
        for zone in ZONES:
            packets = (self.staging / (zone + ".pcap")).open("wb", buffering=0)
            errors = (self.staging / (zone + "-capture.stderr")).open("wb", buffering=0)
            self.handles.extend((packets, errors))
            command = [self.tools["tcpdump"], "-n", "-i", INTERFACES[zone], "--immediate-mode", "-U", "-s", str(capture.SNAPLEN),
                       "-c", "2000", "-w", "-", capture.capture_filter(zone)]
            process = subprocess.Popen(self.namespace_command("router", command), stdout=packets, stderr=errors)
            self.captures[zone] = process
            self.processes.append(process)
        for _ in range(50):
            require(all(process.poll() is None for process in self.captures.values()), "A zone capture exited before readiness.")
            if all(b"listening on" in (self.staging / (zone + "-capture.stderr")).read_bytes() for zone in ZONES):
                return
            time.sleep(0.1)
        raise RuntimeError("The three zone captures did not become ready.")

    def stop_captures(self):
        def read_captures():
            return {zone: (self.staging / (zone + ".pcap")).read_bytes() for zone in ZONES}
        deadline = time.monotonic() + 5
        while True:
            require(set(self.captures) == set(ZONES) and all(process.poll() is None for process in self.captures.values()),
                    "A zone capture ended unexpectedly.")
            try:
                capture.validate_captures(read_captures(), self.probes)
                break
            except base.CaptureIncomplete as error:
                require(time.monotonic() < deadline, "Segmentation capture deadline expired: " + str(error))
                time.sleep(0.05)
        for process in self.captures.values():
            process.send_signal(signal.SIGINT)
        for process in self.captures.values():
            require(process.wait(timeout=10) == 0, "A zone capture did not close successfully.")
        result = capture.validate_captures(read_captures(), self.probes)
        statistics = {}
        for zone in ZONES:
            log = (self.staging / (zone + "-capture.stderr")).read_text()
            dropped = re.findall(r"(?m)^(\d+) packets dropped by kernel$", log)
            recorded = re.findall(r"(?m)^(\d+) packets captured$", log)
            require(len(dropped) == len(recorded) == 1 and int(dropped[0]) == 0,
                    "Zone capture statistics are missing or report kernel packet drops: " + zone)
            require(int(recorded[0]) == result["capture_packet_counts"][zone], "Closed PCAP count differs from tcpdump statistics: " + zone)
            statistics[zone] = {"packets_captured": int(recorded[0]), "kernel_dropped_packets": 0}
            decoded = self.command([self.tools["tcpdump"], "-nn", "-tt", "-r", str(self.staging / (zone + ".pcap"))]).stdout
            (self.staging / (zone + "-packets.txt")).write_text(decoded)
        result["capture_statistics"] = statistics
        return result


def exercise_matrix(lab, *, baseline=False):
    rows = []
    for row in MATRIX:
        expected = "allow" if baseline else row["expected"]
        counter = row_counter(row, "allow" if expected == "allow" else "drop")
        before = lab.counters()[counter]
        probe = lab.probe(row["from"], row["to"], row["port"])
        healthy = None
        if expected == "allow":
            require_response(probe, row["to"], row["port"])
        else:
            healthy = lab.probe(row["to"], row["to"], row["port"])
        after = lab.counters()[counter]
        if expected == "deny":
            require_denial(probe, healthy, row["to"], row["port"], before, after)
        else:
            require(after > before, "The allowed matrix row's own counter did not increase.")
        rows.append({**row, "expected_in_phase": expected, "observed": "allowed" if expected == "allow" else "blocked",
                     "probe": probe, "destination_health": healthy,
                     "counter": {"name": counter, "before": before, "after": after, "delta": after - before}})
    return rows


def require_complete_inventory(probes):
    tuples = {(row["from"], row["to"], row["port"]) for row in MATRIX}
    require(len(tuples) == len(MATRIX) == 12 and len(ALLOWED) == 3, "The intended segmentation matrix is incomplete.")
    routed = [probe for probe in probes if probe["from"] != probe["to"]]
    controls = [probe for probe in probes if probe["from"] == probe["to"]]
    require(len(routed) == 37 and len(controls) == 18
            and len({probe["source_port"] for probe in probes}) == len(probes),
            "The segmentation exercise did not record the complete set of distinct probes and controls.")
    for phase in ("baseline", "restricted", "repaired"):
        rows = [probe for probe in routed if probe["phase"] == phase]
        require(len(rows) == 12 and {(probe["from"], probe["to"], probe["port"]) for probe in rows} == tuples,
                "A segmentation phase is missing or duplicates a matrix row: " + phase)
        for probe in rows:
            key = (probe["from"], probe["to"], probe["port"])
            expected = "response" if phase == "baseline" or key in ALLOWED else "connect_timeout"
            require(probe["outcome"] == expected, "A segmentation phase outcome differs from the intended matrix.")
    injected = [probe for probe in routed if probe["phase"] == "injected_misconfiguration"]
    require(len(injected) == 1 and (injected[0]["from"], injected[0]["to"], injected[0]["port"]) == EXCEPTION
            and injected[0]["outcome"] == "response", "The deliberate exception inventory is incorrect.")


def run_exercise(lab):
    lab.setup()
    lab.start_services()
    lab.apply_policy("baseline")
    lab.start_captures()
    lab.phase = "baseline"
    baseline = exercise_matrix(lab, baseline=True)
    lab.apply_policy()
    lab.phase = "restricted"
    restricted = exercise_matrix(lab)
    lab.apply_policy("misconfigured")
    lab.phase = "injected_misconfiguration"
    before = lab.counters()["injected_user_app_9090"]
    unexpected = lab.probe(*EXCEPTION)
    after = lab.counters()["injected_user_app_9090"]
    require_response(unexpected, "app", 9090)
    require(after > before, "The deliberately permissive rule was not observed by its own counter.")
    violation = {"expected_policy_violation": True, "observed_policy_violation": True, "detected": True,
                 "probe": unexpected, "counter": {"name": "injected_user_app_9090", "before": before, "after": after, "delta": after - before}}
    lab.apply_policy()
    lab.phase = "repaired"
    repaired = exercise_matrix(lab)
    require_complete_inventory(lab.probes)
    coverage = lab.stop_captures()
    require(coverage["routed_flows_verified"] == 37, "Capture verification did not cover all 37 routed probes.")
    return {"baseline": baseline, "restricted": restricted, "injected_misconfiguration": violation,
            "repaired": repaired, "capture_verification": coverage,
            "summary": {"matrix_rows": 12, "baseline_allowed": 12, "restricted_allowed": 3, "restricted_denied": 9,
                        "injected_violations_detected": 1, "repaired_allowed": 3, "repaired_denied": 9,
                        "routed_probes": 37, "denied_connections": 18, "destination_health_controls": 18}}


def run(output):
    tools = base.preflight()
    source = source_identity()
    destination = base.new_output(output)
    staging = destination / "staging"
    staging.mkdir(mode=0o700)
    lab = SegmentationLab(tools, staging)
    report = {"format": "heltemes-network-segmentation-lab", "version": 1, "ok": False,
              "started_at_utc": timestamp(), "source": source,
              "topology": {"zones": ZONES, "gateways": GATEWAYS, "router_interfaces": INTERFACES, "namespaces": lab.names},
              "captures": {zone: {"namespace_role": "router", "interface": INTERFACES[zone],
              "filter": capture.capture_filter(zone), "snaplen": capture.SNAPLEN} for zone in ZONES},
              "baseline_policy_sha256": hashlib.sha256(policy_text("baseline").encode()).hexdigest(),
              "scope": {"synthetic_only": True, "aws_deployed": False, "real_evidence_inputs": False,
              "new_connection_policy": "IPv4 TCP matrix; source/destination interfaces, exact IP addresses, and service ports",
              "reply_policy": "established reply direction for explicitly allowed tuples only",
              "spoof_resistance_tested": False, "ssh_tested": False, "identity_authentication_tested": False,
              "ipv6_tested": False, "physical_network_hardware_tested": False}}
    try:
        report["results"] = run_exercise(lab)
        require(source_identity() == source, "Segmentation source changed during execution.")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = str(error).replace(str(ROOT), "<source>").replace(str(destination), "<report>")
    finally:
        try:
            report["cleanup"] = lab.cleanup()
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            report["cleanup"] = {"ok": False, "error": str(error)}
        report["completed_at_utc"] = timestamp()
    report["ok"] = "error" not in report and report["cleanup"]["ok"]
    (staging / "REPORT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if not report["ok"]:
        raise RuntimeError("Segmentation exercise failed: " + " ".join(value for value in (report.get("error"), report["cleanup"].get("error")) if value))
    (staging / "policy.nft").write_text(policy_text())
    (staging / "misconfigured-policy.nft").write_text(policy_text("misconfigured"))
    matrix = {"format": "heltemes-segmentation-matrix", "version": 1, "intended": MATRIX,
              "observations": {phase: report["results"][phase] for phase in ("baseline", "restricted", "repaired")},
              "injected_exception": report["results"]["injected_misconfiguration"]}
    (staging / "MATRIX.json").write_text(json.dumps(matrix, indent=2, sort_keys=True) + "\n")
    (staging / "SUMMARY.md").write_text(f"""# HELTEMES Evidence three-zone segmentation exercise

Source commit `{source['commit']}`. Completed {report['completed_at_utc']}.

- All 12 ordered source/destination/service combinations succeeded in the routed baseline.
- The intended policy allowed 3 combinations and denied 9 with TCP-connect timeouts, healthy destination controls, and matching row-specific drop counters.
- The forbidden user-to-app TCP9090 exception was detected, then all 12 rows passed again after repair.
- All 37 routed probes have matching source-interface and destination-interface capture evidence; denied attempts did not reach their destination interface.
- Three server processes, three capture processes, four namespaces, and six virtual-link endpoints were cleaned up before publication.

MATRIX.json compares intended and observed behavior. REPORT.json includes probe times, counters, capture coverage, source fingerprints, and cleanup.
Each PCAP contains only this isolated synthetic IPv4/TCP exercise. Packet observations across interfaces include forwarded duplicates.
This demonstrates routed segmentation; it does not establish authentication, SSH configuration, spoof resistance, IPv6 policy, physical hardware behavior, or AWS deployment.
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
        parser.exit(1, "Network segmentation lab stopped: " + str(error) + "\n")
    print(json.dumps({"ok": result["ok"], "source_commit": result["source"]["commit"], "cleanup": result["cleanup"]}, indent=2))


if __name__ == "__main__":
    main()
