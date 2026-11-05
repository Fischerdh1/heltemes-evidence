"""Exercise routing and default-deny forwarding in disposable Linux namespaces."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.ci_reviewer import github_context

CLIENT = "10.203.1.2"
SERVER = "10.203.2.2"
CAPTURE_FILTER = f"host {CLIENT} and host {SERVER} and tcp and (port 8080 or port 9090)"
SOURCE_FILES = ("scripts/network_lab.py", "scripts/ci_reviewer.py", "scripts/package_reviewer.py",
                "scripts/package_release.py", "scripts/reviewer_demo.py")
PROBE_CODE = r'''
import http.client, json, socket, sys
port = int(sys.argv[1])
source_port = int(sys.argv[2])
connection = http.client.HTTPConnection("10.203.2.2", port, timeout=1.2,
                                      source_address=("", source_port))
try:
    connection.connect()
    connection.request("GET", "/synthetic", headers={"Connection": "close"})
    response = connection.getresponse()
    body = response.read(4097)
    result = {"outcome": "response", "status": response.status,
              "payload": json.loads(body) if len(body) <= 4096 else None}
except (TimeoutError, socket.timeout):
    result = {"outcome": "timeout"}
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
import json, threading, time
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"synthetic": True, "service_port": self.server.server_port}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
servers = [ThreadingHTTPServer(("10.203.2.2", port), Handler) for port in (8080, 9090)]
for server in servers:
    threading.Thread(target=server.serve_forever, daemon=True).start()
while True:
    time.sleep(1)
'''


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def preflight():
    require(sys.platform == "linux", "The namespace exercise requires a disposable Linux host.")
    require(os.geteuid() == 0, "The Linux namespace exercise requires administrator privileges.")
    tools = {name: shutil.which(name) for name in ("ip", "nft", "tcpdump", "sysctl", "git")}
    require(all(tools.values()), "Install iproute2, nftables, tcpdump, procps, and Git before running the lab.")
    return tools


def new_output(value):
    path = Path(value).expanduser().absolute()
    require(".." not in path.parts, "Output paths must be direct paths without parent traversal.")
    require(not any(part.is_symlink() for part in (path, *path.parents)), "Output paths must avoid symbolic links.")
    reserved = {"data", "backups", "custody", ".heltemes-keys", ".heltemes-trust"}
    require(not reserved.intersection(part.casefold() for part in path.parts), "Choose an output outside evidence and custody storage.")
    require(not str(path).casefold().startswith("/library/heltemes evidence"), "Managed installation paths are protected.")
    path.mkdir(mode=0o700)
    return path


def source_identity(root=ROOT, environment=None):
    root = Path(root).resolve()
    def git(*arguments):
        process = subprocess.run(["git", "-c", f"safe.directory={root}", "-C", str(root), *arguments],
                                 capture_output=True, check=False, timeout=30)
        require(process.returncode == 0, "Git could not identify the committed lab source.")
        return process.stdout
    require(Path(git("rev-parse", "--show-toplevel").decode().strip()) == root,
            "The lab source must be a Git repository root.")
    commit = git("rev-parse", "HEAD").decode().strip()
    tree = git("rev-parse", "HEAD^{tree}").decode().strip()
    hashes = {}
    for name in SOURCE_FILES:
        content = (root / name).read_bytes()
        require(content == git("show", f"{commit}:{name}"), "Lab source differs from its committed version.")
        hashes[name] = hashlib.sha256(content).hexdigest()
    return {"commit": commit, "tree": tree, "source_sha256": hashes,
            "github": github_context(commit, os.environ if environment is None else environment)}


def policy_text(misconfigured=False):
    exception = f"ip saddr {CLIENT} ip daddr {SERVER} tcp dport 9090 counter name unexpected_allow accept\n" if misconfigured else ""
    return f"""flush ruleset
table inet heltemes_lab {{
    counter allowed {{ }}
    counter denied_9090 {{ }}
    counter unexpected_allow {{ }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
        {exception}ip saddr {CLIENT} ip daddr {SERVER} tcp dport 9090 counter name denied_9090 drop
        ct state established,related accept
        ip saddr {CLIENT} ip daddr {SERVER} tcp dport 8080 counter name allowed accept
    }}
}}
"""


def successful_response(probe, port):
    return (probe.get("outcome") == "response" and probe.get("status") == 200
            and probe.get("payload") == {"synthetic": True, "service_port": port})


def require_denied(probe, healthy, before, after):
    require(probe.get("outcome") == "timeout", "The forbidden connection did not time out as required.")
    require(successful_response(healthy, 9090), "The forbidden service is unhealthy, so denial is inconclusive.")
    require(after > before, "The router's forbidden-port drop counter did not increase.")


class NamespaceLab:
    def __init__(self, tools, staging):
        self.tools = tools
        self.staging = staging
        suffix = secrets.token_hex(5)
        self.names = {role: f"he-lab-{suffix}-{role}" for role in ("client", "router", "server")}
        self.link_names = [f"he{suffix}{letter}" for letter in "abcd"]
        self.created_names = []
        self.created_links = []
        self.host_links = []
        self.processes = []
        self.handles = []
        self.capture = None
        self.probes = []
        self.next_source_port = 40000
        self.phase = "readiness"

    def command(self, arguments, *, input=None, check=True):
        process = subprocess.run(arguments, input=input, capture_output=True, text=True, timeout=15)
        if check:
            require(process.returncode == 0, "A scoped namespace operation failed: " + process.stderr.strip()[:500])
        return process

    def namespace_command(self, role, arguments):
        name = self.names[role]
        require(name in self.created_names, "Namespace execution requires an exclusively created lab namespace.")
        return [self.tools["ip"], "netns", "exec", name, *arguments]

    def run_in(self, role, arguments, **options):
        return self.command(self.namespace_command(role, arguments), **options)

    def setup(self):
        for name in self.names.values():
            self.command([self.tools["ip"], "netns", "add", name])
            self.created_names.append(name)
        for role in self.names:
            self.run_in(role, [self.tools["ip"], "link", "set", "lo", "up"])
        endpoints = (("client", "eth0", "10.203.1.2/24", "router", "lan0", "10.203.1.1/24"),
                     ("router", "lan1", "10.203.2.1/24", "server", "eth0", "10.203.2.2/24"))
        for index, (left, left_name, left_ip, right, right_name, right_ip) in enumerate(endpoints):
            first, second = self.link_names[index * 2:index * 2 + 2]
            self.command([self.tools["ip"], "link", "add", first, "type", "veth", "peer", "name", second])
            self.created_links.extend((first, second))
            self.host_links.extend((first, second))
            for interface, role, local_name, address in ((first, left, left_name, left_ip), (second, right, right_name, right_ip)):
                self.command([self.tools["ip"], "link", "set", interface, "netns", self.names[role]])
                self.host_links.remove(interface)
                self.run_in(role, [self.tools["ip"], "link", "set", interface, "name", local_name])
                self.run_in(role, [self.tools["ip"], "addr", "add", address, "dev", local_name])
                self.run_in(role, [self.tools["ip"], "link", "set", local_name, "up"])
        self.run_in("client", [self.tools["ip"], "route", "add", "default", "via", "10.203.1.1"])
        self.run_in("server", [self.tools["ip"], "route", "add", "default", "via", "10.203.2.1"])
        self.run_in("router", [self.tools["sysctl"], "-w", "net.ipv4.ip_forward=1"])

    def start_services(self):
        errors = (self.staging / "service.stderr").open("wb")
        self.handles.append(errors)
        process = subprocess.Popen(self.namespace_command("server", [sys.executable, "-I", "-S", "-B", "-c", SERVICE_CODE]),
                                   stdout=subprocess.DEVNULL, stderr=errors)
        self.processes.append(process)
        for _ in range(40):
            require(process.poll() is None, "Synthetic HTTP services exited before readiness.")
            if all(successful_response(self.probe("server", port, record=False), port) for port in (8080, 9090)):
                return
            time.sleep(0.1)
        raise RuntimeError("Synthetic services did not become healthy.")

    def probe(self, role, port, *, record=True):
        require(role in ("client", "server") and port in (8080, 9090), "Probe target is outside the synthetic lab.")
        source_port = self.next_source_port
        self.next_source_port += 1
        require(source_port < 50000, "The bounded fresh-probe port range was exhausted.")
        started = timestamp()
        process = self.run_in(role, [sys.executable, "-I", "-S", "-B", "-c", PROBE_CODE, str(port), str(source_port)])
        result = json.loads(process.stdout)
        require(result.get("source_port") == source_port, "Probe source-port provenance did not match.")
        result.update({"from": role, "destination": SERVER, "port": port, "phase": self.phase,
                       "started_at_utc": started, "completed_at_utc": timestamp()})
        if record:
            self.probes.append(result)
        return result

    def start_capture(self):
        packet_file = (self.staging / "packet-capture.pcap").open("wb", buffering=0)
        errors = (self.staging / "capture.stderr").open("wb", buffering=0)
        self.handles.extend((packet_file, errors))
        arguments = [self.tools["tcpdump"], "-n", "-i", "lan0", "-U", "-s", "512", "-c", "2000", "-w", "-", CAPTURE_FILTER]
        self.capture = subprocess.Popen(self.namespace_command("router", arguments), stdout=packet_file, stderr=errors)
        self.processes.append(self.capture)
        for _ in range(50):
            require(self.capture.poll() is None, "Namespace packet capture exited before readiness.")
            if b"listening on" in (self.staging / "capture.stderr").read_bytes():
                return
            time.sleep(0.1)
        raise RuntimeError("Namespace packet capture did not become ready.")

    def apply_policy(self, misconfigured=False):
        self.run_in("router", [self.tools["nft"], "-f", "-"], input=policy_text(misconfigured))

    def counters(self):
        result = json.loads(self.run_in("router", [self.tools["nft"], "-j", "list", "table", "inet", "heltemes_lab"]).stdout)
        counters = {entry["counter"]["name"]: entry["counter"]["packets"]
                    for entry in result["nftables"] if "counter" in entry}
        require(set(counters) == {"allowed", "denied_9090", "unexpected_allow"}, "Named firewall counters are missing.")
        return counters

    def stop_capture(self):
        require(self.capture is not None and self.capture.poll() is None, "Capture ended unexpectedly during the exercise.")
        self.capture.send_signal(signal.SIGINT)
        require(self.capture.wait(timeout=10) == 0, "Packet capture did not close successfully.")
        raw = (self.staging / "packet-capture.pcap").read_bytes()
        require(24 < len(raw) < 4 * 1024 * 1024, "Packet capture is empty or exceeds its bound.")
        decoded = self.command([self.tools["tcpdump"], "-nn", "-tt", "-r", str(self.staging / "packet-capture.pcap")]).stdout
        require(CLIENT in decoded and SERVER in decoded and ".8080" in decoded and ".9090" in decoded,
                "Packet capture lacks the expected synthetic traffic.")
        (self.staging / "packet-capture.txt").write_text(decoded)

    def cleanup(self):
        errors = []
        for process in reversed(self.processes):
            try:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            except (OSError, subprocess.SubprocessError):
                errors.append("A tracked lab process could not be stopped.")
        for handle in self.handles:
            handle.close()
        for name in reversed(self.created_names):
            try:
                self.command([self.tools["ip"], "netns", "delete", name])
            except (RuntimeError, subprocess.SubprocessError):
                errors.append("An owned network namespace could not be removed.")
        # Moved endpoints are removed with their owned namespaces. Never revisit
        # their former host names, which another process could have reused.
        for name in self.host_links:
            try:
                present = self.command([self.tools["ip"], "link", "show", "dev", name], check=False)
                if present.returncode == 0:
                    self.command([self.tools["ip"], "link", "delete", name])
            except (RuntimeError, subprocess.SubprocessError):
                errors.append("An owned virtual link could not be removed.")
        names = self.command([self.tools["ip"], "netns", "list"]).stdout.splitlines()
        remaining = {line.split()[0] for line in names if line.strip()}.intersection(self.created_names)
        if remaining:
            errors.append("Owned network namespaces remain after cleanup.")
        require(not errors, " ".join(errors))
        return {"ok": True, "owned_namespaces_removed": len(self.created_names),
                "tracked_processes_stopped": len(self.processes), "owned_virtual_links_removed": len(self.created_links)}


def run_exercise(lab):
    lab.setup()
    lab.start_services()
    lab.start_capture()
    lab.phase = "baseline"
    baseline = {str(port): lab.probe("client", port) for port in (8080, 9090)}
    require(all(successful_response(baseline[str(port)], port) for port in (8080, 9090)),
            "Baseline routing did not reach both healthy services.")
    lab.apply_policy()
    lab.phase = "protected"
    allowed = lab.probe("client", 8080)
    require(successful_response(allowed, 8080), "Required traffic was blocked by the protected policy.")
    before = lab.counters()
    denied = lab.probe("client", 9090)
    healthy = lab.probe("server", 9090)
    protected = lab.counters()
    require_denied(denied, healthy, before["denied_9090"], protected["denied_9090"])
    lab.apply_policy(misconfigured=True)
    lab.phase = "misconfigured"
    unexpected = lab.probe("client", 9090)
    misconfigured = lab.counters()
    require(successful_response(unexpected, 9090) and misconfigured["unexpected_allow"] > 0,
            "The injected permissive rule was not detected by the forbidden-service probe.")
    lab.apply_policy()
    lab.phase = "repaired"
    repaired_before = lab.counters()
    repaired_denied = lab.probe("client", 9090)
    repaired_healthy = lab.probe("server", 9090)
    repaired_allowed = lab.probe("client", 8080)
    repaired = lab.counters()
    require_denied(repaired_denied, repaired_healthy, repaired_before["denied_9090"], repaired["denied_9090"])
    require(successful_response(repaired_allowed, 8080), "The repaired policy blocked required traffic.")
    lab.stop_capture()
    return {"baseline": baseline, "protected": {"allowed": allowed, "denied": denied, "service_health": healthy,
            "counters_before": before, "counters_after": protected},
            "injected_misconfiguration": {"detected": True, "expected_policy_violation": True,
            "observed_policy_violation": True, "unexpected_response": unexpected, "counters": misconfigured},
            "repaired": {"allowed": repaired_allowed, "denied": repaired_denied, "service_health": repaired_healthy,
            "counters_before": repaired_before, "counters_after": repaired}}


def run(output):
    tools = preflight()
    source = source_identity()
    destination = new_output(output)
    staging = destination / "staging"
    staging.mkdir(mode=0o700)
    lab = NamespaceLab(tools, staging)
    report = {"format": "heltemes-network-lab", "version": 1, "ok": False, "started_at_utc": timestamp(),
              "source": source, "topology": {"client": CLIENT, "client_gateway": "10.203.1.1",
              "server": SERVER, "server_gateway": "10.203.2.1", "namespaces": lab.names},
              "capture": {"namespace_role": "router", "interface": "lan0", "filter": CAPTURE_FILTER, "snaplen": 512},
              "scope": {"synthetic_only": True, "linux_network_namespaces": True,
              "firewall": "nftables forwarding", "aws_deployed": False, "real_evidence_inputs": False,
              "physical_network_hardware_tested": False, "tls_or_identity_authentication_tested": False}}
    try:
        report["results"] = run_exercise(lab)
        require(source_identity() == source, "Lab source or Git identity changed during the exercise.")
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
        details = [report.get("error"), report["cleanup"].get("error")]
        raise RuntimeError("Network exercise failed: " + " ".join(detail for detail in details if detail))
    (staging / "policy.nft").write_text(policy_text())
    (staging / "misconfigured-policy.nft").write_text(policy_text(True))
    summary = f"""# HELTEMES Evidence network-security lab

Source commit `{source['commit']}`. Completed {report['completed_at_utc']}.

- Both synthetic services responded through the routed baseline.
- Protected policy allowed TCP8080 and blocked TCP9090 with a positive drop-counter change and healthy server control.
- The forbidden-service probe detected the deliberately permissive TCP9090 rule.
- Repaired policy blocked TCP9090 while preserving TCP8080 access.
- Packet capture ran only on the isolated router's client-facing interface.
- All owned namespaces, virtual links, and tracked service/capture processes were cleaned up.

Inspect REPORT.json for observed probes, counter changes, source fingerprints, and scope.
The PCAP and decoded packet text contain this synthetic exercise's traffic.
This exercise demonstrates Linux routing and forwarding policy with virtual interfaces.
AWS, TLS authentication, physical networking hardware, and live Evidence services have separate verification requirements.
"""
    (staging / "SUMMARY.md").write_text(summary)
    filenames = ("REPORT.json", "packet-capture.pcap", "packet-capture.txt", "policy.nft", "misconfigured-policy.nft", "SUMMARY.md")
    manifest = {name: hashlib.sha256((staging / name).read_bytes()).hexdigest() for name in filenames}
    (staging / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    publish = destination / "publish"
    publish.mkdir(mode=0o755)
    for name in (*filenames, "MANIFEST.json"):
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
        parser.exit(1, "Network lab stopped: " + str(error) + "\n")
    print(json.dumps({"ok": result["ok"], "source_commit": result["source"]["commit"], "cleanup": result["cleanup"]}, indent=2))


if __name__ == "__main__":
    main()
