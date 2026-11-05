"""Verify committed monitoring history through real systemd process crashes."""
from __future__ import annotations

import argparse
from collections import Counter
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_lab as base
from scripts import network_monitoring_lab as monitoring
from scripts import network_monitor_service as service
from scripts import network_segmentation_lab as segmentation

require, timestamp = base.require, base.timestamp
SOURCE_FILES = (*monitoring.SOURCE_FILES, "scripts/network_monitor_store.py",
                "scripts/network_monitor_service.py", "scripts/network_monitor_restart_lab.py")
PUBLIC_FILES = ("REPORT.json", "APPROVED_POLICY.json", "OBSERVATIONS.json", "JOURNAL.json",
                "ALERTS.json", "EVENTS.jsonl", "SERVICE.json", "SUMMARY.md", "policy.nft",
                *(name for zone in segmentation.ZONES for name in (zone + ".pcap", zone + "-packets.txt")))
CANARIES = monitoring.CANARIES
PHASES = ("reference", "baseline", "rule_drift", "forbidden_open", "committed_before_crash",
          "first_restart_reference", "still_forbidden", "repair_rules_only",
          "uncommitted_recovery", "second_restart_reference", "final_canaries")
COMPLETE = {"baseline", "uncommitted_recovery", "final_canaries"}
FORBIDDEN = {"forbidden_open", "committed_before_crash", "still_forbidden"}
CRITICAL_KEY = "forbidden_path_open:user->app:9090"
MANAGER_PROPERTIES = ("LoadState", "ActiveState", "SubState", "MainPID", "NRestarts",
                      "ExecMainCode", "ExecMainStatus")


def preflight():
    tools = base.preflight()
    for name in ("systemctl", "systemd-run"):
        tools[name] = shutil.which(name)
    require(all(tools.values()), "The disposable Linux VM requires systemd-run and systemctl.")
    result = subprocess.run([tools["systemctl"], "show", "--property=Version", "--value"],
                            capture_output=True, text=True, timeout=10)
    require(result.returncode == 0 and result.stdout.strip(), "A running systemd system manager is required.")
    return tools


def source_identity(root=ROOT, environment=None):
    root = Path(root).resolve()
    identity = monitoring.source_identity(root, environment)
    for name in SOURCE_FILES[len(monitoring.SOURCE_FILES):]:
        content = (root / name).read_bytes()
        result = subprocess.run(["git", "-c", f"safe.directory={root}", "-C", str(root),
                                 "show", f"{identity['commit']}:{name}"], capture_output=True, timeout=30)
        require(result.returncode == 0 and content == result.stdout, "Restart lab source differs from its committed version.")
        identity["source_sha256"][name] = hashlib.sha256(content).hexdigest()
    return identity


class SystemdMonitor:
    """Own exactly one transient service and one short private /run directory."""
    def __init__(self, tools, staging):
        self.tools, self.staging = tools, staging
        self.token = secrets.token_hex(10)
        self.unit = "heltemes-rst-" + self.token + ".service"
        self.description = "HELTEMES disposable restart lab " + self.token
        self.state_root = self.state = None
        self.created = False
        self.start_attempted = False
        self.observed_processes = set()
        self.manager_records = []

    def command(self, arguments, check=True):
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=10)
        if check:
            require(result.returncode == 0, "An owned monitor-service operation failed.")
        return result

    def show(self, *, require_owner=False):
        result = self.command([self.tools["systemctl"], "show", "--no-pager",
                               "--property=" + ",".join((*MANAGER_PROPERTIES, "Description")), self.unit], check=False)
        properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        require(properties.get("LoadState") in {"loaded", "not-found"}, "The owned service state could not be established.")
        if require_owner and properties["LoadState"] != "not-found":
            require(properties.get("Description") == self.description, "The service identity differs from this invocation.")
        filtered = {key: properties.get(key, "") for key in MANAGER_PROPERTIES}
        for key in ("MainPID", "NRestarts", "ExecMainCode", "ExecMainStatus"):
            value = filtered[key]
            require(value == "" or value.isdecimal(), "The manager returned malformed numeric state.")
            filtered[key] = int(value or 0)
        return filtered

    def initialize(self, approved):
        self.state_root = Path(tempfile.mkdtemp(prefix="he-rst-", dir="/run"))
        self.state_root.chmod(0o700)
        self.state = self.state_root / "state"
        require(len(os.fsencode(self.state / "monitor.sock")) < 100, "The private socket path is too long.")
        approved_file = self.staging / "approved-input.json"
        approved_file.write_text(json.dumps(approved, sort_keys=True) + "\n")
        approved_file.chmod(0o600)
        self.command([sys.executable, "-I", "-S", "-B", str(ROOT / "scripts/network_monitor_service.py"),
                      "init", "--state", str(self.state), "--approved", str(approved_file)])

    def start(self):
        require(self.state is not None and not self.created, "The monitor must be initialized once before service start.")
        require(self.show()["LoadState"] == "not-found", "The transient service name is already in use.")
        self.start_attempted = True
        arguments = [self.tools["systemd-run"], "--quiet", "--collect", "--expand-environment=no", "--unit=" + self.unit,
                     "--description=" + self.description, "--service-type=exec",
                     "--property=Restart=on-failure", "--property=RestartSec=1.5s",
                     "--property=UMask=0077", "--property=NoNewPrivileges=yes",
                     "--property=PrivateTmp=yes", "--property=ProtectSystem=strict",
                     "--property=ReadWritePaths=" + str(self.state_root),
                     "--property=RestrictAddressFamilies=AF_UNIX",
                     sys.executable, "-I", "-S", "-B", str(ROOT / "scripts/network_monitor_service.py"),
                     "serve", "--state", str(self.state), "--allow-test-crashes"]
        result = self.command(arguments, check=False)
        observed = self.show(require_owner=True)
        self.created = observed["LoadState"] == "loaded"
        require(result.returncode == 0 and self.created, "The transient monitor service did not start.")
        status, manager = self.wait_ready()
        require(manager["NRestarts"] == 0, "The service unexpectedly restarted before the first controlled crash.")
        self.manager_records.append({"phase": "initial_start", "observed_at_utc": timestamp(), "manager": manager,
                                     "process_id": status["process_id"], "instance_id": status["instance_id"],
                                     "committed_count": status["committed_count"], "status": status["current_evaluation"]["status"]})
        return status

    def request(self, payload):
        require(self.state is not None and self.created, "A private owned monitor service is required.")
        return service.request(self.state, payload, timeout=5)

    def wait_ready(self, previous=None, minimum_restarts=0):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            manager = self.show(require_owner=True)
            if manager["ActiveState"] == "active" and manager["MainPID"] > 0 and manager["NRestarts"] >= minimum_restarts:
                try:
                    status = self.request({"command": "status"})
                    ready = status.get("ok") is True and status.get("process_id") == manager["MainPID"]
                    if previous is not None:
                        ready = ready and status["process_id"] != previous["process_id"] and status["instance_id"] != previous["instance_id"]
                    if ready:
                        self.observed_processes.add(status["process_id"])
                        return status, manager
                except (OSError, ValueError, RuntimeError, EOFError):
                    pass
            time.sleep(0.05)
        raise RuntimeError("The restarted monitor did not become independently verified and ready.")

    def crash(self, payload, expected_exit):
        previous = self.request({"command": "status"})
        before_manager = self.show(require_owner=True)
        try:
            self.request(payload)
        except (OSError, ValueError, RuntimeError, EOFError):
            pass
        else:
            raise RuntimeError("The deliberately crashed request unexpectedly acknowledged success.")
        exit_manager = None
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            candidate = self.show(require_owner=True)
            if candidate["ExecMainStatus"] == expected_exit and candidate["MainPID"] == 0:
                exit_manager = candidate
                break
            time.sleep(0.05)
        require(exit_manager is not None, "The manager did not report the expected injected process exit.")
        restarted, after_manager = self.wait_ready(previous, before_manager["NRestarts"] + 1)
        require(after_manager["NRestarts"] == before_manager["NRestarts"] + 1,
                "The service restarted more than once for the controlled crash.")
        require(restarted["current_evaluation"]["status"] == "unknown",
                "Restart must publish unknown coverage before accepting fresh observations.")
        record = {"phase": payload["observation"]["phase"], "request_id": payload["request_id"],
                  "test_crash": payload["test_crash"], "expected_exit": expected_exit,
                  "acknowledgement_received": False, "before": before_manager, "exit": exit_manager,
                  "after": after_manager, "previous_process_id": previous["process_id"],
                  "restarted_process_id": restarted["process_id"], "previous_instance_id": previous["instance_id"],
                  "restarted_instance_id": restarted["instance_id"],
                  "committed_count_before": previous["committed_count"],
                  "committed_count_after_restart": restarted["committed_count"],
                  "restart_status": restarted["current_evaluation"]["status"]}
        self.manager_records.append(record)
        return restarted, record

    def cleanup(self):
        unloaded = not self.start_attempted
        if self.start_attempted:
            before = self.show(require_owner=True)
            if before["LoadState"] != "not-found":
                self.command([self.tools["systemctl"], "stop", self.unit])
                self.command([self.tools["systemctl"], "reset-failed", self.unit], check=False)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                state = self.show(require_owner=True)
                require(state["MainPID"] == 0 and state["ActiveState"] not in {"active", "activating"},
                        "The owned monitor process remains active after stop.")
                if state["LoadState"] == "not-found":
                    unloaded = True
                    break
                time.sleep(0.05)
            require(unloaded, "The owned transient unit was not unloaded.")
        if self.state_root is not None and self.state_root.exists():
            require(self.state_root.parent == Path("/run") and self.state_root.name.startswith("he-rst-")
                    and not self.state_root.is_symlink(), "Private state cleanup is outside its owned path.")
            shutil.rmtree(self.state_root)
        removed = self.state_root is None or not self.state_root.exists()
        require(removed, "The private disposable monitor state remains after cleanup.")
        return {"ok": True, "transient_unit_unloaded": unloaded, "private_state_removed": removed,
                "verified_process_instances": len(self.observed_processes), "active_main_pid": 0}


def critical(status):
    incidents = [a for a in status["alerts"] if a["key"] == CRITICAL_KEY and a["state"] == "open"]
    require(len(incidents) == 1, "The unresolved forbidden-access incident was lost or duplicated.")
    return incidents[0]


def require_unknown(status):
    require(status["current_evaluation"]["status"] == "unknown", "Restart coverage was not explicitly unknown.")
    require(status["current_evaluation"]["phase"] == "monitor_restart", "Readiness did not include a committed startup gap.")
    require("telemetry_gap:collector" in status["current_evaluation"]["active_alert_keys"],
            "Restart did not preserve a visible telemetry gap.")


def expected_probes(phase):
    if phase in COMPLETE:
        return tuple((*row, "connect_timeout" if row == ("user", "app", 9090) else "response") for row in CANARIES)
    if phase in FORBIDDEN:
        return (("user", "app", 9090, "response"),)
    return ()


def require_inventory(lab, observations):
    require(tuple(row["observation"]["phase"] for row in observations) == PHASES, "Controller observation inventory differs.")
    routed = [p for p in lab.probes if p["from"] != p["to"]]
    controls = [p for p in lab.probes if p["from"] == p["to"]]
    require(len(routed) == 12 and len(controls) == 3
            and len({p["source_port"] for p in lab.probes}) == len(lab.probes),
            "The full routed/health inventory is missing or reuses a port.")
    require(Counter(p["outcome"] for p in routed) == {"response": 9, "connect_timeout": 3}, "Unexpected routed outcomes.")
    for record in observations:
        observation = record["observation"]
        phase = observation["phase"]
        probes = observation["probes"]
        require(tuple((p["from"], p["to"], p["port"], p["outcome"]) for p in probes) == expected_probes(phase),
                "A restart phase has unexpected probe coverage: " + phase)
        require([p for p in routed if p["phase"] == phase] == probes, "A routed probe is missing from the controller record.")
        for probe in probes:
            if probe["outcome"] == "response":
                segmentation.require_response(probe, probe["to"], probe["port"])
            else:
                health = probe["destination_health"]
                segmentation.require_response(health, probe["to"], probe["port"])
                require(health in controls and health["from"] == health["to"] == probe["to"], "A denial lacks its own healthy destination.")


def run_exercise(lab, supervisor):
    lab.setup()
    lab.start_services()
    lab.apply_policy()
    approved = lab.ruleset()
    pinned = copy.deepcopy(approved)
    supervisor.initialize(approved)
    initial = supervisor.start()
    require_unknown(initial)
    lab.start_captures()
    observations, trace = [], []

    def observe(phase, rows=(), crash_point=None):
        lab.phase = phase
        probes = []
        for source, target, port in rows:
            probe = lab.probe(source, target, port)
            probe["destination_health"] = lab.probe(target, target, port) if probe["outcome"] == "connect_timeout" else None
            probes.append(probe)
        ruleset = lab.ruleset()
        observation = {"phase": phase, "observed_at_utc": timestamp(), "ruleset": ruleset,
                       "collection_error": None, "probes": probes}
        request = {"command": "observe", "request_id": phase, "observation": observation}
        if crash_point:
            request["test_crash"] = crash_point
        observations.append(copy.deepcopy(request))
        if crash_point:
            return request
        response = supervisor.request(request)
        require(response.get("ok") is True and response.get("duplicate") is False, "A fresh observation was not committed exactly once.")
        trace.append({"phase": phase, "request_id": phase, "committed_sequence": response["committed_sequence"],
                      "evaluation": response["evaluation"]})
        return response["current_status"]

    observe("reference")
    baseline = observe("baseline", CANARIES)
    require(baseline["current_evaluation"]["status"] == "healthy", "Fresh baseline canaries did not establish healthy coverage.")
    lab.apply_policy("misconfigured")
    drift = observe("rule_drift")
    require("rule_drift:ruleset" in drift["current_evaluation"]["active_alert_keys"], "Rule drift was not detected before the forbidden connection.")
    opened = observe("forbidden_open", (("user", "app", 9090),))
    original_incident = critical(opened)["id"]

    committed_request = observe("committed_before_crash", (("user", "app", 9090),), "after_commit_before_ack")
    restarted, committed_crash = supervisor.crash(committed_request, 72)
    require_unknown(restarted)
    require(critical(restarted)["id"] == original_incident, "Committed alert identity changed after restart.")
    require(restarted["committed_count"] == committed_crash["committed_count_before"] + 2,
            "The committed observation and startup gap did not survive the after-commit crash.")
    retry_payload = {key: value for key, value in committed_request.items() if key != "test_crash"}
    before_retry = supervisor.request({"command": "status"})
    retry = supervisor.request(retry_payload)
    after_retry = supervisor.request({"command": "status"})
    require(retry.get("ok") is True and retry.get("duplicate") is True and retry.get("result_is_historical") is True
            and retry["committed_sequence"] == committed_crash["committed_count_before"] + 1,
            "The acknowledgement-loss retry was not tied to its original commit.")
    require(before_retry["committed_count"] == after_retry["committed_count"]
            and before_retry["head_digest"] == after_retry["head_digest"]
            and before_retry["alerts"] == after_retry["alerts"], "A committed retry duplicated journal rows or incidents.")
    require_unknown(retry["current_status"])
    trace.append({"phase": "committed_retry", "duplicate": True, "committed_sequence": retry["committed_sequence"],
                  "count_before": before_retry["committed_count"], "count_after": after_retry["committed_count"],
                  "head_before": before_retry["head_digest"], "head_after": after_retry["head_digest"],
                  "result_is_historical": retry["result_is_historical"],
                  "historical_evaluation": retry["evaluation"], "current_status": retry["current_status"]["current_evaluation"]["status"]})
    conflicting = copy.deepcopy(retry_payload)
    conflicting["observation"]["phase"] = "conflicting_retry"
    rejection = supervisor.request(conflicting)
    after_conflict = supervisor.request({"command": "status"})
    require(rejection == {"ok": False, "error": "request_rejected"} and after_conflict == after_retry,
            "Conflicting request content was not rejected without changing accepted state.")
    conflict = {"request_id": conflicting["request_id"], "rejected": True,
                "count_before": after_retry["committed_count"], "count_after": after_conflict["committed_count"],
                "head_before": after_retry["head_digest"], "head_after": after_conflict["head_digest"]}

    observe("first_restart_reference")
    still_bad = observe("still_forbidden", (("user", "app", 9090),))
    require(critical(still_bad)["id"] == original_incident, "The existing forbidden incident was reopened under another identity.")
    lab.apply_policy()
    repaired_rules = observe("repair_rules_only")
    require("rule_drift:ruleset" not in repaired_rules["current_evaluation"]["active_alert_keys"],
            "Restored rules did not clear configuration drift.")
    require(critical(repaired_rules)["id"] == original_incident, "Rule-only repair cleared the behavioral finding.")

    candidate = observe("uncommitted_recovery", CANARIES, "before_commit")
    second_restart, uncommitted_crash = supervisor.crash(candidate, 71)
    require_unknown(second_restart)
    require(critical(second_restart)["id"] == original_incident, "Uncommitted recovery incorrectly cleared the stored incident.")
    require(second_restart["committed_count"] == uncommitted_crash["committed_count_before"] + 1,
            "The uncommitted recovery was accepted instead of only recording a startup gap.")

    observe("second_restart_reference")
    final = observe("final_canaries", CANARIES)
    require(final["current_evaluation"]["status"] == "healthy", "Fresh post-restart canaries did not establish healthy coverage.")
    require(all(a["severity"] == "info" for a in final["alerts"] if a["state"] == "open"),
            "A significant incident remains unresolved after final revalidation.")
    exported = supervisor.request({"command": "export"})
    require(exported.get("ok") is True and exported["approved_policy"] == approved == pinned,
            "The pinned reference changed while recovering.")
    rows = exported["rows"]
    require(len(rows) == final["committed_count"] == 13, "The committed journal has an unexpected size.")
    identifiers = [row["request_id"] for row in rows]
    require(identifiers.count("committed_before_crash") == 1 and "uncommitted_recovery" not in identifiers,
            "Crash-boundary journal contents differ from the committed operations.")
    require(sum(row["sample"]["phase"] == "monitor_restart" for row in rows) == 3,
            "Every service instance must first record an explicit startup gap.")
    recovered = [e for e in exported["events"] if e["key"] == CRITICAL_KEY and e["action"] == "resolved"]
    require(len(recovered) == 1 and recovered[0]["phase"] == "final_canaries",
            "The incident resolved without the final committed fresh evidence.")
    require_inventory(lab, observations)
    capture = lab.stop_captures()
    require(capture["routed_flows_verified"] == 12, "Capture evidence omits a routed probe, including the uncommitted candidate.")
    return {"approved": approved, "observations": observations, "journal": exported, "trace": trace,
            "service": {"unit_kind": "systemd_transient", "restart_policy": "on-failure", "restart_delay_seconds": 1.5,
                        "initial_status": initial, "manager_observations": supervisor.manager_records,
                        "crashes": [committed_crash, uncommitted_crash],
                        "process_instances": len(supervisor.observed_processes), "conflicting_retry": conflict,
                        "request_trace": trace, "retry": next(t for t in trace if t["phase"] == "committed_retry")},
            "results": {"final_evaluation": final["current_evaluation"], "final_healthy": True,
                        "committed_journal_rows": 13, "startup_gap_rows": 3,
                        "controller_observations": 11, "routed_probes": 12, "responses": 9, "denials": 3,
                        "health_controls": 3, "controlled_process_crashes": 2, "automatic_restarts": 2,
                        "capture_verification": capture}}


def run(output):
    tools = preflight()
    source = source_identity()
    destination = base.new_output(output)
    staging = destination / "staging"
    staging.mkdir(mode=0o700)
    lab = monitoring.MonitoringLab(tools, staging)
    supervisor = SystemdMonitor(tools, staging)
    report = {"format": "heltemes-network-monitor-restart-lab", "version": 1, "ok": False,
              "started_at_utc": timestamp(), "source": source,
              "topology": {"zones": segmentation.ZONES, "gateways": segmentation.GATEWAYS,
                           "router_interfaces": segmentation.INTERFACES, "namespaces": lab.names},
              "scope": {"synthetic_only": True, "aws_deployed": False, "real_evidence_inputs": False,
                        "systemd_service_tested": True, "process_crashes_tested": True, "vm_reboot_tested": False,
                        "physical_power_loss_tested": False, "administrator_resistant_storage": False,
                        "external_notifications": False, "dedicated_service_account": False}}
    exercise = None
    try:
        exercise = run_exercise(lab, supervisor)
        report["results"] = exercise["results"]
        report["approved_policy_sha256"] = monitoring.monitor.policy_fingerprint(exercise["approved"])
        require(source_identity() == source, "Restart exercise source changed during execution.")
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        report["error"] = str(error).replace(str(ROOT), "<source>").replace(str(destination), "<report>")
    finally:
        cleanup = {}
        for name, function in (("service", supervisor.cleanup), ("network", lab.cleanup)):
            try:
                cleanup[name] = function()
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                cleanup[name] = {"ok": False, "error": str(error).replace(str(ROOT), "<source>").replace(str(destination), "<report>")}
        cleanup["ok"] = all(value["ok"] for value in cleanup.values())
        report["cleanup"] = cleanup
        report["completed_at_utc"] = timestamp()
    report["ok"] = "error" not in report and report["cleanup"]["ok"]
    (staging / "REPORT.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if not report["ok"]:
        raise RuntimeError("Restart exercise failed: " + report.get("error", "Owned resource cleanup failed."))
    documents = {"APPROVED_POLICY.json": exercise["approved"], "OBSERVATIONS.json": exercise["observations"],
                 "JOURNAL.json": exercise["journal"], "ALERTS.json": exercise["journal"]["alerts"],
                 "SERVICE.json": exercise["service"]}
    for name, value in documents.items():
        (staging / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    (staging / "EVENTS.jsonl").write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in exercise["journal"]["events"]))
    (staging / "policy.nft").write_text(segmentation.policy_text())
    (staging / "SUMMARY.md").write_text(f"""# HELTEMES Evidence restart-safe monitoring exercise

Source commit `{source['commit']}`. Completed {report['completed_at_utc']}.

- A real transient systemd service ran in a disposable Linux VM. Two deliberate process exits (72 and 71) each produced a changed PID/instance and one automatic supervisor restart.
- A crash after commit but before acknowledgement preserved the observation and original unresolved alert. Retrying the same request returned its historical commit without another journal row or duplicate incident.
- Restart first committed unknown monitoring coverage. Persisted findings remained visible.
- A crash before committing a would-be recovery left that observation uncommitted and the original incident unresolved. Its actual network probes remain visible in the separate controller record and captures.
- Fresh post-restart rules and all three canaries established recovery. The forbidden-access incident resolved only at the final committed canary observation.
- Thirteen journal rows (ten observations plus three startup gaps), eleven controller observations, twelve routed probes, and three healthy destination controls were verified.
- Three complete captures reported zero kernel drops. The owned service, private state directory, four namespaces, six link endpoints, and six network service/capture processes were cleaned up before publication.

Final monitored state: **healthy**. Informational packet observations may remain open; all significant conditions resolved through fresh evidence.

## Saved alert lifecycle

{monitoring.alert_table(exercise['journal']['alerts'])}

Inspect SERVICE.json for manager states, exit codes, changed process identities, and retry evidence. JOURNAL.json contains only committed rows; OBSERVATIONS.json also preserves the deliberately uncommitted candidate.
This tests process termination and supervisor restart, not a VM reboot, physical power loss, permanent production service, or resistance to an administrator changing every local reference.
AWS, the installed Evidence application, and its real signing key and trusted history were outside the exercise.
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
    arguments = parser.parse_args()
    try:
        result = run(arguments.output)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, "Monitor restart lab stopped: " + str(error) + "\n")
    print(json.dumps({"ok": result["ok"], "source_commit": result["source"]["commit"],
                      "results": {key: value for key, value in result["results"].items()
                                  if key != "capture_verification" and key != "final_evaluation"},
                      "cleanup": result["cleanup"]}, indent=2))


if __name__ == "__main__":
    main()
