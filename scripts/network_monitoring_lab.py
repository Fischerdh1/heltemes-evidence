"""Exercise bounded monitoring and alert recovery on disposable Linux networks."""
from __future__ import annotations

import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_lab as base
from scripts import network_segmentation_lab as segmentation
from scripts import network_monitor as monitor

require, timestamp = base.require, base.timestamp
SOURCE_FILES = (*segmentation.SOURCE_FILES, "scripts/network_monitor.py", "scripts/network_monitoring_lab.py")
PUBLIC_FILES = ("REPORT.json", "APPROVED_POLICY.json", "SNAPSHOTS.json", "EVALUATIONS.json", "ALERTS.json",
                "EVENTS.jsonl", "SUMMARY.md", "policy.nft", "overblocked-policy.nft",
                *(name for zone in segmentation.ZONES for name in (zone + ".pcap", zone + "-packets.txt")))
CANARIES = (("user", "app", 8080), ("user", "app", 9090), ("management", "app", 9090))
PHASES = ("reference", "approved_baseline", "blocked_repeat_one", "blocked_repeat_two",
          "rule_drift_before_probe", "forbidden_open", "forbidden_repeated", "telemetry_loss",
          "telemetry_restored_bad", "repair_rules_only", "repair_canaries", "overblocked_rules_only",
          "overblocked_canary", "final_repair_rules_only", "final_canaries")
EXPECTED_PROBES = {
    phase: tuple((*row, "connect_timeout" if row == ("user", "app", 9090) else "response") for row in CANARIES)
    for phase in ("approved_baseline", "repair_canaries", "final_canaries")
}
EXPECTED_PROBES.update({phase: (("user", "app", 9090, "connect_timeout"),)
                        for phase in ("blocked_repeat_one", "blocked_repeat_two")})
EXPECTED_PROBES.update({phase: (("user", "app", 9090, "response"),)
                        for phase in ("forbidden_open", "forbidden_repeated", "telemetry_restored_bad")})
EXPECTED_PROBES["overblocked_canary"] = (("user", "app", 8080, "connect_timeout"),)


def overblocked_policy():
    policy = segmentation.policy_text()
    original = "counter name allow_user_app_8080 accept"
    require(policy.count(original) == 1, "The controlled overblock target is not unique.")
    return policy.replace(original, "counter name drop_user_app_8080 drop")


def source_identity(root=ROOT, environment=None):
    root = Path(root).resolve()
    identity = segmentation.source_identity(root, environment)
    for name in SOURCE_FILES[len(segmentation.SOURCE_FILES):]:
        content = (root / name).read_bytes()
        result = subprocess.run(["git", "-c", f"safe.directory={root}", "-C", str(root),
                                 "show", f"{identity['commit']}:{name}"], capture_output=True, timeout=30)
        require(result.returncode == 0 and content == result.stdout, "Monitoring source differs from its committed version.")
        identity["source_sha256"][name] = hashlib.sha256(content).hexdigest()
    return identity


class MonitoringLab(segmentation.SegmentationLab):
    def ruleset(self):
        result = self.run_in("router", [self.tools["nft"], "-j", "-a", "list", "ruleset"])
        return json.loads(result.stdout)

    def apply_overblock(self):
        self.run_in("router", [self.tools["nft"], "-f", "-"], input=overblocked_policy())


def active_codes(evaluation, engine):
    keys = set(evaluation["active_alert_keys"])
    return {alert["code"] for alert in engine.alerts if alert["key"] in keys and alert["state"] == "open"}


def require_active(evaluation, engine, *codes):
    require(set(codes) <= active_codes(evaluation, engine), "The monitor missed an expected alert in " + evaluation["phase"])


def require_not_active(evaluation, engine, *codes):
    require(not set(codes).intersection(active_codes(evaluation, engine)), "An alert did not recover correctly in " + evaluation["phase"])


def alert_table(alerts):
    lines = ["| Alert | Severity | Scope | Occurrence | Opened sample | Resolved sample | Observations |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    def cell(value):
        return str(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")
    for alert in alerts:
        values = (alert["code"], alert["severity"], alert["scope"], alert["occurrence"],
                  alert["opened_sequence"], alert["resolved_sequence"] if alert["state"] == "resolved" else "Open",
                  alert["observations"])
        lines.append("| " + " | ".join(cell(value) for value in values) + " |")
    return "\n".join(lines)


def require_inventory(lab, samples):
    require(tuple(sample["phase"] for sample in samples) == PHASES
            and [sample["sequence"] for sample in samples] == list(range(1, 16)), "Monitoring sample sequence is incomplete.")
    routed = [probe for probe in lab.probes if probe["from"] != probe["to"]]
    controls = [probe for probe in lab.probes if probe["from"] == probe["to"]]
    require(len(routed) == 15 and len(controls) == 6
            and len({probe["source_port"] for probe in lab.probes}) == len(lab.probes), "Monitoring probe/control inventory is incomplete or reuses ports.")
    require(Counter(probe["outcome"] for probe in routed) == {"response": 9, "connect_timeout": 6}, "Unexpected monitored connection outcomes.")
    for sample in samples:
        phase = sample["phase"]
        actual = tuple((probe["from"], probe["to"], probe["port"], probe["outcome"]) for probe in sample["probes"])
        require(actual == EXPECTED_PROBES.get(phase, ()), "Monitoring canary inventory differs in " + phase)
        require([probe for probe in routed if probe["phase"] == phase] == sample["probes"], "A routed probe is missing from its sample.")
        for probe in sample["probes"]:
            if probe["outcome"] == "response":
                segmentation.require_response(probe, probe["to"], probe["port"])
                require(probe.get("destination_health") is None, "A successful canary has an unexpected health control.")
            else:
                health = probe["destination_health"]
                segmentation.require_response(health, probe["to"], probe["port"])
                require(health in controls and health["from"] == health["to"] == probe["to"]
                        and health["phase"] == phase, "A denial lacks its matching destination-local health control.")
    losses = [sample for sample in samples if sample["ruleset"] is None]
    require(len(losses) == 1 and losses[0]["phase"] == "telemetry_loss"
            and losses[0]["collection_error"] == "injected_collection_loss", "The telemetry-loss injection was not recorded explicitly.")


def run_exercise(lab):
    require(tuple(monitor.CANARIES) == CANARIES, "Driver canaries differ from the monitored contract.")
    lab.setup()
    lab.start_services()
    lab.apply_policy()
    approved = lab.ruleset()
    pinned = copy.deepcopy(approved)
    engine = monitor.Monitor(approved, max_gap_seconds=30)
    lab.start_captures()
    samples, expectations = [], []
    started = time.monotonic()

    def sample(phase, rows=(), *, loss=False):
        lab.phase = phase
        probes = []
        for source, target, port in rows:
            probe = lab.probe(source, target, port)
            probe["destination_health"] = None
            if probe["outcome"] == "connect_timeout":
                probe["destination_health"] = lab.probe(target, target, port)
            probes.append(probe)
        ruleset = None if loss else lab.ruleset()
        value = {"sequence": len(samples) + 1, "phase": phase, "observed_at_utc": timestamp(),
                 "elapsed_seconds": time.monotonic() - started,
                 "ruleset": ruleset,
                 "collection_error": "injected_collection_loss" if loss else None, "probes": probes}
        samples.append(copy.deepcopy(value))
        evaluated = engine.observe(value)
        return evaluated

    initial = sample("reference")
    require(initial["telemetry_valid"] and initial["policy_matches"] and initial["status"] != "healthy",
            "A rule-only reference observation must not claim healthy canary coverage.")
    baseline = sample("approved_baseline", CANARIES)
    require(baseline["status"] == "healthy", "The approved baseline lacks verified complete coverage.")
    require_active(baseline, engine, "blocked_traffic")
    require_not_active(baseline, engine, "rule_drift", "forbidden_path_open", "allowed_path_unavailable", "telemetry_gap")
    first = sample("blocked_repeat_one", (("user", "app", 9090),))
    second = sample("blocked_repeat_two", (("user", "app", 9090),))
    require_active(first, engine, "blocked_traffic")
    require_active(second, engine, "blocked_traffic")
    blocked_incidents = [alert for alert in engine.alerts if alert["code"] == "blocked_traffic"]
    require(len(blocked_incidents) == 1, "Repeated drops opened duplicate incidents instead of updating the existing one.")
    expectations.append("Repeated blocked traffic updates one informational incident; packet deltas are not attack or unique-connection counts.")

    lab.apply_policy("misconfigured")
    drift = sample("rule_drift_before_probe")
    require_active(drift, engine, "rule_drift", "counter_discontinuity")
    require_not_active(drift, engine, "forbidden_path_open")
    opened = sample("forbidden_open", (("user", "app", 9090),))
    repeated = sample("forbidden_repeated", (("user", "app", 9090),))
    require_active(opened, engine, "rule_drift", "forbidden_path_open")
    require_active(repeated, engine, "rule_drift", "forbidden_path_open")
    require(len([a for a in engine.alerts if a["code"] == "forbidden_path_open"]) == 1,
            "Repeated forbidden responses opened duplicate policy-violation incidents.")
    expectations.append("Rule drift is detected before a forbidden canary proves that the incorrect permit exposes the endpoint.")

    loss = sample("telemetry_loss", loss=True)
    require(loss["status"] == "unknown" and not loss["telemetry_valid"], "Missing telemetry must not report a healthy network.")
    require_active(loss, engine, "telemetry_gap", "rule_drift", "forbidden_path_open")
    restored_bad = sample("telemetry_restored_bad", (("user", "app", 9090),))
    require_active(restored_bad, engine, "rule_drift", "forbidden_path_open")
    expectations.append("Explicitly injected collection loss produces unknown coverage and preserves unresolved network alerts.")

    lab.apply_policy()
    repaired_rules = sample("repair_rules_only")
    require_not_active(repaired_rules, engine, "rule_drift")
    require_active(repaired_rules, engine, "forbidden_path_open", "counter_discontinuity")
    repaired = sample("repair_canaries", CANARIES)
    require(repaired["status"] == "healthy", "The repaired canaries did not establish healthy monitored coverage.")
    require_not_active(repaired, engine, "rule_drift", "forbidden_path_open", "counter_discontinuity", "telemetry_gap")
    expectations.append("An approved ruleset alone does not clear forbidden reachability; fresh denied canary, healthy service, and positive drop delta establish recovery.")

    lab.apply_overblock()
    overblocked_rules = sample("overblocked_rules_only")
    require_active(overblocked_rules, engine, "rule_drift", "counter_discontinuity")
    overblocked = sample("overblocked_canary", (("user", "app", 8080),))
    require_active(overblocked, engine, "rule_drift", "allowed_path_unavailable")
    require(overblocked["counter_deltas"].get("drop_user_app_8080", 0) > 0, "The overblock lacks its matching drop-counter evidence.")
    expectations.append("An overly restrictive rule triggers drift and allowed-path availability alerts while the destination remains healthy.")

    lab.apply_policy()
    final_rules = sample("final_repair_rules_only")
    require_not_active(final_rules, engine, "rule_drift")
    require_active(final_rules, engine, "allowed_path_unavailable", "counter_discontinuity")
    final = sample("final_canaries", CANARIES)
    require(final["status"] == "healthy" and final["telemetry_valid"] and final["policy_matches"]
            and {(row["from"], row["to"], row["port"]) for row in final["canaries_checked"]} == set(CANARIES),
            "The final sample lacks fresh complete monitored coverage.")
    require_not_active(final, engine, "rule_drift", "forbidden_path_open", "allowed_path_unavailable", "telemetry_gap", "counter_discontinuity")
    require(approved == pinned, "The approved monitoring reference changed during the exercise.")
    require_inventory(lab, samples)
    coverage = lab.stop_captures()
    require(coverage["routed_flows_verified"] == 15, "Captures do not cover all monitored canaries.")
    return {"approved_policy": approved, "samples": samples, "evaluations": engine.evaluations,
            "alerts": engine.alerts, "events": engine.events,
            "results": {"scenario_assertions": expectations, "capture_verification": coverage,
                        "final_policy_compliant": True, "final_evaluation": final,
                        "summary": {"samples": 15, "routed_probes": 15, "successful_connections": 9,
                                    "denied_connections": 6, "destination_health_controls": 6,
                                    "canaries_per_complete_sample": 3, "injected_telemetry_losses": 1,
                                    "injected_rule_faults": 2}}}


def run(output):
    tools = base.preflight()
    source = source_identity()
    destination = base.new_output(output)
    staging = destination / "staging"
    staging.mkdir(mode=0o700)
    lab = MonitoringLab(tools, staging)
    report = {"format": "heltemes-network-monitoring-lab", "version": 1, "ok": False,
              "started_at_utc": timestamp(), "source": source,
              "topology": {"zones": segmentation.ZONES, "gateways": segmentation.GATEWAYS,
                           "router_interfaces": segmentation.INTERFACES, "namespaces": lab.names},
              "scope": {"synthetic_only": True, "aws_deployed": False, "real_evidence_inputs": False,
                        "bounded_sampled_monitor": True, "continuous_daemon": False, "external_notifications": False,
                        "authentication_tested": False, "physical_network_hardware_tested": False,
                        "ipv6_tested": False, "same_privilege_attacker_resistance": False},
              "sampling": {"max_gap_seconds": 30, "canaries": [{"from": s, "to": d, "port": p} for s, d, p in CANARIES],
                           "counter_semantics": "packet deltas, not unique connections or proof of an attack",
                           "reference_origin": "Snapshot of committed intended policy installed in the fresh owned router namespace; pinned for this run"}}
    exercise = None
    try:
        exercise = run_exercise(lab)
        report["results"] = exercise["results"]
        report["approved_policy_sha256"] = monitor.policy_fingerprint(exercise["approved_policy"])
        require(source_identity() == source, "Monitoring source changed during execution.")
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
        raise RuntimeError("Monitoring exercise failed: " + " ".join(value for value in (report.get("error"), report["cleanup"].get("error")) if value))
    documents = {"APPROVED_POLICY.json": exercise["approved_policy"], "SNAPSHOTS.json": exercise["samples"],
                 "EVALUATIONS.json": exercise["evaluations"], "ALERTS.json": exercise["alerts"]}
    for name, value in documents.items():
        (staging / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    (staging / "EVENTS.jsonl").write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in exercise["events"]))
    (staging / "policy.nft").write_text(segmentation.policy_text())
    (staging / "overblocked-policy.nft").write_text(overblocked_policy())
    (staging / "SUMMARY.md").write_text(f"""# HELTEMES Evidence network monitoring exercise

Source commit `{source['commit']}`. Completed {report['completed_at_utc']}.

- Fifteen observations (fourteen live ruleset snapshots and one injected collection gap) and fifteen routed canaries passed the scenario checks: nine successful connections, six denials, and six destination-local health controls.
- Repeated blocked packets updated one informational incident; packet totals do not identify unique connections or prove an attack.
- A permissive rule raised drift before any forbidden probe, then a successful forbidden probe raised a reachability alert.
- Explicitly injected collection loss preserved unresolved alerts and reported unknown coverage.
- Repair required fresh behavior evidence; counter replacement/reset did not become a negative delta or a clean interval.
- An overly restrictive rule raised an allowed-path availability alert; final repair passed all three monitored canaries.
- Three closed captures covered all fifteen routed probes with zero kernel drops. Four namespaces, six virtual endpoints, and six service/capture processes were cleaned up.

Final monitored coverage: **{exercise['results']['final_evaluation']['status']}**, with the approved ruleset and all three canaries freshly verified.

## Observed alert lifecycle

{alert_table(exercise['alerts'])}

Sample numbers link to SNAPSHOTS.json and EVALUATIONS.json. Repeated observations update the same occurrence; a later recurrence opens another occurrence.
An informational blocked-traffic alert can remain open while the tested policy is healthy. Its resolution means no new drops in an observed interval, not proof that an attack ended.

Inspect SNAPSHOTS.json, EVALUATIONS.json, ALERTS.json, and EVENTS.jsonl together. Event IDs connect alert lifecycle changes to numbered observations.
This is a bounded sampled demonstration, not a continuously deployed monitor or external notification service. It may miss changes between samples.
The pinned reference comes from the committed policy applied to a fresh disposable router, not an administrator-resistant external trust service.
AWS and the real Evidence key/history remain outside this exercise.
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
        parser.exit(1, "Network monitoring lab stopped: " + str(error) + "\n")
    print(json.dumps({"ok": result["ok"], "source_commit": result["source"]["commit"],
                      "summary": result["results"]["summary"], "cleanup": result["cleanup"]}, indent=2))


if __name__ == "__main__":
    main()
