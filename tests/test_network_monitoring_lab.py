"""Portable orchestration checks; the fixture does not simulate Linux packets."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import network_monitoring_lab as lab

TOOLS = {name: "/tools/" + name for name in ("ip", "nft", "tcpdump", "sysctl", "git")}


class ScenarioFixture:
    """Supplies deterministic nft-shaped observations to the real alert engine."""
    def __init__(self):
        self.probes, self.phase, self.generation = [], "readiness", 0
        self.names = dict.fromkeys((*lab.segmentation.ZONES, "router"), "owned-test")
        self.apply_policy()

    def setup(self):
        pass

    start_services = setup
    start_captures = setup

    def apply_policy(self, mode="restricted"):
        self.mode = mode
        self.generation += 1
        self.counts = dict.fromkeys(lab.monitor.COUNTERS, 0)

    def apply_overblock(self):
        self.apply_policy("overblocked")

    def ruleset(self):
        records = [{"metainfo": {"version": "fixture"}},
                   {"table": {"family": "inet", "name": lab.monitor.TABLE, "handle": self.generation}}]
        for index, name in enumerate(sorted(self.counts)):
            records.append({"counter": {"family": "inet", "table": lab.monitor.TABLE,
                            "name": name, "handle": self.generation * 100 + index + 1,
                            "packets": self.counts[name], "bytes": self.counts[name] * 60}})
        records.append({"chain": {"family": "inet", "table": lab.monitor.TABLE, "name": "forward",
                                  "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}})
        rules = []
        for index, row in enumerate(lab.segmentation.MATRIX, 50):
            source, target, port = row["from"], row["to"], row["port"]
            allowed = (source, target, port) in lab.segmentation.ALLOWED
            expr = [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": source + "0"}},
                    {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": target + "0"}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": lab.segmentation.ZONES[source]}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": lab.segmentation.ZONES[target]}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": port}}]
            if allowed:
                expr.append({"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": {"set": ["new", "established"]}}})
            expr.append({"match": {"op": "==", "left": {"ct": {"key": "direction"}}, "right": "original"}})
            blocked = not allowed or self.mode == "overblocked" and (source, target, port) == ("user", "app", 8080)
            counter = ("drop" if blocked else "allow") + f"_{source}_{target}_{port}"
            expr.extend([{"counter": counter}, {"drop" if blocked else "accept": None}])
            rules.append({"rule": {"family": "inet", "table": lab.monitor.TABLE, "chain": "forward",
                                   "handle": self.generation * 100 + index, "expr": expr}})
        if self.mode == "misconfigured":
            original = next(rule for rule in rules if {"counter": "drop_user_app_9090"} in rule["rule"]["expr"])
            injected = copy.deepcopy(original)
            injected["rule"]["handle"] += 50
            injected["rule"]["expr"][-2:] = [{"counter": "injected_user_app_9090"}, {"accept": None}]
            rules.insert(0, injected)
        records.extend(rules)
        return {"nftables": records}

    def probe(self, source, target, port):
        key = (source, target, port)
        value = {"from": source, "to": target, "destination": lab.segmentation.ZONES[target], "port": port,
                 "phase": self.phase, "source_port": 40000 + len(self.probes), "started_at_utc": lab.timestamp()}
        denied = source != target and (key not in lab.segmentation.ALLOWED
                  and not (self.mode == "misconfigured" and key == lab.segmentation.EXCEPTION)
                  or self.mode == "overblocked" and key == ("user", "app", 8080))
        if denied:
            value["outcome"] = "connect_timeout"
            self.counts[f"drop_{source}_{target}_{port}"] += 2
        else:
            value.update({"outcome": "response", "status": 200,
                          "payload": {"synthetic": True, "zone": target, "service_port": port}})
            if source != target:
                name = "injected_user_app_9090" if key == lab.segmentation.EXCEPTION else f"allow_{source}_{target}_{port}"
                self.counts[name] += 6
        value["completed_at_utc"] = lab.timestamp()
        self.probes.append(value)
        return value

    def stop_captures(self):
        return {"ok": True, "routed_flows_verified": 15}


class MonitoringLabTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="network-monitoring-tests-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()

    def test_complete_scenario_uses_real_engine_and_preserves_pinned_reference(self):
        fixture = ScenarioFixture()
        result = lab.run_exercise(fixture)
        self.assertEqual(len(result["samples"]), 15)
        self.assertEqual(len(fixture.probes), 21)
        self.assertTrue(result["results"]["final_policy_compliant"])
        self.assertEqual(result["results"]["final_evaluation"]["status"], "healthy")
        self.assertEqual(lab.monitor.policy_fingerprint(result["approved_policy"]),
                         lab.monitor.policy_fingerprint(result["samples"][-1]["ruleset"]))
        self.assertEqual([s["phase"] for s in result["samples"]], list(lab.PHASES))

    def test_rule_drift_precedes_forbidden_probe_and_loss_does_not_resolve_it(self):
        result = lab.run_exercise(ScenarioFixture())
        samples, events = result["samples"], result["events"]
        drift = next(e for e in events if e["code"] == "rule_drift" and e["action"] == "opened")
        forbidden = next(e for e in events if e["code"] == "forbidden_path_open" and e["action"] == "opened")
        self.assertLess(drift["sequence"], forbidden["sequence"])
        self.assertFalse(samples[drift["sequence"] - 1]["probes"])
        loss = samples[7]
        self.assertIsNone(loss["ruleset"])
        self.assertEqual(loss["collection_error"], "injected_collection_loss")
        self.assertFalse(any(e["action"] == "resolved" and e["code"] in {"rule_drift", "forbidden_path_open"}
                             for e in events if e["sequence"] == loss["sequence"]))

    def test_repair_requires_fresh_denial_and_overblock_requires_response_recovery(self):
        result = lab.run_exercise(ScenarioFixture())
        events = result["events"]
        recovered = [e for e in events if e["action"] == "resolved" and e["code"] == "forbidden_path_open"]
        self.assertEqual([e["phase"] for e in recovered], ["repair_canaries"])
        availability = [e for e in events if e["code"] == "allowed_path_unavailable"]
        self.assertEqual(availability[0]["evidence"]["reason"], "healthy_destination_and_drop_evidence")
        self.assertEqual(availability[-1]["phase"], "final_canaries")
        self.assertEqual(availability[-1]["action"], "resolved")

    def test_missing_alert_cannot_be_published_as_successful_scenario(self):
        original = lab.monitor.Monitor.observe
        def erase(engine, sample):
            result = original(engine, sample)
            if sample["phase"] == "forbidden_open":
                result["active_alert_keys"] = []
            return result
        with patch.object(lab.monitor.Monitor, "observe", erase), self.assertRaisesRegex(RuntimeError, "missed an expected alert"):
            lab.run_exercise(ScenarioFixture())

    def test_missing_capture_flow_fails_scenario(self):
        fixture = ScenarioFixture()
        fixture.stop_captures = lambda: {"ok": True, "routed_flows_verified": 14}
        with self.assertRaisesRegex(RuntimeError, "all monitored canaries"):
            lab.run_exercise(fixture)

    def test_unknown_final_status_cannot_be_published_as_compliant(self):
        original = lab.monitor.Monitor.observe
        def unknown(engine, sample):
            result = original(engine, sample)
            if sample["phase"] == "final_canaries":
                result["status"] = "unknown"
            return result
        with patch.object(lab.monitor.Monitor, "observe", unknown), self.assertRaisesRegex(RuntimeError, "fresh complete monitored coverage"):
            lab.run_exercise(ScenarioFixture())

    def test_inventory_rejects_missing_sample_probe_reused_port_and_false_loss(self):
        fixture = ScenarioFixture()
        result = lab.run_exercise(fixture)
        scenarios = []
        changed = copy.deepcopy(result["samples"])
        changed.pop()
        scenarios.append((copy.deepcopy(fixture.probes), changed))
        changed = copy.deepcopy(result["samples"])
        changed[1]["probes"].pop()
        scenarios.append((copy.deepcopy(fixture.probes), changed))
        changed_probes = copy.deepcopy(fixture.probes)
        changed_probes[1]["source_port"] = changed_probes[0]["source_port"]
        scenarios.append((changed_probes, copy.deepcopy(result["samples"])))
        changed = copy.deepcopy(result["samples"])
        changed[7]["collection_error"] = None
        scenarios.append((copy.deepcopy(fixture.probes), changed))
        for probes, samples in scenarios:
            with self.subTest(count=len(samples)), self.assertRaises(RuntimeError):
                lab.require_inventory(Mock(probes=probes), samples)

    def test_overblock_changes_only_exact_permit_to_existing_drop_counter(self):
        original = lab.segmentation.policy_text()
        changed = lab.overblocked_policy()
        self.assertEqual(changed.replace("counter name drop_user_app_8080 drop", "counter name allow_user_app_8080 accept"), original)
        self.assertEqual(changed.count("counter name drop_user_app_8080 drop"), 1)
        with patch.object(lab.segmentation, "policy_text", return_value=original.replace("allow_user_app_8080", "other")), self.assertRaises(RuntimeError):
            lab.overblocked_policy()

    def test_snapshot_and_overblock_commands_are_scoped_to_owned_router(self):
        instance = lab.MonitoringLab(TOOLS, self.base)
        with self.assertRaisesRegex(RuntimeError, "exclusively created"):
            instance.ruleset()
        instance.created_names.append(instance.names["router"])
        response = subprocess.CompletedProcess([], 0, '{"nftables": []}', "")
        with patch.object(instance, "command", return_value=response) as command:
            self.assertEqual(instance.ruleset(), {"nftables": []})
            self.assertEqual(command.call_args.args[0], [TOOLS["ip"], "netns", "exec", instance.names["router"],
                                                        TOOLS["nft"], "-j", "-a", "list", "ruleset"])
            instance.apply_overblock()
            self.assertEqual(command.call_args.kwargs["input"], lab.overblocked_policy())
            self.assertEqual(command.call_args.args[0][:4], [TOOLS["ip"], "netns", "exec", instance.names["router"]])

    def test_mac_guard_stops_before_creating_output_or_source_read(self):
        output = self.base / "refused"
        with patch.object(lab.base.sys, "platform", "darwin"), patch.object(lab, "source_identity") as identity:
            with self.assertRaisesRegex(RuntimeError, "disposable Linux"):
                lab.run(output)
        self.assertFalse(output.exists())
        identity.assert_not_called()

    def test_failed_scenario_still_cleans_up_and_never_publishes(self):
        output = self.base / "failed"
        instance = Mock(names={}, cleanup=Mock(return_value={"ok": True}))
        with patch.object(lab.base, "preflight", return_value=TOOLS), patch.object(lab, "source_identity", return_value={"commit": "a" * 40}), \
             patch.object(lab, "MonitoringLab", return_value=instance), patch.object(lab, "run_exercise", side_effect=RuntimeError("missing expected alert")):
            with self.assertRaisesRegex(RuntimeError, "missing expected alert"):
                lab.run(output)
        instance.cleanup.assert_called_once()
        self.assertFalse((output / "publish").exists())
        self.assertFalse(json.loads((output / "staging/REPORT.json").read_text())["ok"])

    def successful_run_fixture(self, output):
        scenario = lab.run_exercise(ScenarioFixture())
        instance = Mock(names={})
        instance.cleanup.return_value = {"ok": True, "owned_namespaces_removed": 4,
                                         "owned_virtual_links_removed": 6, "tracked_processes_stopped": 6}
        def exercise(value):
            for zone in lab.segmentation.ZONES:
                (output / "staging" / (zone + ".pcap")).write_bytes(b"mocked portable publication fixture")
                (output / "staging" / (zone + "-packets.txt")).write_text("synthetic fixture\n")
            return scenario
        return instance, exercise

    def test_publication_has_exact_allowlist_manifest_and_no_private_stderr(self):
        output = self.base / "success"
        instance, exercise = self.successful_run_fixture(output)
        with patch.object(lab.base, "preflight", return_value=TOOLS), patch.object(lab, "source_identity", return_value={"commit": "a" * 40}), \
             patch.object(lab, "MonitoringLab", return_value=instance), patch.object(lab, "run_exercise", side_effect=exercise):
            report = lab.run(output)
        self.assertTrue(report["ok"])
        publish = output / "publish"
        self.assertEqual({p.name for p in publish.iterdir()}, set(lab.PUBLIC_FILES) | {"MANIFEST.json"})
        self.assertEqual(len(list(publish.iterdir())), 16)
        manifest = json.loads((publish / "MANIFEST.json").read_text())
        self.assertEqual(len(manifest), 15)
        for name, expected in manifest.items():
            self.assertEqual(hashlib.sha256((publish / name).read_bytes()).hexdigest(), expected)
            self.assertEqual((publish / name).stat().st_mode & 0o777, 0o644)
        self.assertTrue((publish / "EVENTS.jsonl").read_text().endswith("\n"))
        summary = (publish / "SUMMARY.md").read_text()
        self.assertIn("Final monitored coverage: **healthy**", summary)
        self.assertIn("| forbidden_path_open | critical | user->app:9090 | 1 | 6 | 11 |", summary)

    def test_cleanup_failure_prevents_publication(self):
        output = self.base / "cleanup-failure"
        instance, exercise = self.successful_run_fixture(output)
        instance.cleanup.side_effect = RuntimeError("owned namespace remains")
        with patch.object(lab.base, "preflight", return_value=TOOLS), patch.object(lab, "source_identity", return_value={"commit": "a" * 40}), \
             patch.object(lab, "MonitoringLab", return_value=instance), patch.object(lab, "run_exercise", side_effect=exercise):
            with self.assertRaisesRegex(RuntimeError, "owned namespace remains"):
                lab.run(output)
        self.assertFalse((output / "publish").exists())

    def test_source_change_during_run_prevents_publication(self):
        output = self.base / "changed-source"
        instance, exercise = self.successful_run_fixture(output)
        with patch.object(lab.base, "preflight", return_value=TOOLS), \
             patch.object(lab, "source_identity", side_effect=[{"commit": "a" * 40}, {"commit": "b" * 40}]), \
             patch.object(lab, "MonitoringLab", return_value=instance), patch.object(lab, "run_exercise", side_effect=exercise):
            with self.assertRaisesRegex(RuntimeError, "source changed"):
                lab.run(output)
        self.assertFalse((output / "publish").exists())

    def test_new_source_files_must_match_the_committed_bytes(self):
        for name in lab.SOURCE_FILES[len(lab.segmentation.SOURCE_FILES):]:
            file = self.base / name
            file.parent.mkdir(exist_ok=True)
            file.write_bytes(b"expected")
        old = {"commit": "a" * 40, "source_sha256": {}}
        def git(arguments, **kwargs):
            self.assertIn(f"safe.directory={self.base}", arguments)
            return subprocess.CompletedProcess(arguments, 0, b"expected", b"")
        with patch.object(lab.segmentation, "source_identity", return_value=old), patch.object(lab.subprocess, "run", side_effect=git):
            identity = lab.source_identity(self.base)
        self.assertEqual(len(identity["source_sha256"]), 2)
        with patch.object(lab.segmentation, "source_identity", return_value=old), \
             patch.object(lab.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, b"different", b"")):
            with self.assertRaisesRegex(RuntimeError, "committed version"):
                lab.source_identity(self.base)


if __name__ == "__main__":
    unittest.main()
