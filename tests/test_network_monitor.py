"""Offline evidence/lifecycle tests; these do not simulate kernel networking."""
import copy
from datetime import datetime, timedelta, timezone
import unittest

from scripts import network_monitor as monitor


def ruleset():
    objects = [{"metainfo": {"version": "test", "json_schema_version": 1}},
               {"table": {"family": "inet", "name": monitor.TABLE, "handle": 1}}]
    for index, name in enumerate(sorted(monitor.COUNTERS), 2):
        objects.append({"counter": {"family": "inet", "table": monitor.TABLE, "name": name,
                                    "handle": index, "packets": 0, "bytes": 0}})
    objects.append({"chain": {"family": "inet", "table": monitor.TABLE, "name": "forward", "handle": 30,
                             "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}})
    for index, (source, target, port) in enumerate(sorted(monitor.ROWS), 31):
        allowed = (source, target, port) in monitor.ALLOWED
        prefix, verdict = ("allow", "accept") if allowed else ("drop", "drop")
        expressions = [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": source + "0"}},
                       {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": target + "0"}},
                       {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": monitor.ZONES[source]}},
                       {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": monitor.ZONES[target]}},
                       {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": port}}]
        if allowed:
            expressions.append({"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": {"set": ["new", "established"]}}})
        expressions.extend([{"match": {"op": "==", "left": {"ct": {"key": "direction"}}, "right": "original"}},
                            {"counter": f"{prefix}_{source}_{target}_{port}"}, {verdict: None}])
        objects.append({"rule": {"family": "inet", "table": monitor.TABLE, "chain": "forward", "handle": index, "expr": expressions}})
    return {"nftables": objects}


def count(raw, name, packets):
    entry = next(entry["counter"] for entry in raw["nftables"] if entry.get("counter", {}).get("name") == name)
    entry["packets"] += packets
    entry["bytes"] += packets * 60


def overblock(raw, source="user", target="app", port=8080):
    rule = next((entry["rule"] for entry in raw["nftables"]
                 if {"counter": f"allow_{source}_{target}_{port}"} in entry.get("rule", {}).get("expr", [])), None)
    if rule is None:
        return
    rule["expr"][-2:] = [{"counter": f"drop_{source}_{target}_{port}"}, {"drop": None}]


def response(target, port):
    return {"outcome": "response", "status": 200,
            "payload": {"synthetic": True, "zone": target, "service_port": port}}


class Fixture:
    def __init__(self):
        self.raw = ruleset()
        self.monitor = monitor.Monitor(self.raw)
        self.sequence, self.port = 0, 40000
        self.time = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def sample(self, rows=(), *, bad=False, unavailable=False):
        self.sequence += 1
        self.time += timedelta(seconds=2)
        phase = "sample-" + str(self.sequence)
        probes = []
        for source, target, port in rows:
            self.port += 1
            base = {"from": source, "to": target, "destination": monitor.ZONES[target], "port": port,
                    "source_port": self.port, "phase": phase,
                    "started_at_utc": (self.time - timedelta(seconds=1)).isoformat(),
                    "completed_at_utc": (self.time - timedelta(milliseconds=500)).isoformat(),
                    "destination_health": None}
            allowed = (source, target, port) in monitor.ALLOWED
            if allowed and unavailable:
                overblock(self.raw, source, target, port)
            if (allowed and not unavailable) or (not allowed and bad):
                base.update(response(target, port))
            else:
                base["outcome"] = "connect_timeout"
                health = {**base, **response(target, port), "from": target,
                          "started_at_utc": (self.time - timedelta(milliseconds=400)).isoformat(),
                          "completed_at_utc": (self.time - timedelta(milliseconds=200)).isoformat()}
                health.pop("destination_health")
                base["destination_health"] = health
                count(self.raw, f"drop_{source}_{target}_{port}", 2)
            probes.append(base)
        return {"sequence": self.sequence, "phase": phase, "observed_at_utc": self.time.isoformat(),
                "elapsed_seconds": self.sequence * 2, "ruleset": copy.deepcopy(self.raw),
                "collection_error": None, "probes": probes}

    def observe(self, *args, **kwargs):
        return self.monitor.observe(self.sample(*args, **kwargs))

    def active(self, code):
        return [a for a in self.monitor.alerts if a["code"] == code and a["state"] == "open"]


class NetworkMonitorTests(unittest.TestCase):
    def test_only_known_volatile_metadata_is_ignored(self):
        original = ruleset()
        altered = copy.deepcopy(original)
        altered["nftables"][0]["metainfo"]["version"] = "different"
        altered["nftables"][1]["table"]["handle"] = 99
        altered["nftables"][-1]["rule"]["handle"] = 99
        count(altered, "drop_user_app_9090", 3)
        self.assertEqual(monitor.policy_fingerprint(original), monitor.policy_fingerprint(altered))
        self.assertEqual(original["nftables"][1]["table"]["handle"], 1)

    def test_rule_and_expression_order_and_semantic_fields_change_reference(self):
        original = ruleset()
        for mutate in (lambda r: r["nftables"].reverse(),
                       lambda r: r["nftables"][-2]["rule"]["expr"].reverse(),
                       lambda r: r["nftables"][-2]["rule"]["expr"][0]["match"].update({"right": 9090}),
                       lambda r: r["nftables"][-1]["rule"]["expr"][0].update({"handle": "semantic"}),
                       lambda r: r["nftables"].append({"quota": {"name": "q", "bytes": 1, "used": 0}})):
            altered = copy.deepcopy(original)
            mutate(altered)
            self.assertNotEqual(monitor.policy_fingerprint(original), monitor.policy_fingerprint(altered))

    def test_empty_malformed_and_nonfinite_rulesets_are_rejected(self):
        for value in ({}, {"nftables": []}, {"nftables": [{"metainfo": {}}]},
                      {"nftables": [{"rule": []}]}, {"nftables": [{"rule": {}, "table": {}}]},
                      {"nftables": [{"quota": {"bytes": float("nan")}}]}):
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError)):
                monitor.canonical_ruleset(value)

    def test_approved_reference_needs_complete_counter_identity(self):
        original = ruleset()
        for field in ("handle", "packets"):
            raw = copy.deepcopy(original)
            del raw["nftables"][2]["counter"][field]
            with self.assertRaises(ValueError):
                monitor.Monitor(raw)
        raw = copy.deepcopy(original)
        raw["nftables"].pop(2)
        with self.assertRaises(ValueError):
            monitor.Monitor(raw)

    def test_no_probe_or_partial_probe_snapshot_is_not_healthy(self):
        fixture = Fixture()
        self.assertEqual(fixture.observe()["status"], "unknown")
        self.assertEqual(fixture.observe([monitor.CANARIES[0]])["status"], "unknown")
        self.assertEqual(fixture.observe(monitor.CANARIES)["status"], "healthy")

    def test_blocked_packets_are_info_and_repeated_observations_coalesce(self):
        fixture = Fixture()
        first = fixture.observe(monitor.CANARIES)
        self.assertEqual(first["status"], "healthy")
        fixture.observe([monitor.CANARIES[1]])
        incidents = fixture.active("blocked_traffic")
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["severity"], "info")
        self.assertEqual(incidents[0]["observations"], 2)
        events = [e for e in fixture.monitor.events if e["code"] == "blocked_traffic"]
        self.assertEqual([e["action"] for e in events], ["opened", "updated"])
        self.assertTrue(all(e["evidence"]["packet_delta"] == 2 for e in events))
        fixture.observe()
        self.assertFalse(fixture.active("blocked_traffic"))
        self.assertEqual(fixture.monitor.events[-1]["evidence"]["reason"], "no_new_drops_in_observed_interval")
        fixture.observe([monitor.CANARIES[1]])
        self.assertEqual(fixture.active("blocked_traffic")[0]["occurrence"], 2)

    def test_rule_drift_detects_before_probe_and_never_rebaselines_reference(self):
        fixture = Fixture()
        approved = fixture.monitor.approved_fingerprint
        fixture.raw["nftables"][-1]["rule"]["expr"] = [{"accept": None}]
        first = fixture.observe()
        self.assertEqual(first["status"], "alerting")
        self.assertFalse(first["policy_matches"])
        fixture.observe()
        self.assertEqual(len(fixture.active("rule_drift")), 1)
        self.assertEqual(fixture.active("rule_drift")[0]["observations"], 2)
        self.assertEqual(fixture.monitor.approved_fingerprint, approved)
        fixture.raw = ruleset()
        fixture.observe()
        self.assertFalse(fixture.active("rule_drift"))

    def test_forbidden_success_stays_open_until_explicit_denial_evidence(self):
        fixture = Fixture()
        fixture.observe([monitor.CANARIES[1]], bad=True)
        fixture.observe([monitor.CANARIES[1]], bad=True)
        self.assertEqual(len(fixture.active("forbidden_path_open")), 1)
        self.assertEqual(fixture.active("forbidden_path_open")[0]["observations"], 2)
        fixture.observe()
        self.assertTrue(fixture.active("forbidden_path_open"))
        sample = fixture.sample([monitor.CANARIES[1]])
        sample["probes"][0]["destination_health"] = None
        fixture.monitor.observe(sample)
        self.assertTrue(fixture.active("forbidden_path_open"))
        fixture.observe([monitor.CANARIES[1]])
        self.assertFalse(fixture.active("forbidden_path_open"))

    def test_allowed_failure_reports_counter_and_destination_support(self):
        fixture = Fixture()
        overblock(fixture.raw)
        fixture.observe()
        result = fixture.observe([monitor.CANARIES[0]], unavailable=True)
        incident = fixture.active("allowed_path_unavailable")[0]
        self.assertEqual(result["status"], "alerting")
        self.assertEqual(incident["last_evidence"]["reason"], "healthy_destination_and_drop_evidence")
        fixture.observe()
        self.assertTrue(fixture.active("allowed_path_unavailable"))
        fixture.observe([monitor.CANARIES[0]])
        self.assertFalse(fixture.active("allowed_path_unavailable"))

    def test_failure_without_drop_or_healthy_control_does_not_claim_firewall(self):
        fixture = Fixture()
        sample = fixture.sample([monitor.CANARIES[0]], unavailable=True)
        sample["probes"][0]["destination_health"] = None
        fixture.monitor.observe(sample)
        self.assertEqual(fixture.active("allowed_path_unavailable")[0]["last_evidence"]["reason"],
                         "allowed_service_unavailable_cause_unconfirmed")

    def test_missing_telemetry_preserves_network_alert_and_recovery_needs_fresh_interval(self):
        fixture = Fixture()
        fixture.observe([monitor.CANARIES[1]], bad=True)
        sample = fixture.sample()
        sample.update(ruleset=None, collection_error="synthetic failure")
        result = fixture.monitor.observe(sample)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["telemetry_valid"])
        self.assertTrue(fixture.active("forbidden_path_open"))
        self.assertTrue(fixture.active("telemetry_gap"))
        result = fixture.observe([monitor.CANARIES[1]])
        self.assertTrue(all(v is None for v in result["counter_deltas"].values()))
        self.assertTrue(fixture.active("forbidden_path_open"))
        result = fixture.observe(monitor.CANARIES)
        self.assertEqual(result["status"], "healthy")
        self.assertFalse(fixture.active("telemetry_gap"))
        self.assertFalse(fixture.active("counter_discontinuity"))
        self.assertFalse(fixture.active("forbidden_path_open"))

    def test_duplicate_stale_and_skipped_samples_never_clear_existing_alerts(self):
        for mode in ("duplicate", "stale_elapsed", "stale_utc", "skipped"):
            with self.subTest(mode=mode):
                fixture = Fixture()
                fixture.observe([monitor.CANARIES[1]], bad=True)
                sample = fixture.sample()
                if mode == "duplicate":
                    sample["sequence"] = 1
                elif mode == "stale_elapsed":
                    sample["elapsed_seconds"] = 0
                elif mode == "stale_utc":
                    sample["observed_at_utc"] = "2025-01-01T00:00:00+00:00"
                else:
                    sample["sequence"] = 3
                result = fixture.monitor.observe(sample)
                self.assertEqual(result["status"], "unknown")
                self.assertTrue(fixture.active("forbidden_path_open"))
                self.assertTrue(fixture.active("telemetry_gap"))

    def test_time_gap_is_unknown_and_does_not_count_unseen_packets_as_zero(self):
        fixture = Fixture()
        fixture.observe(monitor.CANARIES)
        sample = fixture.sample()
        sample["elapsed_seconds"] = 50
        result = fixture.monitor.observe(sample)
        self.assertFalse(result["telemetry_valid"])
        self.assertEqual(result["counter_deltas"], {})
        self.assertTrue(fixture.active("telemetry_gap"))

    def test_table_or_counter_identity_changes_break_continuity_without_policy_drift(self):
        for kind in ("table", "counter"):
            with self.subTest(kind=kind):
                fixture = Fixture()
                fixture.observe(monitor.CANARIES)
                next(entry[kind] for entry in fixture.raw["nftables"] if kind in entry)["handle"] += 100
                result = fixture.observe()
                self.assertTrue(result["policy_matches"])
                self.assertTrue(all(v is None for v in result["counter_deltas"].values()))
                self.assertTrue(fixture.active("counter_discontinuity"))
                self.assertEqual(fixture.observe(monitor.CANARIES)["status"], "healthy")

    def test_counter_decrease_or_missing_counter_never_emits_negative_deltas(self):
        for mode in ("decrease", "missing"):
            with self.subTest(mode=mode):
                fixture = Fixture()
                fixture.observe(monitor.CANARIES)
                counter = next(entry["counter"] for entry in fixture.raw["nftables"] if entry.get("counter", {}).get("name") == "drop_user_app_9090")
                if mode == "decrease":
                    counter.update(packets=0, bytes=0)
                else:
                    fixture.raw["nftables"] = [entry for entry in fixture.raw["nftables"] if entry.get("counter") is not counter]
                result = fixture.observe()
                self.assertTrue(all(v is None for v in result["counter_deltas"].values()))
                self.assertTrue(fixture.active("counter_discontinuity"))

    def test_wrong_destination_phase_payload_and_reused_probe_port_fail_closed(self):
        for field, value in (("destination", "10.204.30.2"), ("phase", "other"), ("payload", {"synthetic": False}), ("port", 22)):
            with self.subTest(field=field):
                fixture = Fixture()
                sample = fixture.sample([monitor.CANARIES[0]])
                sample["probes"][0][field] = value
                self.assertEqual(fixture.monitor.observe(sample)["status"], "unknown")
                self.assertTrue(fixture.active("telemetry_gap"))
        fixture = Fixture()
        first = fixture.sample([monitor.CANARIES[0]])
        fixture.monitor.observe(first)
        second = fixture.sample([monitor.CANARIES[0]])
        second["probes"][0]["source_port"] = first["probes"][0]["source_port"]
        self.assertEqual(fixture.monitor.observe(second)["status"], "unknown")

    def test_unknown_denial_without_health_is_not_healthy_even_with_full_canary_inventory(self):
        fixture = Fixture()
        sample = fixture.sample(monitor.CANARIES)
        sample["probes"][1]["destination_health"] = None
        result = fixture.monitor.observe(sample)
        self.assertEqual(len(result["canaries_checked"]), 3)
        self.assertEqual(result["status"], "unknown")

    def test_drop_named_accept_rule_cannot_claim_block_or_resolve_forbidden_access(self):
        fixture = Fixture()
        fixture.observe([monitor.CANARIES[1]], bad=True)
        rule = next(entry["rule"] for entry in fixture.raw["nftables"]
                    if {"counter": "drop_user_app_9090"} in entry.get("rule", {}).get("expr", []))
        rule["expr"][-1] = {"accept": None}
        result = fixture.observe([monitor.CANARIES[1]])
        self.assertEqual(result["counter_deltas"]["drop_user_app_9090"], 2)
        self.assertFalse(result["drop_attribution"]["drop_user_app_9090"])
        self.assertFalse(fixture.active("blocked_traffic"))
        self.assertTrue(fixture.active("forbidden_path_open"))
        self.assertTrue(fixture.active("rule_drift"))

    def test_shared_counter_with_an_accept_reference_loses_drop_attribution(self):
        fixture = Fixture()
        extra = copy.deepcopy(next(entry for entry in fixture.raw["nftables"]
                                   if {"counter": "drop_user_app_9090"} in entry.get("rule", {}).get("expr", [])))
        extra["rule"]["expr"][-1] = {"accept": None}
        fixture.raw["nftables"].append(extra)
        result = fixture.observe([monitor.CANARIES[1]])
        self.assertFalse(result["drop_attribution"]["drop_user_app_9090"])
        self.assertFalse(fixture.active("blocked_traffic"))

    def test_wrong_scope_drop_counter_cannot_diagnose_allowed_path_failure(self):
        fixture = Fixture()
        sample = fixture.sample([monitor.CANARIES[0]], unavailable=True)
        rule = next(entry["rule"] for entry in sample["ruleset"]["nftables"]
                    if {"counter": "drop_user_app_8080"} in entry.get("rule", {}).get("expr", []))
        rule["expr"][0]["match"]["right"] = "management0"
        result = fixture.monitor.observe(sample)
        self.assertFalse(result["drop_attribution"]["drop_user_app_8080"])
        self.assertEqual(fixture.active("allowed_path_unavailable")[0]["last_evidence"]["reason"],
                         "allowed_service_unavailable_cause_unconfirmed")

    def test_rule_replacement_preserving_counter_needs_a_new_drop_interval(self):
        fixture = Fixture()
        fixture.observe([monitor.CANARIES[1]], bad=True)
        rule = next(entry["rule"] for entry in fixture.raw["nftables"]
                    if {"counter": "drop_user_app_9090"} in entry.get("rule", {}).get("expr", []))
        rule["expr"][-1] = {"accept": None}
        fixture.observe()
        count(fixture.raw, "drop_user_app_9090", 3)
        rule["expr"][-1] = {"drop": None}
        result = fixture.observe([monitor.CANARIES[1]])
        self.assertEqual(result["counter_deltas"]["drop_user_app_9090"], 5)
        self.assertTrue(result["drop_rule_bindings"]["drop_user_app_9090"])
        self.assertFalse(result["drop_attribution"]["drop_user_app_9090"])
        self.assertTrue(fixture.active("forbidden_path_open"))
        self.assertFalse(fixture.active("blocked_traffic"))
        result = fixture.observe([monitor.CANARIES[1]])
        self.assertTrue(result["drop_attribution"]["drop_user_app_9090"])
        self.assertFalse(fixture.active("forbidden_path_open"))

    def test_dynamic_counter_reference_disables_drop_attribution(self):
        fixture = Fixture()
        fixture.observe([monitor.CANARIES[1]], bad=True)
        fixture.raw["nftables"].append({"rule": {"family": "inet", "table": monitor.TABLE, "chain": "forward",
            "handle": 200, "expr": [{"counter": {"map": {"key": {"meta": {"key": "mark"}},
                                                         "data": {"set": [[1, "drop_user_app_9090"]]}}}}, {"accept": None}]}})
        result = fixture.observe([monitor.CANARIES[1]])
        self.assertFalse(any(result["drop_rule_bindings"].values()))
        self.assertFalse(fixture.active("blocked_traffic"))
        self.assertTrue(fixture.active("forbidden_path_open"))

    def test_returned_evaluation_and_caller_mutations_do_not_rewrite_saved_history(self):
        fixture = Fixture()
        sample = fixture.sample(monitor.CANARIES)
        result = fixture.monitor.observe(sample)
        result["status"] = "forged"
        sample["probes"][0]["payload"]["synthetic"] = False
        self.assertEqual(fixture.monitor.evaluations[0]["status"], "healthy")
        self.assertEqual(fixture.monitor.events[0]["evidence"]["packet_delta"], 2)

    def test_full_driver_style_incident_sequence_recovers_only_after_canaries(self):
        fixture = Fixture()
        fixture.observe()
        fixture.observe(monitor.CANARIES)
        fixture.observe([monitor.CANARIES[1]])
        fixture.observe([monitor.CANARIES[1]])
        fixture.raw["nftables"][-1]["rule"]["expr"] = [{"accept": None}]
        fixture.raw["nftables"][1]["table"]["handle"] = 500
        fixture.observe()
        fixture.observe([monitor.CANARIES[1]], bad=True)
        fixture.observe([monitor.CANARIES[1]], bad=True)
        lost = fixture.sample()
        lost.update(ruleset=None, collection_error="synthetic failure")
        fixture.monitor.observe(lost)
        fixture.observe([monitor.CANARIES[1]], bad=True)
        fixture.raw = ruleset()
        fixture.observe()
        self.assertTrue(fixture.active("forbidden_path_open"))
        self.assertEqual(fixture.observe(monitor.CANARIES)["status"], "healthy")
        fixture.raw["nftables"][-2]["rule"]["expr"][-1] = {"drop": None}
        fixture.raw["nftables"][1]["table"]["handle"] = 600
        fixture.observe()
        fixture.observe([monitor.CANARIES[0]], unavailable=True)
        fixture.raw = ruleset()
        fixture.observe()
        self.assertTrue(fixture.active("allowed_path_unavailable"))
        self.assertEqual(fixture.observe(monitor.CANARIES)["status"], "healthy")
        self.assertFalse(any(a["state"] == "open" and a["severity"] in {"warning", "high", "critical"}
                             for a in fixture.monitor.alerts))


if __name__ == "__main__":
    unittest.main()
