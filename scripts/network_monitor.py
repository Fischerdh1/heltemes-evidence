"""Evidence-bound alerts for a bounded, synthetic network-monitoring exercise.

This module neither configures networking nor sends external notifications. A caller
supplies a pinned approved ruleset and timestamped observations from its owned lab.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import math

ZONES = {"user": "10.204.10.2", "app": "10.204.20.2", "management": "10.204.30.2"}
PORTS = (8080, 9090)
ALLOWED = frozenset({("user", "app", 8080), ("management", "app", 8080), ("management", "app", 9090)})
CANARIES = (("user", "app", 8080), ("user", "app", 9090), ("management", "app", 9090))
ROWS = frozenset((source, target, port) for source in ZONES for target in ZONES if source != target for port in PORTS)
TABLE = "heltemes_segmentation"
COUNTERS = frozenset(f"{verdict}_{source}_{target}_{port}" for source, target, port in ROWS
                     for verdict in ("allow", "drop")) | {"injected_user_app_9090"}
FAILURES = frozenset({"connect_timeout", "read_timeout", "socket_error", "protocol_error"})


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def utc(value):
    require(isinstance(value, str), "Observation timestamp must be UTC text.")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed),
            "Observation timestamp must include UTC offset.")
    return parsed.timestamp()


def canonical_ruleset(raw):
    """Remove only documented volatile object metadata; retain rule ordering."""
    require(isinstance(raw, dict) and set(raw) == {"nftables"} and isinstance(raw["nftables"], list),
            "A complete nft JSON ruleset is required.")
    require(1 <= len(raw["nftables"]) <= 512, "Ruleset inventory is empty or oversized.")
    result = []
    for entry in raw["nftables"]:
        require(isinstance(entry, dict) and len(entry) == 1, "Invalid nft object envelope.")
        kind, value = next(iter(entry.items()))
        require(isinstance(kind, str) and isinstance(value, dict), "Invalid nft object.")
        if kind == "metainfo":
            continue
        # Do not recursively remove keys: expression values can have semantic names.
        normalized = copy.deepcopy(value)
        if kind in {"table", "chain", "rule", "counter", "set", "map", "flowtable", "quota", "limit", "ct helper", "ct timeout", "ct expectation"}:
            normalized.pop("handle", None)
        if kind == "counter" and "name" in normalized:
            normalized.pop("packets", None)
            normalized.pop("bytes", None)
        result.append({kind: normalized})
    require(result, "Ruleset contains no configuration.")
    require(len(json.dumps(result, sort_keys=True, allow_nan=False)) <= 512_000, "Ruleset exceeds size limit.")
    return {"nftables": result}


def policy_fingerprint(raw):
    encoded = json.dumps(canonical_ruleset(raw), sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def counter_snapshot(raw):
    tables, counters = [], {}
    for entry in raw["nftables"]:
        if "table" in entry:
            value = entry["table"]
            if value.get("family") == "inet" and value.get("name") == TABLE:
                require(integer(value.get("handle"), 1), "Named table identity is unavailable.")
                tables.append(value["handle"])
        if "counter" in entry:
            value = entry["counter"]
            if value.get("family") != "inet" or value.get("table") != TABLE:
                continue
            name = value.get("name")
            require(isinstance(name, str) and name not in counters, "Counter names are missing or duplicate.")
            require(all(integer(value.get(field)) for field in ("packets", "bytes"))
                    and integer(value.get("handle"), 1), "Counter values or identity are invalid.")
            counters[name] = {field: value[field] for field in ("packets", "bytes", "handle")}
    require(len(tables) <= 1, "Duplicate monitored table identity.")
    return {"table_handle": tables[0] if tables else None, "counters": counters}


def good_response(probe, target, port):
    return (probe.get("outcome") == "response" and probe.get("status") == 200
            and probe.get("payload") == {"synthetic": True, "zone": target, "service_port": port})


def counter_expressions(value):
    """Find counter expressions without interpreting dynamic or anonymous forms."""
    found = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "counter":
                found.append(child)
            found.extend(counter_expressions(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(counter_expressions(child))
    return found


def named_references(value):
    return [reference for reference in counter_expressions(value) if isinstance(reference, str)]


def scoped_rules(raw):
    rules = []
    for entry in canonical_ruleset(raw)["nftables"]:
        rule = entry.get("rule")
        if rule and rule.get("family") == "inet" and rule.get("table") == TABLE:
            rules.append(rule)
    return rules


def approved_drop_templates(raw):
    templates, rules = {}, scoped_rules(raw)
    for source, target, port in ROWS:
        prefix = "allow" if (source, target, port) in ALLOWED else "drop"
        original_name = f"{prefix}_{source}_{target}_{port}"
        target_name = f"drop_{source}_{target}_{port}"
        candidates = [rule for rule in rules if original_name in named_references(rule.get("expr"))]
        require(len(candidates) == 1, "Approved reference lacks an unambiguous per-row counter rule.")
        rule = copy.deepcopy(candidates[0])
        expressions = rule.get("expr")
        require(isinstance(expressions, list) and len(expressions) >= 2
                and expressions[-2:] == [{"counter": original_name}, {"accept" if prefix == "allow" else "drop": None}],
                "Approved counter must immediately precede its expected verdict.")
        expressions[-2:] = [{"counter": target_name}, {"drop": None}]
        templates[target_name] = rule
    return templates


def drop_bindings(raw, templates):
    rules = scoped_rules(raw)
    unknown_form = any(not isinstance(reference, str) for rule in rules
                       for reference in counter_expressions(rule.get("expr")))
    result = {}
    for name, template in templates.items():
        references = [rule for rule in rules if name in named_references(rule.get("expr"))]
        result[name] = not unknown_form and bool(references) and all(rule == template for rule in references)
    return result


class Monitor:
    """Coalesce incidents while retaining each observation's evidence references."""
    def __init__(self, approved_ruleset, max_gap_seconds=30):
        require(type(max_gap_seconds) in (int, float) and math.isfinite(max_gap_seconds) and max_gap_seconds > 0,
                "Sampling gap bound must be positive and finite.")
        self.approved_fingerprint = policy_fingerprint(approved_ruleset)
        self.approved_policy = canonical_ruleset(approved_ruleset)
        self._drop_templates = approved_drop_templates(approved_ruleset)
        self._previous = counter_snapshot(approved_ruleset)
        self._previous["drop_bindings"] = drop_bindings(approved_ruleset, self._drop_templates)
        require(self._previous["table_handle"] is not None and set(self._previous["counters"]) == COUNTERS,
                "Approved reference lacks the complete monitored counter inventory.")
        self.max_gap_seconds = max_gap_seconds
        self.events, self.alerts, self.evaluations = [], [], []
        self._active, self._occurrences = {}, {}
        self._sequence, self._elapsed, self._timestamp = 0, None, None
        self._seen_ports = set()

    def _signal(self, code, scope, severity, active, evidence, sample):
        key = code + ":" + scope
        incident = self._active.get(key)
        if not active and incident is None:
            return
        action = "updated" if active and incident is not None else "opened" if active else "resolved"
        if action == "opened":
            occurrence = self._occurrences.get(key, 0) + 1
            self._occurrences[key] = occurrence
            incident = {"id": key + "#" + str(occurrence), "key": key, "code": code, "scope": scope,
                        "severity": severity, "state": "open", "occurrence": occurrence,
                        "opened_sequence": sample.get("sequence"), "resolved_sequence": None,
                        "observations": 0, "event_ids": []}
            self.alerts.append(incident)
            self._active[key] = incident
        event = {"id": f"event-{len(self.events) + 1:04d}", "alert_id": incident["id"], "key": key,
                 "code": code, "severity": severity, "action": action,
                 "sequence": sample.get("sequence"), "phase": sample.get("phase"),
                 "observed_at_utc": sample.get("observed_at_utc"), "evidence": copy.deepcopy(evidence)}
        self.events.append(event)
        incident["event_ids"].append(event["id"])
        incident["last_seen_sequence"] = sample.get("sequence")
        incident["last_evidence"] = copy.deepcopy(evidence)
        if active:
            incident["observations"] += 1
        else:
            incident["state"] = "resolved"
            incident["resolved_sequence"] = sample.get("sequence")
            del self._active[key]

    def _validate_probes(self, probes, sample_time, phase, previous_time):
        require(isinstance(probes, list) and len(probes) <= 12, "Probe inventory is invalid.")
        rows, ports = set(), set()
        for probe in probes:
            require(isinstance(probe, dict), "Probe is not an object.")
            row = (probe.get("from"), probe.get("to"), probe.get("port"))
            require(row in ROWS and row not in rows, "Probe is outside the matrix or duplicates a row.")
            source, target, port = row
            require(probe.get("destination") == ZONES[target] and probe.get("phase") == phase,
                    "Probe destination or phase is inconsistent.")
            source_port = probe.get("source_port")
            require(integer(source_port, 40000) and source_port < 50000
                    and source_port not in self._seen_ports and source_port not in ports, "Probe port is invalid or reused.")
            started, completed = utc(probe.get("started_at_utc")), utc(probe.get("completed_at_utc"))
            require(started <= completed <= sample_time and (previous_time is None or started >= previous_time),
                    "Probe is stale or outside its observation window.")
            outcome = probe.get("outcome")
            require(outcome in FAILURES or good_response(probe, target, port), "Probe response is malformed or belongs to the wrong service.")
            health = probe.get("destination_health")
            if health is not None:
                require(isinstance(health, dict) and health.get("from") == target and health.get("to") == target
                        and health.get("destination") == ZONES[target] and health.get("port") == port
                        and health.get("phase") == phase, "Destination health evidence is inconsistent.")
                require(health.get("outcome") in FAILURES or good_response(health, target, port), "Health response is malformed.")
                require(started <= utc(health.get("started_at_utc")) <= utc(health.get("completed_at_utc")) <= sample_time,
                        "Health evidence is stale or outside its observation window.")
            rows.add(row)
            ports.add(source_port)
        return rows, ports

    def observe(self, sample):
        require(isinstance(sample, dict), "Observation must be an object.")
        require(len(self.evaluations) < 1000, "Bounded monitor observation limit exceeded.")
        event_start = len(self.events)
        evaluation = {key: sample.get(key) for key in ("sequence", "phase", "observed_at_utc")}
        evaluation.update({"status": "unknown", "telemetry_valid": False, "policy_matches": None,
                           "policy_fingerprint": None, "counter_deltas": {}, "drop_attribution": {}, "drop_rule_bindings": {},
                           "canaries_checked": [], "diagnostics": []})
        try:
            sequence, elapsed = sample.get("sequence"), sample.get("elapsed_seconds")
            require(integer(sequence, 1) and sequence > self._sequence, "Observation sequence is stale or duplicated.")
            sequence_gap = sequence != self._sequence + 1
            require(type(elapsed) in (int, float) and math.isfinite(elapsed) and elapsed >= 0
                    and (self._elapsed is None or elapsed >= self._elapsed), "Observation elapsed time is invalid or stale.")
            sample_time = utc(sample.get("observed_at_utc"))
            require(self._timestamp is None or sample_time >= self._timestamp, "Observation UTC timestamp moved backwards.")
            require(isinstance(sample.get("phase"), str) and 1 <= len(sample["phase"]) <= 100, "Observation phase is invalid.")
            # Consume the envelope even when collection failed, allowing the next
            # fresh sequence to recover without pretending the missing interval was quiet.
            gap = self._elapsed is not None and elapsed - self._elapsed > self.max_gap_seconds
            old_time = self._timestamp
            self._sequence, self._elapsed, self._timestamp = sequence, elapsed, sample_time
            require(not sample.get("collection_error") and sample.get("ruleset") is not None,
                    "Ruleset collection is unavailable.")
            fingerprint = policy_fingerprint(sample["ruleset"])
            counters = counter_snapshot(sample["ruleset"])
            rows, ports = self._validate_probes(sample.get("probes"), sample_time, sample["phase"], old_time)
            if gap or sequence_gap:
                self._previous = None
                raise ValueError("Observation gap exceeds the sampling bound or skips a sequence.")
            self._seen_ports.update(ports)
        except (ValueError, TypeError, KeyError, OverflowError) as error:
            self._previous = None
            evaluation["diagnostics"].append(str(error))
            self._signal("telemetry_gap", "collector", "high", True, {"reason": str(error), "coverage": "unknown"}, sample)
            return self._finish(evaluation, event_start)

        evaluation["telemetry_valid"] = True
        evaluation["policy_fingerprint"] = fingerprint
        evaluation["policy_matches"] = fingerprint == self.approved_fingerprint
        self._signal("rule_drift", "ruleset", "high", not evaluation["policy_matches"],
                     {"approved_fingerprint": self.approved_fingerprint, "observed_fingerprint": fingerprint,
                      "reason": "rules_match_approved_reference" if evaluation["policy_matches"] else "rules_differ_from_approved_reference"}, sample)
        previous = self._previous
        continuous = (previous is not None and counters["table_handle"] is not None
                      and previous["table_handle"] == counters["table_handle"]
                      and set(counters["counters"]) == set(previous["counters"]) == COUNTERS)
        if continuous:
            continuous = all(value["handle"] == previous["counters"][name]["handle"]
                             and value["packets"] >= previous["counters"][name]["packets"]
                             and value["bytes"] >= previous["counters"][name]["bytes"]
                             for name, value in counters["counters"].items())
        deltas = {name: counters["counters"][name]["packets"] - previous["counters"][name]["packets"] if continuous else None
                  for name in sorted(COUNTERS)}
        evaluation["counter_deltas"] = deltas
        bindings = drop_bindings(sample["ruleset"], self._drop_templates)
        # The counter may survive a rule replacement. A verified current drop rule
        # cannot classify packets counted while the previous rule accepted traffic.
        attribution = {name: bool(continuous and bindings[name] and previous["drop_bindings"][name])
                       for name in self._drop_templates}
        evaluation["drop_attribution"] = attribution
        evaluation["drop_rule_bindings"] = bindings
        counters["drop_bindings"] = bindings
        self._previous = counters
        self._signal("counter_discontinuity", "counters", "warning", not continuous,
                     {"reason": "continuous_observed_interval" if continuous else "counter_identity_reset_missing_or_prior_gap",
                      "delta_coverage": "known" if continuous else "unknown"}, sample)
        if continuous:
            self._signal("telemetry_gap", "collector", "high", False,
                         {"reason": "fresh_complete_snapshot_and_continuous_counter_interval"}, sample)
            for name, delta in deltas.items():
                if name.startswith("drop_") and attribution[name]:
                    self._signal("blocked_traffic", name, "info", delta > 0,
                                 {"counter": name, "packet_delta": delta,
                                  "reason": "blocked_packets_observed" if delta else "no_new_drops_in_observed_interval",
                                  "interpretation": "Packet counts include retries; a denial alone is not evidence of an attack."}, sample)
        else:
            evaluation["diagnostics"].append("Counter interval is unknown; observed values establish a new measurement baseline only.")

        for probe in sample["probes"]:
            row = (probe["from"], probe["to"], probe["port"])
            source, target, port = row
            scope = f"{source}->{target}:{port}"
            delta = deltas[f"drop_{source}_{target}_{port}"]
            healthy = good_response(probe.get("destination_health") or {}, target, port)
            response = good_response(probe, target, port)
            evidence = {"probe_source_port": probe["source_port"], "outcome": probe["outcome"],
                        "destination_healthy": healthy, "drop_packet_delta": delta,
                        "drop_attribution_confirmed": attribution[f"drop_{source}_{target}_{port}"],
                        "rule_fingerprint": fingerprint}
            if row in ALLOWED:
                evidence["reason"] = ("expected_response_observed" if response else "healthy_destination_and_drop_evidence"
                                      if healthy and delta is not None and delta > 0 and evidence["drop_attribution_confirmed"]
                                      else "allowed_service_unavailable_cause_unconfirmed")
                self._signal("allowed_path_unavailable", scope, "high", not response, evidence, sample)
            elif response:
                evidence["reason"] = "forbidden_service_response_observed"
                self._signal("forbidden_path_open", scope, "critical", True, evidence, sample)
            elif (probe["outcome"] == "connect_timeout" and healthy and delta is not None and delta > 0
                  and evidence["drop_attribution_confirmed"]):
                evidence["reason"] = "denial_reverified_with_health_and_drop_evidence"
                self._signal("forbidden_path_open", scope, "critical", False, evidence, sample)
            else:
                evaluation["diagnostics"].append("Denial is unconfirmed for " + scope)
        evaluation["canaries_checked"] = [{"from": source, "to": target, "port": port}
                                          for source, target, port in CANARIES if (source, target, port) in rows]
        verified = set(CANARIES).issubset(rows) and continuous and not evaluation["diagnostics"]
        evaluation["status"] = "alerting" if any(a["severity"] in {"high", "critical"} for a in self._active.values()) else "healthy" if verified else "unknown"
        # An informational expected-denial alert does not make the tested policy unhealthy.
        return self._finish(evaluation, event_start)

    def _finish(self, evaluation, event_start):
        evaluation["active_alert_keys"] = sorted(self._active)
        evaluation["emitted_event_ids"] = [event["id"] for event in self.events[event_start:]]
        self.evaluations.append(copy.deepcopy(evaluation))
        return copy.deepcopy(evaluation)
