"""Bounded archival, deterministic replay, and process-crash recovery on disposable state."""
import copy
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import network_monitor_archive as archive
from scripts import network_monitor_service as service
from scripts import network_monitor_store as store
from test_network_monitor import Fixture, ruleset

ROOT = Path(__file__).resolve().parents[1]


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hma-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.state = self.base / "s"
        self.fixture = Fixture()

    def initialize(self, **options):
        return archive.initialize(self.state, ruleset(), **options)

    def observation(self, *, gap=False, **options):
        sample = self.fixture.sample(**options)
        observation = {key: sample[key] for key in store.OBSERVATION_KEYS}
        if gap:
            observation.update(ruleset=None, collection_error="test_collection_missing", probes=[])
        return observation, sample["elapsed_seconds"]

    def fill(self, journal, count, *, gap=False):
        for _ in range(count):
            observation, elapsed = self.observation(gap=gap)
            journal.append("sample-" + str(self.fixture.sequence), observation, elapsed)

    def test_opt_in_identity_preserves_legacy_format_and_refuses_implicit_migration(self):
        identity = self.initialize()
        self.assertEqual(identity["engine_sha256"], store.engine_hash())
        self.assertEqual(identity["archive_engine_sha256"], archive.implementation_hash())
        with self.assertRaises(ValueError):
            store.Journal(self.state)
        with self.assertRaises(ValueError):
            self.initialize()
        legacy = self.base / "legacy"
        store.initialize(legacy, ruleset())
        with self.assertRaises(ValueError):
            archive.ArchiveJournal(legacy)
        with store.Journal(legacy) as old:
            self.assertEqual(old.status()["committed_count"], 0)

    def test_budget_configuration_is_explicit_and_cannot_advertise_impossible_rows(self):
        for options in ({"segment_rows": 31}, {"segment_rows": 257}, {"segment_rows": True},
                        {"max_rows": 4097}, {"segment_rows": 128, "max_rows": 4096},
                        {"max_archive_bytes": 1023}, {"max_archive_bytes": archive.MAX_ARCHIVE_BYTES + 1}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.initialize(**options)
        self.assertFalse(self.state.exists())

    def test_270_real_shaped_snapshots_cross_legacy_cap_and_reopen_exactly(self):
        self.initialize()
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 270)
            self.assertEqual(journal.total_count, 270)
            self.assertEqual(len(journal.rows), 14)
            self.assertEqual(journal.connection.execute("SELECT count(*) FROM observations").fetchone(), (14,))
            self.assertEqual(journal.status()["archives"]["archived_rows"], 256)
            before = journal.export()
            self.assertEqual([row["sequence"] for row in before["rows"]], list(range(1, 271)))
            self.assertEqual(journal.last_row["sequence"], 270)
        with archive.ArchiveJournal(self.state) as reopened:
            self.assertEqual(reopened.export(), before)
            self.assertEqual(reopened.head_digest, before["rows"][-1]["row_digest"])

    def test_over_1000_rows_keep_runtime_bounded_without_losing_incident_history(self):
        self.initialize()
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 1005, gap=True)
            self.assertEqual(journal.total_count, 1005)
            self.assertEqual(len(journal.engine.evaluations), 1)
            self.assertEqual(len(journal.engine.events), 1)
            incident = journal.engine.alerts[0]
            self.assertEqual(incident["id"], "telemetry_gap:collector#1")
            self.assertEqual(incident["event_count"], 1005)
            self.assertEqual(len(incident["event_ids"]), archive.EVENT_REFERENCES)
            self.assertTrue(incident["event_ids_truncated"])
            exported = journal.export()
            self.assertEqual(len(exported["alerts"][0]["event_ids"]), 1005)
            self.assertEqual([event["id"] for event in exported["events"]], [f"event-{n:04d}" for n in range(1, 1006)])
        with archive.ArchiveJournal(self.state) as reopened:
            self.assertEqual(reopened.export(), exported)
            self.assertEqual(reopened.engine.alerts[0]["event_count"], 1005)

    def test_append_advances_one_bounded_engine_without_replaying_old_segments(self):
        self.initialize(segment_rows=32, max_rows=512)
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 40)
            calls = []
            original = archive.StreamingMonitor.observe
            def observed(engine, sample):
                calls.append(sample["sequence"])
                return original(engine, sample)
            with patch.object(archive.StreamingMonitor, "observe", observed), patch.object(journal, "_read_segment", side_effect=AssertionError("unneeded historical read")):
                self.fill(journal, 1)
            self.assertEqual(calls, [41])

    def test_archived_duplicate_is_exact_and_conflicting_content_is_rejected(self):
        self.initialize(segment_rows=32, max_rows=512)
        with archive.ArchiveJournal(self.state) as journal:
            first, elapsed = self.observation()
            accepted = journal.append("original", first, elapsed)
            self.fill(journal, 40)
        with archive.ArchiveJournal(self.state) as journal:
            self.assertTrue(journal.has_request("original"))
            duplicate = journal.append("original", first, 999)
            self.assertEqual({**accepted, "duplicate": True}, duplicate)
            self.assertEqual(journal.total_count, 41)
            altered = copy.deepcopy(first)
            altered["phase"] = "altered"
            with self.assertRaisesRegex(ValueError, "conflicts"):
                journal.append("original", altered, 999)

    def test_last_row_survives_empty_active_segment_for_service_restart(self):
        self.initialize(segment_rows=32, max_rows=512)
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 32)
            self.assertEqual(journal.rows, [])
            previous = journal.last_row
            with patch.object(service, "utc_now", lambda: (self.fixture.time + timedelta(seconds=1)).isoformat()):
                running = service.Service(journal, freshness_seconds=20)
            self.assertEqual(running.base_elapsed, previous["sample"]["elapsed_seconds"])
            self.assertEqual(journal.last_row["sequence"], 33)
            self.assertEqual(running.status()["freshness"]["capacity_remaining"], 512 - 33)

    def test_archived_duplicate_does_not_refresh_live_freshness_after_restart(self):
        self.initialize(segment_rows=32, max_rows=512)
        with archive.ArchiveJournal(self.state) as journal:
            first, elapsed = self.observation()
            journal.append("old", first, elapsed)
            self.fill(journal, 31)
            with patch.object(service, "utc_now", lambda: (self.fixture.time + timedelta(seconds=1)).isoformat()):
                running = service.Service(journal, freshness_seconds=20)
                result = running.dispatch({"command": "observe", "request_id": "old", "observation": first})
            self.assertTrue(result["duplicate"])
            self.assertTrue(result["result_is_historical"])
            self.assertIsNone(result["current_status"]["freshness"]["last_accepted_request_id"])
            self.assertEqual(result["current_status"]["current_evaluation"]["status"], "unknown")
            self.assertEqual(journal.total_count, 33)

    def test_live_archive_export_is_rejected_without_building_history_or_changing_freshness(self):
        self.initialize(segment_rows=32, max_rows=512)
        elapsed = [0.0]
        with archive.ArchiveJournal(self.state) as journal, \
                patch.object(service, "utc_now", lambda: (self.fixture.time + timedelta(seconds=1)).isoformat()), \
                patch.object(service.time, "monotonic", lambda: elapsed[0]):
            running = service.Service(journal, freshness_seconds=20)
            for index, rows in enumerate(((), archive.monitor.CANARIES), 1):
                observation, _ = self.observation(rows=rows)
                elapsed[0] += 2
                running.dispatch({"command": "observe", "request_id": "live-" + str(index), "observation": observation})
            before = journal.export()
            accepted = copy.deepcopy(running.last_accepted)
            live = running.status()
            self.assertEqual(live["current_evaluation"]["status"], "healthy")
            with patch.object(journal, "export", side_effect=AssertionError("history must not be built")) as export:
                result = running.dispatch({"command": "export"})
            export.assert_not_called()
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"], "offline_export_required")
            self.assertIn("offline archive export", result["message"])
            self.assertEqual(journal.export(), before)
            self.assertEqual(running.last_accepted, accepted)
            self.assertEqual(running.status(), live)
            self.assertFalse(live["history_summary"]["socket_export_available"])
            self.assertTrue(live["history_summary"]["full_history_available_in_offline_export"])

    def test_incident_occurrence_and_event_identity_continue_across_archive_boundary(self):
        self.initialize(segment_rows=32, max_rows=512)
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 34, gap=True)
            self.fill(journal, 2)
            self.fill(journal, 1, gap=True)
            alert = journal.engine._active["telemetry_gap:collector"]
            self.assertEqual(alert["id"], "telemetry_gap:collector#2")
            exported = journal.export()
            self.assertEqual(len({event["id"] for event in exported["events"]}), len(exported["events"]))
            self.assertEqual(exported["alerts"][0]["state"], "resolved")
        with archive.ArchiveJournal(self.state) as reopened:
            self.assertEqual(reopened.export(), exported)
            self.assertEqual(reopened.engine._active["telemetry_gap:collector"]["id"], alert["id"])

    def test_process_crashes_at_both_handoff_boundaries_preserve_single_commit(self):
        for point in ("archive_staging_durable", "archive_file_durable", "archive_metadata_committed"):
            with self.subTest(point=point):
                state = self.base / point
                archive.initialize(state, ruleset(), segment_rows=32, max_rows=512)
                with archive.ArchiveJournal(state) as journal:
                    self.fill(journal, 31, gap=True)
                observation, elapsed = self.observation(gap=True)
                payload = self.base / (point + ".json")
                payload.write_text(json.dumps(observation))
                code = ("import json,os,sys; from scripts.network_monitor_archive import ArchiveJournal; "
                        "j=ArchiveJournal(sys.argv[1]); value=json.loads(open(sys.argv[2]).read()); "
                        "j.append('crash-boundary',value,float(sys.argv[4]),fault=lambda p: os._exit(73) if p==sys.argv[3] else None)")
                result = subprocess.run([sys.executable, "-c", code, str(state), str(payload), point, str(elapsed)],
                                        cwd=ROOT, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 73, result.stderr.decode())
                with archive.ArchiveJournal(state) as reopened:
                    self.assertEqual(reopened.total_count, 32)
                    self.assertEqual(len(reopened.segments), 1)
                    self.assertEqual(reopened.rows, [])
                    retried = reopened.append("crash-boundary", observation, 999)
                    self.assertTrue(retried["duplicate"])
                    self.assertEqual(retried["committed_sequence"], 32)
                    self.assertEqual(len(list(reopened.iter_rows())), 32)

    def test_torn_staging_prefix_is_rebuilt_only_after_verified_database_replay(self):
        self.initialize(segment_rows=32, max_rows=512)
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 31, gap=True)
            original = store.write_new
            def torn(path, raw):
                if path.name.endswith(".pending"):
                    original(path, raw[:73])
                    raise OSError("simulated interrupted segment write")
                original(path, raw)
            with patch.object(store, "write_new", torn), self.assertRaises(OSError):
                self.fill(journal, 1, gap=True)
            self.assertEqual(journal.total_count, 32)
            self.assertEqual(journal.status()["current_evaluation"]["status"], "unknown")
        with archive.ArchiveJournal(self.state) as reopened:
            self.assertEqual(reopened.total_count, 32)
            self.assertEqual(reopened.rows, [])
            self.assertEqual(reopened.recovery_actions[0]["action"], "rebuilt_verified_staging_prefix")
            self.assertEqual(reopened.recovery_actions[0]["staged_bytes"], 73)
            self.assertEqual(len(list((self.state / "archives").iterdir())), 1)

    def test_invalid_staging_or_final_orphan_is_never_adopted_or_deleted(self):
        for final in (False, True):
            with self.subTest(final=final):
                state = self.base / ("final" if final else "staged")
                archive.initialize(state, ruleset(), segment_rows=32, max_rows=512)
                with archive.ArchiveJournal(state) as journal:
                    self.fill(journal, 31, gap=True)
                    def fail(point):
                        if point == ("archive_file_durable" if final else "archive_staging_durable"):
                            raise OSError("stop")
                    observation, elapsed = self.observation(gap=True)
                    with self.assertRaises(OSError):
                        journal.append("boundary", observation, elapsed, fault=fail)
                filename = "segment-000001.json" + ("" if final else ".pending")
                target = state / "archives" / filename
                target.write_bytes(b"altered")
                with self.assertRaises(ValueError):
                    archive.ArchiveJournal(state)
                self.assertEqual(target.read_bytes(), b"altered")

    def test_archive_publication_failure_knows_committed_row_and_blocks_new_writes(self):
        self.initialize(segment_rows=32, max_rows=512)
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 31, gap=True)
            observation, elapsed = self.observation(gap=True)
            def fail(point):
                if point == "archive_file_durable":
                    raise OSError("fsync boundary failure")
            with self.assertRaises(OSError):
                journal.append("committed", observation, elapsed, fault=fail)
            self.assertEqual(journal.total_count, 32)
            self.assertTrue(journal.append("committed", observation, elapsed)["duplicate"])
            with self.assertRaisesRegex(ValueError, "unavailable"):
                journal.append("not-committed", observation, elapsed)
            self.assertIn("archive_handoff_failed", journal.status()["current_evaluation"]["diagnostics"])
        with archive.ArchiveJournal(self.state) as reopened:
            self.assertEqual(reopened.total_count, 32)
            self.assertIsNone(reopened.failure)

    def test_archive_budget_failure_is_unknown_and_does_not_commit_boundary(self):
        self.initialize(segment_rows=32, max_rows=512, max_archive_bytes=1024)
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 31, gap=True)
            with self.assertRaisesRegex(ValueError, "byte budget"):
                self.fill(journal, 1, gap=True)
            self.assertEqual(journal.total_count, 31)
            self.assertEqual(journal.status()["current_evaluation"]["status"], "unknown")
            self.assertEqual(list((self.state / "archives").iterdir()), [])
        with archive.ArchiveJournal(self.state) as reopened:
            self.assertEqual(reopened.total_count, 31)

    def test_total_row_budget_is_finite_and_never_deletes_old_segments(self):
        self.initialize(segment_rows=32, max_rows=32)
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 32, gap=True)
            original = journal.export()
            with self.assertRaisesRegex(ValueError, "total row budget"):
                self.fill(journal, 1, gap=True)
            self.assertEqual(journal.export(), original)
            self.assertEqual(journal.capacity_remaining, 0)
            self.assertEqual(journal.status()["current_evaluation"]["status"], "unknown")
        with archive.ArchiveJournal(self.state) as reopened:
            self.assertEqual(reopened.export(), original)

    def test_full_default_4096_row_budget_and_all_16_segments_replay(self):
        self.initialize()
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 4096, gap=True)
            self.assertEqual(len(journal.segments), 16)
            self.assertEqual(journal.rows, [])
            self.assertEqual(journal.capacity_remaining, 0)
            self.assertEqual(journal.engine.event_count, 4096)
            digest = journal.head_digest
        with archive.ArchiveJournal(self.state) as reopened:
            self.assertEqual(reopened.total_count, 4096)
            self.assertEqual(reopened.head_digest, digest)
            self.assertEqual(reopened.engine.event_count, 4096)
            self.assertEqual(len(reopened.engine.alerts[0]["event_ids"]), 16)

    def test_before_commit_failure_does_not_advance_history(self):
        self.initialize(segment_rows=32, max_rows=512)
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 4, gap=True)
            original = journal.export()
            def fail(point):
                if point == "before_commit":
                    raise OSError("transaction failure")
            observation, elapsed = self.observation(gap=True)
            with self.assertRaises(OSError):
                journal.append("failed", observation, elapsed, fault=fail)
            self.assertEqual(journal.export(), original)
        with archive.ArchiveJournal(self.state) as reopened:
            self.assertEqual(reopened.export(), original)

    def test_missing_changed_renamed_linked_or_unexpected_archive_blocks_reopen(self):
        self.initialize(segment_rows=32, max_rows=512)
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 32, gap=True)
        segment = self.state / "archives" / "segment-000001.json"
        original = segment.read_bytes()
        for mutation in ("missing", "changed", "renamed", "mode", "hardlink", "symlink", "unexpected"):
            with self.subTest(mutation=mutation):
                extra = self.base / "held"
                if mutation == "missing":
                    segment.rename(extra)
                elif mutation == "changed":
                    segment.write_bytes(original.replace(b"test_collection_missing", b"fake_collection_missing", 1))
                elif mutation == "renamed":
                    segment.rename(segment.with_name("segment-000002.json"))
                elif mutation == "mode":
                    segment.chmod(0o644)
                elif mutation == "hardlink":
                    os.link(segment, extra)
                elif mutation == "symlink":
                    segment.rename(extra)
                    segment.symlink_to(extra)
                else:
                    store.write_new(segment.with_name("unexpected.json"), b"{}")
                with self.assertRaises((ValueError, OSError)):
                    archive.ArchiveJournal(self.state)
                if mutation == "missing":
                    extra.rename(segment)
                elif mutation == "changed":
                    segment.write_bytes(original)
                elif mutation == "renamed":
                    segment.with_name("segment-000002.json").rename(segment)
                elif mutation == "mode":
                    segment.chmod(0o600)
                elif mutation == "hardlink":
                    extra.unlink()
                elif mutation == "symlink":
                    segment.unlink()
                    extra.rename(segment)
                else:
                    segment.with_name("unexpected.json").unlink()

    def test_changed_result_with_recomputed_file_hash_still_fails_deterministic_replay(self):
        self.initialize(segment_rows=32, max_rows=512)
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 32, gap=True)
        segment = self.state / "archives" / "segment-000001.json"
        value = json.loads(segment.read_text())
        value["rows"][0]["evaluation"]["status"] = "healthy"
        raw = (store.encoded(value) + "\n").encode()
        segment.write_bytes(raw)
        with closing(sqlite3.connect(self.state / "monitor.sqlite3")) as connection:
            with connection:
                connection.execute("UPDATE segments SET byte_count=?,file_digest=?", (len(raw), hashlib.sha256(raw).hexdigest()))
        with self.assertRaisesRegex(ValueError, "deterministic replay"):
            archive.ArchiveJournal(self.state)

    def test_duplicate_ids_across_archives_are_rejected_on_replay(self):
        self.initialize(segment_rows=32, max_rows=512)
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 34, gap=True)
        with closing(sqlite3.connect(self.state / "monitor.sqlite3")) as connection:
            with connection:
                connection.execute("UPDATE observations SET request_id='sample-1' WHERE sequence=33")
        with self.assertRaisesRegex(ValueError, "duplicated"):
            archive.ArchiveJournal(self.state)

    def test_offline_export_streams_full_rows_and_does_not_replace_output(self):
        self.initialize(segment_rows=32, max_rows=512)
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 70, gap=True)
            expected = list(journal.iter_rows())
            with self.assertRaises(BlockingIOError):
                archive.export_offline(self.state, self.base / "locked.json")
        output = self.base / "export.json"
        result = archive.export_offline(self.state, output)
        self.assertEqual(result["committed_count"], 70)
        self.assertEqual(json.loads(output.read_text())["rows"], expected)
        self.assertTrue(json.loads(output.read_text())["history_complete"])
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            archive.export_offline(self.state, output)

    def test_offline_export_cli_runs_in_isolated_python_and_writes_new_private_file(self):
        self.initialize(segment_rows=32, max_rows=512)
        with archive.ArchiveJournal(self.state) as journal:
            self.fill(journal, 33, gap=True)
        output = self.base / "cli.json"
        result = subprocess.run([sys.executable, "-I", "-S", "-B", str(ROOT / "scripts/network_monitor_archive.py"),
                                 "--state", str(self.state), "--output", str(output)],
                                cwd=self.base, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout)["committed_count"], 33)
        self.assertEqual(len(json.loads(output.read_text())["rows"]), 33)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_private_archive_directory_and_lifetime_lock_are_required(self):
        self.initialize()
        with archive.ArchiveJournal(self.state):
            with self.assertRaises(BlockingIOError):
                archive.ArchiveJournal(self.state)
        (self.state / "archives").chmod(0o755)
        with self.assertRaises(ValueError):
            archive.ArchiveJournal(self.state)


if __name__ == "__main__":
    unittest.main()
