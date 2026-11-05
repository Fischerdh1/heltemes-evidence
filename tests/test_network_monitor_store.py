"""Journal consistency and fail-closed state tests using disposable identities."""
import copy
from contextlib import closing
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from scripts import network_monitor_store as store
from scripts.network_monitor_service import Service
from test_network_monitor import ruleset


def observation(raw=None, phase="sample"):
    return {"phase": phase, "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "ruleset": raw if raw is not None else ruleset(), "collection_error": None, "probes": []}


class MonitorStoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hms-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.state = self.base / "state"
        self.approved = ruleset()
        self.identity = store.initialize(self.state, self.approved)

    def mutate(self, sql, arguments=()):
        with closing(sqlite3.connect(self.state / "monitor.sqlite3")) as connection:
            with connection:
                connection.execute(sql, arguments)

    def test_initialization_pins_identity_and_private_files_with_required_sqlite_mode(self):
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        for name in ("service.lock", "identity.json", "monitor.sqlite3"):
            self.assertEqual((self.state / name).stat().st_mode & 0o777, 0o600)
        with store.Journal(self.state) as journal:
            self.assertEqual(journal.identity, self.identity)
            self.assertEqual(journal.connection.execute("PRAGMA journal_mode").fetchone(), ("delete",))
            self.assertEqual(journal.connection.execute("PRAGMA synchronous").fetchone(), (2,))
            self.assertEqual(journal.connection.execute("PRAGMA trusted_schema").fetchone(), (0,))
            self.assertEqual(journal.status()["committed_count"], 0)

    def test_existing_state_initialization_never_replaces_identity(self):
        before = (self.state / "identity.json").read_bytes()
        with self.assertRaises(ValueError):
            store.initialize(self.state, self.approved)
        self.assertEqual((self.state / "identity.json").read_bytes(), before)

    def test_missing_required_state_is_not_recreated(self):
        for name in ("monitor.sqlite3", "identity.json", "service.lock"):
            with self.subTest(name=name):
                path = self.state / name
                held = path.with_suffix(path.suffix + ".held")
                path.rename(held)
                try:
                    with self.assertRaises((ValueError, OSError, sqlite3.Error)):
                        store.Journal(self.state)
                    self.assertFalse(path.exists())
                finally:
                    held.rename(path)

    def test_pin_or_engine_mismatch_refuses_existing_database(self):
        path = self.state / "identity.json"
        original = path.read_bytes()
        for key, value in (("database_id", "1" * 32), ("engine_sha256", "2" * 64), ("version", 2)):
            with self.subTest(key=key):
                identity = copy.deepcopy(self.identity)
                identity[key] = value
                path.write_text(json.dumps(identity))
                with self.assertRaises(ValueError):
                    store.Journal(self.state)
                path.write_bytes(original)

    def test_permissions_links_and_state_aliases_are_refused(self):
        identity = self.state / "identity.json"
        identity.chmod(0o644)
        with self.assertRaises(ValueError):
            store.Journal(self.state)
        identity.chmod(0o600)
        alias = self.base / "alias"
        alias.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(ValueError):
            store.Journal(alias)
        hard = self.base / "identity-hardlink"
        os.link(identity, hard)
        with self.assertRaises(ValueError):
            store.Journal(self.state)
        hard.unlink()
        self.state.chmod(0o755)
        with self.assertRaises(ValueError):
            store.Journal(self.state)
        self.state.chmod(0o700)

    def test_lifetime_lock_rejects_second_writer(self):
        with store.Journal(self.state):
            with self.assertRaises(BlockingIOError):
                store.Journal(self.state)
        with store.Journal(self.state) as reopened:
            self.assertEqual(reopened.status()["committed_count"], 0)

    def test_duplicate_request_returns_exact_original_commit_without_new_history(self):
        value = observation(self.approved)
        with store.Journal(self.state) as journal:
            first = journal.append("request-one", value, 0)
            duplicate = journal.append("request-one", value, 100)
            self.assertFalse(first["duplicate"])
            self.assertTrue(duplicate["duplicate"])
            self.assertEqual(first["evaluation"], duplicate["evaluation"])
            self.assertEqual(len(journal.rows), 1)
            conflict = copy.deepcopy(value)
            conflict["ruleset"]["nftables"][1]["table"]["handle"] = True
            with self.assertRaisesRegex(ValueError, "conflicts"):
                journal.append("request-one", conflict, 101)
        with store.Journal(self.state) as reopened:
            self.assertEqual(len(reopened.rows), 1)
            self.assertEqual(reopened.rows[0]["sample"], {**value, "sequence": 1, "elapsed_seconds": 0})

    def test_failed_transaction_does_not_advance_accepted_memory_or_database(self):
        with store.Journal(self.state) as journal:
            journal.append("accepted", observation(self.approved), 0)
            before = journal.export()
            def fail(point):
                if point == "before_commit":
                    raise RuntimeError("injected failure")
            with self.assertRaisesRegex(RuntimeError, "injected"):
                journal.append("uncommitted", observation(self.approved), 1, fault=fail)
            self.assertEqual(journal.export(), before)
        with store.Journal(self.state) as reopened:
            self.assertEqual(reopened.export(), before)

    def test_missing_tail_or_corrupt_saved_result_is_rejected_on_replay(self):
        with store.Journal(self.state) as journal:
            journal.append("accepted", observation(self.approved), 0)
        original = (self.state / "monitor.sqlite3").read_bytes()
        self.mutate("DELETE FROM observations")
        with self.assertRaisesRegex(ValueError, "head"):
            store.Journal(self.state)
        (self.state / "monitor.sqlite3").write_bytes(original)
        with closing(sqlite3.connect(self.state / "monitor.sqlite3")) as connection:
            with connection:
                row = connection.execute("SELECT evaluation FROM observations").fetchone()
                altered = json.loads(row[0]); altered["status"] = "healthy"
                connection.execute("UPDATE observations SET evaluation=?", (json.dumps(altered),))
        with self.assertRaisesRegex(ValueError, "replay"):
            store.Journal(self.state)

    def test_unknown_schema_trigger_column_or_index_is_rejected(self):
        original = (self.state / "monitor.sqlite3").read_bytes()
        for sql in ("ALTER TABLE observations ADD COLUMN extra TEXT", "CREATE INDEX unexpected ON observations(request_id)",
                    "CREATE TABLE sqliteXunexpected (value TEXT)",
                    "CREATE TRIGGER sqliteXunexpected AFTER INSERT ON observations BEGIN UPDATE config SET head_sequence=0; END",
                    "CREATE TRIGGER unexpected AFTER INSERT ON observations BEGIN UPDATE config SET head_sequence=0; END"):
            with self.subTest(sql=sql):
                self.mutate(sql)
                with self.assertRaisesRegex(ValueError, "schema"):
                    store.Journal(self.state)
                (self.state / "monitor.sqlite3").write_bytes(original)

    def test_truncated_database_and_unexpected_sidecar_refuse_without_reinitializing(self):
        path = self.state / "monitor.sqlite3"
        original = path.read_bytes()
        path.write_bytes(original[:128])
        with self.assertRaises((ValueError, sqlite3.Error)):
            store.Journal(self.state)
        self.assertEqual(path.read_bytes(), original[:128])
        path.write_bytes(original)
        sidecar = self.state / "monitor.sqlite3-wal"
        store.write_new(sidecar, b"not accepted")
        with self.assertRaises(ValueError):
            store.Journal(self.state)

    def test_restart_boundary_is_committed_and_replay_preserves_incident_identity(self):
        with store.Journal(self.state) as journal:
            first = Service(journal)
            before = first.status()
            self.assertEqual(before["current_evaluation"]["status"], "unknown")
            self.assertEqual(journal.rows[-1]["request"]["kind"], "restart")
        with store.Journal(self.state) as journal:
            second = Service(journal)
            after = second.status()
            self.assertNotEqual(first.instance_id, second.instance_id)
            self.assertEqual(after["committed_count"], 2)
            self.assertEqual(len(journal.engine.alerts), 1)
            self.assertEqual(journal.engine.alerts[0]["id"], before["alerts"][0]["id"])
            self.assertEqual(after["current_evaluation"]["status"], "unknown")

    def test_observation_contract_rejects_extra_fields_and_reserved_client_id(self):
        with store.Journal(self.state) as journal:
            with self.assertRaises(ValueError):
                journal.append("normal", {**observation(), "sequence": 44}, 0)
            with self.assertRaises(ValueError):
                journal.append("_restart_" + "1" * 32, observation(), 0)
            self.assertEqual(len(journal.rows), 0)


if __name__ == "__main__":
    unittest.main()
