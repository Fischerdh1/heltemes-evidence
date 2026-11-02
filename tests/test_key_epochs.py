"""Public key history and verifier-only recovery, using disposable real keys.

These tests construct trusted receipts directly to exercise the public format.
They do not claim to authorize recovery; the recovery workflow tests cover that
separate protected authority and its durable signing gate.
"""
import copy
import shutil
import sqlite3
import tempfile
import unittest
import uuid
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from heltemes.core import Repository
from heltemes import protection as p


class KeyEpochTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.data = self.base / "data"
        self.repo = Repository(self.data)
        self.repo.seed_demo()
        with p.repository_lock(self.data):
            p.initialize_protection(self.data)
        self.trust = p.default_trust_dir(self.data)
        self.keys = p.default_key_dir(self.data)
        self.original_anchor, self.original_receipt = p._anchor(self.trust / "anchor.json")
        self.original_checkpoint = (self.trust / "checkpoints/00000001.json").read_bytes()
        self.original_key = (self.keys / "signing_key").read_bytes()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def rewrite(path, value):
        path.chmod(0o600)
        path.write_bytes(value if isinstance(value, bytes) else p._canonical(value))
        path.chmod(0o400)

    def generate_key(self):
        temporary = self.base / ("candidate-" + uuid.uuid4().hex)
        p._crypto(["-q", "-t", "ed25519", "-N", "", "-C", p.SIGNER, "-f", str(temporary)], input_bytes=b"")
        public = p._public_key(temporary.with_suffix(".pub").read_text().strip())
        identities = self.keys / "identities"
        identities.mkdir(mode=0o700, exist_ok=True)
        key = identities / (p._sha(public.encode("utf-8")) + ".key")
        temporary.rename(key)
        key.chmod(0o400)
        return key, public

    def transition(self, *, snapshot=None):
        old_anchor, _ = p._anchor(self.trust / "anchor.json")
        old_payload, _ = p._load_chain(self.trust / "checkpoints", old_anchor)
        key, public = self.generate_key()
        transition_id, approval = str(uuid.uuid4()), p._sha(b"independently accepted test approval")
        payload = p._new_payload(old_anchor["archive_id"], old_anchor["sequence"] + 1,
                                 old_anchor["checkpoint_sha256"],
                                 copy.deepcopy(old_payload["snapshot"]) if snapshot is None else snapshot)
        payload.update(version=2, key_transition={"transition_id": transition_id,
                       "approval_sha256": approval,
                       "from_key_fingerprint": old_anchor["key_fingerprint"],
                       "to_key_fingerprint": p._fingerprint(public)})
        checkpoint = p._canonical({"payload": payload, "signature": p._signature(payload, key)})
        anchor = p.transition_anchor(old_anchor, payload, checkpoint, public, transition_id, approval)
        p._exclusive(self.trust / "checkpoints" / p._checkpoint_name(payload["sequence"]), checkpoint)
        self.rewrite(self.trust / "anchor.json", anchor)
        return anchor, payload, key

    def append_run(self, name="later-run"):
        with closing(sqlite3.connect(self.repo.db_path)) as db, db:
            db.execute("INSERT INTO runs(id,started_at,finished_at,status,mode,cik,filings_added) VALUES(?,?,?,?,?,?,?)",
                       (name, "2026-01-05T00:00:00Z", "2026-01-05T00:00:01Z", "success", "demo", "0000000001", 0))

    def append_checkpoint(self, anchor, key):
        payload = p._new_payload(anchor["archive_id"], anchor["sequence"] + 1,
                                 anchor["checkpoint_sha256"], p._snapshot(self.data))
        checkpoint = p._canonical({"payload": payload, "signature": p._signature(payload, key)})
        next_anchor = p._new_anchor(anchor["public_key"], payload, checkpoint, previous_anchor=anchor)
        p._exclusive(self.trust / "checkpoints" / p._checkpoint_name(payload["sequence"]), checkpoint)
        self.rewrite(self.trust / "anchor.json", next_anchor)
        return next_anchor

    def test_legacy_receipt_and_historical_bytes_survive_key_transition(self):
        self.assertEqual(self.original_anchor["version"], 1)
        self.assertNotIn("key_epochs", self.original_anchor)
        self.assertEqual(p.verify_protection(self.data)["status"], "sealed")
        anchor, _, _ = self.transition()
        result = p.verify_protection(self.data)
        self.assertEqual(result["status"], "sealed")
        self.assertEqual(result["sequence"], 2)
        self.assertEqual(anchor["key_epochs"][0]["public_key"], self.original_anchor["public_key"])
        self.assertEqual((self.trust / "checkpoints/00000001.json").read_bytes(), self.original_checkpoint)
        self.assertEqual((self.keys / "signing_key").read_bytes(), self.original_key)

    def test_new_key_cannot_resign_old_history(self):
        _, _, key = self.transition()
        first = p._json(self.original_checkpoint)
        first["signature"] = p._signature(first["payload"], key)
        self.rewrite(self.trust / "checkpoints/00000001.json", first)
        result = p.verify_protection(self.data)
        self.assertEqual(result["status"], "failed")
        self.assertIn("signing/verification failed", result["issues"][0]["error"])

    def test_valid_new_signature_cannot_change_authorization_tuple(self):
        anchor, payload, key = self.transition()
        payload["key_transition"]["approval_sha256"] = "f" * 64
        checkpoint = p._canonical({"payload": payload, "signature": p._signature(payload, key)})
        self.rewrite(self.trust / "checkpoints/00000002.json", checkpoint)
        anchor["checkpoint_sha256"] = p._sha(checkpoint)
        self.rewrite(self.trust / "anchor.json", anchor)
        result = p.verify_protection(self.data)
        self.assertEqual(result["status"], "failed")
        self.assertIn("independently pinned authorization", result["issues"][0]["error"])

    def test_transition_cannot_silently_seal_pending_additions(self):
        self.append_run()
        self.transition(snapshot=p._snapshot(self.data))
        result = p.verify_protection(self.data)
        self.assertEqual(result["status"], "failed")
        self.assertIn("last accepted snapshot", result["issues"][0]["error"])

    def test_pending_rows_remain_pending_across_transition(self):
        self.append_run()
        self.transition()
        result = p.verify_protection(self.data)
        self.assertEqual(result["status"], "pending")
        self.assertEqual(result["pending_records"], 1)
        self.assertEqual(result["sequence"], 2)

    def test_normal_future_checkpoint_preserves_epoch_schedule(self):
        anchor, _, key = self.transition()
        self.append_run()
        next_anchor = self.append_checkpoint(anchor, key)
        self.assertEqual(next_anchor["key_epochs"], anchor["key_epochs"])
        self.assertEqual(next_anchor["version"], 2)
        self.assertEqual(p.verify_protection(self.data)["status"], "sealed")

    def test_old_key_cannot_sign_after_its_epoch(self):
        anchor, _, _ = self.transition()
        self.append_run()
        self.append_checkpoint(anchor, self.keys / "signing_key")
        self.assertEqual(p.verify_protection(self.data)["status"], "failed")

    def test_multiple_transitions_have_distinct_sequence_bound_keys(self):
        first, _, _ = self.transition()
        second, _, _ = self.transition()
        self.assertEqual([item["start_sequence"] for item in second["key_epochs"]], [1, 2, 3])
        self.assertEqual(second["key_epochs"][:2], first["key_epochs"])
        self.assertEqual(p.verify_protection(self.data)["status"], "sealed")
        self.assertEqual((self.trust / "checkpoints/00000001.json").read_bytes(), self.original_checkpoint)

    def test_receipt_epoch_validation_rejects_ambiguous_or_substituted_schedule(self):
        good, _, _ = self.transition()
        mutations = []
        missing = copy.deepcopy(good)
        del missing["key_epochs"]
        mutations.append(missing)
        reordered = copy.deepcopy(good)
        reordered["key_epochs"].reverse()
        mutations.append(reordered)
        boolean = copy.deepcopy(good)
        boolean["key_epochs"][0]["start_sequence"] = True
        mutations.append(boolean)
        reused = copy.deepcopy(good)
        reused["key_epochs"][-1].update(public_key=good["key_epochs"][0]["public_key"],
                                      key_fingerprint=good["key_epochs"][0]["key_fingerprint"])
        mutations.append(reused)
        changed_current = copy.deepcopy(good)
        changed_current.update(public_key=self.original_anchor["public_key"],
                               key_fingerprint=self.original_anchor["key_fingerprint"])
        mutations.append(changed_current)
        extra = copy.deepcopy(good)
        extra["key_epochs"][1]["authority"] = "self-declared"
        mutations.append(extra)
        for candidate in mutations:
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                p._validate_anchor(candidate)

    def test_transition_requires_exact_prior_head_and_new_identity(self):
        anchor, payload, key = self.transition()
        checkpoint = (self.trust / "checkpoints/00000002.json").read_bytes()
        changed = copy.deepcopy(payload)
        changed["previous_checkpoint_sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            p.transition_anchor(self.original_anchor, changed, checkpoint, anchor["public_key"],
                                payload["key_transition"]["transition_id"], payload["key_transition"]["approval_sha256"])
        with self.assertRaises(ValueError):
            p._new_anchor(self.original_anchor["public_key"], payload, checkpoint, previous_anchor=anchor)
        self.assertEqual(p.active_key_path(self.keys, anchor), key)
        self.assertEqual(p.active_key_path(self.keys, self.original_anchor), self.keys / "signing_key")

    def test_v2_public_backup_verifies_and_restores_without_any_private_key(self):
        self.transition()
        files = p.backup_files(self.data)
        self.assertEqual(set(files), {"protection.json", "protection/checkpoints/00000001.json", "protection/checkpoints/00000002.json"})
        self.assertNotIn(b"OPENSSH PRIVATE KEY", b"".join(files.values()))
        staging = self.base / "staging"
        shutil.copytree(self.data, staging)
        for name, content in files.items():
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                target.chmod(0o600)
            target.write_bytes(content)
        receipt = Path(p.export_receipt(self.data, self.base / "receipt-v2.json"))
        old_receipt = self.base / "receipt-v1.json"
        old_receipt.write_bytes(self.original_receipt)
        self.assertEqual(p.validate_backup_protection(staging, receipt)["status"], "sealed")
        self.assertEqual(p.validate_backup_protection(staging, old_receipt)["status"], "failed")
        destination = self.base / "restored"
        p.install_restored_trust(staging, destination, receipt)
        staging.rename(destination)
        self.assertEqual(p.verify_protection(destination)["status"], "sealed")
        self.assertFalse(p.default_key_dir(destination).exists())

    def test_noop_sealing_still_checks_recovery_gate(self):
        with patch("heltemes.key_recovery.gate_signing", side_effect=ValueError("recovery incomplete")):
            with p.repository_lock(self.data), self.assertRaisesRegex(ValueError, "recovery incomplete"):
                p.seal_checkpoint(self.data)
        self.assertEqual((self.trust / "anchor.json").read_bytes(), self.original_receipt)


if __name__ == "__main__":
    unittest.main()
