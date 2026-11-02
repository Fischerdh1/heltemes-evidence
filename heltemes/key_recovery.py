"""Explicit, fail-closed key transitions. Public verification never needs this journal.

The native installation accepts only administrator-owned approval files outside
custodian/collector writable directories. Standalone archives use the operator's
explicit approval digest; they do not claim separate-account authorization.
"""
from __future__ import annotations

import fcntl
import os
import sqlite3
import stat
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path

from . import protection as p
from .local_accounts import PREFIX, policy_for, private_snapshot, _reject_acl, _protected

AUTHORIZATIONS = PREFIX / "recovery-authorizations"
REQUEST_FORMAT = "heltemes-key-recovery-authorization"


def _private(path, directory=False):
    path = p._safe_path(path)
    info = path.stat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077 or (not directory and info.st_nlink != 1):
        raise ValueError("Recovery material must be owner-only, unlinked, and owned by the custodian.")
    _reject_acl(path)
    return path


def recovery_dir(trust):
    trust = p._safe_path(trust)
    return trust.parent / (trust.name + ".recovery")


@contextmanager
def recovery_lock(trust):
    """Derived from the trust vault, so selecting another key directory cannot bypass it."""
    trust = p._safe_path(trust)
    path = trust.parent / ("." + trust.name + ".recovery.lock")
    fd = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("Unsafe recovery writer lock.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("Another signing or recovery operation is running.") from error
        yield
    finally:
        os.close(fd)


@contextmanager
def _context(data_dir):
    policy = policy_for(data_dir)
    if policy:
        policy.require("custodian")
        with private_snapshot(policy) as data, recovery_lock(policy.trust_dir):
            yield data, policy.trust_dir, policy.key_dir
    else:
        data = p._data_path(data_dir)
        trust, keys = p.default_trust_dir(data), p.default_key_dir(data)
        with p.repository_lock(data), recovery_lock(trust):
            yield data, trust, keys


def _public_from_key(path):
    key = _private(p._private_key(path))
    return p._public_key(p._crypto(["-y", "-f", str(key)], input_bytes=b"").decode("ascii").strip())


def _archive(data, trust, anchor):
    if {item.name for item in trust.iterdir()} != {"anchor.json", "checkpoints"}:
        raise ValueError("Unexpected public trust material; signing remains blocked.")
    status, snapshot, files = p._verified(data, anchor, trust / "checkpoints")
    p._check_evidence(data, snapshot)
    return status, snapshot, files


def _approval(raw):
    value = p._json(raw)
    fields = {"format", "version", "action", "transition_id", "archive_id", "old_receipt", "old_receipt_sha256", "candidate_public_key", "candidate_key_fingerprint"}
    if set(value) != fields or value["format"] != REQUEST_FORMAT or type(value["version"]) is not int or value["version"] != 1 or value["action"] != "replace_signing_key":
        raise ValueError("Unsupported recovery authorization.")
    p._archive_id(value["transition_id"])
    p._validate_anchor(value["old_receipt"])
    old = value["old_receipt"]
    new = p._public_key(value["candidate_public_key"])
    if (new != value["candidate_public_key"] or value["archive_id"] != old["archive_id"]
            or value["old_receipt_sha256"] != p._sha(p._canonical(old))
            or value["candidate_key_fingerprint"] != p._fingerprint(new)
            or new in {epoch["public_key"] for epoch in p._key_epochs(old)}):
        raise ValueError("Recovery authorization identity or receipt binding is invalid.")
    if old["sequence"] >= p.MAX_CHECKPOINTS or len(p._key_epochs(old)) >= p.MAX_KEY_EPOCHS:
        raise ValueError("Archive transition limit reached.")
    if p._canonical(value) != raw:
        raise ValueError("Recovery authorization must use the exact canonical review document.")
    return value


def _authorized(path, expected, data, trust, keys):
    path = p._safe_path(path)
    if not isinstance(expected, str) or not p._HASH.fullmatch(expected):
        raise ValueError("An independently approved authorization SHA-256 is required.")
    if any(path == root or path.is_relative_to(root) for root in (data, trust, keys, recovery_dir(trust))):
        raise ValueError("Authorization must be kept outside evidence, trust, keys, and the recovery journal.")
    # This exact fixed trust path also covers custodian private snapshots.
    if trust == PREFIX / "custody/trust":
        if path.parent != AUTHORIZATIONS or path.suffix != ".json":
            raise ValueError("Managed recovery requires a separately installed administrator approval.")
        for item, directory in ((PREFIX, True), (AUTHORIZATIONS, True), (path, False)):
            _protected(item, {0}, directory=directory)
    raw = p._read(path, 32_768)
    if p._sha(raw) != expected:
        raise ValueError("Recovery authorization differs from the independently approved digest.")
    return _approval(raw)


def plan_recovery(data_dir, candidate_key, receipt, output):
    """Produce a public review document; this is not authorization or a transition."""
    with _context(data_dir) as (data, trust, keys):
        anchor, _ = p._anchor(trust / "anchor.json")
        independent, _ = p._anchor(receipt)
        if anchor != independent:
            raise ValueError("The independent receipt is not the currently accepted head.")
        _archive(data, trust, anchor)
        if _pending(trust, anchor):
            raise ValueError("Finish the existing recovery before planning another.")
        new = _public_from_key(candidate_key)
        request = {"format": REQUEST_FORMAT, "version": 1, "action": "replace_signing_key",
                   "transition_id": str(uuid.uuid4()), "archive_id": anchor["archive_id"],
                   "old_receipt": anchor, "old_receipt_sha256": p._sha(p._canonical(anchor)),
                   "candidate_public_key": new, "candidate_key_fingerprint": p._fingerprint(new)}
        raw = p._canonical(request)
        _approval(raw)
        target = p._safe_path(output)
        if any(target == root or target.is_relative_to(root) for root in (data, trust, keys, recovery_dir(trust))):
            raise ValueError("Save the public review request outside protected archive directories.")
        p._exclusive(target, raw)
        return {"ok": True, "state": "review_required", "request": str(target), "authorization_sha256": p._sha(raw),
                "transition_id": request["transition_id"], "old_key_fingerprint": anchor["key_fingerprint"],
                "new_key_fingerprint": request["candidate_key_fingerprint"], "sequence": anchor["sequence"],
                "meaning": "Public plan only. Explicit independent approval is required before prepare."}


def _records(trust):
    folder = recovery_dir(trust)
    if not folder.exists():
        return {}
    _private(folder, True)
    result = {}
    for item in folder.iterdir():
        p._archive_id(item.name)
        _private(item, True)
        if {child.name for child in item.iterdir()} - {"prepared.json", "candidate.key", "completion.json", ".completion.tmp"}:
            raise ValueError("Unexpected recovery journal content; signing remains blocked.")
        prepared = p._json(p._read(_private(item / "prepared.json")))
        if set(prepared) != {"format", "version", "transition_id", "authorization_path", "authorization_sha256", "authorization", "checkpoint", "new_anchor"} or prepared["format"] != "heltemes-key-transition" or type(prepared["version"]) is not int or prepared["version"] != 1 or prepared["transition_id"] != item.name:
            raise ValueError("Malformed durable recovery intent.")
        result[item.name] = (item, prepared)
    return result


def _pending(trust, anchor):
    records = _records(trust)
    accepted = {e["transition_id"] for e in p._key_epochs(anchor)[1:]}
    if not accepted.issubset(records):
        raise ValueError("Committed recovery authorization is missing; signing remains blocked.")
    pending = [name for name, (folder, _) in records.items() if name not in accepted or not (folder / "completion.json").exists()]
    if len(pending) > 1:
        raise ValueError("Conflicting unfinished recoveries; signing remains blocked.")
    return pending


def _record_valid(folder, record, data, trust, keys):
    if not isinstance(record["authorization_path"], str):
        raise ValueError("Malformed recovery authorization location.")
    approval = _authorized(record["authorization_path"], record["authorization_sha256"], data, trust, keys)
    if approval != record["authorization"] or approval["transition_id"] != record["transition_id"]:
        raise ValueError("Recovery intent differs from its independent authorization.")
    old, envelope = approval["old_receipt"], record["checkpoint"]
    if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
        raise ValueError("Malformed recovery checkpoint.")
    payload = envelope["payload"]
    if not isinstance(payload, dict):
        raise ValueError("Malformed recovery checkpoint payload.")
    expected = {"transition_id": record["transition_id"], "approval_sha256": record["authorization_sha256"],
                "from_key_fingerprint": old["key_fingerprint"], "to_key_fingerprint": approval["candidate_key_fingerprint"]}
    if (set(payload) != {"version", "archive_id", "sequence", "previous_checkpoint_sha256", "sealed_at", "snapshot", "key_transition"}
            or payload["version"] != 2 or payload["archive_id"] != old["archive_id"] or payload["sequence"] != old["sequence"] + 1
            or payload["previous_checkpoint_sha256"] != old["checkpoint_sha256"] or payload["key_transition"] != expected):
        raise ValueError("Recovery checkpoint differs from the approved transition.")
    p._verify_signature(payload, envelope["signature"], approval["candidate_public_key"])
    target = p.transition_anchor(old, payload, p._canonical(envelope), approval["candidate_public_key"], record["transition_id"], record["authorization_sha256"])
    if target != record["new_anchor"]:
        raise ValueError("Recovery target receipt differs from its approved checkpoint.")
    return approval


def _completion(record):
    return {"format": "heltemes-key-transition-complete", "version": 1, "transition_id": record["transition_id"],
            "prepared_sha256": p._sha(p._canonical(record)), "checkpoint_sha256": record["new_anchor"]["checkpoint_sha256"],
            "authorization_sha256": record["authorization_sha256"]}


def _committed(data, trust, keys, anchor):
    records = _records(trust)
    _, _, files = _archive(data, trust, anchor)
    _committed_records(records, data, trust, keys, anchor, files)


def _committed_records(records, data, trust, keys, anchor, files):
    epochs = p._key_epochs(anchor)[1:]
    if set(records) != {e["transition_id"] for e in epochs}:
        raise ValueError("Recovery is unfinished or its committed journal is missing; signing remains blocked.")
    for index, epoch in enumerate(epochs):
        folder, record = records[epoch["transition_id"]]
        approval = _record_valid(folder, record, data, trust, keys)
        old = approval["old_receipt"]
        # Bind each authorization to the same accepted epoch prefix and exact old head.
        if (p._key_epochs(old) != p._key_epochs(anchor)[:index + 1]
                or old["archive_id"] != anchor["archive_id"] or old["sequence"] + 1 != epoch["start_sequence"]
                or p._sha(files[p._checkpoint_name(old["sequence"])]) != old["checkpoint_sha256"]
                or p._canonical(record["checkpoint"]) != files[p._checkpoint_name(epoch["start_sequence"])]
                or record["new_anchor"]["key_epochs"][-1] != epoch):
            raise ValueError("Committed recovery is inconsistent with the accepted signed history.")
        complete = p._json(p._read(_private(folder / "completion.json"), 4096))
        if complete != _completion(record):
            raise ValueError("Durable recovery completion is missing or invalid; signing remains blocked.")


def gate_signing(data, trust, keys, anchor):
    """Caller holds recovery_lock through signing/commit. Never completes recovery."""
    p._validate_anchor(anchor)
    _committed(data, trust, keys, anchor)
    key = p.active_key_path(keys, anchor)
    _private(keys, True)
    if anchor["version"] == 2:
        _private(keys / "identities", True)
    if _public_from_key(key) != p._public_key(anchor["public_key"]):
        raise ValueError("Installed private key is not the approved active identity; signing remains blocked.")
    return key


def prepare_recovery(data_dir, candidate_key, authorization, expected_sha256):
    with _context(data_dir) as (data, trust, keys):
        approval = _authorized(authorization, expected_sha256, data, trust, keys)
        anchor, _ = p._anchor(trust / "anchor.json")
        if anchor != approval["old_receipt"]:
            raise ValueError("Recovery approval does not name the current accepted head.")
        if _pending(trust, anchor):
            raise ValueError("An unfinished recovery already exists. Resume it explicitly.")
        _committed(data, trust, keys, anchor)  # Does not require a missing old private key.
        _, snapshot, files = _archive(data, trust, anchor)
        if _public_from_key(candidate_key) != approval["candidate_public_key"]:
            raise ValueError("Candidate key does not match the approved fingerprint.")
        root = recovery_dir(trust)
        if not root.exists():
            p._mkdir(root)
        _private(root, True)
        target = root / approval["transition_id"]
        if target.exists():
            raise ValueError("Recovery identity already exists; use resume.")
        # An unpublished temporary directory cannot authorize anything. Atomic
        # rename publishes the complete durable intent before any active key/head write.
        with tempfile.TemporaryDirectory(prefix=".recovery-prepare-", dir=root.parent) as temporary:
            stage = Path(temporary).resolve()
            os.chmod(stage, 0o700)
            key_bytes = p._read(candidate_key, 16_384)
            p._exclusive(stage / "candidate.key", key_bytes)
            if _public_from_key(stage / "candidate.key") != approval["candidate_public_key"]:
                raise ValueError("Candidate key changed during preparation.")
            latest = p._json(files[p._checkpoint_name(anchor["sequence"])] )["payload"]
            payload = {"version": 2, "archive_id": anchor["archive_id"], "sequence": anchor["sequence"] + 1,
                       "previous_checkpoint_sha256": anchor["checkpoint_sha256"], "sealed_at": p._now(),
                       "snapshot": latest["snapshot"], "key_transition": {
                           "transition_id": approval["transition_id"], "approval_sha256": expected_sha256,
                           "from_key_fingerprint": anchor["key_fingerprint"], "to_key_fingerprint": approval["candidate_key_fingerprint"]}}
            checkpoint = {"payload": payload, "signature": p._signature(payload, stage / "candidate.key")}
            new_anchor = p.transition_anchor(anchor, payload, p._canonical(checkpoint), approval["candidate_public_key"], approval["transition_id"], expected_sha256)
            record = {"format": "heltemes-key-transition", "version": 1, "transition_id": approval["transition_id"],
                      "authorization_path": str(p._safe_path(authorization)), "authorization_sha256": expected_sha256,
                      "authorization": approval, "checkpoint": checkpoint, "new_anchor": new_anchor}
            p._exclusive(stage / "prepared.json", p._canonical(record))
            p._sync_directory(stage)
            os.rename(stage, target)
            p._sync_directory(root)
        return {"ok": True, "state": "prepared", "signing_allowed": False, "transition_id": approval["transition_id"],
                "meaning": "Signing remains blocked until explicit resume verifies and durably completes this transition."}


def _boundary(name):
    """Test injection hook. Production never reads an environment crash switch."""


def _replace(path, content, temporary_name):
    temporary = path.parent / temporary_name
    if temporary.exists():
        # Only the exact deterministic interrupted write can be reused.
        if p._read(temporary) != content:
            raise ValueError("Interrupted recovery write differs from the approved content.")
    else:
        p._exclusive(temporary, content)
    _boundary("before_" + path.name)
    os.replace(temporary, path)
    p._sync_directory(path.parent)


def _partial(data, trust, keys, folder, record):
    approval = _record_valid(folder, record, data, trust, keys)
    old, new = approval["old_receipt"], record["new_anchor"]
    trust_inventory = {item.name for item in trust.iterdir()}
    if trust_inventory not in ({"anchor.json", "checkpoints"}, {"anchor.json", "checkpoints", ".recovery-anchor.tmp"}):
        raise ValueError("Unexpected public trust material during recovery.")
    if ".recovery-anchor.tmp" in trust_inventory and p._read(trust / ".recovery-anchor.tmp") != p._canonical(new):
        raise ValueError("Interrupted public receipt differs from the authorized recovery.")
    current, _ = p._anchor(trust / "anchor.json")
    if current not in (old, new):
        raise ValueError("Current trust head is neither the approved old nor exact recovery head.")
    expected = {p._checkpoint_name(i) for i in range(1, old["sequence"] + 1)}
    transition_name = p._checkpoint_name(new["sequence"])
    inventory = {item.name for item in (trust / "checkpoints").iterdir()}
    if inventory not in (expected, expected | {transition_name}):
        raise ValueError("Unexpected checkpoint history during recovery.")
    if transition_name in inventory and p._read(trust / "checkpoints" / transition_name) != p._canonical(record["checkpoint"]):
        raise ValueError("Partial transition checkpoint differs from its approved intent.")
    # Verify the exact accepted prefix even while its one authorized successor is
    # present. No public files are deleted/hidden to make verification pass.
    with tempfile.TemporaryDirectory(prefix="heltemes-recovery-prefix-") as temporary:
        prefix = Path(temporary).resolve()
        for name in expected:
            p._exclusive(prefix / name, p._read(trust / "checkpoints" / name))
        latest, prefix_files = p._load_chain(prefix, old)
        _, snapshot, _ = p._verified(data, old, prefix)
        p._check_evidence(data, snapshot)
        if p._canonical(latest["snapshot"]) != p._canonical(record["checkpoint"]["payload"]["snapshot"]):
            raise ValueError("Recovery would change the last accepted snapshot.")
        previous_records = {name: item for name, item in _records(trust).items() if name != record["transition_id"]}
        _committed_records(previous_records, data, trust, keys, old, prefix_files)
    candidate = folder / "candidate.key"
    if _public_from_key(candidate) != approval["candidate_public_key"]:
        raise ValueError("Staged key differs from the approved identity.")
    return current, approval


def resume_recovery(data_dir):
    with _context(data_dir) as (data, trust, keys):
        anchor, _ = p._anchor(trust / "anchor.json")
        pending = _pending(trust, anchor)
        if not pending:
            gate_signing(data, trust, keys, anchor)
            return {"ok": True, "state": "committed" if anchor["version"] == 2 else "no_transition", "signing_allowed": True, "already_completed": True}
        folder, record = _records(trust)[pending[0]]
        current, approval = _partial(data, trust, keys, folder, record)
        new = record["new_anchor"]
        _private(keys, True)
        identities = keys / "identities"
        if not identities.exists():
            p._mkdir(identities)
        _private(identities, True)
        installed = p.active_key_path(keys, new)
        if not installed.exists():
            p._exclusive(installed, p._read(folder / "candidate.key", 16_384))
        if _public_from_key(installed) != approval["candidate_public_key"]:
            raise ValueError("Installed key does not match the authorized fingerprint.")
        _boundary("after_key_install")
        _partial(data, trust, keys, folder, record)
        _boundary("after_verification")
        checkpoint = trust / "checkpoints" / p._checkpoint_name(new["sequence"])
        if not checkpoint.exists():
            p._exclusive(checkpoint, p._canonical(record["checkpoint"]))
        _boundary("after_checkpoint")
        if current == approval["old_receipt"]:
            _replace(trust / "anchor.json", p._canonical(new), ".recovery-anchor.tmp")
        _boundary("after_anchor")
        _partial(data, trust, keys, folder, record)
        _archive(data, trust, new)
        if _public_from_key(installed) != approval["candidate_public_key"]:
            raise ValueError("Installed key changed before commit.")
        completion = folder / "completion.json"
        _replace(completion, p._canonical(_completion(record)), ".completion.tmp")
        _boundary("after_commit")
        gate_signing(data, trust, keys, new)
        return {"ok": True, "state": "committed", "signing_allowed": True, "already_completed": False,
                "sequence": new["sequence"], "checkpoint_sha256": new["checkpoint_sha256"],
                "public_key_fingerprint": new["key_fingerprint"], "transition_id": record["transition_id"]}


def recovery_status(data_dir):
    try:
        with _context(data_dir) as (data, trust, keys):
            anchor, _ = p._anchor(trust / "anchor.json")
            gate_signing(data, trust, keys, anchor)
            return {"ok": True, "state": "committed" if anchor["version"] == 2 else "original_identity",
                    "signing_allowed": True, "active_key_matches": True, "public_key_fingerprint": anchor["key_fingerprint"],
                    "sequence": anchor["sequence"], "checkpoint_sha256": anchor["checkpoint_sha256"]}
    except (ValueError, OSError, TypeError, KeyError, sqlite3.Error) as error:
        return {"ok": False, "state": "blocked", "signing_allowed": False, "active_key_matches": False, "error": str(error)}
