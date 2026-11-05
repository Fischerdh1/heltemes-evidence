"""Package a passing synthetic reviewer demonstration and the source it ran.

This creates a reviewer artifact, not an application release or installation.
It never reads managed evidence, trust references, or signing keys.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import package_release as release

BUNDLE_DATE = "2026-11-01"
MAX_REPORT_BYTES = 8 * 1024 * 1024
PERSONAL_REPORT = re.compile(rb"(?:/Users/|/home/|/private/var/|/var/folders/|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
HASH = re.compile(r"[0-9a-f]{64}\Z")
DEMO_PHASES = (("baseline", 0), ("tamper", 0), ("verify-tamper", 0), ("restore", 0),
               ("prepare", 0), ("crash", 71), ("verify-crash", 0), ("blocked-seal", 1),
               ("resume", 0), ("restart", 0), ("ordinary-sign", 0), ("final-check", 0))
DEMO_CHECKS = {"mutable_hashes_pass_but_signed_tamper_fails", "exact_synthetic_original_restored",
               "crash_before_final_completion", "fresh_verification_passes_while_signing_blocked",
               "ordinary_signing_blocked_until_explicit_resume", "restart_does_not_repeat_recovery",
               "ordinary_signing_resumes", "earlier_history_and_completion_preserved"}


def _json(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _path(value):
    path = Path(value).expanduser().absolute()
    if ".." in path.parts or any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("Reviewer paths must not traverse symbolic links or parent segments.")
    return path


def _read(path):
    path = _path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_REPORT_BYTES:
            raise ValueError("Report inputs must be bounded ordinary files without hard links.")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(MAX_REPORT_BYTES + 1)
        after = os.fstat(descriptor)
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("Report input changed while being read.")
        if len(content) != before.st_size:
            raise ValueError("Report input size changed while being read.")
    finally:
        os.close(descriptor)
    if release.PRIVATE_KEY.search(content) or b"openssh-key-v1\x00" in content or PERSONAL_REPORT.search(content):
        raise ValueError("Report contains private key material, a contact address, or a personal local path.")
    return content


def _report(report_dir, source):
    folder = _path(report_dir)
    result_bytes = _read(folder / "results.json")
    result = json.loads(result_bytes)
    if (result.get("format") != "heltemes-reviewer-demo" or result.get("version") != 1
            or result.get("ok") is not True or result.get("scratch_removed") is not True):
        raise ValueError("Only a complete, passing, cleaned-up reviewer demo can be packaged.")
    expected_scope = {"synthetic_only": True, "aws_used": False,
                      "native_account_isolation_tested": False, "physical_power_loss_tested": False,
                      "same_user_practice_authorization": True, "network_disabled": True,
                      "real_archive_or_private_key_inputs": False}
    if result.get("scope") != expected_scope:
        raise ValueError("Reviewer demo scope does not match the offline disposable exercise.")
    hashes = result.get("source_sha256")
    required = {name for name in source if name.startswith("heltemes/") and
                (name.endswith(".py") or name.startswith("heltemes/fixtures/") and name.endswith(".json"))}
    required.add("scripts/reviewer_demo.py")
    if not isinstance(hashes, dict) or set(hashes) != required:
        raise ValueError("Demo source hash coverage is missing or unexpected.")
    for name, digest in hashes.items():
        if not isinstance(digest, str) or not HASH.fullmatch(digest) or name not in source or hashlib.sha256(source[name]).hexdigest() != digest:
            raise ValueError("Demo source hash does not match the source being packaged: " + name)
    checks = result.get("checks")
    if not isinstance(checks, dict) or set(checks) != DEMO_CHECKS or any(value is not True for value in checks.values()):
        raise ValueError("Demo checks are missing or did not all pass.")
    summary = result.get("summary", {})
    if (summary.get("baseline_checkpoint"), summary.get("recovery_checkpoint"), summary.get("final_checkpoint")) != (1, 2, 3):
        raise ValueError("Demo checkpoint progression differs from the reviewed scenario.")
    if any(type(summary.get(key)) is not int or summary[key] < 1 for key in ("verified_objects", "synthetic_filings")):
        raise ValueError("Demo verified object and synthetic filing counts are missing.")
    phases = result.get("phases")
    if not isinstance(phases, list) or len(phases) != len(DEMO_PHASES) or any(not isinstance(phase, dict) for phase in phases):
        raise ValueError("Demo phase evidence is incomplete.")
    if tuple((phase.get("name"), phase.get("expected_exit")) for phase in phases) != DEMO_PHASES:
        raise ValueError("Demo phase sequence differs from the reviewed scenario.")
    files = {"report/results.json": result_bytes, "report/WALKTHROUGH.txt": _read(folder / "WALKTHROUGH.txt")}
    names = set()
    for phase in phases:
        name = phase.get("name")
        relative = phase.get("report", "")
        path = PurePosixPath(relative)
        if not isinstance(name, str) or not name or name in names or not re.fullmatch(r"phases/[0-9]{2}-[a-z0-9_-]+\.json", relative):
            raise ValueError("Demo phase name or relative report path is invalid.")
        names.add(name)
        if phase.get("passed") is not True or type(phase.get("expected_exit")) is not int or phase["expected_exit"] not in (0, 1, 71) or phase.get("observed_exit") != phase["expected_exit"]:
            raise ValueError("Demo contains an unexpected phase result.")
        content = _read(folder.joinpath(*path.parts))
        detail = json.loads(content)
        if detail.get("phase") != name or detail.get("returncode") != phase["observed_exit"] or detail.get("expected_exit") != phase["expected_exit"]:
            raise ValueError("Demo phase log does not match its summary.")
        target = "report/" + relative
        if target in files:
            raise ValueError("Duplicate phase report.")
        files[target] = content
    if not {0, 1, 71}.issubset({phase["expected_exit"] for phase in phases}):
        raise ValueError("Demo lacks success, rejection, or abrupt-crash evidence.")
    return result, files


def _page(result, version):
    escape = html.escape
    rows = []
    outcomes = {"baseline": "Baseline sealed", "tamper": "Synthetic edit applied",
                "verify-tamper": "Tamper rejected (expected)", "restore": "Original restored",
                "prepare": "Recovery prepared", "crash": "Expected crash",
                "verify-crash": "Archive valid / signing blocked", "blocked-seal": "Expected rejection",
                "resume": "Recovery completed", "restart": "Already completed / unchanged",
                "ordinary-sign": "Ordinary checkpoint signed", "final-check": "Final verification passed"}
    for number, phase in enumerate(result["phases"], 1):
        expected = phase["expected_exit"]
        label = outcomes[phase["name"]]
        controlled = expected != 0 or phase["name"] in {"verify-tamper", "verify-crash", "prepare"}
        rows.append(f'<tr><td>{number:02d}</td><th scope="row">{escape(phase["name"].replace("_", " ").replace("-", " "))}</th>'
                    f'<td><span class="pill {"controlled" if controlled else "pass"}">{label}</span></td>'
                    f'<td><a href="report/{escape(phase["report"], quote=True)}">Phase log ↗</a></td></tr>')
    summary = result["summary"]
    return ("""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>HELTEMES Evidence · Reviewer package</title>
<style>
:root{color-scheme:light;--ink:#162731;--muted:#536670;--line:#d4dedb;--green:#17634f;--paper:#f5f7f2}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.6 system-ui,-apple-system,sans-serif}main{max-width:1080px;margin:auto;padding:48px 32px 64px}header{border-top:5px solid var(--green);padding:28px 0 25px}.eyebrow{font:700 12px/1.5 system-ui;letter-spacing:.16em;text-transform:uppercase;color:var(--green)}h1{font-size:clamp(32px,5vw,56px);line-height:1.08;letter-spacing:-.04em;margin:13px 0 18px}h2{font-size:24px;letter-spacing:-.02em;margin:0 0 12px}h3{font-size:16px;margin:0 0 8px}.lead{font-size:20px;max-width:740px;margin:0 0 17px}.muted,small{color:var(--muted)}a{color:#115a6c;text-underline-offset:3px}nav{display:flex;gap:20px;flex-wrap:wrap;margin-top:20px}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:22px 0 34px}.stat,.card{background:white;border:1px solid var(--line);padding:23px;border-radius:10px}.stat strong{display:block;font-size:29px;line-height:1.2;color:var(--green)}.stat span{font-size:13px;color:var(--muted)}section{margin-top:36px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.flow{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:21px 0}.flow div{border-left:3px solid var(--green);background:#e9f0e9;padding:15px 17px}.flow b{display:block;font-size:14px}.flow span{font-size:13px}.note{border-left:3px solid #ae7930;padding:12px 18px;background:#f3eddf}table{width:100%;border-collapse:collapse;background:white;border:1px solid var(--line)}td,th{text-align:left;padding:13px 15px;border-bottom:1px solid var(--line);font-size:14px}th{font-weight:600}thead th{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}td:first-child{color:var(--muted);width:45px}.pill{display:inline-block;border-radius:16px;padding:3px 10px;white-space:nowrap;font-size:12px;font-weight:650}.pass{background:#e5f2e9;color:#175c3f}.controlled{background:#f9efd9;color:#725015}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#162731;color:#eaf1e9;border-radius:8px;padding:20px;font-size:13px;line-height:1.7}ul{padding-left:20px}footer{margin-top:38px;padding-top:20px;border-top:1px solid var(--line);font-size:13px}.table-wrap{overflow-x:auto}@media(max-width:650px){main{padding:24px 18px}.stats,.grid,.flow{grid-template-columns:1fr}.stat{padding:18px}.stat strong{font-size:24px}td,th{padding:10px}nav{gap:12px}.lead{font-size:18px}}@media print{body{background:white}main{padding:10px}a{color:inherit}section,.card,tr{break-inside:avoid}}
</style></head><body><main>
<header><div class="eyebrow">HELTEMES Evidence / Synthetic · Offline · Disposable</div>
<h1>Preserve the evidence.<br>Verify the recovery.</h1>
<p><strong>An original security-engineering portfolio project by Fischer Heltemes.</strong></p>
<p class="lead">A reproducible demonstration of signed evidence history and recovery that keeps signing blocked until the authorized transition is complete.</p>
<p class="muted">Reviewer edition · November 1, 2026 · Runtime source v""" + escape(version) + """ · Synthetic data only</p>
<p class="muted">Demo completed (UTC): """ + escape(str(result.get("completed_at_utc", "Unavailable"))) + """</p>
<nav aria-label="Reviewer links"><a href="source/docs/REVIEWER_GUIDE.md">Reviewer guide</a><a href="report/WALKTHROUGH.txt">Observed walkthrough</a><a href="report/results.json">Machine-readable results</a><a href="MANIFEST.json">File fingerprints</a></nav></header>
<div class="stats"><div class="stat"><strong>""" + str(len(result["phases"])) + """ / """ + str(len(result["phases"])) + """</strong><span>phase outcomes matched expectations</span></div><div class="stat"><strong>""" + str(summary["verified_objects"]) + """ objects</strong><span>verified from synthetic evidence</span></div><div class="stat"><strong>1 → 2 → 3</strong><span>baseline → recovery → ordinary signing</span></div></div>
<section><h2>The control being demonstrated</h2><p>Archive verification and permission to sign are separate decisions. Valid preserved evidence can remain readable while new signatures are deliberately blocked.</p>
<div class="flow"><div><b>1 · Preserve</b><span>Seal synthetic filing records against a separate trusted checkpoint.</span></div><div><b>2 · Interrupt</b><span>Exit after recovery verification but before final completion is published.</span></div><div><b>3 · Revalidate</b><span>Check authorization, key identity, history, and durable completion before resuming.</span></div></div>
<p class="note"><strong>An expected rejection is a successful test.</strong> Exit 1 means the unsafe operation was rejected. Exit 71 is the injected process termination. Neither is presented as an unexplained failure.</p></section>
<section class="grid"><article class="card"><div class="eyebrow">Case study 01 / Evidence integrity</div><h2>Change the filing and its fingerprint</h2><p>The exercise alters synthetic filing bytes and the mutable references that describe them. The signed snapshot still identifies the accepted record, so the reconciled edit is rejected.</p><p class="muted">Lesson: a fingerprint stored beside mutable evidence is not an independent trust reference.</p></article><article class="card"><div class="eyebrow">Case study 02 / Recovery resilience</div><h2>Restart after an incomplete transition</h2><p>The exercise terminates a recovery process before its final completion record is published. Verification can pass while signing remains blocked. Explicit revalidation completes recovery; later restart does not repeat it.</p><p class="muted">Lesson: verified evidence does not by itself authorize new signatures.</p></article></section>
<section><h2>Observed phase evidence</h2><div class="table-wrap"><table><thead><tr><th>Step</th><th>Action</th><th>Observed outcome</th><th>Evidence</th></tr></thead><tbody>""" + "".join(rows) + """</tbody></table></div></section>
<section class="grid"><div class="card"><h2>Reproduce it locally</h2><p>Extract this package. Use Python 3.11+ and OpenSSH with signing support at <code>/usr/bin/ssh-keygen</code>. No Python packages, SEC contact, cloud credentials, or administrator password are required.</p>
<pre>cd source
python3 -I -S -B scripts/reviewer_demo.py --output reviewer-run-01</pre>
<p>The output directory must be new. Each run creates a fresh temporary synthetic archive and throwaway identities, then removes that scratch state. Random keys and timestamps differ; expected behavior stays the same.</p></div>
<div class="card"><h2>What this proves—and its limits</h2><ul><li>Tamper rejection against signed history.</li><li>A signing block that survives an interrupted recovery and fresh-process restart.</li><li>Recovery completion followed by ordinary signing, without repeating the transition.</li><li>Same-user practice authorization; this run does not test native account isolation.</li><li>Abrupt process termination, not physical power loss.</li><li>AWS is deferred. No live SEC data or real private keys are used.</li></ul></div></section>
<section><h2>Review the engineering</h2><p>HELTEMES Evidence connects research evidence, software engineering, and security in one original portfolio project. Inspect the design choices, reproduce the observed results, and review the limitations of each control.</p><p><a href="source/docs/ARCHITECTURE.md">Architecture and trust boundaries</a> · <a href="source/docs/THREAT_MODEL.md">Threat model</a> · <a href="source/docs/key-recovery.md">Recovery design</a> · <a href="source/docs/LEARNING_PATH.md">Learning and contribution record</a></p></section>
<footer>This is an offline reviewer artifact, not a deployment or an independent security audit. The manifest detects file changes relative to its recorded hashes; it is not an independently trusted signature. The packaged report is tied to the included demo/runtime source hashes. Files contain no disposable private keys.</footer>
</main></body></html>""").encode()


def package(report, destination, *, root=ROOT):
    destination = _path(destination)
    checksum = destination.with_suffix(destination.suffix + ".sha256")
    if destination.suffix != ".zip" or not destination.parent.is_dir():
        raise ValueError("Choose a new .zip in an existing directory.")
    if os.path.lexists(destination) or os.path.lexists(checksum):
        raise FileExistsError("Reviewer package or checksum already exists; nothing will be overwritten.")
    source = release.source_bytes(_path(root))
    if "docs/REVIEWER_GUIDE.md" not in source:
        raise ValueError("The reviewer guide is missing.")
    version = release.release_version(source)
    result, reports = _report(report, source)
    files = {"source/" + name: content for name, content in source.items()}
    files.update(reports)
    files["index.html"] = _page(result, version)
    files["REVIEWER-BUNDLE.json"] = _json({"format": "heltemes-reviewer-bundle", "version": 1,
        "bundle_date": BUNDLE_DATE, "runtime_version": version,
        "application_release": False, "installed_service_modified": False, "aws_deployed": False,
        "report_source_hashes_verified": True, "private_keys_included": False,
        "report_completed_at_utc": result.get("completed_at_utc"),
        "scope": result["scope"]})
    manifest = {name: hashlib.sha256(content).hexdigest() for name, content in sorted(files.items())}
    files["MANIFEST.json"] = _json(manifest)
    with tempfile.TemporaryDirectory(prefix=".reviewer-package-", dir=destination.parent) as temp:
        staged = Path(temp) / "package.zip"
        with zipfile.ZipFile(staged, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, content in sorted(files.items()):
                archive.writestr(release.zip_entry(name, (2026, 11, 1, 0, 0, 0)), content, compresslevel=9)
        with zipfile.ZipFile(staged) as archive:
            if len(archive.namelist()) != len(files) or set(archive.namelist()) != set(files) or archive.testzip() is not None:
                raise ValueError("Reviewer ZIP inventory or integrity verification failed.")
            for name, content in files.items():
                if archive.read(name) != content:
                    raise ValueError("Reviewer ZIP differs from captured input.")
        digest = hashlib.sha256(staged.read_bytes()).hexdigest()
        staged_checksum = Path(temp) / "package.sha256"
        staged_checksum.write_text(digest + "  " + destination.name + "\n")
        for path in (staged, staged_checksum):
            path.chmod(0o644)
            with path.open("rb") as handle:
                os.fsync(handle.fileno())
        os.link(staged, destination)
        try:
            os.link(staged_checksum, checksum)
        except BaseException:
            if destination.exists() and os.path.samefile(staged, destination):
                destination.unlink()
            raise
        fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return {"archive": str(destination), "checksum": str(checksum), "sha256": digest,
            "files": len(files), "bytes": destination.stat().st_size,
            "runtime_version": version, "bundle_date": BUNDLE_DATE,
            "installed_service_modified": False, "aws_deployed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True, help="Passing synthetic reviewer demo output")
    parser.add_argument("--output", type=Path, required=True, help="New reviewer .zip; existing files are refused")
    args = parser.parse_args()
    try:
        print(json.dumps(package(args.report, args.output), indent=2))
    except (OSError, ValueError) as error:
        parser.exit(1, "Reviewer package refused: " + str(error) + "\n")


if __name__ == "__main__":
    main()
