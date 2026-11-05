"""Build a disposable reviewer artifact tied to one clean Git source snapshot."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import package_reviewer, reviewer_demo

OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
POSITIVE_ID = re.compile(r"[1-9][0-9]{0,19}\Z")


def git(root, *arguments):
    process = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True, timeout=30, check=False,
    )
    if process.returncode:
        raise ValueError("Git could not establish the reviewed source snapshot.")
    return process.stdout


def git_identity(root):
    if Path(git(root, "rev-parse", "--show-toplevel").decode().strip()) != root:
        raise ValueError("Reviewer source must be the Git repository root.")
    commit = git(root, "rev-parse", "HEAD").decode().strip()
    tree = git(root, "rev-parse", "HEAD^{tree}").decode().strip()
    if not OBJECT_ID.fullmatch(commit) or not OBJECT_ID.fullmatch(tree):
        raise ValueError("Git returned an invalid source identity.")
    return {"commit": commit, "tree": tree}


def github_context(commit, environment):
    """Record selected public identifiers, never arbitrary runner environment."""
    actions = environment.get("GITHUB_ACTIONS")
    if actions in (None, "", "false"):
        return None
    if actions != "true":
        raise ValueError("GITHUB_ACTIONS must identify a recognized execution context.")
    if environment.get("GITHUB_SHA") != commit:
        raise ValueError("Checkout HEAD differs from the GitHub-tested commit.")
    event = environment.get("GITHUB_EVENT_NAME")
    if event not in {"push", "pull_request", "workflow_dispatch"}:
        raise ValueError("Unsupported GitHub event for reviewer artifacts.")
    repository = environment.get("GITHUB_REPOSITORY", "")
    run_id = environment.get("GITHUB_RUN_ID", "")
    attempt = environment.get("GITHUB_RUN_ATTEMPT", "")
    if (not REPOSITORY.fullmatch(repository) or not POSITIVE_ID.fullmatch(run_id)
            or not POSITIVE_ID.fullmatch(attempt)
            or environment.get("GITHUB_SERVER_URL") != "https://github.com"):
        raise ValueError("GitHub repository, run, or server identifiers are invalid.")
    pr_head = environment.get("REVIEWER_PR_HEAD_SHA", "")
    if event == "pull_request":
        if not OBJECT_ID.fullmatch(pr_head):
            raise ValueError("Pull-request provenance requires its head commit separately.")
    elif pr_head:
        raise ValueError("A pull-request head was supplied for a different event.")
    return {
        "repository": repository, "event": event, "run_id": run_id,
        "run_attempt": attempt,
        "run_url": f"https://github.com/{repository}/actions/runs/{run_id}",
        "tested_commit": commit,
        "tested_commit_kind": "pull_request_merge" if event == "pull_request" else "checkout",
        "pull_request_head_commit": pr_head or None,
    }


def tracked_source(root, commit):
    source = {}
    records = git(root, "ls-tree", "-rz", commit)
    for record in records.split(b"\0"):
        if not record:
            continue
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, object_id = metadata.decode().split()
        name = raw_name.decode()
        if not package_reviewer.release.allowed(PurePosixPath(name)):
            continue
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise ValueError("Packaged Git source must contain ordinary files.")
        source[name] = git(root, "cat-file", "blob", object_id)
    return source


def require_source_match(root, expected):
    actual = package_reviewer.release.source_bytes(root)
    if set(actual) != set(expected):
        raise ValueError("Packaged source inventory differs from the tracked commit.")
    if any(content != expected[name] for name, content in actual.items()):
        raise ValueError("Packaged source bytes differ from the tracked commit.")


def verify_package(archive_path, expected_source):
    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum = archive_path.with_suffix(".zip.sha256").read_text()
    if checksum != f"{digest}  {archive_path.name}\n":
        raise ValueError("Reviewer ZIP checksum does not match its bytes.")
    with zipfile.ZipFile(archive_path) as archive:
        names = archive.namelist()
        manifest = json.loads(archive.read("MANIFEST.json"))
        if (not isinstance(manifest, dict) or len(names) != len(set(names))
                or set(names) != set(manifest) | {"MANIFEST.json"}
                or archive.testzip() is not None):
            raise ValueError("Reviewer ZIP inventory or manifest is invalid.")
        for name, expected_hash in manifest.items():
            if hashlib.sha256(archive.read(name)).hexdigest() != expected_hash:
                raise ValueError("Reviewer ZIP entry differs from its manifest.")
        source_names = {name.removeprefix("source/") for name in names if name.startswith("source/")}
        if source_names != set(expected_source):
            raise ValueError("Reviewer ZIP source inventory differs from its commit.")
        for name, expected_content in expected_source.items():
            if archive.read("source/" + name) != expected_content:
                raise ValueError("Reviewer ZIP source bytes differ from its commit.")
    return {
        "filename": archive_path.name, "sha256": digest,
        "bytes": archive_path.stat().st_size,
        "manifested_files": len(manifest), "source_files": len(expected_source),
    }


def summary_text(verification, phases):
    source, demo = verification["source"], verification["demo"]
    github = verification["github"]
    lines = [
        "# HELTEMES Evidence reviewer verification", "",
        f"Tested source commit: `{source['commit']}`.",
        f"Source tree: `{source['tree']}`.",
        f"Demo completed at {demo['completed_at_utc']} using Python {demo['python_version']}.",
        f"All {len(phases)} phase outcomes matched expectations; temporary practice state was removed.",
        f"All {source['files']} packaged source files match the tested commit.", "",
    ]
    if github:
        lines += [f"[GitHub run]({github['run_url']}) (attempt {github['run_attempt']}).",
                  "Artifact prepared for upload with 30 days of requested retention."]
        if github["pull_request_head_commit"]:
            lines += ["The tested commit is the proposed merge result.",
                      f"Pull-request head: `{github['pull_request_head_commit']}`."]
    else:
        lines += ["Artifact prepared locally. GitHub execution context is absent."]
    lines += ["", "| Phase | Expected exit | Observed exit |",
              "| --- | --- | --- |"]
    lines += [f"| {phase['name']} | {phase['expected_exit']} | {phase['observed_exit']} |" for phase in phases]
    lines += ["", "Exit 71 is the injected process termination; exit 1 is the expected blocked-signing attempt.",
              f"Reviewer ZIP SHA-256: `{verification['package']['sha256']}`.", "",
              "This run uses same-user synthetic evidence and disposable keys. Native account isolation,",
              "physical power loss, live SEC collection, and AWS deployment have separate verification requirements.",
              "The source and artifact hashes establish consistency with this Git snapshot.",
              "Project-controlled CI results require review of the tested code and workflow."]
    return "\n".join(lines) + "\n"


def build(output, *, root=ROOT, environment=None):
    root = package_reviewer._path(root)
    identity = git_identity(root)
    github = github_context(identity["commit"], os.environ if environment is None else environment)
    expected = tracked_source(root, identity["commit"])
    require_source_match(root, expected)
    destination = package_reviewer._path(output)
    if destination.is_relative_to(root) and package_reviewer.release.allowed(destination.relative_to(root) / "SUMMARY.md"):
        raise ValueError("Reviewer output must be outside packaged source directories.")
    destination = reviewer_demo.new_report_directory(destination)
    result = reviewer_demo.run_demo(destination / "demo")
    if result.get("ok") is not True or result.get("scratch_removed") is not True:
        raise ValueError("Reviewer demo failed; successful publication was withheld.")
    staged = destination / "staging"
    staged.mkdir(mode=0o700)
    package_reviewer.package(destination / "demo", staged / "reviewer.zip", root=root)
    package = verify_package(staged / "reviewer.zip", expected)
    verification = {
        "format": "heltemes-ci-reviewer", "version": 1, "ok": True,
        "source": {**identity, "files": len(expected), "all_packaged_source_matches_commit": True},
        "github": github,
        "demo": {"phase_count": len(result["phases"]),
                 "started_at_utc": result["started_at_utc"],
                 "completed_at_utc": result["completed_at_utc"],
                 "python_version": result["python_version"], "platform": result["platform"],
                 "checks": result["checks"], "scope": result["scope"], "scratch_removed": True},
        "package": package,
        "artifact": {"state": "prepared_for_upload" if github else "local_only",
                     "requested_retention_days": 30 if github else None},
    }
    metadata = (json.dumps(verification, indent=2, sort_keys=True) + "\n").encode()
    (staged / "CI-VERIFICATION.json").write_bytes(metadata)
    (staged / "CI-VERIFICATION.json.sha256").write_text(
        hashlib.sha256(metadata).hexdigest() + "  CI-VERIFICATION.json\n"
    )
    (destination / "SUMMARY.md").write_text(summary_text(verification, result["phases"]))
    require_source_match(root, expected)
    if git_identity(root) != identity:
        raise ValueError("Git HEAD changed during the reviewer build.")
    staged.rename(destination / "publish")
    return verification


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New output directory with an existing parent")
    arguments = parser.parse_args()
    try:
        result = build(arguments.output)
    except (OSError, ValueError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        parser.exit(1, "Reviewer CI build refused: " + str(error) + "\n")
    print(json.dumps({"ok": True, "source": result["source"], "package": result["package"]}, indent=2))


if __name__ == "__main__":
    main()
