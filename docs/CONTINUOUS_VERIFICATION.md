# Reviewable evidence for each change

The `reviewer` job in `Verify project` runs after both Python test jobs, Terraform validation, and the isolated Linux network lab succeed. It creates a fresh synthetic archive, runs the existing 12-phase demonstration, packages the source and results, and retains a downloadable artifact for 30 days. A new run has its own identifiers and timestamps. The network lab retains its own packet capture and policy observations. See [the network lab guide](NETWORK_LAB.md) for that separate report.

## Inspect a run

1. Open the repository's **Actions** tab and select the relevant `Verify project` run.
2. Confirm all jobs succeeded and open the `reviewer` job summary. Read the tested commit and actual demo completion time.
3. Download the artifact named `reviewer-<commit>-<run ID>-<attempt>`. GitHub requires sign-in to download workflow artifacts.
4. Extract that artifact, then verify its two checksum files before extracting `reviewer.zip`.

```sh
shasum -a 256 -c reviewer.zip.sha256
shasum -a 256 -c CI-VERIFICATION.json.sha256
unzip reviewer.zip -d reviewer-source
cd reviewer-source/source
python3 -I -S -B scripts/reviewer_demo.py --output reviewer-run-01
```

The destination and report directory must be new. The ZIP's `index.html` links to the saved walkthrough and phase results. Each replay uses different temporary keys and timestamps while checking the same expected outcomes.

## What the additional check establishes

The existing packager binds the demo report to the demonstrated runtime source and rejects incomplete outcomes or unsafe report content. `scripts/ci_reviewer.py` additionally compares the complete packaged source inventory and bytes with the tracked Git snapshot. Its public verification record identifies the commit, tree, Python version, report time, workflow run, and package hashes without recording personal checkout paths or credentials.

On a pull request, GitHub normally checks out a temporary merge commit. The report labels that tested commit and records the proposed branch head separately. Reviewers should use the tested commit when comparing source. A pull-request artifact contains the proposed source and follows the same trust assumptions as that pull request.

The overview retains its November 1, 2026 reviewer-edition label and displays the actual demo completion time separately. The artifact summary describes the particular run. The application version remains governed by the runtime's version metadata.

## Publication and retention

The workflow uses read-only repository permissions and a fresh checkout. The upload step names four specific files: the reviewer ZIP, its checksum, the public verification JSON, and its checksum. It runs only after successful demonstration, packaging, and source comparison. Unexpected failures remain visible in the job log and stop that job.

Workflow artifacts expire after 30 days or can be removed earlier with repository administration. Preserve selected milestones as separately checked, tagged reviewer releases. The published [November 2 reviewer release](https://github.com/Fischerdh1/heltemes-evidence/releases/tag/reviewer-2026-11-02) is the existing reference milestone.

The demo uses synthetic evidence, disposable signing identities, and same-account practice authorization. Actual macOS account permissions, off-device custody, source authenticity, and physical power-loss behavior each require their own evidence. AWS deployment remains deferred. A file hash establishes consistency relative to its reference, and the reference's custody determines how much trust it provides.

## Reproduce the complete artifact build locally

Use a clean, committed source checkout with Git, Python 3.11+, and OpenSSH signing support at `/usr/bin/ssh-keygen`. From its root:

```sh
mkdir -p work
python3 -I -S -B scripts/ci_reviewer.py --output work/reviewer-ci
```

The builder requires source parity with the current Git commit. Commit an intended change on a development branch before generating its final report. Ordinary test and demo commands can still be used while editing. Local builds identify their local context in the verification record.

## References

- [GitHub workflow artifacts and retention](https://docs.github.com/en/actions/tutorials/store-and-share-data)
- [Pull-request workflow events and merge commits](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#pull_request)
- [Upload Artifact action inputs and download behavior](https://github.com/actions/upload-artifact)
