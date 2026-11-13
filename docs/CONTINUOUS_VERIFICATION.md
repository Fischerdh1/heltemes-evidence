# Reviewable evidence for each change

The `reviewer` job in `Verify project` runs after both Python test jobs, Terraform validation, and all network and recovery jobs described below succeed. It creates a fresh synthetic archive, runs the existing 12-phase demonstration, packages the source and results, and retains a downloadable artifact for 30 days. A new run has its own identifiers and timestamps. The network lab retains its own packet capture and policy observations. See [the network lab guide](NETWORK_LAB.md) for that separate report.

The required `network_lab` job runs the routing/firewall exercise, the [DNS/TLS exercise](NETWORK_SERVICES_LAB.md), the [segmentation exercise](NETWORK_SEGMENTATION.md), the [monitoring exercise](NETWORK_MONITORING.md), and the [service-restart exercise](NETWORK_MONITOR_RESTART.md). Each has a separate artifact. A successful earlier exercise does not establish that the entire job passed; verify all five results and the final job status. DNS/TLS uploads exclude temporary private keys. All five artifacts use the same 30-day retention period.

The separate `monitor_reboot` job boots and reboots a disposable Ubuntu guest, verifies persistent monitoring state and automatic service startup, and publishes a sixth network artifact. Its [full-reboot guide](NETWORK_MONITOR_REBOOT.md) explains the additional evidence. The required `reviewer` job runs its prerequisite guard even if an earlier job fails or is skipped, and explicitly requires all prerequisite results to be `success`. A dependency alone would allow the reviewer job to be skipped, which is insufficient as an explicit success gate.

The separate `monitor_powercut` job performs two abrupt cuts of the entire disposable VM and cold-starts the same disk after each. Its [power-cut guide](NETWORK_MONITOR_POWERCUT.md) describes the unfinished-transaction and lost-response cases, automatic unknown coverage, and fresh recovery checks. It publishes a seventh network artifact and is included in the explicit reviewer prerequisite guard. This simulates guest power loss while the host remains powered.

The separate `monitor_automatic` job runs an independent five-second collector and a monitor with a 20-second missing-data deadline. Its [automatic monitoring guide](NETWORK_MONITOR_AUTOMATIC.md) covers a paused-but-existing collector, detection before inspection, preserved incidents, and fresh recovery after supervisor restart. Its eighth network artifact contains the exact source identity, two unit definitions, service and journal observations, collector receipts, and three interface captures. This job is also required by the explicit reviewer guard. The new units are enabled for boot; this particular exercise stays within one boot and the 256-row history limit.

The separate `monitor_archive` job extends the journal with two replay-verified archive segments. Its [history archive guide](NETWORK_MONITOR_ARCHIVE.md) covers more than 256 autonomous observations, process crashes at both archive handoff boundaries, exact-request retries, and rejection of missing or altered segments. Its ninth network artifact includes the original segment bytes. The explicit reviewer guard requires this job to succeed.

The separate `monitor_archive_reboot` job tests the archived format through a full guest OS reboot. Its [archive reboot guide](NETWORK_MONITOR_ARCHIVE_REBOOT.md) covers host-held preboot references, unchanged segments and history prefix, automatic unknown startup, explicit reconstruction of the disposable network, and a third rollover after fresh recovery. Its tenth network artifact is required by the explicit reviewer guard.

The separate `monitor_archive_powercut` job kills the entire disposable VM at three archive handoff boundaries, then cold-starts the retained disk after each. The [archive power-loss guide](NETWORK_MONITOR_ARCHIVE_POWERCUT.md) explains interrupted staging, file publication, committed metadata, exact retries, and fresh network recovery. Its eleventh network artifact binds host-held references to the recovered history. The explicit reviewer guard requires this job as well. These are bounded submitted observations; continuous collection is exercised separately.

The `monitor_archive_retry` job verifies both retryable rejections through a Unix socket in a disposable guest. It checks that the same saved request commits once and a duplicate replay leaves the journal unchanged. [Retry checks](NETWORK_MONITOR_ARCHIVE_REBOOT.md#retry-checks-in-ci)

The `clean_restore` job runs six synthetic backup and signing checks on a fresh Ubuntu guest. It requires a matching public receipt for protected restore, rejects rollback and signed-record tampering, and confirms public-only recovery. Inspect `CLEAN-RESTORE.json` and `MANIFEST.json` in `clean-machine-restore-<commit>-<run ID>-<attempt>`. Reviewer packaging requires both jobs to succeed. [Clean-machine restore](CLEAN_MACHINE_RESTORE.md)

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
- [Required checks and skipped dependent jobs](https://docs.github.com/en/pull-requests/how-tos/merge-and-close-pull-requests/troubleshooting-required-status-checks)
