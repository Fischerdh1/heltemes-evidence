# HELTEMES Evidence

[![Verify project](https://github.com/Fischerdh1/heltemes-evidence/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Fischerdh1/heltemes-evidence/actions/workflows/ci.yml)

**Earnings Research Platform**

An original security-engineering portfolio project by **Fischer Heltemes**.

**Hosted verification:** the first GitHub Actions run passed all 336 software tests on both Python 3.12 and 3.14 and validated the prepared Terraform configuration. See the [dated hosted-check record](docs/GITHUB_VERIFICATION.md). AWS remains undeployed.

A local-first SEC evidence workspace with a Python collector, preserved source documents, a searchable dashboard, signed checkpoints, integrity checks, backup/recovery, and an eight-lesson learning path. AWS deployment code is included separately.

**Review the project:** start with the [reviewer guide](docs/REVIEWER_GUIDE.md) for the architecture, two case studies, contribution boundaries, and a two-minute presentation script. Create a `work/` folder, then run `python3 -I -S -B scripts/reviewer_demo.py --output work/reviewer-demo-01` for an offline demonstration using fresh synthetic evidence and throwaway keys. It exercises tampering and crash/restart recovery without opening the real archive or changing the installed service. The output directory must be new. AWS stays deferred.

**Review a code change:** the `reviewer` CI job packages a fresh demo after the Python, Terraform, network-lab, full-VM-reboot, virtual-power-loss, automatic-monitoring, history-archiving, archive-reboot, and archive-power-loss jobs pass, compares every packaged source file with the tested Git commit, and retains the resulting artifact for 30 days. Follow [continuous verification](docs/CONTINUOUS_VERIFICATION.md) to inspect or reproduce a run. The [portfolio roadmap](docs/PORTFOLIO_ROADMAP.md) connects future improvements with practical demonstrations through November 2029.

**Network-security case study:** the [isolated Linux network lab](docs/NETWORK_LAB.md) exercises a client, router, and synthetic server in separate network namespaces on a disposable GitHub runner. Its checks cover permitted traffic, a firewall drop with a healthy destination, a detected policy mistake, repair, and cleanup. Successful runs retain the packet capture, rules, observations, and file manifest for 30 days.

**DNS and TLS diagnosis:** the [service-layer expansion](docs/NETWORK_SERVICES_LAB.md) distinguishes an unknown DNS name, a blocked TCP connection, an incorrect certificate hostname, and an untrusted certificate issuer. It verifies a successful HTTPS request before and after the failure exercises, records packet evidence, and removes its temporary certificate keys before publishing results.

**Network segmentation:** the [three-zone exercise](docs/NETWORK_SEGMENTATION.md) separates user, application, and management networks. Its matrix permits three of twelve tested new-connection paths, verifies the nine denied paths against healthy services, detects a deliberately opened management endpoint, and repeats the full matrix after repair. Three scoped captures show packets at the source and destination interfaces.

**Monitoring and alerts:** the [monitoring exercise](docs/NETWORK_MONITORING.md) samples installed firewall rules, packet counters, and active connection checks. It distinguishes expected drops, rule drift, forbidden access, legitimate access failures, and missing telemetry; records alert opening, updates, and evidence-based recovery; and retains scoped packet captures. This is a bounded lab monitor, not a continuously deployed monitoring service.

**Restart-safe monitoring:** the [service-restart exercise](docs/NETWORK_MONITOR_RESTART.md) stores observations and alert outcomes transactionally, runs a real transient Linux service, and tests abrupt exits before commit and after commit before acknowledgement. Restarts preserve committed incidents, mark coverage unknown, and require fresh checks for recovery. All five network exercises must pass the required `network_lab` check.

**Monitoring across a VM reboot:** the [full-reboot exercise](docs/NETWORK_MONITOR_REBOOT.md) saves history on the guest disk and enables automatic service startup. A disposable Ubuntu guest reboots while the controller checks the changed Linux boot identity, preserved journal and incident, and fresh verification before recovery. The required reviewer check also waits for this separate `monitor_reboot` job.

**Automatic collection and missing-data detection:** the [automatic monitoring exercise](docs/NETWORK_MONITOR_AUTOMATIC.md) runs an independent collector every five seconds and a monitor with a 20-second freshness deadline. It freezes the collector while the monitor continues running, requires a durable missing-data gap before any status request, and verifies fresh recovery after a supervisor restart. The bounded `monitor_automatic` job is required by the reviewer gate; external notifications and continuous production operation remain separate work.

**Bounded history archiving:** the [archive exercise](docs/NETWORK_MONITOR_ARCHIVE.md) extends monitoring beyond the original 256-row limit with replay-verified segments, exact-request retries, and process-crash recovery at both archive handoff boundaries. The `monitor_archive` job requires real autonomous observations, preserved incident identity, and rejection of missing or changed segments on disposable copies.

**Archived history across a VM reboot:** the [archive reboot exercise](docs/NETWORK_MONITOR_ARCHIVE_REBOOT.md) preserves two sealed segments and the unresolved incident through a full guest reboot, checks automatic monitor startup to unknown coverage, and requires fresh network checks before recovery. Collection then seals a third segment without resetting its sequence or probe allocation. The reviewer gate requires the separate `monitor_archive_reboot` job.

**Archived history after abrupt virtual power loss:** the [archive power-loss exercise](docs/NETWORK_MONITOR_ARCHIVE_POWERCUT.md) kills the entire disposable VM at three archive handoff boundaries and cold-starts the same disk each time. It checks exact history preservation, completion of an interrupted handoff, historical retries without duplicate observations, and unknown coverage until fresh network checks justify recovery. The separate `monitor_archive_powercut` job uses bounded submitted lab observations and is required by the reviewer gate.

**Release 0.4.0 — October 26, 2026:** authorized signing-key recovery and durable completion checks are installed in the managed local app. The code-only update preserved the original signing identity and checkpoint 2; no key transition was started. All 322 software tests and 19 native permission/key checks passed. Apple 10-Q and 10-K evidence remains alongside clearly labeled synthetic records. See the [verification record](docs/VERIFICATION.md) and [recovery guide](docs/key-recovery.md). AWS remains deferred.

**Local protection update — October 11, 2026:** signed checkpoints protect accepted filing records and fingerprint references against changes confined to the archive. New records wait for explicit sealing; protected recovery needs a separately saved public receipt. See the [local protection guide](docs/LOCAL_PROTECTION.md) for setup and limits, and the [validation record](docs/VERIFICATION.md) for observed checks.

**Separate accounts — release 0.3:** a macOS installer and trusted operator workflow separate collection from key custody. On Fischer's Mac, native activation completed October 11 at 9:55 p.m. Central: all 18 access checks passed and the six objects retained their original checkpoint. The running managed dashboard was checked again at 9:57 p.m. Use the [account separation guide](docs/LOCAL_ACCOUNTS.md) for normal operation and the [verification record](docs/VERIFICATION.md) for evidence and limits. A fresh installation still needs its own native checks. AWS remains deferred.

**Abrupt virtual power loss:** the [power-cut exercise](docs/NETWORK_MONITOR_POWERCUT.md) kills the disposable VM before commit and after commit before acknowledgement. Each cold start reopens the same disk; checks distinguish an interrupted save from a completed save with a lost response. Coverage remains unknown until fresh network checks pass. This separate `monitor_powercut` job is also required by the reviewer gate.

**Crash-safe recovery:** the local application supports an explicitly authorized key transition, durable recovery intent, and a signing block that survives restart until recovery is revalidated and completed. Existing key files and signed checkpoints are preserved. See [the recovery guide](docs/key-recovery.md) for the approval boundary, command workflow, and interrupted-state behavior. A source update alone does not upgrade the managed installation or authorize a key transition.

## Open the platform

Requires Python 3.11 or later. Local signed checkpoints also require installed OpenSSH at `/usr/bin/ssh-keygen` with signing/verification support. There are no third-party Python dependencies for local use. Python 3.14 is available on the build machine.

For the activated installation on this Mac, **`Launch.command`** opens the managed dashboard. macOS runs the collector as a background service; use **`Manage Local Protection.command`** for starting/stopping it, independent verification, and deliberate signing. Use **`Configure SEC.command`** for its contact setting. Follow [the account guide](docs/LOCAL_ACCOUNTS.md); do not initialize or continue collecting into the legacy workspace.

For the supervised review and recovery exercise on this installation, **`Review and Back Up Filings.command`** binds sealing to an explicitly reviewed snapshot, exports its matching public receipt and backup, and tests a fresh verifier-only restore. It pauses the dashboard during review and requires native administrator authentication. See the [workflow instructions](docs/LOCAL_ACCOUNTS.md#review-one-exact-snapshot-and-test-its-backup) and the verification record for what has actually been run.

For a fresh, single-account practice workspace only, run:

```sh
python3 -m heltemes --data-dir work/practice demo
python3 -m heltemes --data-dir work/practice serve --port 8766
```

Then open http://127.0.0.1:8766 and keep that practice server's Terminal window open. The managed dashboard uses port 8765. Both bind only to this computer. The separate-account service does not schedule collection.

## Enable actual SEC collection

For the managed installation, open **`Configure SEC.command`**. The command below and subsequent terminal examples apply to a separate single-account workspace:

```sh
python3 -m heltemes configure
```

Enter a contact email you are comfortable sending to the SEC in automated request headers. It is stored with owner-only file permissions in `data/settings.json`, excluded from version control and evidence backups. You do not need to share it in chat. Refresh the dashboard after saving it.

An existing `SEC_USER_AGENT` environment variable takes precedence over the local setting. `.env.example` is explanatory and is not loaded or executed. No SEC API key is required. If collecting real data is blocked or partially succeeds, retain that failed run and investigate; do not label sample records as live.

HTTPS certificate verification stays enabled. On macOS, if Python has neither default certificate path, the collector uses the installed `/etc/ssl/cert.pem` trust bundle. Explicit `SSL_CERT_FILE` or `SSL_CERT_DIR` settings take precedence and invalid settings stop collection. Restart a running dashboard after changing collector code.

Use **Collect filings** in the dashboard, enter a verified company CIK, select a form and small limit, then inspect the saved result. An equivalent command is:

```sh
python3 -m heltemes collect --cik 0000320193 --forms 10-Q 10-Q/A --limit 3
```

The example CIK identifies Apple in the SEC API documentation. It is an engineering example, not a stock recommendation. The client permits only official SEC HTTPS endpoints, identifies itself, limits requests to one per second within a process, bounds responses/retries, and stops on access denials. Do not run parallel collectors to bypass SEC access limits.

## What works

- Source JSON and selected primary filing documents saved by SHA-256 content hash.
- SQLite filing index with separate collection attempts and observations; document or metadata revisions are preserved.
- Explicit `demo` and `live` modes, plus successful, partial, and failed runs.
- Search and filtering, record inspection, source links, and safe evidence downloads.
- On-demand byte/database verification, signed checkpoints, and separately pinned fingerprint references.
- Explicit operator sealing after new collection; the dashboard distinguishes sealed, pending, failed, and unconfigured protection.
- Protected ZIP backup/restore with a separately retained public trust receipt. Unsigned legacy archives remain visibly distinct.
- Explicit key recovery with a durable signing block, separately authorized replacement identity, and verification of historical key epochs.
- Loopback binding, Host/Origin checks, mutation tokens, request limits, security response headers, and safe text rendering.
- Eight lessons tied to actual project files. Completion marks are self-reported and stored in the browser.
- AWS Lambda/S3/Scheduler/IAM/CloudWatch/CloudTrail Terraform, optional alerts and budget warning, and optional GitHub OIDC code deployment.

## Scope and boundaries

This release collects a company's **recent** SEC submissions and selected **primary documents**. It does not paginate the complete historical archive or collect every 8-K earnings exhibit. It does not supply consensus, whispers, prices, options, transcripts, automated QES scores, trade signals, or broker execution. Existing QES records and adopted rules are not modified.

Acceptance time, filing date, retrieval time, checkpoint time, and a research decision's creation time are distinct. A new download or checkpoint cannot establish what was known before an earlier earnings event. Signed checkpoints detect changes to sealed records even if a document and its database hash are both replaced, provided the separately pinned trusted reference remains intact. In the default workspace, the operating-system account owner can still change the private signing key and trusted reference. An activated separate-account installation removes that authority from the collector; the custodian and administrator remain trusted. This is tamper detection within that boundary, not administrator-proof immutable storage.

The local dashboard is single-user development software, not an authenticated public web service. AWS provisions a private scheduled collector and archive; it does not host this dashboard or automatically synchronize cloud records back into local SQLite. See [deployment](docs/DEPLOYMENT.md) before using AWS.

## Verify and recover

The commands in this section apply to the default single-account workspace. For the managed separate-account installation, use the operator workflow in [LOCAL_ACCOUNTS.md](docs/LOCAL_ACCOUNTS.md).

For a new archive, establish local protection once after reviewing its records:

```sh
python3 -m heltemes protect init
python3 -m heltemes verify
```

`protect init` creates the signing identity and first checkpoint. Future collections remain pending until reviewed and explicitly sealed with `python3 -m heltemes protect seal`. Neither collection nor the dashboard silently advances the checkpoint. Follow the [local protection guide](docs/LOCAL_PROTECTION.md) for the trust boundary and operating procedure.

For a fully sealed archive, retain a matching receipt and backup using new filenames:

```sh
python3 -m unittest discover -s tests -v
python3 -m heltemes verify
python3 -m heltemes protect receipt work/evidence-receipt.json
python3 -m heltemes backup backups/evidence.zip
python3 -m heltemes restore backups/evidence.zip restored-data --trust-receipt work/evidence-receipt.json
python3 -m heltemes --data-dir restored-data verify
```

Keep the public receipt separately from its matching backup; it identifies the exact signing key and checkpoint to trust during recovery. The private signing key and active trusted reference are excluded from the backup. Backup refuses to replace an existing archive; protected backup also refuses pending or failed verification. Restore requires a new or empty destination and supplies verification material without a private signing key. The recovery test must preserve the original archive. An archive with no checkpoint still uses unsigned checksums, without authenticated recovery. More details: [operations runbook](docs/OPERATIONS.md).

## Learn and explain

Open **Learn the system** in the dashboard. Begin with **Follow the data**: identify an input, the operation on that input, and the durable output. Complete the exercise before marking it finished.

The portfolio documents the system's design decisions, failure investigations, and observed operating results. Demonstrated understanding means being able to explain the controls, reproduce the experiments, diagnose failures, and maintain the system. Record specific contributions and evidence as the project develops.

- [Learning path and contribution log](docs/LEARNING_PATH.md)
- [Threat model and security limits](docs/THREAT_MODEL.md)
- [Local signed checkpoints and trusted recovery](docs/LOCAL_PROTECTION.md)
- [Crash-safe signing-key recovery](docs/key-recovery.md)
- [Operations and incident response](docs/OPERATIONS.md)
- [Cloud deployment and verification](docs/DEPLOYMENT.md)
- [Primary-source research](docs/SOURCES.md)
- [Validation record](docs/VERIFICATION.md)

## Project map

```text
heltemes/            Local collector, evidence storage, CLI and HTTP server
  sec.py             Bounded official SEC access and payload validation
  core.py            Evidence archive, SQLite index, verification and recovery
  protection.py      Signed checkpoints and separate local trust reference
  key_recovery.py    Authorized key transitions and restart-safe signing gate
  config.py          Private local SEC contact configuration
  server.py          Loopback-only dashboard API
  web/               Dashboard and lesson cards
cloud/               AWS Lambda adapter; separate S3 evidence layout
infra/               Terraform configuration and provider lock
scripts/             Local launcher and reproducible Lambda packaging
examples/            Clearly labeled synthetic SEC-shaped fixtures and lessons
tests/              Failure, security, integrity and recovery checks
docs/               Learning, sources, threat model, operations and deployment
```

The `data/`, `backups/`, `work/`, `.heltemes-keys/`, `.heltemes-trust/`, local environment settings, cloud state, and provider cache are excluded from Git. Do not publish actual private records, contact settings, signing keys, Terraform state, or credentials. The distributable source ZIP must contain none of them.
