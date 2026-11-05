# Portfolio development through November 2029

Proposed roadmap, November 4, 2026. Fischer's goal is to develop demonstrable network and cloud security experience over the next three years. Progress is measured by completed work, saved results, and the ability to explain and repeat the work. The time windows below can change as skills and priorities develop.

HELTEMES Evidence is the current flagship project. Its evidence-integrity, recovery, and isolated Linux network lab are case studies within the repository. The network lab supplies an initial routing/firewall exercise to expand into broader network-security work. AWS deployment remains deferred until Fischer explicitly resumes it.

## Verified starting point

- The November 2 reviewer release is pinned to source commit `9572889f6c6b59e685cfc6a0528255d62115778b`. It includes a 12-phase synthetic tampering and crash/restart demo, source, phase reports, and checksums. Package extraction and reproduction passed. [Published reviewer release](https://github.com/Fischerdh1/heltemes-evidence/releases/tag/reviewer-2026-11-02)
- The release's GitHub checks passed 336 tests on each of Python 3.12 and 3.14, plus Terraform formatting and configuration validation. This is the same suite exercised on two interpreters. [Release verification run](https://github.com/Fischerdh1/heltemes-evidence/actions/runs/41547479699)
- The October 26 managed-installation record reports v0.4.0 and 19 successful actual-account permission/key checks. It documents the collector/custodian boundary at that time. A fresh native health or permission claim needs a fresh check. The portable reviewer demo uses synthetic evidence and disposable identities under one account. [Dated native verification](VERIFICATION.md)
- Off-device backup custody remains unverified, and this workflow has no verified available external backup destination. Completing that milestone requires an explicitly chosen destination, a matching evidence backup and independent receipt, and a successful restore check.

## First implementation milestone

Per-commit reviewer artifacts are the first additional milestone. The workflow retains inspectable demo results alongside CI checks. The following acceptance criteria apply to each run. Record completion against the actual passing run and downloaded artifact.

- CI runs the disposable reviewer demonstration and requires all expected phase outcomes.
- An unexpected failure or missing phase causes the job to fail.
- The retained package includes the report, phase evidence, reviewer instructions, and checksum, with a recorded source commit, workflow run, and Python version.
- Uploads are limited to explicitly selected reviewer outputs. Real evidence, contact settings, signing keys, and private trust state are excluded.
- A readable summary explains expected rejection/crash outcomes and links them to their phase evidence.
- A downloaded artifact matches its recorded hashes and reproduces successfully from the included source.
- Retention is documented, and selected tagged releases preserve longer-term review milestones.

GitHub workflow artifacts support storing build and test outputs after a run. Their retention period is bounded by repository settings, so a CI download has an expiry that reviewers should be able to identify. [GitHub artifact documentation](https://docs.github.com/en/actions/tutorials/store-and-share-data)

Implementation can proceed with development assistance. Optional walkthroughs connect each completed change to its source and observed results, including why a check rejected an operation and how the fix was verified. Record the actual level of help and understanding in the contribution log. A lesson receives completion credit when its demonstration is performed. [Contribution and learning log](LEARNING_PATH.md#contribution-and-learning-log)

The [network lab](NETWORK_LAB.md) is an additional implementation milestone configured to produce its own hosted run and packet evidence. Its checks distinguish a firewall denial from an unavailable service, detect an intentionally over-permissive rule, and verify the repair. Treat a particular run as complete only after its recorded checks, capture, and cleanup pass.

The [DNS and TLS expansion](NETWORK_SERVICES_LAB.md) adds explicit name resolution, certificate-hostname and issuer checks, and a firewall-denied TLS scenario with a healthy-service control. Each run has its own source-bound report, packet evidence, temporary-key cleanup, and acceptance result. This advances the networking stage while AWS remains deferred.

The [segmentation expansion](NETWORK_SEGMENTATION.md) adds user, application, and management networks with a twelve-case access matrix. It verifies scoped return traffic, denied new connections, a deliberately permissive exception, repair, and packet observations on both sides of the router. Its acceptance is tied to the particular hosted run and inspected artifact.

The [monitoring expansion](NETWORK_MONITORING.md) adds sampled rule comparison, blocked-packet observations, active connection checks, and alert lifecycles. Its disposable run exercises incorrect permits, incorrect denials, an explicitly simulated telemetry outage, and repair. This is run-scoped detection evidence; continuously deployed monitoring and external notification delivery remain separate future work.

The [service-restart expansion](NETWORK_MONITOR_RESTART.md) adds a transactional monitoring journal and a transient Linux service. Its acceptance requires real process exits, supervisor restarts, preserved committed incidents, idempotent retries, and fresh recovery evidence. It does not establish VM reboot, physical power-loss, or production-operation behavior.

The [full-reboot expansion](NETWORK_MONITOR_REBOOT.md) separately tests an orderly Linux guest reboot using persistent disk storage and an enabled boot service. Acceptance requires changed boot identity, automatic startup, exact preservation of committed history, and fresh recovery observations. Physical power loss and continuous production operation remain separate milestones.

The [virtual power-cut expansion](NETWORK_MONITOR_POWERCUT.md) tests two abrupt guest interruptions on the same disk: before transaction commit and after commit before acknowledgement. Acceptance requires observed whole-VM termination, automatic startup on a new kernel boot, exact committed-history recovery, an idempotent retry, and fresh network verification. The host remains powered; this does not establish physical storage power-loss behavior.

The [automatic monitoring expansion](NETWORK_MONITOR_AUTOMATIC.md) adds bounded unattended collection and independent freshness deadlines. Acceptance requires silence to become unknown without a status request, preservation of the existing incident while rules are repaired, an observed supervisor restart, and fresh baseline/canary evidence before recovery. Collector/network reconstruction across boot, separate-account authority, and external notification delivery remain separate milestones.

The [history archive expansion](NETWORK_MONITOR_ARCHIVE.md) adds finite segmented retention beyond the original active-journal limit. Acceptance requires real automatic observations across two rollovers, preserved incident identity, both archive handoff process-crash recoveries, exact retries, and altered/missing segment rejection. Indefinite operation, automatic expiry, independent custody, and archive-aware full-VM power-loss testing remain separate milestones.

## Proposed stages

| Planning window | Engineering work | Evidence required | What Fischer should be able to do |
| --- | --- | --- | --- |
| November 2026–April 2027 | Maintain HELTEMES Evidence, finish CI reviewer artifacts, review a real dependency update, and complete an off-device recovery exercise when a destination is available | Passing run and downloaded artifact, reviewed change with relevant checks, independently retained receipt and verified restore | Follow collection through Python and SQLite, explain timestamps and trust references, diagnose a failing check, and make a small change with a testable reason |
| May 2027–April 2028, or earlier as implementation progresses | Expand the initial network lab with Linux service administration, additional segmentation, DNS/TLS investigation, and logs | Saved topology and configuration, permitted and denied traffic tests, packet captures, and an incident investigation with a verified fix | Trace packet flow, explain why a connection succeeds or fails, interpret relevant logs, and change a rule without breaking required access |
| May 2028–April 2029, subject to an explicit decision to resume AWS | Deploy and operate the prepared Evidence cloud collector in a controlled account with scoped identities, audit events, recovery, alerts, and cost controls | Live permission tests including denied operations, version recovery, captured audit events, a tested notification path, measured costs, and verified teardown | Explain each role's authority, distinguish configuration from effective access, investigate a failed collection, recover an object, and account for operating cost |
| May–November 2029 | Maintain the systems and prepare selected case studies around actual design decisions, failures, and improvements | Dated releases, maintenance records, repeated recovery exercises, measured operational results, and a reproducible interview demonstration | Explain tradeoffs, diagnose a new variation of a failure, defend the scope of a result, and identify the next useful improvement |

These stages are proposals. Networking-lab completion and cloud operation require their own implementation and acceptance records. Each resume update should refer to completed milestones and link to the evidence supporting its wording.

## Evidence and learning practice

For each completed milestone, preserve the source revision, date, test conditions, observed result, relevant limitations, and a short explanation of the decision. Use the existing contribution log to record Fischer's work, development tools and assistance, and what he can explain or repeat unaided. Review earlier entries without rewriting them to imply earlier knowledge. [Learning path](LEARNING_PATH.md)

This focus on tasks and observable capability follows the structure used by the NICE Framework, which describes cybersecurity work through tasks, knowledge, and skills. The framework can help identify gaps and choose meaningful demonstrations as career interests become more specific. [NICE framework guidance](https://www.nist.gov/itl/applied-cybersecurity/nice/nice-framework-resource-center/getting-started)

NIST's Secure Software Development Framework supplies practices for integrating security into development and maintenance. Use it as guidance when reviewing code integrity, release handling, and responses to software weaknesses, and document which practices were actually implemented and checked. [NIST SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)

Revisit this roadmap after meaningful milestones. Prefer a specific demonstrated improvement over additional project names or features whose behavior Fischer cannot yet explain.
