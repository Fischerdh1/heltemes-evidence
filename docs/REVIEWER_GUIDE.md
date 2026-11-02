# HELTEMES Evidence — reviewer guide

Reviewer edition: November 1, 2026. Application version: 0.4.0.

An original security-engineering portfolio project by **Fischer Heltemes**.

**A local SEC evidence archive that separates collection, acceptance, integrity verification, and permission to sign.** Python and SQLite preserve source documents and observations; SHA-256 and Ed25519 checkpoints detect changes against a separately protected reference. A managed macOS installation separates collection from key custody. Recovery blocks signing until the exact authorized identity and history have been revalidated and completion has been durably recorded.

This is one security-engineering project with two case studies: evidence integrity and restart-safe identity recovery. AWS configuration is prepared but deployment is deferred. It does not score trades, execute orders, or establish the truth of a company's financial statements.

## Review in five minutes

1. Read the scope and boundaries below.
2. Run the offline demo. It generates synthetic filings and throwaway keys; it needs no SEC contact, API credentials, administrator password, or running dashboard.
3. Open its `WALKTHROUGH.txt` and `results.json`. Each phase has its own machine-readable record in `phases/`.
4. Inspect [the architecture](ARCHITECTURE.md), [threat model](THREAT_MODEL.md), and [recovery implementation](../heltemes/key_recovery.py).
5. Use the questions at the end to distinguish observed behavior from broader security claims.

The downloadable reviewer bundle also includes an offline `index.html`, the exact source, a passing demo report, and a file-hash manifest. A manifest detects changes relative to a trusted copy; it is not an independent attestation or trusted timestamp.

## Reproduce it

Requirements: macOS or Linux, Python 3.11 or later, and OpenSSH `/usr/bin/ssh-keygen` with Ed25519 signing/verification support. The demo uses the Python standard library. Windows and other environments have not been verified for this edition.

From the source directory (the bundle's `source/` folder):

```sh
mkdir -p work
python3 -I -S -B scripts/reviewer_demo.py --output work/reviewer-demo-01
```

The output directory must be new. For a second run, choose `work/reviewer-demo-02`. Never reuse a prior result directory: the harness refuses to overwrite it. Random keys, identifiers, and timestamps change between runs; the expected security outcomes remain the same.

The harness creates a fresh temporary practice archive. It does not accept an existing archive, key, trust directory, or backup as input. Worker processes load this checkout's application code using isolated Python. The temporary archive and private keys are removed after the exercise; retained reports contain no private keys. Deletion is ordinary temporary-file cleanup, not guaranteed forensic erasure.

No installed service is upgraded or restarted. No live SEC request, account creation, cloud deployment, or real key transition is part of this command. Run it as your normal user.

To run the software suite separately:

```sh
python3 -B -W error::ResourceWarning -m unittest discover -s tests -v
```

The suite includes isolated fixtures and mocks for privileged installation behavior. It does not recreate native account separation merely by passing. The saved [verification record](VERIFICATION.md) distinguishes the earlier actual-account checks from software tests.

## Case study 1: changing a filing and its mutable fingerprint

**Problem:** an attacker able to modify an evidence archive may replace a document and change its database checksum to agree with the replacement. Comparing only those two mutable values would accept the altered bytes.

**Design:** a signed checkpoint records the accepted evidence and metadata. The expected signer and latest checkpoint are pinned separately. The demo changes a synthetic document and reconciles the mutable references, then asks the normal verification path to evaluate the altered archive.

**Expected result:** verification rejects the changed accepted snapshot. Restoring the exact saved synthetic bytes and index restores verification. The actual phase records establish which checks failed; the case study is not an assumption that every possible tamper is covered.

**Boundary:** an administrator able to replace the archive, code, keys, and all trusted references remains outside this local protection. A genuine SEC document can also contain misleading financial claims. Preservation and truth are different questions.

## Case study 2: crash during an authorized identity transition

**Problem:** a replacement key may already be installed and a new checkpoint may already verify when a crash interrupts recovery. Allowing ordinary signing at that point could bypass unfinished recovery checks.

**Design:** record durable intent, block ordinary signing, revalidate the approved key and accepted history, then write the final completion record last. Fresh recovery-status, resume, and signing requests check that the completion record is bound to the exact authorization, prepared record, and transition checkpoint. Restarting the dashboard alone does not perform the private custodian checks.

**Demonstration:** the harness deliberately terminates one worker at `before_completion.json`. The temporary completion file exists, but the final completion record has not been published. A new process can verify the archive while ordinary signing remains blocked. An explicit resume revalidates and commits recovery. A later resume reports that recovery is already completed without adding another transition. Finally, an ordinary synthetic record is sealed to prove signing works again.

**Boundary:** this uses a same-user practice authorization and abrupt process termination. It is not a native administrator-approval test, a hostile administrator test, or a physical power-loss experiment. The underlying application's recovery checks are real; the identity and evidence used for the demonstration are disposable.

## Evidence and claim boundaries

| Claim | Evidence to inspect | What it does not establish |
| --- | --- | --- |
| Synthetic tampering is rejected | Demo phase logs and verification result | Authenticity of live SEC retrieval or financial claims |
| Restart blocks unfinished recovery | Crash exit, fresh verification, failed ordinary-signing attempt | Physical power-loss behavior on every filesystem |
| Completed recovery is not repeated | Fresh resume result and unchanged history/completion fingerprints | Authorization by an independent organization |
| Signing resumes after completion | New ordinary synthetic checkpoint and verification | A transition of Fischer's real signing identity |
| Separate local accounts were checked | Dated native results in `VERIFICATION.md` | OS separation in this same-user portable demo |
| Source can be inspected and rerun | Source hashes, bundle manifest, reproducible command | An external security audit or hosted CI pass |
| Cloud architecture is prepared | `infra/` and `docs/DEPLOYMENT.md` | An operating AWS deployment |

The previously saved v0.4.0 verification records 322 software tests and 19 actual-account permission/key checks. Those are historical results, not the test count or native-verification status of each new reviewer run. The new run records its own timestamp and source hashes. Off-device backup custody remains a separate acceptance check.

The [reviewer edition verification](REVIEWER_VERIFICATION.md) records this edition's software test results, demo observations, and limitations separately.

## Project ownership and engineering practice

HELTEMES Evidence is Fischer Heltemes's original portfolio project connecting earnings-research evidence, software engineering, and security. Its local-first requirements, explicit acceptance workflow, and recovery exercises address a concrete need: preserving research inputs while making changes and interrupted recovery detectable.

The [learning path](LEARNING_PATH.md) provides a log for recording code changes, investigations, tests, and tools or references used. Review the demonstrated results and the reasoning behind each design choice. Specific implementation and operating claims should match the work and evidence the author can explain.

## A two-minute live walkthrough

This is a presentation script, not a prerecorded video. Use the saved demo output or run the command while presenting.

**0:00–0:20 — Purpose.** “I wanted a research archive where downloading a filing, accepting it, and proving that it has not changed are separate operations. This demo uses synthetic evidence and disposable keys.”

**0:20–0:50 — Tampering.** “I changed both a filing and its mutable fingerprint. The signed snapshot still remembers the accepted version, so verification rejects the replacement. Here is the observed failure and the verified restoration.”

**0:50–1:25 — Crash.** “Next, recovery installs an approved practice identity but crashes before final completion. The archive can still verify. Signing remains blocked because valid evidence alone does not prove that recovery completed.”

**1:25–1:45 — Restart.** “Explicit resume revalidates the transition and records completion. Another restart checks that committed state without repeating recovery. An ordinary new checkpoint shows that signing is available again.”

**1:45–2:00 — Scope and results.** “HELTEMES Evidence is my original security-engineering portfolio project. This demo shows tamper detection and recovery behavior we can reproduce. Administrator-proof storage and cloud deployment are outside the demonstrated scope.”

## Questions to ask the author

- Where is the trusted reference, and who can replace it in each operating mode?
- Why can evidence verification pass while signing is blocked?
- Which exact checks make a completed recovery safe to reuse after restart?
- What would happen if both the archive and its only trust reference were rolled back?
- Which design decisions, code changes, and investigations can Fischer explain and reproduce?
- What remains untested, and what evidence would be needed to support the next claim?

## Build a new reviewer bundle

After the demo passes, from the source directory:

```sh
python3 -I -S -B scripts/package_reviewer.py --report work/reviewer-demo-01 --output work/HELTEMES-Evidence-reviewer.zip
```

The packager requires a fresh destination, checks that the report matches the source being packaged, and excludes runtime evidence, keys, settings, and the real archive. Keep the generated checksum separately if it will be used to check a later copy. This creates a local artifact; it does not publish to GitHub or update the installed application.
