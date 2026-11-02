# Changelog

## 0.4.0 — October 26, 2026

Add explicit signing-key recovery with protected administrator approval, a durable recovery journal, shared signing/recovery locks, exact replacement-key checks, and restart validation. Incomplete transitions block signing. Completed transitions are revalidated without being repeated. Transition checkpoints preserve the last accepted snapshot; versioned public-key receipts keep original signatures verifiable and original private keys are never overwritten. Recovery does not implicitly seal pending records.

Add a guarded code-only updater for the existing managed installation. It retains old application code and migration provenance, verifies the same accepted head and signing identity under actual service accounts, and requires permission and listener checks before reporting success. Native installation is a separate step from source tests. AWS remains deferred.

The native code update completed after administrator authentication, followed by fresh version 0.4.0 health and restricted collector process checks. Checkpoint 2 and the original identity are unchanged; all 19 permission/key checks passed. No key transition occurred. See docs/VERIFICATION.md for the recorded scope and limitations.

## Managed recovery completed — October 19, 2026

The native supervised workflow accepted the exact reviewed Apple 10-K additions as checkpoint 2 at 10:57 p.m. Central. All eight objects verified, the matching backup and separate public receipt were exported, a fresh verifier-only restore passed, and the dashboard resumed under collector UID 450 with native listener and health confirmation. The original archive identity, signing key, and checkpoint-1 history were preserved. Off-device copying remains pending; AWS remains deferred. This is an operational verification record after the immutable 0.3.2 source package was built, not an application upgrade.

## 0.3.2 — October 19, 2026

Include the final startup repairs in a new source release while retaining historical packages. Packaging captures and verifies source bytes, refuses to overwrite existing release files, excludes local evidence and private runtime material, and rebuilds the bundled cloud code from current source. Managed operation instructions now lead with the separate-account workflow, with practice servers on port 8766. An assistant-run checkpoint-1 recovery and paired-tamper exercise passed; Apple’s real 10-K was collected into the managed archive and awaits explicit custodian sealing. Building this release does not upgrade the installed 0.3.1 service or deploy AWS.

Add a supervised managed recovery launcher for the existing archive. Custody accepts only the exact reviewed snapshot, prior checkpoint, and live accessions; signing uses the same private copy that was checked. The workflow preserves an already accepted checkpoint on later backup failure, exports bounded verified backup bytes without the signing key, tests a fresh restore against its public receipt, and guards dashboard restart with independent verification. Native completion and off-device recovery remain separate from software test results.

## Native account separation activated — October 11, 2026

The reviewed log-permission repair succeeded at 9:55 p.m. Central. All 18 actual-account permission checks passed, all six evidence objects verified against the unchanged original checkpoint, and the dashboard's actual collector UID, listener PID, and managed health response passed before the root-owned completion report was saved. Fresh service and HTTP checks at 9:57 p.m. confirmed the managed dashboard running with separate local accounts, four sealed filings, and no pending records. No new checkpoint or filing was created; AWS remains deferred.

## Workspace startup repair — October 11, 2026

The completed native startup inspection verified the managed archive's six objects against the original sealed checkpoint and confirmed both service accounts. It also confirmed that root-owned mode `0640` collector logs deny service writes, leaving startup diagnostics empty. Added a narrowly guarded repair of those two log modes to `0660`, with the parent directory remaining protected, followed by fresh account-boundary tests, independent verification, and actual dashboard identity/health checks. Completion reports are published only after complete writes, and interruption handling attempts to stop an unverified service. The future installer now grants service log writing while protecting the log directory. Sixty-three focused tests passed; successful native startup is still required. AWS remains deferred, and the existing v0.3.1 ZIP remains a historical build.

## Workspace activation follow-up — October 11, 2026

Added private activation diagnostics that exclude native password authentication. The saved retry confirmed a pre-migration failure at the collector's stored `UserShell` attribute. Narrow recovery handles missing shell/home fields only when effective macOS account settings already match the intended disabled values; explicit conflicts remain rejected, and final stored settings are mandatory. The launcher labels this update **Diagnostic retry 2**. Account separation remains unverified until a successful native administrator run and real permission probes.

## 0.3.1 — October 11, 2026

The first native macOS activation stopped when the installer attempted to replace the collector account's OS-assigned GeneratedUID. Preserve and read that identifier instead. Native command failures now retain their diagnostic output. Added a narrowly bound recovery path for the inspected early failure, with exact existing account/group UUIDs, numeric identities, root-directory identity, unchanged checkpoint, and no copied application or evidence. Recovery never deletes accounts or reinitializes trust. The original archive still verifies; successful activation requires new native permission and service checks.

## 0.3.0 — October 11, 2026

Added an optional macOS installation with separate collector and custodian accounts, fixed protected trust configuration, root-owned application code, explicit operator signing, and private snapshot validation. Migration preserves the existing checkpoint identity and accepted history. Includes an activation plan, permission probes under actual service identities, and a local operator guide. Installation needs administrator authentication; source tests do not establish active OS separation. AWS is unchanged. See docs/LOCAL_ACCOUNTS.md and docs/VERIFICATION.md for activation status and observed validation.

## 0.2.0 — October 11, 2026

Added local Ed25519 signed checkpoints with an external public trust vault and separate private signing-key directory. Checkpoints preserve complete schema/record snapshots, chain history, detect archive-only paired document/hash tampering and rollback, and show new records as pending until explicitly sealed. Added read-only source-file permissions, shared process locks, protected backup/restore with independently supplied public receipts, and checkpoint-aware downloads. Dashboard separates byte consistency from reference protection; no HTTP signing/reset endpoint exists. Existing live history was sealed without changing original records or source bytes. Full suite: 89 tests passed. AWS remains undeployed. See docs/VERIFICATION.md and docs/LOCAL_PROTECTION.md.

## Product name and learning checkpoint — October 10, 2026

Fischer adopted **HELTEMES Evidence — Earnings Research Platform**. Current product documentation uses the adopted name; original collection facts remain preserved. Fischer also correctly distinguished source filing time from local retrieval time in a verbal check. This records that specific understanding, not independent operation or full lesson mastery. See docs/FIRST_LIVE_COLLECTION.md.

## Post-build validation — October 10, 2026

Configured private local SEC contact, collected and inspected the first real Apple 10-Q, preserved a repeat observation without duplicating the filing, and verified recovery from a new backup. Fixed missing macOS Python CA defaults through the installed system trust bundle while retaining HTTPS certificate and hostname checks. Test suite now passes 58 tests. AWS remains undeployed. See docs/FIRST_LIVE_COLLECTION.md.

## 0.1.0 — October 10, 2026

Initial assistant-built release for Fischer's learning and research infrastructure project. Includes local evidence collection/indexing/dashboard, synthetic fixtures, backup/recovery, security controls and tests, guided exercises, AWS infrastructure and CI/CD source. Live SEC access and AWS operation remain unverified until configured and actually exercised. See docs/VERIFICATION.md.
