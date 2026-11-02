# Threat model

Initial design review: October 11, 2026. Documentation updated November 1, 2026 for the managed account boundary and v0.4.0 recovery workflow. This document states security boundaries and verification targets; it does not replace the dated observations in [VERIFICATION.md](VERIFICATION.md).

## Scope and assets

The local application is a single-user evidence collection and learning tool. It stores public filing documents, collection metadata, a searchable local database, and verification/operation records. Its browser interface is intended for loopback access on the operator's own computer.

The important assets are the fidelity of preserved evidence, the distinction between live and demo records, the ability to notice collection failure, and the ability to restore data. Local signing keys and trusted checkpoint references protect accepted archive history and require separate handling from the evidence itself. The system does not store broker credentials or execute trades. SEC contact details, signing keys, and future cloud credentials must stay out of public project files.

Local contact setup stores the chosen address as part of the request user agent in `settings.json` inside the selected data directory, with owner-only read/write permissions. It is excluded from evidence backups and source control. It is transmitted to the SEC on live requests and is an identification contact, not an authentication credential. This file is not encrypted; the operating-system user and privileged administrators can read it. A nonempty `SEC_USER_AGENT` environment value takes precedence over local settings.

## Boundaries

```text
SEC public endpoints
      | HTTPS; treat all responses as untrusted input
      v
Python collector → saved evidence + SQLite records
                              |
                              v
                    local dashboard and controls
                              |
                              v
                     operator's web browser

Prepared AWS deployment → separate deployment and verification stage
```

The loopback boundary reduces network exposure; it does not provide user authentication or isolate the application from other software running as the same operating-system user. Do not place the local server on the public internet, bind it to all interfaces, or treat it as a multi-user application.

In standalone mode, signed checkpoint history and the accepted public keys/latest checkpoint are kept under a matching `.heltemes-trust/` directory outside `data/`; protected backups carry a public copy of the signed history. Private keys are under `.heltemes-keys/`, also outside `data/`. A signing key is an unencrypted owner-readable file (`0400`) inside an owner-only directory (`0700`). The CLI signs explicitly; no HTTP endpoint initializes, signs, or resets trust. These are application and filesystem boundaries, **not** isolation from the same operating-system account. See [LOCAL_PROTECTION.md](LOCAL_PROTECTION.md).

## Optional managed account boundary

The separate-account installer puts executable code and the fixed runtime policy under root ownership, runs the collector as a dedicated non-admin account, and keeps signing material and trusted history under a different custodian account. The collector may read public references but cannot update them or select substitute trust paths. Signing uses a private, validated snapshot rather than trusting advisory locks on collector-owned files. Only actual installation and permission probes establish this operating-system boundary; see [LOCAL_ACCOUNTS.md](LOCAL_ACCOUNTS.md).

The custodian and administrator remain trusted. Collector compromise can fabricate pending inputs, delete its own evidence, or lie through the dashboard. Use the installed verifier independently during an incident. This is neither hardware key custody nor immutable storage.

Recovery adds an administrator-owned approval outside both service accounts' writable directories. The approval binds the exact candidate public key and last accepted checkpoint to one transition. The custodian's private journal records prepared intent and durable completion; public receipts retain the authorized key epochs needed to verify old signatures. The collector cannot approve a replacement key. See the [managed boundary diagram](ARCHITECTURE.md#managed-local-trust-boundary).

## Verification is separate from signing permission

Public archive verification uses evidence, signed checkpoints, and a trusted public receipt. It does not need the private signing key or recovery journal. New signing additionally requires the authorized active private key, intact recovery authorization and prepared records, and completion matching the exact transition. A passing archive check can coexist with blocked signing after a crash or key substitution.

The repeatable reviewer demo tests application behavior in a fresh, same-user synthetic workspace. It cannot demonstrate native collector/custodian isolation, independent human authorization, off-device custody, or physical power-loss durability. The historical native permission checks are separate evidence; rerun them on a new managed installation before claiming its boundary works.

## Threats, controls, and limits

| Threat | Intended protection or procedure | Residual limit and evidence to check |
| --- | --- | --- |
| Malicious or malformed filing content | Treat filings as untrusted data. Display text or provide downloads; never execute saved filing HTML inside the dashboard | Verify browser rendering and response headers. An external source or downloaded file may be handled differently by other software |
| Fetching an attacker-controlled URL | Constrain collection to expected SEC HTTPS endpoints and validate metadata used in paths | Check validation, redirect handling, and rejection tests; hostname approval alone is insufficient if redirects escape it |
| Accidental corruption or deletion | Hash verification, read-only preserved source files, signed checkpoints, backups, and restore to a separate destination | The owner can change file permissions. A backup on the same disk does not survive loss of that disk |
| Filing and database hash changed together | Compare current records against a signed snapshot whose key and latest checkpoint are pinned outside the evidence archive | Detection depends on the trusted reference remaining intact. Standalone account compromise or managed custodian/administrator compromise exceeds this boundary |
| Metadata edits, record deletion, or archive rollback | Canonical snapshots cover filing/source references and collection history; chained checkpoints are checked against the separately pinned latest checkpoint | The first checkpoint cannot establish what happened before enrollment. A false new record can be accepted if the operator seals it |
| New collection mistaken for sealed evidence | Explicit pending status until operator sealing; verification does not automatically sign | Pending does not mean corrupt, and a successful byte check does not mean all new records are checkpointed |
| Forged or rolled-back protected backup | Restore requires an independently saved public receipt for the exact checkpoint and signing identity; verifies before activation | A receipt obtained only from the backup supplies no independent trust. Older backup/receipt pairs remain historical recovery points, not the latest state |
| Archive and local trust rolled back together | Protect the trust directory and retain the latest accepted receipt independently | A mutually consistent old archive/receipt pair cannot reveal a newer head by itself. Managed permissions constrain the collector, not an administrator who can roll back all local state |
| Unapproved replacement key or a valid signature from the wrong key | Bind authorization to the exact candidate public key and fingerprint; derive and compare the installed key's public identity before signing | A key's ability to sign does not authorize it. Managed approval depends on trusted administration; standalone practice approval remains under the same account |
| Replayed or changed recovery authorization | Verify the independently approved document digest, archive identity, exact old head, transition identity, and key; require root-owned approval in managed mode | Compromise of the approval authority remains outside the boundary. A public plan is not approval |
| Crash after intent, key installation, or checkpoint publication | Record intent before changing active state; block ordinary signing until explicit resume revalidates the partial transition and durably publishes completion | Archive verification may pass while signing is blocked. Temporary completion files do not establish commit. Process interruption is not proof of survival under every storage or power failure |
| Completion file exists but has been changed or fabricated | Validate completion against the exact prepared record, authorization digest, transition identity, and checkpoint on every signing gate | File existence and permissions alone are insufficient. A changed completion is rejected, not silently rewritten; trusted custody must preserve or recover the required records |
| Missing recovery journal or completion after a transition | Refuse ordinary signing; require the authorized state and explicit recovery verification before completion | A missing completion may be handled by explicit resume only if the prepared state and authorization fully revalidate. Missing approval/journal requires investigation; no new-key generation or trust reset is automatic |
| Restart repeats an already completed recovery | Revalidate the committed journal, historical key epochs, archive, and installed active key; return `already_completed: true` on valid resume | Valid completion is not a permanent bypass: later changes must block signing. New ordinary checkpoints are separate from key transitions |
| A false impression of pre-event evidence | Keep source acceptance time and local retrieval time separate | Local time and hashes do not provide independent trusted timestamping; no claim of immutable custody |
| Demo records mistaken for research | Persistent source-mode labels and distinct practice directories | Users can still export or misrepresent data; verify labels remain with records and visible output |
| Collection fails but data appears current | Record failure, incomplete results, and retrieval times; inspect run status | No success claim without saved evidence. A running process is not proof of a completed collection |
| Repeated collection erases history | Preserve filing identity and retained evidence; amendments remain distinct filings | Metadata corrections and prior retrievals need explicit provenance; inspect actual retention behavior |
| Untrusted archive escapes restoration directory | Validate archive members and restore into a new destination | Test absolute paths, parent traversal, and links; do not restore unknown archives into real evidence directories |
| Local dashboard accessed by unintended software | Loopback bind; allowed Host/Origin checks; token required for state-changing requests; bounded JSON bodies | The token protects browser requests, not user identity. No application login; other local processes and a compromised operator account remain limitations |
| Excessive requests or runaway work | Limited collection scope, request pacing, timeouts, and bounded retries | SEC availability and access policy remain external dependencies; multiple independent collectors aggregate load |
| Exposure of credentials | Environment or cloud identity configuration; exclude local secrets from version control | Environment variables are not a secret vault; privileged local users can still inspect processes or files |
| Unintended exposure of the SEC contact | Local setup avoids requiring chat disclosure; owner-only settings file; excluded from backups and source control | Live requests send the contact to the SEC. Local file permissions do not protect against a compromised account or administrator |
| Future cloud over-permission or unexpected costs | Narrow IAM policies, private storage, logging, cost alerts, and disabled scheduling until configured | Deployment files do not establish deployed controls; verify permissions and costs in the target account |

## What this version does not prove

- Complete SEC historical coverage. The recent submissions feed and selected forms are a limited collection scope.
- Immutable or independently audited evidence. Checkpoints detect archive-only edits against a separately pinned reference. Standalone account owners and managed administrators can still replace key, trust, code, and evidence; the custodian also remains trusted.
- Protection against changes made before the first checkpoint, or against false new evidence explicitly accepted into a later checkpoint.
- Independent clock accuracy, pre-earnings possession, or a trustworthy point-in-time backtest.
- Cloud deployment, email delivery, continuous availability, or timed maintenance merely because supporting files exist.
- Validated financial figures, market expectations, a QES verdict, trading profitability, or a scoring advantage.
- Security against a compromised operating system or a determined administrator with control of the account.
- Independent authorization, actual-account separation, off-device recovery, or physical power-loss durability from a same-user synthetic demo alone.

## Before extending the boundary

Public or multi-user access needs a new design: authentication, authorization, transport security, session protections, network controls, retention rules, and operational ownership. Keep the current server local until that design is implemented and verified.

For AWS, confirm private access, the effective permissions of each role, evidence-bucket data events, version recovery, and the actual notification path. S3 versioning supports recovery, while administrators with sufficient permissions can still delete versions; it is not a substitute for an independently controlled retention design. See [the source register](SOURCES.md).
