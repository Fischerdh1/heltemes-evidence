# Separate local accounts

HELTEMES Evidence can run its collector and signing custodian under different macOS service accounts. This is a local installation; it does not deploy AWS resources or collect a filing during setup. Source implementation and an activated, tested installation are different milestones. Check the installation report before claiming account separation is active.

## What changes and why

| Responsibility | Account | Authority |
| --- | --- | --- |
| Collect and serve the loopback dashboard | `_hevidence_collect` | Write evidence and collection history; read public checkpoints. No access to the private key or permission to replace the trusted reference. |
| Review and sign a stable snapshot | `_hevidence_custody` | Read collection data; use the signing key; advance the trusted checkpoint after validation. No dashboard or network listener runs as this account. |
| Install code and manage the service | Mac administrator | Install root-owned code and fixed settings; deliberately invoke the custodian. Administrator authority remains trusted. |

These are dedicated service identities with disabled interactive login. They have no administrator membership, login password, or passwordless signing grant. Your usual Mac login remains unchanged. A read-only shared group lets the custodian read collected evidence and the collector read public checkpoints; it does not give the collector access to the key or write access to custody.

The managed installation lives at `/Library/HELTEMES Evidence`. Its parent, application code, and runtime configuration are owned by root. The collector owns `data`; the custodian owns `custody`. The key is private inside `custody/keys`. Public reference material is inside `custody/trust`. A folder controlled by the collector is never used to select the signing key or trusted reference.

## Signing without trusting a running collector

An advisory lock coordinates ordinary operations, but a compromised collector could ignore it. The custodian therefore makes its own bounded, private copy of the database, marker, and evidence. It rejects linked paths, validates the copied bytes and previously accepted history, and signs that stable copy. New records still require operator review. Changing incoming data during copying can cause validation to fail; it cannot rewrite the already accepted history.

The dashboard has no signing endpoint. A valid signature does not authorize the collector to move the accepted checkpoint. Only the separate custody identity can update the pinned reference.

## Walk through activation

**Current installation status, October 11, 9:57 p.m. Central:** separate-account protection is active on Fischer's Mac. The native repair passed all 18 permission checks and independent verification of six objects against the original checkpoint. The running collector and live dashboard health were confirmed, and the protected installation report exists. Use **Manage Local Protection.command** for normal operation. Activation and repair are complete; the numbered activation procedure applies to a fresh installation.

1. Close the legacy dashboard's Terminal window if it is running. Setup refuses an occupied port instead of stopping an unrelated process.
2. Open **Activate Local Protection.command** in this project folder. It displays the concrete migration plan and the checkpoint it will preserve.
3. Enter your Mac administrator password at the Terminal `Password:` prompt. Characters do not appear while you type. This credential is handled by macOS `sudo`; it is not stored by this project.
4. Setup creates the accounts, copies the unchanged archive and signing identity, verifies access under the real accounts, and starts the dashboard only after checks pass. Keep the output if it stops; do not remove the new accounts or reset a checkpoint to force success.
5. The browser opens the managed dashboard. Its protection card should say **Separate local accounts**. A protected installation report is saved at `/Library/HELTEMES Evidence/installation-report.json`. The dashboard label alone is not a substitute for that report and independent verification.

Open **Manage Local Protection.command** for independent verification, sealing reviewed additions, exporting the public trust receipt, backups, and starting or stopping the service. Its administrator prompt is the handoff to the restricted custodian; the browser never receives signing authority. **Launch.command** opens the managed dashboard after activation and refuses to quietly resume the legacy archive. **Configure SEC.command** updates the managed collector's contact after activation.

For a new filing: collect in the dashboard, inspect its source and collection metadata, then choose **Verify independently** in the management menu. New records remain pending. Choose **Seal reviewed new records** only after your review; the service pauses during signing. A failed seal leaves it stopped for investigation. Export the new receipt and create a matching backup after a successful seal. Receipts cover the last accepted checkpoint, so one exported while additions are pending does not include them.

The setup creates a background dashboard service that starts with macOS. It does not schedule SEC requests, sign automatically, or create an assistant monitoring automation.

## Review one exact snapshot and test its backup

**Review and Back Up Filings.command** is a supervised workflow for Fischer's existing managed archive. Its fixed archive identity prevents accidental use against a different installation. Source tests do not establish that this workflow has completed natively; consult the latest verification record.

1. Run the launcher in Terminal. macOS handles administrator authentication directly. The helper checks the protected installation and independently verifies the evidence, then pauses collection while the custodian prepares a stable snapshot.
2. The launcher saves `review-request.json` inside a new private `work/managed-recovery-...` directory. Keep Terminal open. Review the complete snapshot against the accepted checkpoint and the expected new collection. The approval must name the exact snapshot digest, prior checkpoint, request identifier, and reviewed accessions. The helper does not generate its own approval merely because a signature can be created.
3. A matching private `approval.json` permits the next step. The launcher waits at most 20 minutes, then checks administrator authentication again. Custody rechecks the exact snapshot before signing. A different collection date, fingerprint, record, or accepted checkpoint invalidates the approval.
4. After sealing, the helper exports only the identified evidence backup and public receipt. It restores the backup into a fresh verifier directory, checks it against that receipt, and confirms the prior dashboard state before declaring local completion. No signing key is exported. Saved results remain private diagnostics, not signed attestations of the assistant's review.
5. Copy the matching backup and public receipt to the chosen off-device destination and verify them after reading them back. Keep a separately controlled receipt or receipt fingerprint as well: an encrypted drive protects stored data when locked, but does not by itself prevent an authorized writer from replacing both files.

The dashboard pauses during review, so leave this workflow's Terminal open until it finishes. Cancellation before signing can request a guarded restart using the unchanged reviewed state. If signing or export is interrupted, retain the saved result and inspect the accepted checkpoint before retrying. A completed checkpoint is never undone just because a later backup step fails. Reusing the identical approved transition can finish the backup without signing an additional checkpoint.

The workflow does not recreate accounts, rerun migration, replace the managed application, reset trust, or deploy AWS. The installed management menu remains available for routine independent verification and service control.

## Repair the inspected startup failure

**Completed October 11 at 9:55 p.m. Central.** The log-permission correction was followed by successful permission, archive, and startup checks. This section records the repair procedure; it is not a remaining action for the current installation. The helper refuses to replace an existing completion report.

The completed native inspection found that the collector cannot write its two diagnostic logs. Both are empty, root-owned, and mode `0640`. This is a confirmed logging defect; another startup error may become visible after log writing works.

**Repair Local Protection.command** is reserved for the specifically reviewed, migrated installation. It validates the fixed accounts, protected application, stopped service, original checkpoint, and protected paths before granting shared-group write access to the two log files (`0660`). The containing directory stays root-owned `0750`, so the collector cannot replace the log paths. These are writable diagnostics, not append-only or cryptographically trusted evidence.

Run this launcher in Terminal and enter the Mac administrator password only at its native prompt. That authentication is required to change root-owned file modes and start the system service. The launcher saves the repair result privately without capturing the password. It retests actual account permissions and independent checkpoint verification, then requires the dashboard's actual process ID, collector user ID, and local health response before reporting success. A failure retains diagnostics and stops an unproved service. It never recreates accounts, recopies the archive, resets trust, or signs a replacement checkpoint. AWS remains deferred.

Use **Manage Local Protection.command** after a successful repair. Do not infer current service health from an old installation report; verify the live dashboard and independent archive result.

## Preserve the existing history

Installation copies the existing archive, signing identity, public checkpoint chain, and trust reference into a new managed location. It checks the same archive ID, checkpoint number, checkpoint digest, and public key fingerprint. It does **not** initialize a replacement identity, change collection dates, or seal a new baseline.

The existing workspace remains a legacy recovery copy. Its private key is still in Fischer's account, which remains a trusted administrator; setup does not erase it or claim it has been securely erased. Do not continue collecting into the legacy copy after switching to the managed dashboard. Independently kept receipts and backups are a separate recovery practice.

## Activation and proof

The installer first produces a read-only plan. Activation requires a Mac administrator because ordinary application permissions cannot create accounts, change file owners, or install a system service. Enter that credential only in your Mac's own prompt, never in chat.

The installer refuses to overwrite an existing managed installation or reuse unexpected accounts. A partially completed installation must be inspected rather than reset or silently enrolled again. It leaves the original archive intact.

Before reporting success, installation must test actions under the actual collector and custodian identities. The collector must be unable to read the private key, write or replace the trust record and its parent, or edit installed code/settings. It must still be able to read public checkpoints and verify the migrated archive. The expected checkpoint must remain unchanged. Unit tests alone do not establish those operating-system permissions.

The dashboard runs on `127.0.0.1:8765`. macOS manages the background collector service after activation; startup does not automatically collect filings or sign new records. A network-accessible dashboard is outside this design.

## First activation failure and the reviewed retry

The initial activation stopped while assigning a replacement `GeneratedUID` to the collector. macOS had already assigned one. Release 0.3.1 reads and preserves the assigned identifier, and includes the native error text if a future operation fails. The exact reason behind the original exit code was not captured; this record does not claim a general macOS policy that all UUID writes are forbidden.

For Fischer's observed early failure, the existing activation launcher has a separately prepared local recovery specification. It binds the exact collector and group UUIDs, numeric IDs, installation directory identity, and accepted checkpoint. After native administrator authentication, recovery must confirm that the installation directory is still empty and protected, the custodian and service do not exist, the IDs are not shared, and the account has no unexpected authentication or group membership. Any mismatch stops the retry. It preserves existing identities and fills only reviewed service-account settings before the original migration and live permission checks. It records each account step in a root-owned journal.

This is not a general permission to reuse existing accounts or resume arbitrary partial installations. Machine-specific recovery instructions stay in ignored local `work/` and are excluded from the source release. Reopen **Activate Local Protection.command** only after the reviewed recovery specification has been prepared. If this retry stops, retain the output and journal for investigation.

The current workspace launcher displays **Diagnostic retry 2** and saves each attempt to a private file in `work/activation-logs/`. Authentication is handled directly by macOS with normal Terminal input and output; that step is not captured. Only the subsequent noninteractive installer output is saved, together with its exit status and preflight messages. The launcher keeps the window open on failure. Diagnostic files are troubleshooting records under your own account, not signed evidence or proof that account separation succeeded.

The first saved diagnostic attempt confirmed successful authentication and then stopped at the collector's stored `UserShell` attribute. The initial failure occurred before shell/home settings were explicitly written. The narrowly bound recovery now permits those attributes to be absent only when macOS's effective account lookup already reports the intended disabled shell and empty home. Explicit conflicting or malformed attributes still fail. Setup writes the missing settings and requires their stored values in the final account check before migration. This change does not loosen UUID, numeric identity, credential, checkpoint, or directory protections.

The second diagnostic attempt created both accounts and reached dashboard startup after migration and the initial permission checks. Its final listener check failed, and setup stopped the service without writing a completion report. This later partial installation no longer qualifies for the empty-directory recovery path. Use **Diagnose Local Protection.command** for a fixed administrator inspection of startup details and independent verification; its output is saved privately. Do not rerun migration or treat the existing runtime configuration as evidence of completed activation.

## Limits

- Custodian and administrator compromise remain outside this boundary. Both signing authority and the accepted reference reside in the custodian account.
- The key remains an unencrypted file protected by account permissions. Passphrase or hardware-backed signing and key rotation are separate changes.
- Collector compromise can destroy or deny access to incoming data, and can invent new records. Signed history detects changes to accepted records; it does not establish that newly submitted evidence is true.
- A compromised dashboard can lie about its own display. For an incident, use the installed verifier through the administrator-operated command, not a status message supplied only by the collector.
- Checkpoint timestamps come from the local clock. Receipts and backups on this computer do not protect against disk loss.
- AWS deployment remains deferred.

## Explain it back

The collector can read the public trust record. Why does that not let it approve a different history? Demonstrate denied access using the installation's permission probe; do not attack the real key or edit the real archive to practice.

## Sources

- [Apple: users and groups](https://support.apple.com/guide/mac-help/add-a-user-or-group-mchl3e281fc9/mac)
- [Apple: creating launch daemons and agents](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [Python: isolated interpreter mode](https://docs.python.org/3/using/cmdline.html#cmdoption-I)

See [LOCAL_PROTECTION.md](LOCAL_PROTECTION.md) for checkpoint semantics and [VERIFICATION.md](VERIFICATION.md) for checks actually performed.
