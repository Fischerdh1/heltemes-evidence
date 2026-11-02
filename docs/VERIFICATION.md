# Crash-safe recovery installed — October 26, 2026

The managed dashboard is now **0.4.0**. After Fischer entered the administrator password in Terminal, the guarded code-only upgrade completed and a fresh HTTP/launchd check confirmed the restricted collector at PID 53416, UID 450. All 16 installed application files match both the reviewed source and the updated root-owned installation manifest. The updater retains the previous application under `/Library/HELTEMES Evidence/.code-upgrade/old-app` and preserves the original migration report provenance.

The custodian verified the same accepted archive, original private/public signing identity, and **checkpoint 2** (`374c657fdf28073d435989caa87237474828c572c0b5122e72b9f1ed01932eac`). Five filings remain sealed, with no pending records. All **19 actual-account permission and key checks passed**. No replacement key was installed, no recovery transition was started, and no new checkpoint was signed. The historical checkpoint-1/checkpoint-2 backups and receipts and the 0.3.2 source ZIP retain their original SHA-256 values. AWS remains deferred; off-device custody remains unverified.

**322 software tests passed**, with resource warnings treated as errors. Production recovery tests use disposable archives and actual Ed25519 signatures. Seven separate abrupt-process crash points cover key installation, verification, checkpoint publication, receipt replacement, and completion publication. Fresh-process checks remain blocked before completion; committed restart revalidates and does not repeat the transition. Tests also cover wrong installed keys, missing original keys, changed evidence, invalid authorization, missing/malformed completion, multiple authorized transitions, later checkpoint signing, and verifier-only public backup restoration. These tests exercise process interruption and filesystem synchronization, not physical power-loss survival or an actual replacement of this archive's signing key.

Native log: `work/upgrade-logs/20261026T045939Z-a02ef8e7.log`. Independent after-update checks and unchanged-artifact comparisons: `work/key-recovery-integration-20261026/verified-result.json`; suite output: `test-suite.log` in that directory. Protected native completion: `/Library/HELTEMES Evidence/.code-upgrade/result.json`. Private diagnostic records are excluded from the source release.

The [recovery guide](key-recovery.md) separates public archive verification from signing availability. A prepared transition blocks ordinary signing until explicit recovery rechecks the independently approved key, accepted history, and installed identity, then durably records completion. Normal collection does not authorize a key change.

---

# Managed sealing and recovery completed — October 19, 2026, 10:57 p.m. Central

After Fischer authenticated in native Terminal, the existing managed workflow completed review, sealing, backup export, a fresh verifier-only restore, and dashboard resumption. Two independent source reviews compared the complete prepared snapshot with the original checkpoint: the schema and all 21 original rows were unchanged, and only the six expected Apple 10-K collection rows were added. The approval bound request `abb15ca6-612a-4ff0-8591-1ff26e7ae36b`, the original checkpoint, accession `0000320193-25-000079`, and snapshot SHA-256 `a3356b3cf0ef0f1cb991b8eefd9bc3ef059f39aecc6c787c3e20e0892cb50518`.

| Check | Observed result |
| --- | --- |
| Accepted history | Checkpoint 2 signed at `2026-10-20T03:57:18Z` (October 19, 10:57:18 p.m. Central), digest `374c657fdf28073d435989caa87237474828c572c0b5122e72b9f1ed01932eac`. It chains to the unchanged checkpoint 1 and retains the original archive ID and signing-key fingerprint. |
| Evidence and records | Eight saved objects verified, five sealed filings (two live and three synthetic), zero pending filings/records, and zero issues. Filing and collection times were preserved; sealing time is a separate later event. |
| Backup | The 240,930-byte ZIP matched SHA-256 `173a91cb493779ccd82c9b932e35cb63d161d302cff2b21d36f6946320a6495c`. It contains the two public checkpoints and evidence, with no signing key or contact settings. |
| Receipt and restore | The separate public receipt matches checkpoint 2. A fresh restored verifier passed all eight objects and the signed chain without a signing key. The temporary custody snapshot and restored verifier use ordinary verification directories; their `same-account` label does not describe the deployed collector/custodian boundary. |
| Dashboard | Native restart confirmed the loopback listener at PID 97854, collector UID 450, and managed health. A subsequent launchd read reported that same process running as `_hevidence_collect`. A separate HTTP refresh from the assistant sandbox was blocked by its network restriction; the native restart supplies the health proof. |
| Off-device recovery | Not completed. No external drive was mounted. The local backup and receipt are ready for a chosen off-device destination; an external drive is not required for local operation. |

Private records are in `work/managed-recovery-20261019T070327Z-f3330f0e4504/`, including `workflow-result.json`, `parent-review.json`, `finish-result.json`, `resume-result.json`, and `restore-verification.json`. Matching checkpoint-2 recovery files and SHA-256 sidecars were also saved beside the project in `outputs/`, without replacing checkpoint-1 files. These local diagnostic records are not independent timestamp attestations or proof of off-device custody.

The historical 0.3.2 source package remains unchanged. Its extracted source passed all 252 tests and the synthetic backup/restore/tamper exercise; this entry records the later native result. The installed application remains 0.3.1, with its previously verified account separation and startup repair. No account recreation, trust reset, key replacement, managed application upgrade, or AWS deployment occurred.

---

# Recovery and managed collection exercise — October 19, 2026 (before native sealing)

The assistant restored the existing checkpoint-1 evidence backup into two new practice directories. The clean restore verified all six objects and the original checkpoint. A separate copy had one document byte changed along with all its mutable asset, filing, and observation fingerprint references. Ordinary consistency passed, but signed verification rejected the changed history with exit code 1. The original backup, receipt, installation report, signed checkpoint, and restored public trust remained unchanged. No signing key was created or copied. Results are retained privately at `work/recovery-drill-20261019/results.json`. This is an assistant-run local recovery demonstration, not proof of unaided user operation or off-device custody.

One real Apple 10-K was then collected through the running managed collector: accession `0000320193-25-000079`, filed October 31, 2025, for the fiscal year ended September 27, 2025. Collection occurred at `2026-10-19T06:27:24Z` (1:27:24 a.m. Central). The preserved 1,520,327-byte document matched SHA-256 `265e9c086a1a681766c287aa6dc5dd76368c3a6b8bca33a12976b5e915c22b9e`; its contents identified Apple, Form 10-K, and the fiscal period. This was an engineering provenance review, not a trading assessment.

After collection, the managed archive correctly remained at checkpoint 1 with one pending filing and six pending rows: one run, two assets, one filing, and two observations. Counts were five filings (two live, three synthetic) and nine observations. **Custodian review/sealing and the new backup/receipt pair remain pending.** The user selected an existing encrypted external drive; it was not mounted when inspected, so off-device copying and restoration are not yet claimed.

Source version 0.3.2 includes the final startup repairs, safer release packaging, and a supervised review/backup launcher. The installed dashboard remains 0.3.1. All **252 software tests passed** with resource warnings treated as errors, including 19 recovery-backend tests, 16 recovery-frontend tests, and 10 packaging tests. The launcher's shell syntax passed; an ordinary-user attempt to invoke its privileged backend was correctly refused before any service or trust change. An independent review found no remaining concrete backend or packaging blocker.

A candidate source ZIP was extracted into a fresh directory. Synthetic collection, initial signing, verification, receipt export, backup, restore, and verification all passed with four evidence objects. Paired document/fingerprint tampering again passed ordinary consistency but was rejected by signed verification. The original synthetic source, backup, receipt, and candidate remained unchanged. These are isolated software and recovery tests; they do not substitute for running the new workflow under the real managed accounts. **That native run and the off-device copy remain pending at source-release preparation.** Earlier records below preserve their historical status. AWS remains deferred.

---

# Separate-account protection active — October 11, 2026, 9:57 p.m. Central

The native repair completed successfully at `2026-10-12T02:55:23.787603Z` (9:55 p.m. Central). The saved result is `work/activation-logs/20261012T025517Z-3573c2595001.log`; the matching completed report is `/Library/HELTEMES Evidence/installation-report.json`, an ordinary root:wheel-owned `0644` file with one hard link. This establishes native activation in addition to the earlier software tests. Earlier entries below retain their historical status.

| Check | Observed result |
| --- | --- |
| Actual account boundaries | All 18 checks passed under the restricted service identities. The collector could write evidence and read public references, but could not read either private-key copy, edit/replace/remove trust, change custody parents, edit installed code/configuration, or replace protected log paths. The custodian's key matched the accepted reference, and the custodian could not write collector data. |
| Independent archive verification | Six objects passed, sealed checkpoint 1 and archive identity unchanged. Original checkpoint digest remains `90a62432678481d201c6b850473cc515478cd16718575ba88e6810a0f4cecc76`. No new checkpoint was signed. |
| Native startup proof | The administrator-run repair verified actual listener PID 7451, collector UID 450, and the managed dashboard health response before publishing the completion report. |
| Fresh service check | macOS reported that same PID 7451 running from the fixed installed application as `_hevidence_collect`, with one run and no exit. An ordinary-session `lsof` did not expose the other account's listener; the saved administrator proof supplies the socket UID check. |
| Fresh HTTP check | At `2026-10-12T02:57:15Z`, `/api/health` returned `status: ok`, version 0.3.1, and `/Library/HELTEMES Evidence/data`. `/api/state` returned `account_isolation: separate-local-accounts`, sealed checkpoint 1, four sealed filings, and zero pending filings/records or issues. |
| Repair scope | Only the two diagnostic log-file modes changed from `0640` to `0660`; the root-owned log directory remains protected. Startup succeeded after that correction. No evidence migration, account recreation, key replacement, or trust reset occurred. |
| Cloud and collection | AWS remains undeployed. SEC contact is configured, but this verification did not collect a new filing or contact the SEC. |

An independent agent also checked the completed report and current service state. This demonstrates the tested local collector/custodian boundary; administrators and the operating system remain trusted. Service-writable logs are diagnostic material, not tamper-proof evidence. New filings still require deliberate custodian review and sealing. Use **Manage Local Protection.command** for normal operation; activation and repair are complete.

---

# Native startup inspection completed — October 11, 2026

The inspection started at 9:21 p.m. Central (`2026-10-12T02:21:20Z`) and saved its completed result at approximately 9:27 p.m. Administrator authentication succeeded and the inspection returned exit status 0. The managed custodian independently verified **all six objects, zero issues, sealed checkpoint 1**, retaining digest `90a62432678481d201c6b850473cc515478cd16718575ba88e6810a0f4cecc76`. Both disabled-login, non-administrator service accounts exist with the expected UIDs 450/451 and shared GID 450. The daemon definition matches the fixed expected configuration.

The service is not registered and no final installation report exists. Both collector logs are empty, root-owned, shared-group-owned, and mode `0640`; those permissions deny collector writes. This confirms a logging defect but does not establish the sole cause of the failed dashboard startup. The bounded system-log query found no matching launchd messages. **Archive verification passed; full activation remains unconfirmed.**

The prepared narrow repair changes only these diagnostic log files to `0660`, leaving their root-owned `0750` parent protected. Service-writable diagnostics are not trusted evidence or append-only records. The repair validates the existing installation, retains the same checkpoint, repeats actual-account permission probes, and requires listener PID, UID, and managed dashboard health before saving a completion report. No account recreation, evidence migration, trust reset, signing, or AWS deployment is part of this repair.

Preparation validation: **63 focused tests passed** (17 startup-repair, 13 repair-frontend, and 33 installer/operator tests), with resource warnings treated as errors. Disposable-file checks exercised the log-mode change without truncation and complete, exclusive report publication. Failure cases cover changed checkpoints, unsafe file metadata, existing reports, incorrect listener identity, failed startup/report writing, and interruption cleanup. Authentication, account operations, and native service activation remain mocked in these tests. The repair launcher's shell syntax passed, and an isolated frontend smoke check used mocked native actions. Read-only comparison confirmed all 15 installed application files match the machine-specific repair binding and the installation directory still has its bound identity. **The repair has not been run natively; dashboard activation remains unconfirmed.**

Saved native result: `work/activation-logs/20261012T022120Z-0fdc3b5ecdc4.log` (private local diagnostic, excluded from source releases).

---

# Migrated installation awaiting startup diagnosis — October 11, 2026

Diagnostic retry 2 began at 8:45 p.m. Central (`2026-10-12T01:45:48Z`). It passed the earlier account-recovery stage, created both service accounts, migrated the installation, and reached the final dashboard startup check. That check failed: `The managed collector did not become the verified loopback listener.` The installer stopped the service and did not write `installation-report.json`.

Read-only inspection confirms collector UID 450 and custodian UID 451, both with disabled shells and shared GID 450. The managed data directory belongs to the collector; the custody directory belongs to the custodian; the application and fixed configuration belong to root. The earlier permission probes precede startup in the installer, so reaching this error indicates those checks returned successfully during that run. Their result was not persisted as a final report; fresh independent verification is still required. **Separate identities and ownership exist, but successful application activation is not established.**

The installed log files were created root-owned with mode `0640`, which does not grant the collector write access. This is a logging compatibility issue to investigate, not a confirmed sole explanation for the startup failure. The protected startup logs cannot be read from the ordinary session, and the system log query is unavailable inside the session sandbox. A fixed **Diagnose Local Protection.command** inspection is prepared to read bounded startup details and independently verify through the installed custodian operator after native administrator authentication. It does not start/stop the service, rerun migration, change permissions, or sign a checkpoint. Its output is a private diagnostic record, not a completion report.

The original archive was reverified at `2026-10-12T01:51:55Z`: all six objects and the original checkpoint passed. No protected account or filesystem changes were made during this follow-up. AWS remains deferred. The activation launcher now directs a migrated partial installation to diagnosis before authentication instead of attempting the earlier empty-directory recovery again.

Diagnostic preparation checks: 16 focused diagnostic tests and 17 activation-frontend tests passed with resource warnings treated as errors. Independent review also ran the 16 diagnostic tests. These checks cover bounded reads/output, protected paths, log metadata, authentication exclusion and refusal to re-enter migration after copying. They do not substitute for the pending native inspection.

---

# Saved-diagnostic recovery follow-up — October 11, 2026

The native attempt logged at 8:37 p.m. Central (`2026-10-12T01:37:47Z`) confirmed successful administrator authentication, then stopped with `Expected one directory attribute value: UserShell`. This reached the root-readable recovery checks but did not complete setup. The custodian and managed launch service remain absent; the original root directory retains its previous identity and timestamps.

The workspace repair permits absent stored shell/home fields only for the exact bound early recovery and only when the effective macOS lookup has the expected name, UID, GID, disabled shell, and empty home. Conflicting or malformed fields still fail. The installer writes the missing fields and requires their explicit stored values before migration. Missing-attribute diagnostics are clearer, and a safe presence/count summary excludes directory attribute values.

**48 focused tests passed** with resource warnings treated as errors: 33 installer/operator tests and 15 activation tests. A second agent independently reviewed the change and ran those tests. The launcher now identifies itself as **Diagnostic retry 2** and continues saving private output without capturing password authentication.

The original archive was reverified at `2026-10-12T01:39:25Z`: six objects passed, checkpoint 1 retained its original digest, and no records were pending. No native account mutation was performed during this software repair. **Separate-account protection is still awaiting successful native activation and actual service-account permission probes.** AWS remains deferred. These workspace changes follow the previously packaged 0.3.1 repair; that ZIP remains a historical build.

---

# Account-activation repair verification — October 11, 2026

Release 0.3.1 repairs the first administrator activation attempt. That attempt stopped when macOS rejected an unnecessary write to the collector's `GeneratedUID`. Read-only inspection found the partial collector and shared group; the custodian and launch service were absent. **Account separation is not yet active.**

The installer now reads and preserves macOS-assigned UUIDs. A machine-specific recovery specification binds the retry to the observed account IDs and UUIDs, original root-directory device/inode, and accepted checkpoint. Before writing, the administrator process must confirm the destination is empty, reject unexpected authentication material or memberships, confirm the absent custodian/service, and recheck the same state immediately before its first mutation. It journals changes and surfaces native diagnostic output. This is a narrow repair for the observed failure, not a general account-adoption or reset feature.

| Check | Observed result |
| --- | --- |
| Software suite | 146 tests passed with resource warnings treated as errors, including 28 installer/operator tests and 7 activation-frontend tests. Native directory records and administrator commands are mocked in those tests. |
| Independent review | A second agent reviewed the recovery checks and independently ran the installer and activation tests. No outstanding source-level blocker was found. |
| Original archive | Six source objects still match their saved digests; checkpoint 1 still verifies with digest `90a62432678481d201c6b850473cc515478cd16718575ba88e6810a0f4cecc76`. Counts remain four runs, six assets, four filings and seven observations. |
| Launcher | Failed activation retains its exit status and leaves the Terminal window open so the error can be read. Missing recovery specifications and failed source checks never invoke administrator execution. |
| Actual operating-system checks | Full root-readable directory validation, migration and real service-account access probes still require the native administrator retry. They have not passed yet. |

The updated **Activate Local Protection.command** uses the prepared local recovery specification. The specification is excluded from the distributable source package. No account was deleted or recreated during repair, no new checkpoint was signed, and AWS remains deferred. The previous dated records below describe their respective earlier states.

---

# Separate-account implementation verification — October 11, 2026

Release 0.3.0 implements a managed local collector/custodian boundary. **Administrator activation has not run; the existing archive still uses one account.** No new system account, system service, or AWS deployment is claimed by this record.

| Check | Observed result |
| --- | --- |
| Complete software suite | **128 tests passed**, with resource warnings treated as errors: the prior 89 tests, 19 managed-runtime tests, 17 installer/operator tests, and 3 launcher tests. HTTP tests use actual loopback sockets; SEC/AWS calls remain mocked. |
| Private custodian staging | Actual Ed25519 checks on disposable data; changed sealed history refused; pending records can be sealed; symlinks, hardlinks, FIFO inputs, concurrent file changes, oversized copies and SQLite sidecars rejected. |
| Policy and role checks | Controlled fixtures exercise missing/unsafe fixed configuration, path aliases, substituted trust paths, same-identity configuration, and signing without the custodian role. These are software tests, not actual new-account permission evidence. |
| Key loss | Public verification and receipt export remain possible without the private key; signing new records fails. |
| Installer/operator safeguards | Tests cover non-root refusal, account/ID conflicts, migration links, least-privilege service configuration, protected log locations, isolated runtime dispatch, fixed actions and service startup failures. |
| Read-only installation plan | Passed against this Mac's Python 3.14 runtime and existing checkpoint 1. No installation mutation occurred. |
| Archive preservation | All six source-object digests and all records remain unchanged; checkpoint digest is still `90a62432678481d201c6b850473cc515478cd16718575ba88e6810a0f4cecc76`. Four filings remain: one live Apple 10-Q and three synthetic examples. |
| Launcher and UI checks | Launcher tests refuse a quiet return to the legacy archive when a managed/partial installation exists. JavaScript and command-launcher syntax checks pass. Managed UI/real service operation awaits activation. |
| Review | An independent agent reviewed runtime, installer, operator and activation helpers; no outstanding source-level security blocker was identified. This is not an external audit or proof of OS deployment. |

The public implementation report is `HELTEMES-Evidence-account-separation-verification.json` beside the project. The installer will create a separate, root-owned `/Library/HELTEMES Evidence/installation-report.json` **only after** actual account permission probes, independent verification, and listener UID/health checks succeed. Keep those two reports distinct.

The remaining step is user-operated native administrator activation through **Activate Local Protection.command**. Its need for a credential comes from macOS account creation, ownership changes, and system-service installation. No password is requested in chat or stored by the project. The original key/archive remain intact as a trusted administrator's legacy recovery copy; setup probes that the collector cannot read that original key either.

See [LOCAL_ACCOUNTS.md](LOCAL_ACCOUNTS.md) for the walkthrough, operating menu, and remaining custodian/administrator, new-evidence, timestamp, and disk-loss limits. Earlier dated verification records follow unchanged.

---

# Local protection verification — October 11, 2026

Release 0.2.0 adds signed local checkpoints. The checks below were performed on this Mac with Python 3.14 and the installed OpenSSH signature implementation. AWS was not contacted or deployed, and no new SEC filing was collected.

| Check | Observed result |
|---|---|
| Complete automated suite | **89 tests passed** with resource warnings treated as errors. Includes 21 actual Ed25519 signature tests and 10 protection integration tests. SEC/AWS remain mocked in their existing offline tests. |
| Paired document/reference attack | A same-length change to the Apple document in an isolated restored copy, with all corresponding database references updated, passed basic consistency but failed the signed checkpoint. Backup was refused. |
| Metadata, history, schema and deletion | Tests reject changes to sealed rows/schema, removed records, wrong/missing keys, changed signatures, checkpoint rollback and unsigned downgrade attempts. New rows remain pending. |
| HTTP boundaries | Tests reject signing/reset/import endpoints, paired-tamper downloads and mutable-reference download races. Captured response data is checked against the verified signed row. |
| Backup snapshot | Tampering injected into the copied SQLite snapshot was rejected before archive creation. Protected backups require fully sealed records. |
| Local activation | Checkpoint 1 sealed four filing records: one live Apple 10-Q and three explicitly synthetic examples; six preserved source objects. No pending records. |
| Original history preservation | All four runs, six assets, four filings and seven observations retain their pre-upgrade values. Their canonical table digest remains `5fbff5f2d117cb1e360893b993fcd2d38c0c2e2f50181b211fd4c758af294911`; every source-file digest is unchanged. |
| File permissions | Six source objects are owner-readable only (`0400`). An ordinary write was refused in the disposable recovery copy. The owner can still change permissions. |
| Protected recovery | A backup restored into a separate directory using its separately exported trust receipt; all six objects and the signed checkpoint passed. No signing key was copied into the restore. |
| Dashboard | Browser inspection showed v0.2, Sealed, four sealed filings, zero pending records, and a six-object verification pass. No horizontal overflow in the checked desktop view. Other protection states were exercised through DOM checks and backend tests. |
| Release package | Freshly extracted v0.2 source package completed demo import, checkpoint initialization, public receipt export, protected backup, restore and signed verification. Source and evidence ZIPs contained neither the actual private signing key nor the SEC contact email/settings. |

Checkpoint 1 was created at **2026-10-12T00:28:35Z**, October 11 at 7:28:35 p.m. Central. Its digest is `90a62432678481d201c6b850473cc515478cd16718575ba88e6810a0f4cecc76`. It protects this accepted local baseline from this point forward; it does not certify earlier possession or prove the archive was unmodified before enrollment.

A machine-readable run report is saved beside the project as `HELTEMES-Evidence-local-protection-verification.json`. The protected evidence backup and matching public trust receipt are also saved separately there. They are local copies on the same computer, not independent off-device custody. The deliberately tampered practice copy is under `work/local-protection-upgrade/tamper-probe` and is not the live archive.

The private signing key is unencrypted, outside `data/`, with owner-only permissions. The public trust vault pins its key and latest checkpoint. Software controlling that same operating-system account, or an administrator, can still replace all three. The implementation provides tamper detection against archive-only changes; it does not claim administrator-proof retention, trusted timestamping, SEC signatures, or protection against disk loss. No learner exercise was marked complete.

See [LOCAL_PROTECTION.md](LOCAL_PROTECTION.md) for operation, backup/receipt pairing and recovery. The earlier verification record follows unchanged.

---

# Verification record — October 10, 2026

This record distinguishes implemented features from checks actually performed. The user-facing date uses America/Chicago; timestamps in collected records use UTC.

## Checks completed

| Check | Observed result |
|---|---|
| Python suite, Python 3.14, resource warnings promoted to errors | **58 tests passed** after the live-collection TLS fix (52 at initial build). SEC network behavior and AWS S3 are exercised with controlled fake clients; local HTTP tests use real loopback sockets. |
| SEC parser and request controls | Identifier/host/path validation, real-contact shape validation, malformed arrays, mismatched CIK, response size limits, request spacing, retry behavior, denied access, redirects and slow responses tested. |
| Evidence history | Duplicate observations, revised documents, amendments, unrelated response changes, and partial failures tested. |
| Integrity and recovery | Corrupted/missing blobs, broken references, malicious ZIP paths, symlink entries, archive tampering and occupied restore destinations tested. |
| Local server boundary | Host/Origin/cross-site denial, mutation token, content type, path protection, download attachment headers, corruption refusal and operation lock tested. |
| Contact privacy | Owner-only local settings, environment override, placeholder refusal, symlink refusal and exclusion from evidence backups tested. |
| Cloud adapter | Conditional writes, preserved manifests, partial failures, access denial, no-match results, ignored event overrides, Lambda errors and remaining-time reserves tested with fake AWS clients. |
| JavaScript syntax | Node syntax check passed. |
| Desktop browser | Dashboard rendered; filters narrowed to a single 10-Q; record details showed provenance and hashes; integrity button returned four matching sample objects; lesson page displayed eight exercises; contact dialog blocked unconfigured live collection. |
| Actual local recovery exercise | Three synthetic filings/four preserved objects backed up, restored into a separate directory and verified with zero integrity issues. |
| Terraform | Official Terraform 1.13.5 ARM64 download checked against vendor SHA256SUMS; formatting check, provider initialization and validate succeeded with hashicorp/aws 6.68.0. |
| Source archive startup | Extracted to a fresh directory; demo import, integrity verification and status commands all passed. |
| Lambda package | Deterministic four-file source package generated and inspected by tests; excludes user data/settings/state. |

The initial build contained three synthetic filings, one sample import, and four preserved objects. After live collection, the local workspace contains **one real filing, three synthetic filings, four runs, and six preserved objects**. The four runs comprise one sample import, one failed TLS attempt, one successful first collection, and one successful repeat observation. The original sample timestamps are intentionally fictional and clearly labeled. No learner exercise was marked complete on Fischer's behalf.

## First live collection — October 10, 2026, America/Chicago

- Contact configured in ignored, owner-only local settings; no environment override was present. No email appears in this report or the source archive.
- Initial request failed because this Python installation had no default CA bundle. The failed run remains recorded. A diagnostic request identified `SSLCertVerificationError`; certificate checks were never disabled.
- First successful collection completed at `2026-10-11T03:42:33Z`, using the installed macOS CA bundle. Apple 10-Q accession `0000320193-26-000020`, filed July 31, 2026, report period June 27, 2026, was returned by the SEC recent-submissions endpoint.
- The downloaded primary document is 1,018,321 bytes. Its inline XBRL identity fields independently matched Apple Inc., CIK 0000320193, form 10-Q, and June 27, 2026. This is a content inspection, not an independent signature validation.
- A permanent macOS fallback was added, with hostname and certificate verification retained. Six focused tests cover platform trust selection, invalid overrides, injected test clients, and no retry on certificate verification failure.
- A second normal CLI collection, without a certificate environment override, completed at `2026-10-11T03:44:54Z`. It added zero duplicate filings and retained a second observation of the same filing.
- Six preserved objects passed local integrity checks. The updated evidence backup was restored into a separate directory and verified; private contact settings were excluded.
- The local dashboard displayed the live filing and passed its six-object integrity check. Automatic approval review rejected stopping the already-running preview process; it still uses the previously loaded collector until restarted. New CLI processes use the verified fix.

See [the walkthrough](FIRST_LIVE_COLLECTION.md) for the actual evidence identifiers and learning exercise.

## Not established

- Broad live SEC compatibility: one Apple primary filing was exercised; this does not establish every issuer, form, document size, content encoding, or rate-limit condition.
- Completeness of historical filings or earnings exhibits: the implemented scope is recent submissions plus selected primary documents.
- AWS deployment, effective account permissions, scheduled operation, real alert delivery, cloud restoration, or actual operating costs.
- GitHub-hosted CI execution or a published remote repository. Workflow files are prepared; local test execution is separate evidence.
- Public hosting/authentication, mobile-browser QA, penetration testing, regulatory compliance, or tamper resistance against the local/account administrator.
- Independent authorship or mastery by Fischer, trading performance, forecast quality, or a validated investment edge.

## Package verification

Branding follow-up: Fischer adopted HELTEMES Evidence — Earnings Research Platform. The refreshed dashboard title, sidebar, and heading were checked in the browser. The three existing contact-configuration tests, JavaScript syntax check, source archive inventory/privacy check, and Terraform formatting check passed. A repeat Terraform validation could not start the installed AWS provider (plugin handshake/startup failure); the earlier successful validation above remains a historical result. The infrastructure edit changed only the default project name and example contact label; no deployment was attempted.

The distributable source ZIP excludes runtime evidence, backups, local contact settings, Terraform state and provider cache. Its file inventory and manifest are checked during packaging. A release checksum is provided beside the ZIP. The prepared Lambda archive is inside the project under `dist/collector.zip`; rebuild it after editing collector source.

## Operating state

The dashboard was launched on loopback for inspection. Use `Launch.command` to start it for ongoing local use and keep that Terminal window open. No startup daemon, recurring assistant monitor, AWS schedule, or external notification is active. The prepared AWS schedule defaults disabled until account-specific acceptance checks pass.
