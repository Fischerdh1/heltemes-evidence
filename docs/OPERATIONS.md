# Operations runbook

This runbook covers local operation and the handoff to a prepared AWS deployment. Commands below run from the project directory. Use a separate practice data directory for exercises.

## Managed installation on Fischer's Mac

The separately owned installation is `/Library/HELTEMES Evidence`; its dashboard uses `http://127.0.0.1:8765`. Start with **Manage Local Protection.command** for independent verification, deliberate sealing, public receipts, backups, and service control. See [LOCAL_ACCOUNTS.md](LOCAL_ACCOUNTS.md). The terminal examples below describe a standalone or practice workspace, not a way to bypass managed account permissions. Never run `protect init` against the managed archive or silently return to the legacy copy.

A source ZIP is an application release, not an evidence backup. Installing new source and accepting new evidence are separate operations. The recovery exercise restores a backup against its matching public receipt into a new directory; it does not replace the production archive or recover a private signing key.

For the supervised exercise on Fischer's installed archive, **Review and Back Up Filings.command** pauses collection, saves the exact custodian snapshot for review, accepts a matching explicit approval, and creates and restores the corresponding backup/receipt pair. Follow the [review workflow](LOCAL_ACCOUNTS.md#review-one-exact-snapshot-and-test-its-backup). Native administrator authentication stays in Terminal, and a software test result alone does not establish native completion or off-device recovery.

## Status vocabulary

| Status | Meaning |
| --- | --- |
| Demo | Synthetic records used to exercise the program; not company evidence |
| Live collection | A run using SEC endpoints; inspect its result to establish whether it succeeded |
| Verified locally | The selected local checks passed at a recorded time; not independent validation |
| Sealed | Saved records match the signed checkpoint and separately pinned local reference |
| Pending | Previously sealed history still matches, but new records have not been checkpointed |
| Protection failed | A trusted reference, signature, chain, or previously sealed record does not verify |
| Unconfigured protection | Only basic byte/database checks are available; references have no signed checkpoint |
| Prepared for AWS | Deployment files exist; resources and access have not necessarily been created or tested |
| Operating on AWS | Requires observed resources, successful execution, stored output, and tested controls in the target account |

Keep these statuses separate in project notes and demonstrations. Nothing in this runbook establishes a background maintenance schedule.

## Start with synthetic data

```sh
python3 -m heltemes --data-dir work/practice demo
python3 -m heltemes --data-dir work/practice verify
python3 -m heltemes --data-dir work/practice serve --port 8766
```

Visit `http://127.0.0.1:8766`. Read the source-mode label and retrieval times before interpreting the dashboard. Use Control-C in the terminal to stop this practice server. Port 8765 is reserved for the managed dashboard.

The dashboard can seed demo records, collect when configured, verify evidence, download a public trust receipt, and create a backup. It cannot initialize, sign, or reset checkpoints. These operations affect the selected data directory. Demo seeding reuses a previous successful demo run instead of pretending to collect new evidence. For a terminal status view, use `python3 -m heltemes --data-dir work/practice status`.

## Establish local protection

Requires installed OpenSSH at `/usr/bin/ssh-keygen` with signing support. Stop collection, review the intended archive, then initialize protection **once** for that archive:

```sh
python3 -m heltemes --data-dir data verify
python3 -m heltemes --data-dir data protect init
python3 -m heltemes --data-dir data verify
```

Initialization creates a local signing identity and the first checkpoint. It does not prove the evidence was protected before this step. Keep the private signing key and active trusted reference outside the archive and out of source control. They live in matching `.heltemes-keys/` and `.heltemes-trust/` directories beside the selected data directory. Same-account software and administrators can still access or replace them; these are not independent identities.

Read **Fingerprint reference protection** in the dashboard separately from **Bytes & database references**. Verification can pass while new records remain pending, or while protection is unconfigured. The [local protection guide](LOCAL_PROTECTION.md) explains those states and the remaining limits.

## Collect live SEC evidence

The collector needs a real operator contact in its SEC request header. A dedicated research or project address is suitable if the operator can receive messages there. You can enter the address locally without sending it to the assistant:

```sh
python3 -m heltemes --data-dir data configure
```

On macOS, opening `Configure SEC.command` provides the same setup for the default data directory. Enter your chosen address at the terminal prompt. The program adds the project name and saves `data/settings.json` with owner-only read/write permissions (`0600`). The file is excluded from source control and evidence backups. Your contact is transmitted to the SEC in live request headers; it is not an API key or authentication credential.

Refresh an already running dashboard after saving the setting. Local settings are read for each collection; no server restart is needed. Configuration belongs to the selected data directory, so use its matching `--data-dir` when configuring a practice or restored repository.

Alternatively, set `SEC_USER_AGENT` in your local environment with the project name and actual contact. A nonempty environment value overrides the saved setting. If you change that environment value, restart the server from the updated environment. Do not publish the contact in the repository, invent an address, or substitute a sample address to get around validation.

After configuration, run:

```sh
python3 -m heltemes --data-dir data collect --cik 0000320193 --limit 3
python3 -m heltemes --data-dir data verify
python3 -m heltemes --data-dir data serve --port 8765
```

The example CIK identifies Apple. It is a software demonstration target, not a ticker recommendation or a QES review. Confirm the company identity and requested forms in the resulting records. The command-line default is exact `10-Q`; include `--forms 10-Q 10-Q/A` to include its amendments. Other forms are selected only when explicitly requested. The local command permits 1–20 selected filings, and the dashboard limits a run to 10.

Keep requests infrequent and limited. A missing contact, rejected request, timeout, or invalid response is a failed or incomplete collection to investigate. Do not mark it successful by switching to demo data. The source policy is documented in [SOURCES.md](SOURCES.md).

The SEC client permits one request per second within one process, with a 15-second default timeout, at most three attempts per resource, and a 10 MiB response limit. A 403 stops that request immediately, and redirects are rejected. Separate processes do not share the limiter. These intentionally small limits can reject unusually large filings and are part of the current supported scope.

After collection, inspect the run outcome, document count, source URLs, retrieval times, and verification result. A successful metadata request alone does not prove every selected document was retrieved. The current collection scope is recent filings, not a complete company archive.

With local protection enabled, each newly added filing or collection-history record remains pending. A run with zero new filings can still add an observation. After reviewing the new records, stop collection and create the next checkpoint explicitly:

```sh
python3 -m heltemes --data-dir data protect seal
python3 -m heltemes --data-dir data verify
```

Do not use sealing to approve unexplained changes to previously sealed records. A failed protection check requires investigation, and must not be bypassed by removing the trusted reference or generating a replacement signing identity.

## Back up and demonstrate recovery

Stop collection before the exercise. Keep the original data directory intact. For the protected workflow below, initialize protection once and ensure the status is **sealed** with no pending records. Save a public trust receipt and matching backup using new filenames, then restore to a new, nonexistent destination.

```sh
python3 -m heltemes --data-dir data verify
python3 -m heltemes --data-dir data protect receipt work/evidence-receipt.json
python3 -m heltemes --data-dir data backup work/evidence-backup.zip
python3 -m heltemes restore work/evidence-backup.zip work/restored-evidence --trust-receipt work/evidence-receipt.json
python3 -m heltemes --data-dir work/restored-evidence verify
python3 -m heltemes --data-dir work/restored-evidence serve --port 8766
```

Confirm that the restored dashboard shows the expected filings, source modes, and checkpoint. Record the public receipt, checkpoint number/hash, archive path, creation time, restore destination, verification result, and elapsed recovery time. Keep the public receipt separately from its matching backup so an attacker changing the archive cannot also replace the recovery reference. The local staging paths in this example do not create independent custody or prove recovery from a lost device; retain separately controlled copies if the records become important.

Protected backups contain a database snapshot, registered evidence files, and signed checkpoint history as well as a checksum manifest. Pending or failed protection prevents backup. The local format caps expanded content at 200 MiB and 20,000 archive entries. Restore checks the separately supplied public receipt before activation: the signing identity and exact checkpoint must match. An older backup must not pass against a newer receipt. Keep each historical backup paired with its own independently saved receipt. Existing backup files are not overwritten, so use a new filename for each run.

The private signing key, active trusted reference, and contact settings are deliberately absent from the backup. The restored archive receives verification material derived from the supplied receipt; it can be viewed and verified without a signing key or contact. Preserve practice restores as recovery copies. If an operator deliberately resumes work from a verified restore, continued signing requires explicitly supplying the original matching key directory with `protect seal --key-dir PATH-TO-ORIGINAL-KEY-DIRECTORY`. This checks the original signing identity; it does not replace the trusted reference or recover a lost key. See [LOCAL_PROTECTION.md](LOCAL_PROTECTION.md).

An archive whose protection is unconfigured can still use a legacy unsigned backup. For that mode, omit the receipt option when restoring. Checksums establish internal consistency only, not a trusted signing identity. Do not remove protection or omit a required receipt to force a protected restore to pass.

A verification failure requires investigation. Preserve the failing evidence and logs, suspend use of the affected records, and compare them with a known-good backup or re-retrieved source recorded as a new collection. Do not edit the expected hash merely to make the check pass.

## Incident scenarios

| Symptom | First check | Recovery evidence |
| --- | --- | --- |
| Live collection will not start | Saved contact for this data directory, any environment override, and command arguments | A later live run with saved results; no invented contact |
| SEC returns a denial or rate response | Run outcome, request policy, and combined collection frequency | A restrained later attempt; preserve the failed attempt |
| Connection times out | Connectivity, DNS, connection/TLS evidence, and timeout message | Successful request and saved evidence; do not infer the failed network layer from timeout alone |
| Verification reports changed or missing evidence | Exact affected file and stored reference | Preserved incident evidence, clean restore, then verification |
| Bytes match but protection fails | Separate checkpoint issues, sealed record changes, chain, and trusted reference | Preserve both results; restore against a known-good independently retained receipt |
| Zero new filings but protection is pending | New collection runs or observations since the checkpoint | Review the additional history, explicitly seal, then verify and retain a new receipt/backup pair |
| Dashboard appears old | Data directory, last retrieval time, and last run status | Correct dataset opened and a verified collection, when needed |
| Dashboard does not open | Server output and selected port | Loopback URL loads; no change to public binding |
| Restore is rejected | Archive validity, destination state, rejected path, and exact receipt/checkpoint match | Valid archive restored to a new directory against its trusted receipt; never disable path or signature checks |

Use this incident record:

```text
Date/time and timezone:
Environment and data directory:
Expected behavior:
Observed symptom and decisive evidence:
Affected records:
Actions taken, including assistant help:
Verification after recovery:
Unresolved uncertainty:
Prevention or follow-up:
```

## AWS handoff

Use the infrastructure documentation and examples in `infra/`. First inspect the planned resource changes, deployment identity, region, bucket naming, notification destination, collection contact, and expected costs. Keep scheduling disabled until a manual cloud run and storage checks have succeeded.

For operational acceptance, retain evidence of:

1. A deployed collector completing a manual run and preserving its output.
2. Correct private storage and a denied action outside each role's scope.
3. A restored object or dataset with a matching verification result.
4. A collection failure visible in logs and the intended alert reaching its destination.
5. Evidence-bucket object activity appearing in the configured data-event log.
6. The actual recurring schedule, its observed run, and its stop procedure.
7. Actual charges reviewed after billing data has arrived.

These are future deployment acceptance criteria until observed in the target account. Budget notifications are not a hard spending limit. If using GitHub deployment, inspect the actual OIDC subject format before restricting the role; the current official guide documents newer immutable ID subjects. See [SOURCES.md](SOURCES.md).

Stop cloud collection by disabling its schedule first. Preserve needed evidence and review the planned deletion of resources before teardown. Do not delete historical evidence merely to make infrastructure removal succeed. An assistant can help operate an authorized environment, but ongoing monitoring requires an actual configured schedule, access, and a verified notification path.
