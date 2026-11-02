# Local protection for filings and fingerprints

HELTEMES Evidence can seal its local history with a signed checkpoint. Verification then checks the stored evidence against that checkpoint as well as checking the ordinary file hashes. AWS is not needed for this feature.

The boundary is specific: changes inside the evidence archive are detectable while the trusted checkpoint reference outside that archive remains intact. The default workspace uses one account. Release 0.3 also provides a [separate-account local installation](LOCAL_ACCOUNTS.md); that boundary is active only after administrator installation and actual account-permission checks succeed. Neither mode protects against administrator compromise.

## How the pieces fit

| Piece | What it does | What it cannot establish |
| --- | --- | --- |
| Document and raw-response SHA-256 hashes | Detect whether saved bytes differ from their references | A database hash alone cannot detect an attacker replacing both bytes and the hash |
| Signed checkpoint | Captures filing records, source references, and collection history in a canonical snapshot signed with an Ed25519 key | A signature does not establish that the original source or collection metadata was true |
| Checkpoint chain | Links each checkpoint to its predecessor | A chain stored only with the archive cannot tell whether its entire tail was removed |
| Trusted reference outside `data/` | Pins the accepted signing public key and latest checkpoint | The same local account can still change this separate reference |
| Separately saved trust receipt | Provides the public reference required to authenticate a protected restore | A receipt obtained only from the potentially altered backup is not an independent reference |
| Read-only evidence files | Reduce accidental overwrites | The file owner can change permissions; this is not immutable storage |

The signature operations use the installed OpenSSH tool at `/usr/bin/ssh-keygen`, with a project-specific namespace and an allowed signing identity. No third-party Python package is required. See the official [OpenSSH signing and verification documentation](https://man.openbsd.org/ssh-keygen).

## The default workspace trust boundary

For a selected `data` directory, the application keeps a matching trust directory under `.heltemes-trust/` and a signing-key directory under `.heltemes-keys/`, beside the data directory. The per-archive directory name derives from the resolved data path. The local trust directory holds `anchor.json` and the public signed history under `checkpoints/`; `data/protection.json` marks the archive as protected. Protected backups carry a copy of that public history, but never the active trusted reference or private signing key.

In the default workspace, the private key is stored as an unencrypted local file without a passphrase. Its file permissions are `0400`; its containing directory is `0700`. Those permissions reduce accidental exposure to other ordinary accounts. They do **not** isolate the key from another process running as the operator. The dashboard has no signing, initialization, or reset endpoint, but the dashboard process still runs under the same operating-system account.

Do not publish either hidden directory, copy the private key into an evidence backup, or treat placing two folders on the same disk as independent custody. Losing the key does not prevent verification with the public reference, but this version cannot recover a lost key or rotate the signing identity. A restored archive receives verification material, not the private signing key.

## Initialize and seal

Run commands from the project directory. Stop collection before creating a checkpoint so the snapshot represents a stable state. Use a separate practice archive when learning.

```sh
python3 -m heltemes --data-dir data verify
python3 -m heltemes --data-dir data protect init
python3 -m heltemes --data-dir data verify
```

Initialization establishes this installation's signing identity and trust configuration and creates the first checkpoint. Later sealing verifies existing protected history, captures the current records, signs a new checkpoint, and advances the trusted reference. An initial checkpoint documents what the archive contains at initialization; it cannot prove that no changes happened before protection was enabled.

Read the verification output and the dashboard's **Fingerprint reference protection** card. A matching byte hash and a valid signed checkpoint are separate results.

| Protection status | Meaning | Next action |
| --- | --- | --- |
| No checkpoint (`unconfigured`) | Only the basic byte/database consistency checks are available | Initialize protection and seal reviewed evidence |
| Sealed (`sealed`) | The archived records match the accepted signed checkpoint | Retain its public receipt and a matching backup |
| New records pending (`pending`) | Previously sealed history still matches; additional records are not yet included in a checkpoint | Review the new filing and collection records, then explicitly seal them |
| Protection failed (`failed`) | A signature, trusted reference, checkpoint chain, or previously sealed record could not be verified | Preserve the failure and investigate; do not replace the reference merely to obtain a pass |

A normal collection does not sign new evidence automatically. Even a repeat collection with zero new filings can add an observation and run history, making the archive pending. Pending records remain visible so that a successful download is not mistaken for an operator-approved checkpoint.

After a reviewed collection:

```sh
python3 -m heltemes --data-dir data verify
python3 -m heltemes --data-dir data protect seal
python3 -m heltemes --data-dir data verify
```

The dashboard can run verification and download the public receipt. It cannot authorize a new checkpoint. A receipt downloaded while records are pending covers only the last sealed checkpoint; save a new receipt after the next seal. The CLI is an explicit operator step, not a separate operating-system identity.

## Save a receipt and prove recovery

Use new names for each checkpoint's receipt and backup. Keep collection stopped while creating the matching pair. The paths below are local staging paths; move or copy the public receipt and the backup into separately controlled storage if they need to survive loss or compromise of this computer.

```sh
python3 -m heltemes --data-dir data protect receipt work/checkpoint-REPLACE-WITH-SEQUENCE.json
python3 -m heltemes --data-dir data backup work/evidence-REPLACE-WITH-SEQUENCE.zip
python3 -m heltemes restore work/evidence-REPLACE-WITH-SEQUENCE.zip work/restored-evidence --trust-receipt work/checkpoint-REPLACE-WITH-SEQUENCE.json
python3 -m heltemes --data-dir work/restored-evidence verify
```

Replace `REPLACE-WITH-SEQUENCE` with the checkpoint number shown by verification. Restore into a new or empty destination. Keep the original evidence intact.

A protected backup is refused when there are pending records or failed checks. It contains the evidence, database snapshot, and public signed checkpoint history. It excludes the private signing key, active trusted reference, and SEC contact setting. Restore requires a separately supplied receipt that matches the backup's exact checkpoint and signing identity; an older backup does not match a newer receipt. Retain receipt/backup pairs when preserving historical recovery points.

A restored archive can be viewed and verified. It does not receive a key to continue signing the original history. Do not run `protect init` over a protected restore to bypass that boundary. Preserve practice restores as recovery copies. If an operator deliberately resumes work from a verified restore and retains the original matching key, `protect seal --key-dir PATH-TO-ORIGINAL-KEY-DIRECTORY` can sign additions after checking that key against the pinned identity. It does not generate or trust a replacement key. A lost private key cannot be recovered from the public receipt or backup.

An archive that has never been protected can still create and restore a legacy unsigned backup. That mode checks internal checksums, not an independently pinned signing identity. Never describe an unsigned restore as authenticated by a checkpoint.

## What a tamper test should show

Use disposable copies and preserve the trusted reference for the test. Do not experiment on the real filing archive.

1. A one-byte edit to a preserved filing fails the normal fingerprint comparison.
2. Updating the file and its database fingerprint together may satisfy that basic comparison, but changing the previously sealed record fails the checkpoint comparison.
3. Editing a source URL, retrieval time, source mode, or another sealed field fails the comparison even if the document bytes are unchanged.
4. Removing previously sealed records or replacing the archive with an older checkpoint fails against the independently retained latest reference.
5. A new, valid collection appears as pending. Reviewing and sealing it advances the reference while retaining earlier checkpoints.
6. A protected restore using the matching separately saved receipt passes; changing the receipt or substituting an older checkpoint must not silently establish a new identity.

Consult the test names and actual results in [VERIFICATION.md](VERIFICATION.md) before claiming any of these behaviors was demonstrated in a particular installation. Assistant-run tests are software validation, not completion of Fischer's learning exercises.

## Remaining limits

- In the default workspace, full compromise of the operator account can expose the key and replace the reference. The separate-account installation isolates the collector after activation. Custodian/administrator compromise remains outside its guarantee; hardware signing and key rotation remain future work.
- A signed checkpoint attests to the accepted local snapshot. It does not make SEC content true, authenticate the SEC as the signer, validate financial figures, or establish an independent collection time.
- The computer's clock supplies checkpoint time. Sealing existing evidence today does not prove the evidence was protected or possessed on its earlier retrieval date.
- A newly collected but false record can be sealed if the operator accepts it. Review the source, timestamps, preservation status, and run outcome before sealing.
- Local read-only files are not WORM storage. Backups and receipts on this disk do not survive disk loss.
- AWS remains prepared but undeployed. These local controls do not establish cloud isolation, retention, monitoring, or IAM behavior.
