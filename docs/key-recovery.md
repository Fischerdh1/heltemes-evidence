# Crash-safe signing-key recovery

This workflow adds an explicit recovery transaction to the local application. Installing the capability does not replace a signing key, create a checkpoint, or reset trusted history. AWS remains deferred.

## The two checks

Archive verification asks whether the preserved evidence and signed history match the accepted public receipt. Signing permission asks an additional question: is the signing identity authorized, with any required recovery fully and durably completed?

An archive can verify while signing remains blocked. This is expected during recovery. A successful signature by a replacement key cannot authorize that key by itself.

## The recovery record

A public recovery request binds one transition to an archive, its exact previously accepted checkpoint and receipt, and the replacement key's exact public identity. It contains no private signing key. Creating this request is preparation for review; it grants no authority and starts no transition.

For the managed installation, authorization must come through the administrator's protected approval location, outside the collector's and custodian's writable directories. The approved document's exact SHA-256 must match the supplied approval digest. The collector cannot approve recovery. A standalone practice archive relies on its operator to independently review and protect the authorization and its digest.

Preparing an approved recovery records durable intent before changing accepted identity. Ordinary checkpoint signing is then blocked, including a request that would otherwise return an unchanged checkpoint. The recovery journal and lock are tied to the trusted reference, so pointing a signing command at another key directory cannot bypass the block.

## What happens after a crash

| Restart state | What the application permits |
| --- | --- |
| Request only | No transition has begun. Existing signing policy still applies. |
| Prepared intent, incomplete transition | Verification may be available; ordinary signing stays blocked. An explicit resume must revalidate the authorized inputs. |
| New checkpoint or reference published, completion absent | Signing stays blocked. Resume accepts only the exact authorized partial state; it does not invent a replacement history. |
| Completed transition | Revalidate authorization, installed key identity, and accepted archive history. If they match, signing may resume without repeating the transition. |
| Missing, changed, or inconsistent recovery material | Stop signing and report the problem. Do not generate another key or reset trust. |

Completion is recorded last, after the new public checkpoint and reference have been written and synchronized. Publishing a completion file is not enough by itself: subsequent signing revalidates the committed state. These are filesystem durability measures tested with process interruptions; they do not promise survival of every hardware failure.

## Keeping old signatures valid

Existing version-1 checkpoints and receipts keep their original bytes. A recovery adds a version-2 transition checkpoint and a receipt that pins the public key authorized for each interval of checkpoint history. The transition copies the last accepted snapshot; it does not silently approve pending filings.

The original private-key file is never overwritten. A replacement key occupies a distinct protected identity slot. Verification of old checkpoints continues to use their original public key. Later checkpoints use the identity authorized by the current receipt. Public receipts and backups still exclude private keys.

## Operator commands

The following commands apply to a separate single-account practice archive. For the managed installation, commands run under the designated custodian identity and use the administrator-approved manifest; do not run practice commands against the legacy workspace or manually edit managed custody files.

```sh
python3 -m heltemes --data-dir work/practice protect recover status
python3 -m heltemes --data-dir work/practice protect recover plan \
  --candidate-key /absolute/private/candidate-key \
  --trust-receipt /absolute/independent/latest-receipt.json \
  --output /absolute/review/recovery-request.json
```

Stop here for independent review. The reviewer must verify the archive identity, latest accepted checkpoint and receipt, replacement key fingerprint, and proposed action. The request's presence or its replacement-key signature is not approval.

For the managed Mac installation, `scripts/authorize_key_recovery.py` installs one specifically reviewed public request. Run it as your normal account with the request path and `--expected-sha256` followed by the exact independently reviewed digest. It displays the archive, accepted checkpoint, and both key fingerprints before native Mac authentication. The administrator helper checks the installed application manifest and obtains a fresh receipt through the actual custodian account. It installs only an exact matching public approval under the root-owned `recovery-authorizations` directory; it does not install a private key, stop the dashboard, or begin recovery. A mismatched or stale request stops the operation. Keep the digest independent of an untrusted request producer rather than treating whatever digest it prints as approval.

Only after the exact request has been authorized, preparation uses `protect recover prepare` with `--candidate-key`, `--authorization`, and the independently approved `--authorization-sha256`. `protect recover resume` explicitly revalidates and completes the recorded transaction. Repeating resume after successful completion checks the committed result instead of creating another transition.

The dashboard has no signing or recovery-approval endpoint. The installed fixed operator's `key-status` action reports signing availability separately from archive verification and runs as the custodian. Routine collection cannot replace the identity.

## Remaining trust boundary

Separate local accounts constrain the collector. They do not make the Mac administrator, recovery authority, or storage hardware untrusted. An administrator who can replace all local approval records, keys, code, and trust references remains outside this protection boundary. Independent off-device receipts and backups, plus a trusted recovery environment when necessary, address different risks. Recovery never treats the financial claims inside a filing as proven true.
