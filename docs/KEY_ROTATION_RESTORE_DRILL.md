# Restore drill after a signing-key change

This local drill combines [authorized signing-key recovery](key-recovery.md) with protected backup and restore. It creates a new synthetic archive and disposable Ed25519 keys in scratch space. The exercise uses one local account to play both the recovery requester and the reviewer. It models their decisions and exercises the application's checks. The [managed macOS account boundary](LOCAL_ACCOUNTS.md) and off-device custody require separate validation.

## Follow the checkpoints

1. **Checkpoint 1 uses Key A.** Seal the first synthetic filing and export a ZIP and public receipt. The receipt pins the exact accepted checkpoint and its public key.
2. **Checkpoint 2 records the approved change to Key B.** Remove the disposable Key A private key to simulate its loss. The existing filing still verifies and an ordinary seal attempt is refused. The drill reviews the recovery request against the accepted receipt and the expected Key B fingerprint. It supplies the approved request's SHA-256 to prepare recovery, then explicitly resumes it to commit the change. The transition preserves checkpoint 1 and carries forward the same accepted filing snapshot.
3. **Checkpoint 3 uses Key B.** Collect and seal a second synthetic filing, then export a fresh ZIP and receipt. The current receipt records where Key B took over. A verifier uses Key A's public key for checkpoint 1 and Key B's public key from checkpoint 2 onward.

## Follow the restores

| Inputs or action | Expected result |
| --- | --- |
| Checkpoint 1 ZIP with checkpoint 1 receipt | Restore and verify the historical snapshot. |
| Checkpoint 3 ZIP with checkpoint 3 receipt | Restore both filings and verify the signed history across both keys. |
| Checkpoint 1 ZIP with checkpoint 3 receipt | Reject the rollback. The backup stops before the accepted head. |
| Checkpoint 3 ZIP with checkpoint 1 receipt | Reject the backup. The supplied receipt pins the earlier head and its Key A history. |
| Add a synthetic filing to the checkpoint 3 restore and attempt to seal | Signing is blocked. The restore has public verification material. Its private signing keys and local recovery journal are absent. The accepted head stays at checkpoint 3 and the new filing stays pending. |

The rejected restores leave no destination archive or trust record. During real recovery, retrieve the current accepted receipt from the location you trust to hold it. The app verifies the backup against the exact receipt you supply. The historical pair still passes when used together, so selecting the current receipt is part of rollback protection.

## Run locally

Use Git, Python 3.11 or later, and OpenSSH's `/usr/bin/ssh-keygen` with SSH signature support from a clean Git checkout containing the drill.

```sh
mkdir -p work
python3 -I -S -B scripts/key_rotation_restore_drill.py --output work/key-rotation-restore
```

Choose a new output directory for each run. On success, `REPORT.json` records the outcomes and `MANIFEST.json` provides the report checksum. The scratch directory and its practice keys, backups, and restored copies are removed. The drill uses no real filings, signing key, or trusted history, and requires no external drive or AWS deployment.

Regular CI runs the same command as `key_rotation_restore`. Reviewer packaging waits for its success. The report includes the tested source revision and workflow identifiers, and the artifact retains only the two JSON files for 30 days. See [continuous verification](CONTINUOUS_VERIFICATION.md).

For an interview, explain how a single restored archive can still verify two signing identities. The latest receipt assigns each key a specific part of the chain. The private key and the durable local recovery record are separate requirements for signing a new checkpoint.
