# Clean-machine restore drill

This drill restores a synthetic filing archive on a fresh disposable Ubuntu VM. The source machine creates two signed checkpoints, exports a backup and public receipt for each, then removes the practice source archive and signing key. The runner transfers the backups over one SSH session and the receipts over another. The VM receives the public checkpoint history and public keys it needs to verify the archive.

The runner holds the receipts separately to model independent custody. The physical off-device custody milestone also requires an actual backup location and a separately controlled trusted receipt.

| Case | What the drill checks |
| --- | --- |
| Latest backup with the latest receipt | Restore succeeds. Every filing and evidence object matches the saved source inventory, and the signed checkpoint verifies. |
| Protected backup with no receipt | Restore fails and leaves the destination and public trust untouched. |
| Older backup with its own older receipt | Restore succeeds as a positive control. This shows the old backup is valid in its original context. |
| Older backup with the latest receipt | Restore fails because the signed history falls short of the independently held checkpoint. |
| Altered filing with updated mutable hashes and the latest receipt | The ZIP manifest and mutable database references agree with the altered bytes. The signed checkpoint still rejects the change. |
| Attempt to sign on a fresh restore after adding practice records | Signing fails without the matching private key. The original checkpoint and pending records remain intact. |

## Run the drill

Use a disposable x86-64 Linux host with the QEMU, cloud-image-utils, OpenSSH, curl, Git and Python prerequisites from the [archive reboot exercise](NETWORK_MONITOR_ARCHIVE_REBOOT.md). From the committed source checkout:

```sh
mkdir -p work
python3 -I -S -B scripts/clean_restore_vm.py --output work/clean-machine-restore
```

The output directory must be new. The controller provisions a digest-pinned guest with no shared host folders. It sends only the allowlisted application source and practice inputs. It checks both transfer hashes, the guest boot identity, and all six results. After cleanup it writes `CLEAN-RESTORE.json` and a SHA-256 manifest. Random IDs, timestamps, and signatures change on each run.

For the interview, show why the older backup passes with its old receipt but fails with the latest one. A good signature says who signed that historical snapshot. The independently held latest receipt says which snapshot the restore must reach. The public receipt cannot recreate missing files or provide signing authority.
