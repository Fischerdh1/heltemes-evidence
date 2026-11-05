# Monitoring history archiving

This opt-in lab stores older monitoring observations in numbered archive segments while keeping the active SQLite journal small. It preserves the global sequence, fingerprint chain, request identity, and incident history. It uses synthetic network traffic in a disposable Linux guest; it does not open the real SEC archive, signing key, or trust record. AWS remains deferred.

## What changes

The original journal stops at 256 observations. The archive format moves complete prefixes into private JSON segment files, then continues the same history in SQLite. Existing journals retain their original format and limits; starting the archive format requires explicit initialization of a new private state directory.

Normal operation retains a bounded current monitoring state rather than every prior evaluation in memory. Status returns current incidents and a bounded recent event list with explicit truncation metadata. Full history remains available through an offline export, reconstructed from all verified segments and active rows. The small socket export keeps its 16 MiB response limit; the offline exporter streams complete rows and their events without that transport limit.

Retention is finite. The default archive format permits at most 4,096 rows in 16 segments of 256 rows and at most 128 MiB of archived bytes. The VM exercise uses 128-row segments and a matching 2,048-row ceiling; the active database also has a 64 MiB limit. Row, segment, byte, and probe budgets are explicit. Reaching a budget or failing persistence stops acceptance and reports unknown coverage; the monitor does not silently delete old history or initialize a new archive. The one-second sampling interval is an exercise setting, not a production recommendation.

## Why the ordering matters

An archive file and a SQLite transaction cannot be committed together as one ordinary database transaction. Rollover therefore uses this order:

1. Commit the new observation in the active database.
2. Write the segment to a private temporary file, synchronize its contents, publish the final name, and synchronize the directory entry.
3. In one SQLite transaction, record the segment descriptor and remove exactly the archived prefix from the active database.
4. Acknowledge the accepted observation to the collector.

An interrupted temporary write can be rebuilt only when it is an exact prefix of the segment reconstructed from verified database rows. An unexpected or altered temporary file is refused. If the process crashes after step 2, the active rows still exist. Restart accepts the unreferenced segment only when its exact bytes match the expected committed prefix. If the process crashes after step 3, the segment and remaining active suffix reconstruct the history exactly once. Missing, unexpected, or altered history causes recovery to stop.

The collector saves its pending request before sending it. After a lost reply, it retries those exact bytes and receives the original result. A duplicate does not refresh telemetry freshness. Restart still records a coverage gap and requires fresh observations.

The implementation uses SQLite's `synchronous=EXTRA` setting with rollback-journal mode, file synchronization, and directory synchronization. These are explicit durability mechanisms, not a claim that hashes make storage immune to an administrator. See [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html) and [synchronous settings](https://www.sqlite.org/pragma.html#pragma_synchronous).

## Repeatable VM exercise

On a disposable x86-64 Linux host with the documented QEMU prerequisites:

```sh
mkdir -p work
python3 -I -S -B scripts/network_monitor_archive_vm.py --output work/monitor-archive
```

The controller refuses macOS before creating an output directory. It boots the same digest-pinned Ubuntu image used by the earlier VM exercises, shares no host directory, and installs only an explicit source allowlist. The required `monitor_archive` CI job runs this exercise; the reviewer gate requires its success.

The acceptance sequence is:

1. Start independent collector and monitor services, establish healthy coverage, and open a real forbidden-path incident in the synthetic network.
2. Collect more than 256 real firewall snapshots, with periodic three-path connection checks. Archive two 128-row segments while preserving the unresolved incident.
3. Kill the monitor at each archive handoff boundary. Observe supervisor restarts, exact pending-request retries, continuous committed history, and unknown coverage until fresh evidence returns.
4. Retry an observation already moved into an archive. It must return its original sequence without appending another row.
5. Repair the synthetic firewall. Require fresh complete connection checks before resolving the original incident.
6. Reject missing and changed archive files on separate disposable state copies.
7. Verify source identity, raw archive bytes, journal history, capture evidence, and cleanup before publishing the report.

To export a larger disposable archive, stop its monitor first, then run the following inside that disposable environment with its synthetic state path and a new output file:

```sh
python3 -I -S -B scripts/network_monitor_archive.py --state /absolute/disposable/state --output /absolute/disposable/history.json
```

The exporter holds the same writer lock, verifies the complete history, and never replaces an existing output. Its final `history_complete` field is written only after every row; an interrupted output is not a complete export. This command is for the disposable monitoring state, not the real Evidence installation.

## Evidence to inspect

| File | Purpose |
| --- | --- |
| `REPORT.json`, `VM.json` | Exact source and run identity, one-boot VM observations, scope, and cleanup |
| `GUEST.json` | Service lifecycle, archive crash boundaries, collector receipts, complete journal, incidents, and negative controls |
| `archive-segment-000001.json`, `archive-segment-000002.json` | Original segment bytes, independently comparable with the journal export |
| `APPROVED_POLICY.json`, `monitor.service`, `collector.service` | Approved synthetic firewall policy and the two service definitions |
| Three `.pcap` and three packet-text files | Actual synthetic connection attempts and capture results |
| `SUMMARY.md`, `MANIFEST.json` | Readable result and fingerprints of all other public files |

A successful run is evidence for bounded automatic archiving and process-crash recovery. It does not establish indefinite production monitoring, automatic expiration, off-device backup, administrator-resistant custody, or physical power-loss durability during archiving. The earlier reboot and power-cut jobs remain separate regression checks; this exercise stays within one guest boot.

## Interview explanation

“I extended a monitoring journal beyond its original 256-row limit by archiving older observations without resetting the sequence or incident identity. I interrupted the archive handoff at two boundaries, restarted the monitor, and verified that committed observations appeared exactly once. The collector retried saved requests after lost replies, and recovery remained unknown until fresh network checks returned. I also rejected missing and altered archive segments on disposable copies. The implementation has explicit retention limits; it is not an administrator-proof archive or an unlimited production service.”
