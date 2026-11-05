# Recovery after abrupt virtual power loss

This exercise extends the [orderly VM reboot lab](NETWORK_MONITOR_REBOOT.md). The host abruptly kills the entire owned QEMU process at two selected transaction boundaries, then starts a new VM process using the same disk. The guest operating system receives no shutdown or reboot request.

The lab uses synthetic network traffic and a newly initialized monitoring journal. AWS, the installed Evidence application, its real key, and its trusted history are outside the exercise. Only allowlisted lab source and temporary access credentials enter the guest.

## What changes

Persistent history and the enabled boot service already exist in the reboot lab. This expansion adds a separately guarded test worker that pauses at an exact save boundary, a host controller that cuts virtual power, and evidence checks for the subsequent cold start. Ordinary monitoring does not enable these test controls.

The lab journal also uses SQLite `synchronous=EXTRA` with rollback-journal DELETE mode. This adds a directory sync after journal removal, strengthening durability of the most recent completed transaction. The existing database schema and identity remain unchanged; no real Evidence database is migrated.

Finished packet captures and their text summaries are flushed to disk before the first cut. Their fingerprints are included in the pre-cut reference retained by the host. Recovery checks those earlier fingerprints again, so a later manifest cannot silently legitimize damaged capture bytes. This preparation happens before the transaction is armed; the paused transaction does not receive an extra persistent-disk flush from the test harness.

A host-observed boundary signal determines when to cut power. A delay chosen by guesswork would not establish whether a transaction had completed. The controller retains reference bytes outside the guest before each cut and compares the recovered journal against them.

## Walk through recovery

1. **Save a real lab incident.** In an isolated three-zone network, a deliberately incorrect rule permits traffic to a restricted endpoint. Packet captures and the monitor record the incident.
2. **Interrupt an unfinished save.** The worker pauses after its SQL changes but before commit. The host kills QEMU immediately after observing the boundary signal. On the next boot, the interrupted request must be absent and all earlier accepted rows must be unchanged.
3. **Inspect automatic startup.** Linux starts the enabled monitor without a manual service start or new database initialization. The monitor verifies and replays its existing journal, then records unknown coverage. The original incident remains open.
4. **Lose a completed save's confirmation.** Another request commits, then the worker pauses before returning its response. The host cuts virtual power again. After cold boot, the committed request must exist exactly once.
5. **Retry safely.** Repeating the same request ID and content returns the original result without adding another observation. That historical response must not replace the current unknown coverage status.
6. **Recheck the network.** New rule observations establish a fresh counter interval. Allowed and forbidden connection checks, with packet evidence, must pass before the original incident resolves and current coverage becomes healthy.

| Cut point | Expected recovered state | Why |
| --- | --- | --- |
| Before transaction commit | Earlier history preserved; interrupted request absent | An incomplete transaction must not become an accepted observation |
| After commit, before response | Completed request preserved exactly once; retry is a duplicate | A lost response does not undo a completed transaction |
| Either cold start | Current coverage unknown; unresolved incident preserved | Saved history cannot prove the network's present condition |

The 30-second sampling limit remains unchanged. Boot and network setup can exceed it, so a fresh rule-only interval precedes the recovery connection checks. Temporary network namespaces and counters are recreated; the saved journal is reopened, not recreated.

## Evidence and acceptance

The controller requires three distinct guest boot identities, two observed QEMU exits caused by SIGKILL, new QEMU processes after both cuts, and the same disk identity throughout. It compares the source snapshot, service configuration, journal identity, exact committed prefixes, incident identity, retry result, and final fresh measurements.

The test does not accept a successful process restart as a full VM cold start. It also does not accept a checksum alone as evidence of correct recovery: the report must satisfy the transaction and incident checks.

The `monitor_powercut` CI job publishes a fixed public artifact only after validation and cleanup. The required `reviewer` job explicitly requires this job and the other prerequisites to succeed, including when a dependency fails or is skipped. Workflow artifacts have a 30-day retention period. Preserve selected milestones separately if longer retention is needed.

Public output contains the source/run identity, host power-cut evidence, before/intermediate/after journal observations, approved policy, boot service configuration, and packet captures. SSH private keys, cloud-init seed contents, disk images, raw console logs, and live database files are excluded.

## Reproduce

Use a clean committed checkout on a disposable x86-64 Linux host with Python 3.11+, Git, curl, OpenSSH client tools, QEMU, `qemu-img`, and `cloud-localds`. Ubuntu packages include `qemu-system-x86 qemu-utils cloud-image-utils openssh-client`.

```sh
mkdir -p work
python3 -I -S -B scripts/network_monitor_powercut_vm.py --output work/monitor-powercut
```

Choose a new output directory. The host controller runs as an ordinary user, pins the Ubuntu image digest and guest SSH host key, and forwards SSH only to loopback. It shares no host directory with the guest. Administrator actions occur only inside the marked disposable guest. macOS is rejected before creating the report or starting a VM.

## Interview explanation

Use this wording after the corresponding actual VM run and downloaded evidence pass verification:

“I tested abrupt loss of a disposable Linux VM at two transaction boundaries. An unfinished save disappeared after recovery; a completed save survived even when its response was lost. Retrying that request did not duplicate it. After each cold start, monitoring stayed unknown until fresh network checks justified recovery.”

## Limits

This is an abrupt **guest power-loss simulation**. The host computer and its physical storage remain powered. QEMU uses explicit `cache=none`, which requests direct disk I/O while honoring guest flushes. The controller verifies those properties before and after boot and immediately before each cut. The guest can change its reported writeback-cache flag; either boolean value is recorded, while direct I/O and enabled flushes remain mandatory. This does not prove physical storage hardware correctly handles power failure. The test does not inject torn sectors, controller faults, disk loss, or every possible interruption inside SQLite's commit implementation.

The precommit case proves an interrupted request was not accepted. It does not, by itself, prove that SQLite replayed a hot rollback journal; some pending changes may still have been in memory when the VM was killed. SQLite's atomic-commit design depends on filesystem and storage behavior, including reliable flushes.

This is a bounded lab with submitted observations, not continuous production monitoring or external alert delivery. Its root-owned guest service is not a separate-account security demonstration. Host-held references help inspect this run but are not independently administered rollback protection. Cleanup removes the disposable VM and temporary credentials without claiming forensic erasure. AWS remains deferred.

## References

- [SQLite atomic commits, interrupted transactions, and storage assumptions](https://www.sqlite.org/atomiccommit.html)
- [SQLite synchronous modes and directory synchronization](https://www.sqlite.org/pragma.html#pragma_synchronous)
- [QEMU disk cache settings](https://www.qemu.org/docs/master/system/invocation.html)
- [QEMU 8.2.2 cache reporting](https://github.com/qemu/qemu/blob/v8.2.2/block/qapi.c) and [guest-controlled virtio writeback setting](https://github.com/qemu/qemu/blob/v8.2.2/hw/block/virtio-blk.c)
- [Existing full VM reboot implementation and evidence](NETWORK_MONITOR_REBOOT.md)
