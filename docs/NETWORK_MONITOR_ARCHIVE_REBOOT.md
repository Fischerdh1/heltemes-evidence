# Archived monitoring history through a full Linux VM reboot

This exercise tests the archived monitoring format across a graceful reboot of a disposable Ubuntu guest. It uses synthetic network traffic and a new monitoring journal. AWS, the real SEC archive, the original signing key, and accepted Evidence trust history remain outside the exercise.

## Recovery sequence

1. The collector takes 270 real firewall observations. Periodic connection checks open a deliberate forbidden-access incident. Older rows move into two 128-row archive segments, and the active database retains the remaining suffix.
2. The collector stops at a clean boundary with no pending request. The enabled monitor stops for a verified offline history export. The host holds the original report, history, segments, policy, units, and six capture files before requesting reboot.
3. Linux reboots. The controller requires a changed kernel boot ID, a guest-triggered QEMU reset, and an observed SSH outage while the same QEMU process and disk remain in use.
4. The enabled monitor starts automatically. It verifies the original archived history and records a startup boundary with unknown coverage. The unresolved incident keeps its identity. Replaying an already archived request returns its original result without adding a row or making coverage fresh.
5. The harness confirms the old synthetic network disappeared, explicitly rebuilds it with the approved rules, and starts the collector. The collector preserves its durable cycle and source-port allocation but uses a new boot-bound configuration and instance identity. Two rule-only samples establish the new counter baseline. Fresh connection checks must pass before the old incident resolves.
6. Collection continues through cycle 400. A third segment seals after reboot without replacing the first two. The final live status is captured, the writer stops, and a verified offline export must match that exact head.
7. The controller compares all preboot public bytes with its held copies, verifies the full history and receipt sequence, then removes owned services, networks, VM, private access keys, seed, and disk before publication.

The complete journal normally contains 402 rows: 400 observations and two startup boundaries. If reconstruction exceeds the monitor's missing-data deadline, one explicit `collector_missing` row records the additional gap. That row reports unknown coverage; it is not a fabricated observation. Monotonic clocks and packet counter identities are not treated as continuous across boots.

## Persistent state and runtime state

The archive and collector allocation live under the disposable guest's `/var/lib/heltemes-archive-reboot-lab`. Runtime resources are recreated at startup. Linux service configuration distinguishes persistent state from service runtime directories; [systemd's execution documentation](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html) describes that lifetime difference.

The monitor is enabled for boot. The collector is started explicitly after the test harness rebuilds the synthetic network. The evidence therefore supports automatic monitor startup and verified archive recovery, not automatic topology provisioning or unattended collector startup.

A configuration from an older boot is refused. A previously committed pending request can still be acknowledged as an exact historical duplicate. A stale, uncommitted request cannot be relabeled as fresh evidence after restart. The exercise reuses the existing archive format; it does not migrate or reset an existing Evidence installation.

## Run and review

On a disposable x86-64 Linux host with QEMU, cloud-image-utils, OpenSSH client, curl, and Git:

```sh
mkdir -p work
python3 -I -S -B scripts/network_monitor_archive_reboot_vm.py --output work/monitor-archive-reboot
```

The controller refuses macOS before creating an output directory. The output must be new. The separate `monitor_archive_reboot` CI job runs the same command; the required reviewer gate explicitly rejects failed, skipped, cancelled, or missing prerequisites.

| Evidence | What to check |
| --- | --- |
| `REPORT.json`, `VM.json` | Exact source/run identity, original preboot fingerprints, changed boot ID, guest reset, same disk, scope, and cleanup |
| `BEFORE.json`, `AFTER.json` | Service observations, collector receipts, incident identity, retry result, and reconstruction steps |
| `BEFORE-HISTORY.json`, `AFTER-HISTORY.json` | Same archive identity, byte-equivalent preboot prefix, one global sequence, verified rows and events |
| Three `archive-segment-*.json` files | Original first two segments and the third segment created after reboot |
| Twelve capture files | Three interface captures and decoded packet text for each boot |
| `APPROVED_POLICY.json`, two unit files | Approved network policy and actual service definitions |
| `MANIFEST.json` | Fingerprint of every other public file |

All archives remain bounded by row, byte, segment, and probe budgets. This test does not establish indefinite production operation, archive handoff durability under sudden power loss, off-device backup, administrator-resistant custody, separate-account isolation, or external alert delivery. A graceful reboot and an abrupt virtual power cut are different tests.

## Interview explanation

“I tested an archived monitoring journal through a full Linux VM reboot. I held the original archive bytes outside the guest, verified that the same disk reopened under a new kernel boot, and checked that automatic startup preserved the unresolved incident while reporting unknown coverage. Fresh network checks were required before recovery. Collection then continued into a third archive segment with the original global history and port allocation intact. The test uses a disposable synthetic network and explicit network reconstruction.”
