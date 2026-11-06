# Archived monitoring history after abrupt virtual power loss

This exercise kills the entire owned QEMU process at three archive handoff boundaries and cold-starts the same disk after each interruption. It extends the graceful [archive reboot exercise](NETWORK_MONITOR_ARCHIVE_REBOOT.md) using a fresh, disposable monitoring journal and synthetic network traffic. AWS, the installed Evidence service, the real signing key, and accepted Evidence history are outside the exercise.

## Why the handoff matters

An observation commits to SQLite before its full active segment moves into an archive file. The archive file and database are different objects: a restart must reconcile them without dropping a committed observation or accepting an incomplete file as history. The existing archive implementation supplies three explicit pause points. Only the guarded exercise worker enables them.

| Virtual power cut | Durable state at the boundary | Required recovery |
| --- | --- | --- |
| `archive_staging_durable` | The observation and temporary file contents are saved, but the temporary filename's directory entry has not been synchronized; the database still holds the active prefix | If the temporary file survives, verify its bytes; if it is absent, rebuild it from the committed prefix; then finish the handoff |
| `archive_file_durable` | The final archive file is saved; the database still holds the active prefix | Accept only the exact matching file, then commit its descriptor and remove the active duplicate |
| `archive_metadata_committed` | The archive descriptor is committed and its rows have left the active database; the response has not arrived | Preserve the completed handoff and return the original result on retry |

All three cuts occur **after the observation commits**. Each boundary request is explicitly labeled as a test collection error; it is not presented as a fresh network measurement. That committed record must survive exactly once in every case. The earlier [transaction power-loss exercise](NETWORK_MONITOR_POWERCUT.md) separately tests an observation interrupted before commit.

## Walk through recovery

1. Build the isolated three-zone network, observe approved traffic, then deliberately permit a forbidden path. Save its incident and fill the active journal with real rule observations.
2. Hold the verified history and completed public evidence outside the guest. Arm the next archive boundary. The worker emits its boundary evidence in volatile memory and stops; the host verifies the exact boundary before killing QEMU. The harness does not request guest shutdown or add a persistent-disk flush after arming.
3. Start a new QEMU process with the same disk. Require a new kernel boot identity and automatic startup of the enabled monitor. Startup verifies the saved history, finishes any interrupted handoff, preserves the incident, and records unknown coverage.
4. Retry the exact boundary request. Its original evaluation must return without adding a row or making current coverage fresh. Repeat the experiment at the other two handoff boundaries, retaining the earlier archive bytes throughout.
5. Explicitly rebuild the disposable network, establish a fresh counter baseline, and run allowed and forbidden connection checks. Fresh evidence must justify resolution of the original incident. Continue into another archive segment to prove the recovered writer can keep operating.
6. Stop the writer for a verified offline export. Compare the full history, archive bytes, incident transitions, source inventory, and packet captures before cleaning up the owned services, VM, disk, and temporary access keys.

The monitor starts automatically after boot. The harness supplies bounded observations and explicitly rebuilds the network. This exercise does not enable the continuous collector or its missing-data timer; those are exercised separately. Its final 520 rows include four startup boundaries, three labeled power-cut test records, and 513 submitted network observations. Four 128-row archive files hold 512 rows, leaving eight active rows.

A submitted observation is not automatically valid coverage. If reconstruction takes longer than the existing 30-second sampling limit, the first postboot rules snapshot records unknown coverage with an explicit interval diagnostic. The next suitable observation establishes a fresh baseline; fresh connection checks are still required before the original incident resolves. The test does not extend that sampling limit to obtain a healthy result.

## Reproduce and inspect

Use a clean committed checkout on a disposable x86-64 Linux host with QEMU, cloud-image-utils, OpenSSH client tools, curl, Git, and Python 3.11 or newer:

```sh
mkdir -p work
python3 -I -S -B scripts/network_monitor_archive_powercut_vm.py --output work/monitor-archive-powercut
```

The output must be new. The controller refuses macOS before creating its output. Guest commands require the dedicated install location, root ownership, a matching disposable-instance marker, and QEMU/KVM virtualization. No host directories are shared with the guest.

The `monitor_archive_powercut` CI job runs this controller and publishes its fixed public file allowlist only after validation and cleanup. The required reviewer gate rejects any failed, skipped, cancelled, or missing prerequisite. Downloaded artifacts identify their exact commit, source hashes, workflow run, and attempt. Artifacts expire after 30 days unless preserved separately.

Check the host report for three SIGKILL exits, four distinct kernel boots, distinct VM processes, one retained disk, verified storage settings, and host-held pre-cut references. Check the guest history for one global sequence, unchanged earlier segments, exact boundary-request preservation, historical retry results, unknown startup coverage, and fresh recovery evidence. A green job or a manifest hash alone does not establish those semantics.

## Limits

This simulates sudden power loss to the **guest**. The host computer and physical disk remain powered. QEMU uses `cache=none`; the controller checks direct I/O and enabled flushes. This does not test broken storage hardware, torn sectors, every possible interruption inside a write, physical disk loss, or independently administered backup. See [QEMU's cache settings](https://www.qemu.org/docs/master/system/invocation.html) and [SQLite's storage assumptions](https://www.sqlite.org/atomiccommit.html).

The journal uses SQLite rollback-journal DELETE mode with `synchronous=EXTRA`, including the extra directory synchronization described in [SQLite's synchronous documentation](https://www.sqlite.org/pragma.html#pragma_synchronous). Recovery still depends on the filesystem and storage honoring synchronization requests.

Archive hashes and deterministic replay check consistency against retained references. They are not signed Evidence checkpoints, administrator-resistant custody, or a guarantee of unlimited retention. The guest monitor runs as root for this isolated lab; it does not establish the real application's separate-account boundary. Cleanup does not claim forensic erasure.

## Interview explanation

Use this explanation after the actual VM run and downloaded artifact pass verification:

“I tested archived monitoring history through three abrupt Linux VM power cuts. Each cut targeted a different point in the database-to-file handoff. On cold start, the monitor verified its history, completed an interrupted handoff when necessary, and kept the original incident open with unknown coverage. Retrying a committed request returned its original result without duplicating it. Fresh network checks were required before recovery, and the journal then continued into another archive segment. This was a disposable guest-power-loss simulation, not a physical storage power-failure test.”
