# Automatic collection and missing-data detection

This bounded exercise adds an independent collector to the disposable Linux network lab. The collector measures installed firewall rules, counters, and real connection attempts every five seconds. The monitor evaluates those observations and separately checks a 20-second freshness deadline. A running collector process is not proof that new observations are arriving.

The exercise uses synthetic traffic and new disposable monitoring state. AWS, the installed Evidence application, its real signing key, and trusted history are outside this work.

## What changes

Two enabled Linux services have different responsibilities. The collector performs measurements; the monitor owns the transactional journal and evaluates freshness. Both run as root inside this guarded disposable lab: this is process separation, not a demonstration of separate-account authority.

The collector uses a monotonic clock for its five-second schedule and skips missed slots instead of sending a burst. It reserves unique probe ports durably before use so a restart cannot reuse an earlier packet identity. Each committed observation has a request identifier and a receipt linking the producer process, actual measurements, and journal sequence.

The monitor's opt-in `--freshness-seconds 20` mode ticks even when no client is connected. If the deadline expires, it records one `collector_missing` boundary for that outage and reports current coverage as unknown. The existing incident stays open. Status requests, duplicate observations, rejected data, and stale or future timestamps cannot renew freshness. Delayed observations consume their remaining freshness window rather than receiving a new full window on arrival. Slow incomplete requests have a bounded read deadline and cannot suppress the idle check indefinitely.

Startup is unknown until fresh measurements establish coverage. A full journal or a persistence failure also reports unknown; the service does not reset or overwrite its history. This exercise retains the existing 256-row cap. Earlier exercises keep their original behavior because freshness is explicitly enabled only for this service.

## Walk through the exercise

1. **Establish healthy coverage automatically.** The collector first samples a rule/counter reference, then checks the allowed application path, denied user-to-management endpoint, and allowed management path. The harness does not submit observations.
2. **Introduce an incorrect permit.** A lab rule allows users to reach the restricted application endpoint. The collector's next measurements detect forbidden access and open a critical incident.
3. **Freeze the collector.** The harness pauses it at an observed idle boundary. Its process still exists, but it produces no measurements. The monitor continues with the same process and instance identity.
4. **Detect silence without being asked.** The harness sends no monitor requests during a 22-second wait. The monitor must commit the missing-data gap before the first subsequent inspection. Coverage becomes unknown and the same critical incident remains open.
5. **Repair the rule while collection is silent.** The corrected rule does not change accepted history or close the incident. There is still no fresh evidence of the network's condition.
6. **Recover through the supervisor.** The stopped collector is killed; systemd starts its replacement using `Restart=on-failure`. A different collector identity establishes a fresh reference and completes all three canaries. Only then may the original incident resolve and coverage become healthy.

The report records the actual timing, journal sequences, service identities, restart count, incident identity, and packet evidence. Acceptance depends on those observations, not merely on the final status or a checksum.

## Evidence and repetition

The `monitor_automatic` CI job runs on a disposable x86-64 Linux host and boots a digest-pinned Ubuntu image. It uses an isolated, pinned SSH connection and shares no host directory with the guest. The host runs without administrator privileges; privileged network changes occur only inside the marked guest. macOS is refused before creating output or a VM.

From a clean committed checkout on a disposable Linux host with Python 3.11+, Git, curl, OpenSSH client tools, QEMU, `qemu-img`, and `cloud-localds`:

```sh
mkdir -p work
python3 -I -S -B scripts/network_monitor_automatic_vm.py --output work/monitor-automatic
```

Choose a new output directory. The fixed 14-file public artifact includes `REPORT.json`, `VM.json`, `GUEST.json`, approved policy, two unit definitions, three packet captures and text summaries, a summary, and manifest. `GUEST.json` contains journal observations and collector receipts. Completed capture files are flushed and fingerprinted before export; the host retains the completed guest report and verifies its exact bytes and source hashes.

The required reviewer job explicitly refuses acceptance if this job or another prerequisite fails, is skipped, or is missing. Artifacts expire after 30 days under this workflow's retention setting. VM disks, access credentials, live database files, and raw private logs are excluded. The guest services, network, and owned VM are cleaned up before publication.

## Interview explanation

Use this after an actual run and its downloaded evidence pass inspection:

“I separated network collection from monitoring. I froze the collector while leaving the monitor running. The monitor independently detected missing observations, kept the unresolved incident open, and required fresh network measurements after automatic collector restart before reporting recovery. I verified the behavior with service identities, a transactional journal, and packet captures.”

## Limits and next work

This is bounded unattended monitoring, not a continuously operated production service. The new units are configured for boot, but this exercise stays within one guest boot and does not demonstrate reconstructing the collector's temporary network after a reboot. Existing reboot and virtual power-loss jobs continue testing their own scenarios separately.

The lab does not implement history rotation, an independently administered monitoring host, separate-account isolation, or external notification delivery. Source timestamps come from the same guest clock and are not independently trusted time. The freshness decision uses monotonic elapsed time, but clock jumps can cause supplied timestamps to be rejected. A local administrator can alter the journal and its references; this lab is not administrator-resistant evidence custody.

The next operational expansion would need bounded history archiving and longer-run tests. Collector/network boot reconstruction and external notification delivery each need their own failure and recovery evidence. AWS remains deferred.

## References

- [Python monotonic clock](https://docs.python.org/3/library/time.html#time.monotonic)
- [systemd service restart behavior](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
- [Existing restart-safe journal](NETWORK_MONITOR_RESTART.md)
- [Existing full reboot exercise](NETWORK_MONITOR_REBOOT.md) and [virtual power-loss exercise](NETWORK_MONITOR_POWERCUT.md)
