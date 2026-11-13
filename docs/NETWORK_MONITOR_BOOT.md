# Automatic network monitoring startup after reboot

This drill uses the archived monitor and collector on a disposable Ubuntu VM. The VM has its own disk and synthetic network. The lab is independent of the installed macOS application and uses no real SEC evidence or AWS resources.

## Boot sequence

1. The monitor starts on its own and replays the persisted journal. Its new startup record sets coverage to **unknown** until fresh observations arrive.
2. A topology service recreates the temporary Linux network namespaces and installs the approved firewall rules inside the synthetic router. It checks the rule fingerprint and publishes configuration for the current boot before signalling readiness.
3. The collector is enabled for boot. Its systemd dependency requires the topology service to be active and ready before the collector can start. New observations establish a counter baseline for the new boot. Coverage becomes healthy after fresh canary tests confirm the expected allowed and denied paths.

Systemd `Type=notify` gives the topology service control over when startup is complete. `BindsTo=` with `After=` makes the collector depend on that readiness and on the topology remaining active. The monitor starts independently, so it can report lost visibility when the collector is blocked. [systemd service reference](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html) · [systemd dependencies](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)

## What to verify

| Stage | Expected evidence |
| --- | --- |
| Normal reboot | A new kernel boot ID on the same VM and disk. Systemd recreates the topology and starts the collector. The old history remains an exact prefix of the new journal. Unknown coverage precedes fresh healthy observations. |
| Firewall setup failure | During boot, a deliberately invalid nftables transaction fails inside the synthetic router. Topology fails and the collector never starts for that boot. The independent monitor reports unknown coverage. The saved journal keeps its previous history and accepts no new collector observations. |
| Reboot after removing the fault | The next boot installs the approved rules automatically and resumes collection. Fresh measurements are required before monitoring returns to healthy. |

The host starts the exercise once. It uses SSH to read results and to set or clear the test fault for the next boot. Each postboot inspection observes the boot-managed services. It sends no service-start or topology-setup command.

## Run the orderly reboot drill

From the committed source on a disposable x86-64 Linux host with the [existing reboot prerequisites](NETWORK_MONITOR_REBOOT.md):

```sh
mkdir -p work
python3 -I -S -B scripts/network_monitor_boot_vm.py --output work/network-monitor-boot
```

Use a new output directory. The completed drill writes the stage reports, VM observations, and a SHA-256 manifest under `publish/`. The source-bound report covers three orderly guest reboots.

An interview explanation can follow the failure. When nftables rejects policy setup, systemd never gives the collector a ready dependency. The monitor stays running and reports that it lacks coverage. Once the approved policy is back, a healthy result requires new traffic checks on the new boot.

## Run the abrupt power-cut drill

Use the same Linux host prerequisites and a new output directory.

```sh
mkdir -p work
python3 -I -S -B scripts/network_monitor_boot_powercut_vm.py --output work/network-monitor-boot-powercut
```

1. The collector pauses after publishing the receipt for a committed observation and before allocating the next cycle. The host saves the journal prefix and the receipt identifying the pause boundary.
2. The host sends `SIGKILL` to the QEMU process while the guest is running. It observes SSH go offline, then launches a new QEMU process using the same disk and checks for a different Linux boot ID.
3. On the new boot, systemd starts the monitor and topology, then starts the collector after the approved firewall is ready. The host only inspects results after starting QEMU, with no service start or provisioning command.
4. The verifier checks that saved journal rows match exactly and that the new boot begins with unknown coverage. New observations establish a fresh counter baseline. The first complete canary set must confirm that the user can reach port 8080, the user is blocked from port 9090, and management can reach port 9090 before the monitor reports healthy.

`publish/BEFORE.json` and `publish/RECOVERED.json` contain the journal and service observations. `VM.json` records the termination and cold start. `MANIFEST.json` gives SHA-256 hashes for the four reports.

The host remains powered throughout. This simulates abrupt guest loss at one committed collector boundary. The [journal power-cut drill](NETWORK_MONITOR_POWERCUT.md) covers interruptions around an in-flight journal transaction.
