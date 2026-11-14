# Durable alert delivery in the network lab

The monitor already records when an incident opens and resolves. This drill follows those committed events into a separate alert receiver inside the same disposable Ubuntu VM. It uses the [segmented network](NETWORK_SEGMENTATION.md) and real TCP probes against its synthetic services.

## How delivery works

The sender reads committed monitor events and saves items awaiting delivery in a SQLite queue. It sends each item to a loopback HTTP receiver using a stable event ID. That ID stays the same across retries and sender restarts. The sender keeps the item pending until it verifies an acknowledgement for the same ID and payload digest.

A fresh shared secret authenticates the request and acknowledgement with HMAC. The receiver checks the request before committing it. A repeated request with the same ID and content can receive another acknowledgement without creating a second accepted event. An ID reused with different content is rejected. This gives the lab at-least-once delivery attempts and one stored event per ID.

## Follow the failure and recovery

1. The lab temporarily changes its firewall so traffic from the user zone can reach port 9090 in the application zone. A successful probe on that path opens an incident in the monitor journal.
2. The sender tries to deliver the opening event while the receiver is offline. The journal still has the incident, and the sender keeps its delivery queued.
3. The receiver starts, commits the event, and drops the acknowledgement on purpose. The receiver now has the alert while the sender still needs proof that it arrived.
4. The drill restarts the sender. It reads the saved queue and retries the same event ID. The receiver recognizes the duplicate and acknowledges it. The sender confirms delivery, with one stored opening event on the receiver.
5. The lab restores the approved firewall rules. Fresh probes confirm that the forbidden path is blocked and the monitor records a resolution for the same incident. The receiver stores the resolution as a distinct event. The drill also checks that unauthenticated and tampered requests are rejected.

## Run and inspect the drill

From a committed checkout on a disposable x86-64 Linux host with the [reboot drill prerequisites](NETWORK_MONITOR_REBOOT.md), choose a new output directory.

```sh
mkdir -p work
python3 -I -S -B scripts/network_monitor_alert_delivery_vm.py --output work/alert-delivery
```

| Report | What to check |
| --- | --- |
| `REPORT.json` | Overall result, tested source revision, and disposable VM cleanup. |
| `DELIVERY.json` | Committed monitor events, sender and receiver records, and the checks for offline delivery, lost acknowledgement, restart, and request rejection. |
| `MANIFEST.json` | SHA-256 digests for the two reports. |

Compare the event ID in the sender queue before restart with the receiver's accepted record after retry. Check that the receiver stored one opening event and that the later resolution references the same incident. A successful retry shows that the message reached the receiver. The receiver's event inventory tells you whether the retry created a duplicate.

The sender and receiver share the guest's trust boundary and communicate over loopback. This drill uses a disposable authentication secret and a local receiver with no external service or recipient. It runs separately from regular CI. AWS, the installed Evidence app, its signing key, and its trusted history remain outside the exercise.
