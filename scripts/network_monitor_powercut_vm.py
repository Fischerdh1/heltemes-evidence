"""Cut power to an owned disposable QEMU guest at two journal boundaries."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitor_reboot_vm as reboot

require, timestamp = reboot.require, reboot.timestamp
GUEST_ROOT = reboot.GUEST_ROOT
GUEST_REPORT = "/var/lib/heltemes-powercut-lab/report/publish"
GUEST_SCRIPT = GUEST_ROOT + "/scripts/network_monitor_powercut_guest.py"
GUEST_SOURCE_FILES = (*reboot.SOURCE_FILES[:-1], "scripts/network_monitor_powercut_guest.py")
SOURCE_FILES = (*GUEST_SOURCE_FILES, "scripts/network_monitor_reboot_vm.py", "scripts/network_monitor_powercut_vm.py")
GUEST_FILES = ("BEFORE.json", "AFTER_BEFORE.json", "AFTER.json", "APPROVED_POLICY.json", "monitor.service",
               *(name for phase in ("before", "after") for zone in ("user", "app", "management")
                 for name in (phase + "-" + zone + ".pcap", phase + "-" + zone + "-packets.txt")))
PUBLIC_FILES = ("REPORT.json", "VM.json", "SUMMARY.md", *GUEST_FILES)
POINTS = ("before_commit", "after_commit_before_ack")
CACHE = {"writeback": True, "direct": True, "no-flush": False}
REQUEST_IDS = {"before_commit": "powercut-uncommitted", "after_commit_before_ack": "powercut-committed"}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def progress(message):
    print("VM power-cut lab: " + message, file=sys.stderr, flush=True)


def preflight():
    require(sys.platform == "linux" and reboot.platform.machine() in {"x86_64", "amd64"},
            "The virtual power-cut exercise requires a disposable x86-64 Linux host; it does not run on macOS.")
    return reboot.preflight()


def source_identity(root=ROOT, environment=None):
    root = Path(root).resolve()
    identity = reboot.monitoring.source_identity(root, environment)
    for name in SOURCE_FILES[len(reboot.monitoring.SOURCE_FILES):]:
        content = (root / name).read_bytes()
        result = subprocess.run(["git", "-c", f"safe.directory={root}", "-C", str(root),
                                 "show", f"{identity['commit']}:{name}"], capture_output=True, timeout=30)
        require(result.returncode == 0 and content == result.stdout,
                "Power-cut lab source differs from its committed version.")
        identity["source_sha256"][name] = hashlib.sha256(content).hexdigest()
    return identity


def source_archive(root=ROOT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name in GUEST_SOURCE_FILES:
            content = (Path(root) / name).read_bytes()
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.uid, entry.gid, entry.mtime = len(content), 0o644, 0, 0, 0
            archive.addfile(entry, io.BytesIO(content))
    return output.getvalue()


def cache_evidence(blocks):
    require(isinstance(blocks, list), "QEMU block inventory is malformed.")
    matches = [block for block in blocks if isinstance(block, dict) and block.get("device") == "he-monitor-disk"]
    require(len(matches) == 1 and isinstance(matches[0].get("inserted"), dict),
            "QEMU did not expose exactly one owned monitor disk.")
    inserted = matches[0]["inserted"]
    require(inserted.get("drv") == "qcow2" and inserted.get("ro") is False
            and inserted.get("cache") == CACHE, "QEMU disk does not honor the required direct I/O and flush settings.")
    return {"device": "he-monitor-disk", "driver": "qcow2", "read_only": False,
            "requested_cache_mode": "none", "cache": dict(CACHE)}


class DisposableVM(reboot.DisposableVM):
    """Reuse private image/transport ownership; each cut destroys the whole VM process."""
    def __init__(self, tools):
        super().__init__(tools)
        self.boots = []
        self.installed = False

    def launch(self, previous=None):
        require(self.directory is not None and self.process is None and self.qmp is None and self.log is None,
                "A cold boot requires a prepared disk and no live previous VM resources.")
        require((previous is None) is (not self.installed), "Cold boot must retain the already installed disk.")
        self.last_launch_started = time.monotonic() - self.started
        qmp_path = self.directory / "qmp.sock"
        if qmp_path.exists() or qmp_path.is_symlink():
            info = qmp_path.lstat()
            require(stat.S_ISSOCK(info.st_mode) and not qmp_path.is_symlink(), "Unexpected object occupies owned QMP socket.")
            qmp_path.unlink()
        self.log = (self.directory / "qemu.log").open("ab")
        arguments = [self.tools["qemu-system-x86_64"], "-m", "2048", "-smp", "2", "-accel", self.accelerator,
                     "-cpu", "host" if self.accelerator == "kvm" else "max", "-display", "none", "-monitor", "none",
                     "-no-reboot", "-serial", "file:" + str(self.directory / "serial.log"),
                     "-qmp", "unix:" + str(qmp_path) + ",server=on,wait=off",
                     "-drive", "file=" + str(self.directory / "disk.qcow2") + ",id=he-monitor-disk,if=virtio,format=qcow2,cache=none",
                     "-drive", "file=" + str(self.directory / "seed.img") + ",if=virtio,format=raw,readonly=on",
                     "-nic", f"user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{self.port}-:22"]
        self.process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 20
        while not qmp_path.exists() and time.monotonic() < deadline:
            self.require_running()
            time.sleep(0.1)
        require(qmp_path.is_socket(), "The owned VM did not expose its private QMP socket.")
        self.qmp = reboot.QMP(qmp_path, self.started)
        self.kvm_status = self.qmp.command("query-kvm")
        require(self.kvm_status.get("enabled") is (self.accelerator == "kvm"), "QEMU acceleration differs from selected mode.")
        disk_cache = cache_evidence(self.qmp.command("query-block"))
        snapshot, _ = self.wait_boot(timeout=360, previous=previous)
        progress("guest SSH ready; checking clean cloud-init completion")
        result = self.ssh("sudo -n cloud-init status --wait --format json", timeout=360, check=False)
        cloud_init = reboot.cloud_init_status(result, self.redact)
        if not self.installed:
            progress("installing only the allowlisted synthetic lab source")
            self.ssh("sudo -n mkdir -p " + GUEST_ROOT + " && sudo -n tar -xz --no-same-owner -f - -C " + GUEST_ROOT,
                     input=source_archive(), timeout=60)
            self.installed = True
        self.boots.append({"boot_number": len(self.boots) + 1, "snapshot": snapshot,
                           "launch_started_elapsed_seconds": self.last_launch_started,
                           "disk_cache": disk_cache, "qmp_kvm": self.kvm_status,
                           "cloud_init": cloud_init, "source_uploaded": previous is None})
        return snapshot

    def guest(self, stage):
        require(stage in {"before", "arm-before", "inspect-before", "after-before", "arm-after", "inspect-after", "after-after", "cleanup"},
                "Unknown power-cut guest stage.")
        result = self.ssh("sudo -n python3 -I -S -B " + GUEST_SCRIPT + " " + stage + " --token " + self.token,
                          timeout=180)
        require(len(result.stdout) <= 1024 * 1024, "Guest stage metadata exceeds its bound.")
        value = json.loads(result.stdout)
        require(isinstance(value, dict) and value.get("ok") is True, "The guest stage did not succeed.")
        return value

    def reference(self, name):
        require(name in {"BEFORE.json", "AFTER_BEFORE.json"}, "Unknown host-held reference.")
        content = self.ssh("sudo -n cat " + GUEST_REPORT + "/" + name, timeout=15).stdout
        require(len(content) <= 8 * 1024 * 1024, "Guest reference exceeds its size limit.")
        return content

    def power_cut(self, point, boundary):
        require(point in POINTS, "Unknown power-cut boundary.")
        before = self.boot_snapshot()
        require(before is not None, "The guest is unreachable before the power cut.")
        validate_boundary(boundary, point, before["boot_id"])
        recheck = self.guest("inspect-before" if point == "before_commit" else "inspect-after")
        validate_boundary(recheck, point, before["boot_id"])
        require(canonical(recheck["boundary"]) == canonical(boundary["boundary"])
                and recheck["manager"]["InvocationID"] == boundary["manager"]["InvocationID"],
                "The live stopped transaction boundary differs from its host-held reference.")
        self.require_running()
        requested = time.monotonic() - self.started
        process = self.process
        process.kill()  # SIGKILL: no guest shutdown and no QEMU exit/flush handler.
        result = process.wait(timeout=15)
        require(result == -signal.SIGKILL and process.poll() == -signal.SIGKILL,
                "The owned QEMU process did not terminate by the requested SIGKILL.")
        terminated = time.monotonic() - self.started
        self.qmp.close(); self.qmp = None
        self.log.close(); self.log = None
        self.process = None
        outage = self.ssh("true", timeout=8, check=False)
        require(outage.returncode != 0, "SSH unexpectedly remained available after the owned VM was killed.")
        require((self.directory / "disk.qcow2").exists(), "The persistent VM disk disappeared after the power cut.")
        progress(point + ": whole VM killed; cold-starting its retained disk")
        after = self.launch(previous=before)
        evidence = {"point": point, "boundary": boundary, "boundary_recheck": recheck, "before": before, "after": after,
                    "signal": "SIGKILL", "qemu_wait_returncode": result, "old_qemu_reaped": True,
                    "power_cut_elapsed_seconds": requested, "qemu_terminated_elapsed_seconds": terminated,
                    "cold_launch_elapsed_seconds": self.last_launch_started,
                    "ssh_unavailable_observed": True, "new_qemu_process": True, "same_disk": True,
                    "guest_shutdown_requested": False, "qemu_graceful_exit_requested": False}
        validate_power_cut(evidence)
        return evidence

    def export_guest(self):
        result = self.ssh("sudo -n tar -cz -C " + GUEST_REPORT + " -- " + " ".join(GUEST_FILES), timeout=60)
        return extract_guest_export(result.stdout)


def validate_boundary(boundary, point, boot_id):
    require(isinstance(boundary, dict) and boundary.get("ok") is True
            and boundary.get("boot_id") == boot_id, "The pause proof belongs to another guest boot.")
    require(boundary.get("worker_state") == "T" and boundary.get("worker_process_state") == "T"
            and boundary.get("worker_stopped_observed") is True and boundary.get("response_received") is False
            and boundary.get("ready_marker_filesystem") == "tmpfs",
            "The transaction worker is not observably stopped at its volatile boundary.")
    marker = boundary.get("boundary")
    require(isinstance(marker, dict) and marker.get("point") == point and marker.get("boot_id") == boot_id,
            "The paused boundary differs from the requested transaction point.")
    require(marker.get("format") == "heltemes-powercut-boundary" and marker.get("version") == 1
            and marker.get("request_id") == REQUEST_IDS[point], "The boundary request identity is invalid.")
    request = marker.get("request", {})
    require(set(request) == {"command", "request_id", "observation"} and request["command"] == "observe"
            and request["request_id"] == marker["request_id"]
            and marker.get("observation_sha256") == digest(request["observation"]),
            "The exact paused observation does not match its host-held fingerprint.")
    require(type(marker.get("process_id")) is int and marker["process_id"] > 0
            and reboot.TOKEN.fullmatch(marker.get("instance_id", ""))
            and boundary.get("manager", {}).get("MainPID") == marker["process_id"]
            and boundary["manager"].get("NRestarts") == 0
            and boundary["manager"].get("ActiveState") == "active",
            "The stopped process does not match its managed worker identity.")
    count = 5 if point == "before_commit" else 6
    rows = marker.get("database_view_rows", [])
    require(marker.get("in_transaction") is (point == "before_commit")
            and marker.get("accepted_in_memory_count") == count and len(rows) == count + 1,
            "The boundary transaction state or candidate count differs.")
    candidate = rows[-1]
    require(candidate.get("sequence") == count + 1 and candidate.get("request_id") == request["request_id"]
            and candidate.get("request") == {"kind": "observation", "observation": request["observation"]}
            and candidate.get("row_digest") == digest({key: value for key, value in candidate.items() if key != "row_digest"}),
            "The paused candidate row does not match the exact requested transaction.")
    require(marker.get("synchronous") == 3 and marker.get("journal_mode") == "delete",
            "The worker did not read back SQLite EXTRA durability and DELETE journaling.")


def validate_power_cut(value):
    before, after = value["before"], value["after"]
    require(value["point"] in POINTS, "Unknown cut point.")
    validate_boundary(value["boundary"], value["point"], before["boot_id"])
    validate_boundary(value["boundary_recheck"], value["point"], before["boot_id"])
    require(canonical(value["boundary"]["boundary"]) == canonical(value["boundary_recheck"]["boundary"]),
            "The live boundary recheck differs from the host-held pause proof.")
    require(before["boot_id"] != after["boot_id"] and before["qemu_pid"] != after["qemu_pid"],
            "A cold start requires both a new kernel boot and a new QEMU process.")
    require(before["disk_identity"] == after["disk_identity"], "The persistent disk was replaced after abrupt termination.")
    require(value["signal"] == "SIGKILL" and value["qemu_wait_returncode"] == -signal.SIGKILL
            and value["old_qemu_reaped"] is True and value["new_qemu_process"] is True and value["same_disk"] is True,
            "The whole-VM abrupt termination proof is incomplete.")
    require(value["ssh_unavailable_observed"] is True and value["guest_shutdown_requested"] is False
            and value["qemu_graceful_exit_requested"] is False, "The power-cut sequence was not an abrupt guest outage.")
    require(before["observed_elapsed_seconds"] <= value["power_cut_elapsed_seconds"]
            <= value["qemu_terminated_elapsed_seconds"] <= value["cold_launch_elapsed_seconds"] < after["observed_elapsed_seconds"],
            "Power-cut lifecycle evidence is out of order.")


def extract_guest_export(content):
    require(len(content) <= reboot.MAX_EXPORT, "The guest export exceeds its size limit.")
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
        entries = archive.getmembers()
        require(len(entries) == len(GUEST_FILES) and {entry.name for entry in entries} == set(GUEST_FILES),
                "The guest export inventory differs from the fixed public allowlist.")
        require(all(entry.isfile() and entry.size <= 8 * 1024 * 1024 for entry in entries)
                and sum(entry.size for entry in entries) <= reboot.MAX_EXPORT, "The guest export has unsafe or oversized entries.")
        files = {entry.name: archive.extractfile(entry).read() for entry in entries}
    require(not any(b"PRIVATE KEY" in value or b"/Users/" in value for value in files.values()),
            "The public guest export includes a private marker.")
    return files


def validate_preserved_history(references, files, source, cuts):
    require(set(references) == {"BEFORE.json", "AFTER_BEFORE.json"}
            and all(files[name] == content for name, content in references.items()),
            "A guest reference changed from its exact bytes retained outside the VM.")
    require(len(cuts) == 2 and [cut["point"] for cut in cuts] == list(POINTS), "Both transaction cuts are required.")
    for cut in cuts:
        validate_power_cut(cut)
    before, middle, after = [json.loads(files[name]) for name in ("BEFORE.json", "AFTER_BEFORE.json", "AFTER.json")]
    expected = {name: source["source_sha256"][name] for name in GUEST_SOURCE_FILES}
    require(all(record["source_sha256"] == expected for record in (before, middle, after)),
            "Guest source bytes differ from the host-verified committed source.")
    require(before["boot"]["boot_id"] == cuts[0]["before"]["boot_id"]
            and middle["boot"]["boot_id"] == cuts[0]["after"]["boot_id"] == cuts[1]["before"]["boot_id"]
            and after["boot"]["boot_id"] == cuts[1]["after"]["boot_id"], "Guest and host cold-boot identities disagree.")
    require(cuts[0]["after"]["qemu_pid"] == cuts[1]["before"]["qemu_pid"]
            and cuts[0]["after"]["disk_identity"] == cuts[1]["before"]["disk_identity"],
            "The intermediate VM or retained disk changed outside the verified cuts.")
    require(len({cuts[0]["before"]["qemu_pid"], cuts[0]["after"]["qemu_pid"], cuts[1]["after"]["qemu_pid"]}) == 3,
            "The exercise did not observe three distinct QEMU process lifetimes.")
    original, first = before["journal"], middle["journal"]
    automatic, final = after["automatic_start"]["journal"], after["journal"]
    journals = (original, first, automatic, final)
    require(all(canonical(journal["identity"]) == canonical(original["identity"])
                and canonical(journal["approved_policy"]) == canonical(original["approved_policy"]) for journal in journals),
            "Persistent journal identity or approved policy was replaced.")
    require([len(journal["rows"]) for journal in journals] == [5, 6, 8, 11],
            "The committed history sizes differ from the two-cut recovery sequence.")
    require(canonical(first["rows"][:5]) == canonical(original["rows"])
            and canonical(automatic["rows"][:6]) == canonical(first["rows"])
            and canonical(final["rows"][:8]) == canonical(automatic["rows"]),
            "A cold boot changed, removed, or repeated its previously accepted history.")
    for index, prior in enumerate((before, middle)):
        marker = cuts[index]["boundary"]["boundary"]
        require(canonical(marker["database_view_rows"][:-1]) == canonical(prior["journal"]["rows"])
                and marker["process_id"] == prior["final_status"]["process_id"]
                and marker["instance_id"] == prior["final_status"]["instance_id"]
                and cuts[index]["boundary"]["manager"]["InvocationID"] == prior["manager"]["InvocationID"],
                "The host-held transaction candidate belongs to another history or worker instance.")
    committed_boundary = cuts[1]["boundary"]["boundary"]
    require(canonical(automatic["rows"][:7]) == canonical(committed_boundary["database_view_rows"]),
            "The unacknowledged committed row differs from its exact host-held candidate.")
    require(all(row["request_id"] != REQUEST_IDS["before_commit"] for row in final["rows"])
            and sum(row["request_id"] == REQUEST_IDS["after_commit_before_ack"] for row in final["rows"]) == 1,
            "The interrupted request was accepted or the committed request was lost or duplicated.")
    require(canonical(middle["automatic_start"]["journal"]) == canonical(first),
            "The first cold boot changed history after its automatic-start inspection.")
    critical_id = before["critical_incident_id"]
    for prior, record, journal in ((before, middle, first), (middle, after, automatic)):
        auto, status = record["automatic_start"], record["automatic_start"]["status"]
        manager = auto["manager"]
        require(auto["no_manual_service_start"] is True
                and status["current_evaluation"]["status"] == "unknown"
                and status["current_evaluation"]["phase"] == "monitor_restart"
                and status["committed_count"] == len(journal["rows"])
                and journal["rows"][-1]["request"]["kind"] == "restart"
                and journal["rows"][-1]["evaluation"]["status"] == "unknown",
                "Automatic startup did not preserve an unknown coverage boundary.")
        require(manager["ActiveState"] == "active" and manager["UnitFileState"] == "enabled"
                and manager["NRestarts"] == 0 and manager["MainPID"] == status["process_id"]
                and manager["InvocationID"] != prior["manager"]["InvocationID"]
                and status["instance_id"] != prior["final_status"]["instance_id"],
                "The enabled worker did not automatically start a new verified boot instance.")
        require(record["critical_incident_id"] == critical_id
                and any(alert["id"] == critical_id and alert["state"] == "open" for alert in status["alerts"]),
                "The original unresolved critical incident was lost during boot.")
        require(all(record["storage"][key] == before["storage"][key] for key in ("target", "source", "fstype", "uuid"))
                and record["volatile_markers_absent"] is True, "Persistent or volatile boot storage proof differs.")
    retry = after["lost_ack_retry"]
    response = retry["response"]
    require(canonical(retry["request"]) == canonical(committed_boundary["request"])
            and retry["history_unchanged"] is True and response["ok"] is True
            and response["duplicate"] is True and response["result_is_historical"] is True
            and response["committed_sequence"] == 7 and response["evaluation"] == automatic["rows"][6]["evaluation"]
            and response["current_status"]["committed_count"] == 8
            and response["current_status"]["current_evaluation"]["status"] == "unknown",
            "The exact lost-acknowledgement retry was not historical and idempotent.")
    require(after["final_status"]["current_evaluation"]["status"] == "healthy"
            and final["rows"][-1]["sample"]["phase"] == "after_canaries"
            and not any(alert["severity"] != "info" and alert["state"] == "open" for alert in after["final_status"]["alerts"]),
            "Fresh network observations did not establish healthy recovery.")
    resolved = [event for event in final["events"] if event["key"] == "forbidden_path_open:user->app:9090" and event["action"] == "resolved"]
    require(len(resolved) == 1 and resolved[0]["sequence"] == 11 and resolved[0]["phase"] == "after_canaries",
            "The original incident resolved before fresh recovery evidence.")
    require(all(record["unit_sha256"] == hashlib.sha256(files["monitor.service"]).hexdigest() for record in (before, middle, after)),
            "The enabled worker unit changed across the cuts.")


def run(output):
    tools = preflight()
    source = source_identity()
    destination = reboot.monitoring.base.new_output(output)
    staging = destination / "staging"
    staging.mkdir(mode=0o700)
    vm = DisposableVM(tools)
    report = {"format": "heltemes-network-monitor-powercut-lab", "version": 1, "ok": False,
              "started_at_utc": timestamp(), "source": source,
              "scope": {"synthetic_only": True, "aws_deployed": False, "real_evidence_inputs": False,
                        "abrupt_guest_power_loss_simulated": True, "full_guest_cold_starts": 2,
                        "physical_host_power_loss_tested": False, "host_storage_remained_powered": True,
                        "torn_sector_or_device_flush_failure_tested": False,
                        "administrator_resistant_storage": False, "continuous_monitoring": False}}
    evidence, files, references = {}, {}, {}
    step = "preparing pinned image and private boot media"
    progress(step + "; selected accelerator=" + vm.accelerator)
    try:
        evidence["image"] = {"url": reboot.IMAGE_URL, "sha256": reboot.IMAGE_SHA256}
        evidence["virtualization"] = vm.prepare()
        step = "booting and provisioning disposable guest"
        progress(step); vm.launch()
        step = "saving initial incident and committed history"
        progress(step)
        stages = {"before": vm.guest("before")}
        references["BEFORE.json"] = vm.reference("BEFORE.json")
        cuts = []
        for point, arm, after_stage, reference in (
                ("before_commit", "arm-before", "after-before", "AFTER_BEFORE.json"),
                ("after_commit_before_ack", "arm-after", "after-after", None)):
            step = "stopping the worker exactly at " + point
            progress(step)
            boundary = vm.guest(arm)
            step = "cutting the whole VM and cold-starting at " + point
            progress(step)
            cuts.append(vm.power_cut(point, boundary))
            step = "checking automatic recovery after " + point
            progress(step)
            stages[after_stage] = vm.guest(after_stage)
            if reference is not None:
                references[reference] = vm.reference(reference)
        evidence.update({"boots": vm.boots, "cuts": cuts, "guest_stages": stages,
                         "references_held_outside_guest": True,
                         "reference_sha256": {name: hashlib.sha256(value).hexdigest() for name, value in references.items()}})
        step = "exporting and comparing exact preserved transactions"
        progress(step); files = vm.export_guest()
        validate_preserved_history(references, files, source, cuts)
        step = "cleaning the guest service and synthetic state"
        progress(step); evidence["guest_cleanup"] = vm.guest("cleanup")
        require(source_identity() == source, "Power-cut lab source changed during execution.")
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        report["error"] = step + ": " + vm.redact(error).replace(str(destination), "<report>")
    finally:
        try:
            progress("stopping the owned VM and removing private credentials and disk")
            evidence["cleanup"] = vm.cleanup()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            evidence["cleanup"] = {"ok": False, "error": vm.redact(error)}
        report["completed_at_utc"] = timestamp()
    report["ok"] = "error" not in report and evidence["cleanup"]["ok"]
    report["cleanup"] = evidence["cleanup"]
    reboot.write_json(staging / "REPORT.json", report)
    if not report["ok"]:
        raise RuntimeError("Virtual power-cut exercise failed: " + report.get("error", "Private VM cleanup failed."))
    for name, content in files.items():
        (staging / name).write_bytes(content)
    reboot.write_json(staging / "VM.json", evidence)
    (staging / "SUMMARY.md").write_text(f"""# HELTEMES Evidence abrupt virtual power-cut exercise

Source commit `{source['commit']}`. Completed {report['completed_at_utc']}.

The host killed the whole owned QEMU process with SIGKILL at two explicitly observed SQLite transaction boundaries. It cold-started a new VM process on the same disposable disk each time. Three QEMU process identities and three Linux kernel boot identities were recorded. No guest shutdown or QEMU graceful-exit command was used for either cut.

At the first cut, the worker had inserted a candidate row but had not committed it. The original five accepted rows survived; the uncommitted request was absent. Automatic startup appended row six with unknown monitoring coverage and the same unresolved incident. At the second cut, SQLite had committed row seven but the caller had not received acknowledgement. That exact host-recorded row survived once. Automatic startup appended row eight; retrying the exact request returned its original result without adding a duplicate or claiming current health. Fresh rules, a valid counter interval, and all three network canaries were required for healthy recovery at row eleven.

Inspect VM.json for the stopped transaction worker, live boundary recheck, SIGKILL wait result, cold boots, verified cache settings, references retained outside the VM, and cleanup evidence. BEFORE.json, AFTER_BEFORE.json, and AFTER.json preserve the journal and network observations. Before/after packet captures substantiate the actual network checks.

The journal uses SQLite DELETE journaling with synchronous=EXTRA, verified by readback. QEMU cache=none uses direct host I/O and honors flushes. The host computer and physical storage remained powered. This is an abrupt guest-power-loss simulation, not a physical host power-failure, torn-sector, failed-device-flush, or hostile-administrator rollback test. The precommit boundary does not by itself establish that a hot journal needed replay. This bounded exercise does not install a continuous production collector. AWS and real Evidence keys/history were outside the exercise.

The guest service and synthetic networks were cleaned up; the final VM process stopped and private SSH credentials, seed image, and disposable disk were removed before publication.
""")
    reboot.write_json(staging / "MANIFEST.json", {name: reboot.sha256_file(staging / name) for name in PUBLIC_FILES})
    publish = destination / "publish"
    publish.mkdir(mode=0o755)
    for name in (*PUBLIC_FILES, "MANIFEST.json"):
        (staging / name).rename(publish / name)
        (publish / name).chmod(0o644)
    destination.chmod(0o755)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="New report directory with an existing parent")
    arguments = parser.parse_args()
    try:
        report = run(arguments.output)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, "VM power-cut lab stopped: " + str(error) + "\n")
    print(json.dumps({"ok": report["ok"], "source_commit": report["source"]["commit"], "cleanup": report["cleanup"]}, indent=2))


if __name__ == "__main__":
    main()
