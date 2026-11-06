"""Verify archived monitoring through three abrupt disposable-VM power cuts."""
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
from scripts import network_monitor_powercut_vm as powercut
from scripts import network_monitor_archive as archive
from scripts import network_monitor_store as store

require, timestamp = reboot.require, reboot.timestamp
GUEST_ROOT = reboot.GUEST_ROOT
GUEST_REPORT = "/var/lib/heltemes-archive-powercut-lab/report/publish"
GUEST_SCRIPT = GUEST_ROOT + "/scripts/network_monitor_archive_powercut_guest.py"
GUEST_SOURCE_FILES = (*reboot.SOURCE_FILES[:-1], "scripts/network_monitor_archive.py",
    "scripts/network_monitor_powercut_guest.py", "scripts/network_monitor_archive_powercut_guest.py")
SOURCE_FILES = (*GUEST_SOURCE_FILES, "scripts/network_monitor_reboot_vm.py",
    "scripts/network_monitor_powercut_vm.py", "scripts/network_monitor_archive_powercut_vm.py")
STAGES = ("before", "after-staging", "after-file", "after")
REPORT_FILES = tuple(name for stage in STAGES for name in (stage.upper() + ".json", stage.upper() + "-HISTORY.json"))
SEGMENT_FILES = tuple(f"archive-segment-{n:06d}.json" for n in range(1, 5))
CAPTURE_FILES = tuple(phase + "-" + zone + suffix for phase in ("before", "after")
    for zone in ("user", "app", "management") for suffix in (".pcap", "-packets.txt"))
COMMON_FILES = ("APPROVED_POLICY.json", "monitor.service")
GUEST_FILES = (*REPORT_FILES, *COMMON_FILES, *CAPTURE_FILES, *SEGMENT_FILES)
PUBLIC_FILES = ("REPORT.json", "VM.json", "SUMMARY.md", *GUEST_FILES)
POINTS = ("archive_staging_durable", "archive_file_durable", "archive_metadata_committed")
LABELS = ("staging", "file", "metadata")
REQUEST_IDS = dict(zip(POINTS, ("archive-powercut-staging", "archive-powercut-file", "archive-powercut-metadata")))
CACHE = powercut.CACHE
MAX_FILE, MAX_EXPORT = 32 * 1024 * 1024, 128 * 1024 * 1024
CRITICAL = "forbidden_path_open:user->app:9090"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def progress(message):
    print("Archive power-cut VM: " + message, file=sys.stderr, flush=True)


def preflight():
    require(sys.platform == "linux" and reboot.platform.machine() in {"x86_64", "amd64"},
            "The archive power-cut exercise requires a disposable x86-64 Linux host; it does not run on macOS.")
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


cache_evidence = powercut.cache_evidence
validate_cache_record = powercut.validate_cache_record


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
        settled_cache = cache_evidence(self.qmp.command("query-block"))
        if not self.installed:
            progress("installing only the allowlisted synthetic lab source")
            self.ssh("sudo -n mkdir -p " + GUEST_ROOT + " && sudo -n tar -xz --no-same-owner -f - -C " + GUEST_ROOT,
                     input=source_archive(), timeout=60)
            self.installed = True
        self.boots.append({"boot_number": len(self.boots) + 1, "snapshot": snapshot,
                           "launch_started_elapsed_seconds": self.last_launch_started,
                           "disk_cache": disk_cache, "disk_cache_after_boot": settled_cache, "qmp_kvm": self.kvm_status,
                           "cloud_init": cloud_init, "source_uploaded": previous is None})
        return snapshot

    def guest(self, stage):
        require(stage in {*STAGES, *("arm-" + label for label in LABELS), *("inspect-" + label for label in LABELS), "cleanup"},
                "Unknown power-cut guest stage.")
        result = self.ssh("sudo -n python3 -I -S -B " + GUEST_SCRIPT + " " + stage + " --token " + self.token,
                          timeout=600, check=False)
        if result.returncode:
            error = (result.stderr or result.stdout).decode(errors="replace")[-12 * 1024:]
            raise RuntimeError("Archive power-cut guest operation failed: " + self.redact(error).strip())
        require(len(result.stdout) <= MAX_FILE, "Guest stage metadata exceeds its bound.")
        value = json.loads(result.stdout)
        require(isinstance(value, dict) and value.get("ok") is True, "The guest stage did not succeed.")
        return value

    def export_guest(self, stage=None):
        names = reference_names(stage) if stage else GUEST_FILES
        result = self.ssh("sudo -n tar -cz -C " + GUEST_REPORT + " -- " + " ".join(names), timeout=60)
        return extract_guest_export(result.stdout, names)

    def power_cut(self, point, boundary):
        require(point in POINTS, "Unknown power-cut boundary.")
        before = self.boot_snapshot()
        require(before is not None, "The guest is unreachable before the power cut.")
        validate_boundary(boundary, point, before["boot_id"])
        recheck = self.guest("inspect-" + LABELS[POINTS.index(point)])
        validate_boundary(recheck, point, before["boot_id"])
        require(canonical(recheck["boundary"]) == canonical(boundary["boundary"])
                and recheck["manager"]["InvocationID"] == boundary["manager"]["InvocationID"],
                "The live stopped transaction boundary differs from its host-held reference.")
        self.require_running()
        disk_cache = cache_evidence(self.qmp.command("query-block"))
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
                    "disk_cache_before_cut": disk_cache,
                    "signal": "SIGKILL", "qemu_wait_returncode": result, "old_qemu_reaped": True,
                    "power_cut_elapsed_seconds": requested, "qemu_terminated_elapsed_seconds": terminated,
                    "cold_launch_elapsed_seconds": self.last_launch_started,
                    "ssh_unavailable_observed": True, "new_qemu_process": True, "same_disk": True,
                    "guest_shutdown_requested": False, "qemu_graceful_exit_requested": False}
        validate_power_cut(evidence)
        return evidence


def replay_rows(rows, approved):
    require(isinstance(rows, list) and 0 < len(rows) <= 2048, "History row count is outside its bound.")
    engine = archive.StreamingMonitor(approved)
    previous, ids, events = "0" * 64, set(), []
    for sequence, row in enumerate(rows, 1):
        require(isinstance(row, dict) and set(row) == archive.ROW_KEYS,
                "History row shape differs.")
        request, sample = row["request"], row["sample"]
        require(type(row["sequence"]) is int and type(sample["sequence"]) is int
                and row["sequence"] == sequence and sample["sequence"] == sequence
                and row["previous_digest"] == previous and row["request_id"] not in ids,
                "Global sequence, prior fingerprint, or request identity differs.")
        require(set(request) == {"kind", "observation"} and request["kind"] in {"restart", "observation"},
                "Invalid committed request kind.")
        archive.ArchiveJournal._validate_observation(request["observation"])
        require(set(sample) == store.OBSERVATION_KEYS | {"sequence", "elapsed_seconds"}
                and all(sample[key] == request["observation"][key] for key in store.OBSERVATION_KEYS),
                "Committed sample differs from its request.")
        request_id = row["request_id"]
        require(isinstance(request_id, str) and ((request["kind"] == "restart"
                and reboot.re.fullmatch(r"_restart_[0-9a-f]{32}", request_id)
                and sample["phase"] == "monitor_restart" and sample["ruleset"] is None
                and sample["collection_error"] == "monitor_restarted" and sample["probes"] == [])
                or (request["kind"] == "observation" and store.REQUEST_ID.fullmatch(request_id))),
                "Committed request identity differs.")
        require(engine.observe(sample) == row["evaluation"] and engine.events == row["events"],
                "History differs from deterministic monitoring replay.")
        require(row["row_digest"] == digest({key: row[key] for key in archive.ROW_KEYS - {"row_digest"}}),
                "History fingerprint differs.")
        events.extend(row["events"]); previous = row["row_digest"]; ids.add(request_id)
    return engine, events


def segment_bytes(identity, rows, number):
    prefix = rows[(number - 1) * 128:number * 128]
    require(len(prefix) == 128, "A segment requires its exact full prefix.")
    value = {"format": "heltemes-monitor-archive-journal-segment", "version": 1,
        "database_id": identity["database_id"], "segment_index": number,
        "first_sequence": prefix[0]["sequence"], "last_sequence": prefix[-1]["sequence"],
        "previous_digest": prefix[0]["previous_digest"], "last_digest": prefix[-1]["row_digest"], "rows": prefix}
    return (canonical(value) + "\n").encode()


def descriptor_for(identity, rows, number):
    raw = segment_bytes(identity, rows, number)
    return {"segment_index": number, "first_sequence": (number - 1) * 128 + 1,
        "last_sequence": number * 128, "row_count": 128, "byte_count": len(raw),
        "file_digest": hashlib.sha256(raw).hexdigest(), "last_digest": rows[number * 128 - 1]["row_digest"]}


def validate_identity(identity, approved):
    require(identity["format"] == "heltemes-monitor-archive-journal" and type(identity["version"]) is int and identity["version"] == 1
            and identity["segment_rows"] == 128 and identity["max_rows"] == 2048
            and identity["max_segments"] == 16 and reboot.TOKEN.fullmatch(identity["database_id"])
            and identity["approved_policy_sha256"] == archive.monitor.policy_fingerprint(approved),
            "Archive identity, policy, or bounds differ.")


def validate_file_proof(proof, raw, name):
    require(isinstance(proof, dict) and all(type(proof.get(key)) is int for key in ("mode", "uid", "nlink", "bytes"))
            and proof.get("name") == name and proof.get("mode") == 0o600
            and proof.get("uid") == 0 and proof.get("nlink") == 1
            and proof.get("bytes") == len(raw) and proof.get("sha256") == hashlib.sha256(raw).hexdigest(),
            "Protected archive file differs from its exact committed segment.")


def validate_boundary(boundary, point, boot_id):
    require(point in POINTS and isinstance(boundary, dict) and boundary.get("ok") is True
            and boundary.get("boot_id") == boot_id, "Pause proof belongs to another boundary or boot.")
    require(boundary.get("worker_state") == "T" and boundary.get("worker_process_state") == "T"
            and boundary.get("worker_stopped_observed") is True and boundary.get("response_received") is False
            and boundary.get("ready_marker_filesystem") == "tmpfs", "Archive worker is not stopped at a volatile boundary.")
    marker = boundary["boundary"]; number = POINTS.index(point) + 1; count = number * 128
    require(marker.get("format") == "heltemes-archive-powercut-boundary" and marker.get("version") == 1
            and marker.get("point") == point and marker.get("boot_id") == boot_id
            and marker.get("request_id") == REQUEST_IDS[point], "Boundary identity differs.")
    request = marker["request"]
    require(set(request) == {"command", "request_id", "observation"} and request["command"] == "observe"
            and request["request_id"] == marker["request_id"]
            and marker.get("observation_sha256") == digest(request["observation"]), "Boundary request differs.")
    manager = boundary["manager"]
    require(type(marker.get("process_id")) is int and marker["process_id"] > 0 and reboot.TOKEN.fullmatch(marker.get("instance_id", ""))
            and manager.get("MainPID") == marker["process_id"] and manager.get("NRestarts") == 0
            and manager.get("ActiveState") == "active" and manager.get("UnitFileState") == "enabled"
            and reboot.TOKEN.fullmatch(manager.get("InvocationID", "")), "Stopped worker identity differs.")
    require(marker.get("in_transaction") is False and marker.get("synchronous") == 3
            and marker.get("journal_mode") == "delete" and marker.get("head_sequence") == count,
            "Archive boundary does not follow a durable observation commit.")
    rows = marker["rows"]; validate_identity(marker["identity"], marker["approved_policy"])
    require(len(rows) == count, "Boundary committed row count differs.")
    replay_rows(rows, marker["approved_policy"])
    require(rows[-1]["request_id"] == request["request_id"]
            and rows[-1]["request"] == {"kind": "observation", "observation": request["observation"]}
            and rows[-1]["row_digest"] == marker["head_digest"], "Boundary candidate differs from exact committed request.")
    committed = point == "archive_metadata_committed"
    descriptors = [descriptor_for(marker["identity"], rows, n) for n in range(1, number + int(committed))]
    require(marker["archive_descriptors"] == descriptors and marker["active_sql_rows"] == (0 if committed else 128),
            "Archive handoff metadata does not match the selected boundary.")
    final_count = number - 1 if point == "archive_staging_durable" else number
    require(len(marker["archive_files"]) == final_count, "Boundary archive inventory differs.")
    for index, proof in enumerate(marker["archive_files"], 1):
        validate_file_proof(proof, segment_bytes(marker["identity"], rows, index), f"segment-{index:06d}.json")
    raw = segment_bytes(marker["identity"], rows, number)
    if point == "archive_staging_durable":
        require(marker["final_file"] is None, "Staged archive was already published.")
        validate_file_proof(marker["pending_file"], raw, f"segment-{number:06d}.json.pending")
    else:
        require(marker["pending_file"] is None, "Published archive still has a conflicting pending file.")
        validate_file_proof(marker["final_file"], raw, f"segment-{number:06d}.json")



def validate_power_cut(value):
    before, after = value["before"], value["after"]
    require(value["point"] in POINTS, "Unknown cut point.")
    validate_cache_record(value["disk_cache_before_cut"])
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


def reference_names(stage):
    require(stage in STAGES[:-1], "Unknown pre-cut reference stage.")
    number = STAGES.index(stage)
    return (*REPORT_FILES[:2 * (number + 1)], *COMMON_FILES, *CAPTURE_FILES[:6], *SEGMENT_FILES[:number])


def extract_guest_export(content, names=GUEST_FILES):
    require(len(content) <= MAX_EXPORT, "Guest export exceeds its size bound.")
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as bundle:
        entries = bundle.getmembers()
        require(len(entries) == len(names) and {entry.name for entry in entries} == set(names),
                "Guest export differs from the fixed public allowlist.")
        require(all(entry.isfile() and 0 <= entry.size <= MAX_FILE for entry in entries)
                and sum(entry.size for entry in entries) <= MAX_EXPORT, "Unsafe guest export entry.")
        files = {entry.name: bundle.extractfile(entry).read() for entry in entries}
    require(not any(b"PRIVATE KEY" in raw or b"/Users/" in raw for raw in files.values()),
            "A private marker appeared in the public export.")
    return files


def validate_history(history, files, segment_count):
    require(history.get('history_complete') is True, 'History export is incomplete.')
    rows, identity, approved = history['rows'], history['identity'], history['approved_policy']
    validate_identity(identity, approved)
    engine, events = replay_rows(rows, approved)
    require(history['events'] == events and history['evaluations'] == [r['evaluation'] for r in rows],
            'Exported event or evaluation history differs from its rows.')
    expected = [descriptor_for(identity, rows, n) for n in range(1, segment_count + 1)]
    require(history['archive_descriptors'] == expected and len(rows) // 128 == segment_count,
            'Archive descriptors do not cover the exact archived prefix.')
    for n in range(1, segment_count + 1):
        require(files[SEGMENT_FILES[n - 1]] == segment_bytes(identity, rows, n),
                'Final exported archive changed the committed historical bytes.')
    return engine


def validate_status(status, rows, *, segments, unknown=False):
    count = len(rows); current = rows[-1]
    require(status['committed_count'] == count and status['head_digest'] == current['row_digest']
            and status['current_evaluation'] == current['evaluation'], 'Status differs from committed history.')
    record = status['archives']
    require(record['sealed_segments'] == segments and record['archived_rows'] == segments * 128
            and record['active_rows'] == count - segments * 128
            and record['capacity_remaining'] == 2048 - count and record['persistence_error'] is None,
            'Status archive accounting differs.')
    if unknown:
        require(current['request']['kind'] == 'restart' and current['evaluation']['status'] == 'unknown'
                and current['sample']['phase'] == 'monitor_restart', 'Cold-start coverage was not unknown.')


def check_incident(status, incident, state='open'):
    matches = [item for item in status['alerts'] if item['key'] == CRITICAL and item['state'] == state]
    require(len(matches) == 1 and matches[0]['id'] == incident, 'Original critical incident identity or state differs.')


def validate_guest(references, files, source, cuts):
    require(set(references) == set(STAGES[:-1]), 'Host-held reference stages differ.')
    for stage, held in references.items():
        require(set(held) == set(reference_names(stage)) and all(files[n] == raw for n, raw in held.items()),
                'Pre-cut public bytes changed from the original host-held reference.')
    require(len(cuts) == 3 and [cut['point'] for cut in cuts] == list(POINTS), 'Three archive handoff cuts are required.')
    for cut in cuts:
        validate_power_cut(cut)
    for first, second in zip(cuts, cuts[1:]):
        require(first['after']['boot_id'] == second['before']['boot_id']
                and first['after']['qemu_pid'] == second['before']['qemu_pid']
                and first['after']['disk_identity'] == second['before']['disk_identity'],
                'Guest or disk changed outside the verified cold starts.')
    boots = [cuts[0]['before'], *(cut['after'] for cut in cuts)]
    require(len({boot['boot_id'] for boot in boots}) == len({boot['qemu_pid'] for boot in boots}) == 4,
            'Four distinct Linux boots and QEMU process lifetimes are required.')
    require(all(boot['disk_identity'] == boots[0]['disk_identity'] for boot in boots), 'Persistent disk identity changed.')
    reports = [json.loads(files[stage.upper() + '.json']) for stage in STAGES]
    histories = [json.loads(files[stage.upper() + '-HISTORY.json']) for stage in STAGES]
    expected_sources = {name: source['source_sha256'][name] for name in GUEST_SOURCE_FILES}
    counts = (127, 255, 383, 520)
    original = histories[0]; incident = reports[0]['critical_incident_id']
    require(json.loads(files['APPROVED_POLICY.json']) == original['approved_policy'], 'Published approved policy differs.')
    for index, (stage, record, history, boot, count) in enumerate(zip(STAGES, reports, histories, boots, counts)):
        require(record['format'] == 'heltemes-monitor-archive-powercut-guest' and record['version'] == 1
                and record['ok'] is True and record['stage'] == stage and record['source_sha256'] == expected_sources,
                'Guest report identity or exact source snapshot differs.')
        require(record['boot']['boot_id'] == boot['boot_id'] and len(history['rows']) == count
                and history['identity'] == original['identity'] and history['approved_policy'] == original['approved_policy'],
                'Guest boot, retained archive identity, or row count differs.')
        number = count // 128; validate_history(history, files, number)
        name = stage.upper() + '-HISTORY.json'; proof = record['history_file']
        require(proof['name'] == name and proof['bytes'] == len(files[name])
                and proof['sha256'] == hashlib.sha256(files[name]).hexdigest(), 'History report binding differs.')
        validate_status(record['final_status'], history['rows'], segments=number)
        require(record['critical_incident_id'] == incident
                and all(record['storage'][key] == reports[0]['storage'][key] for key in ('target', 'source', 'fstype', 'uuid'))
                and record['unit_sha256'] == hashlib.sha256(files['monitor.service']).hexdigest(),
                'Incident, persistent filesystem, or enabled unit identity changed.')
        require(len(record['archive_files']) == number, 'Stage archive inventory differs.')
        for n, proof in enumerate(record['archive_files'], 1):
            validate_file_proof(proof, files[SEGMENT_FILES[n - 1]], f'segment-{n:06d}.json')
        if index < 3:
            require(record['journal_export_method'] == 'readonly_committed_snapshot',
                    'Pre-cut history was not a coherent committed snapshot.')
            check_incident(record['final_status'], incident)
        else:
            require(record['journal_export_method'] == 'stopped_verified_journal'
                    and record['monitor_stopped_for_export']['ActiveState'] == 'inactive'
                    and record['monitor_stopped_for_export']['MainPID'] == 0,
                    'Final history export did not stop its writer.')
        if index:
            require(history['rows'][:len(histories[index - 1]['rows'])] == histories[index - 1]['rows'],
                    'A cold start changed the previously accepted prefix.')
    for index, cut in enumerate(cuts):
        prior, later, marker = reports[index], reports[index + 1], cut['boundary']['boundary']
        count = (index + 1) * 128; rows = histories[index + 1]['rows']
        require(marker['identity'] == original['identity'] and marker['approved_policy'] == original['approved_policy']
                and marker['rows'][:-1] == histories[index]['rows'] and rows[:count] == marker['rows']
                and marker['process_id'] == prior['final_status']['process_id']
                and marker['instance_id'] == prior['final_status']['instance_id']
                and cut['boundary']['manager']['InvocationID'] == prior['manager']['InvocationID'],
                'Cut marker differs from the host-held original prefix, committed candidate, or worker.')
        startup = later['automatic_start']; status, managed = startup['status'], startup['manager']
        startup_history = startup['history']
        require(startup_history['identity'] == original['identity']
                and startup_history['approved_policy'] == original['approved_policy']
                and startup_history['rows'] == rows[:count + 1] and len(startup_history['rows']) == count + 1,
                'Automatic recovery snapshot differs from the exact committed prefix plus restart.')
        validate_history(startup_history, files, index + 1)
        validate_status(status, startup_history['rows'], segments=index + 1, unknown=True)
        require(startup['no_manual_service_start'] is True and managed['ActiveState'] == 'active'
                and managed['UnitFileState'] == 'enabled' and managed['NRestarts'] == 0
                and managed['MainPID'] == status['process_id']
                and managed['InvocationID'] != prior['manager']['InvocationID']
                and status['instance_id'] != prior['final_status']['instance_id']
                and later['volatile_markers_absent'] is True,
                'Enabled monitor did not automatically start a new verified instance.')
        check_incident(status, incident)
        actions = status['archives']['recovery_actions']
        if index == 0:
            expected = [{'action': 'rebuilt_verified_staging_prefix', 'segment_index': 1,
                         'staged_bytes': marker['pending_file']['bytes']}]
            require(actions in ([], expected), 'Staged prefix recovery action differs.')
        elif index == 1:
            require(actions == [{'action': 'accepted_exact_uncommitted_segment', 'segment_index': 2}],
                    'Published archive was not adopted as its exact committed prefix.')
        else:
            require(actions == [], 'Completed archive handoff was unexpectedly repeated.')
        retry = later['lost_ack_retry']; response = retry['response']
        old_status, new_status = retry['before_status'], retry['after_status']
        require(retry['request'] == marker['request'] and response['ok'] is True and response['duplicate'] is True
                and response['result_is_historical'] is True and response['committed_sequence'] == count
                and response['evaluation'] == marker['rows'][-1]['evaluation']
                and old_status['committed_count'] == new_status['committed_count'] == count + 1
                and old_status['head_digest'] == new_status['head_digest'] == rows[count]['row_digest']
                and new_status['current_evaluation']['status'] == 'unknown'
                and response['current_status']['committed_count'] == count + 1
                and response['current_status']['current_evaluation']['status'] == 'unknown',
                'Lost acknowledgement retry changed history or advertised fresh coverage.')
        check_incident(new_status, incident)
        require(sum(row['request_id'] == marker['request_id'] for row in histories[-1]['rows']) == 1,
                'Committed archive-boundary request was lost or duplicated.')
    final_rows = histories[-1]['rows']
    supplied = []
    ranges = (range(2, 128), range(130, 256), range(258, 384), range(386, 521))
    for record, expected_sequences in zip(reports, ranges):
        observations = record['observations']
        require([item['committed_sequence'] for item in observations] == list(expected_sequences),
                'Real observation receipt sequence is incomplete or duplicated.')
        for item in observations:
            row = final_rows[item['committed_sequence'] - 1]
            require(item['request'] == {'command': 'observe', 'request_id': row['request_id'],
                    'observation': row['request']['observation']} and item['evaluation'] == row['evaluation']
                    and row['sample']['ruleset'] is not None and row['sample']['collection_error'] is None,
                    'Submitted network observation differs from its committed receipt.')
        supplied.extend(observations)
    require(len(supplied) == 513, 'Bounded actual network observation count differs.')
    startup_rows = [row for row in final_rows if row['request']['kind'] == 'restart']
    require([row['sequence'] for row in startup_rows] == [1, 129, 257, 385]
            and all(row['evaluation']['status'] == 'unknown' for row in startup_rows),
            'Unexpected restart or coverage boundary.')
    resolutions = [event for event in histories[-1]['events'] if event['key'] == CRITICAL and event['action'] == 'resolved']
    require(len(resolutions) == 1 and resolutions[0]['alert_id'] == incident and resolutions[0]['sequence'] == 388
            and len(final_rows[387]['sample']['probes']) == 3 and final_rows[387]['evaluation']['status'] == 'healthy'
            and final_rows[-1]['evaluation']['status'] == 'healthy' and len(final_rows[-1]['sample']['probes']) == 3,
            'Fresh recovery or continued post-recovery operation differs.')
    require(all(CRITICAL in final_rows[n - 1]['evaluation']['active_alert_keys']
                and final_rows[n - 1]['evaluation']['status'] != 'healthy' for n in (386, 387)),
            'Rule-only baseline prematurely resolved the original incident.')
    for stage, record in (('before', reports[0]), ('after', reports[-1])):
        names = {name for name in CAPTURE_FILES if name.startswith(stage + '-')}
        require(set(record['capture_sha256']) == names and all(hashlib.sha256(files[n]).hexdigest() == checksum
                for n, checksum in record['capture_sha256'].items()), 'Completed packet capture bytes changed.')
        require(record['network_cleanup']['ok'] is True, 'Synthetic network cleanup failed.')
    return reports, histories



def run(output):
    tools = preflight(); source = source_identity()
    destination = reboot.monitoring.base.new_output(output)
    staging = destination / 'staging'; staging.mkdir(mode=0o700)
    vm = DisposableVM(tools)
    report = {'format': 'heltemes-network-monitor-archive-powercut-lab', 'version': 1, 'ok': False,
        'started_at_utc': timestamp(), 'source': source,
        'scope': {'synthetic_only': True, 'aws_deployed': False, 'real_evidence_inputs': False,
            'abrupt_guest_power_loss_simulated': True, 'full_guest_cold_starts': 3,
            'history_rotation_tested': True, 'automatic_monitor_startup_tested': True,
            'network_reconstruction_by_harness': True, 'automatic_collector_startup_tested': False,
            'physical_host_power_loss_tested': False, 'host_storage_remained_powered': True,
            'torn_sector_or_device_flush_failure_tested': False, 'administrator_resistant_history': False,
            'continuous_monitoring': False, 'dedicated_account_isolation_tested': False,
            'external_notification_delivery': False}}
    evidence, files, references, stages, cuts = {}, {}, {}, {}, []
    step = 'preparing pinned image and private boot media'; progress(step)
    try:
        evidence['image'] = {'url': reboot.IMAGE_URL, 'sha256': reboot.IMAGE_SHA256}
        evidence['virtualization'] = vm.prepare()
        step = 'booting and provisioning the disposable guest'; progress(step); vm.launch()
        step = 'collecting initial network incident and first archive prefix'; progress(step)
        stages['before'] = vm.guest('before')
        for index, (point, label) in enumerate(zip(POINTS, LABELS)):
            stage = STAGES[index]
            step = 'holding exact ' + stage + ' public references outside the guest'; progress(step)
            references[stage] = vm.export_guest(stage)
            step = 'pausing immediately at ' + point; progress(step)
            boundary = vm.guest('arm-' + label)
            step = 'killing the whole VM and cold-starting the same disk at ' + point; progress(step)
            cuts.append(vm.power_cut(point, boundary))
            step = 'checking recovered archived history after ' + point; progress(step)
            stages[STAGES[index + 1]] = vm.guest(STAGES[index + 1])
        evidence.update({'boots': vm.boots, 'cuts': cuts, 'guest_stages': stages,
            'references_held_outside_guest': True,
            'reference_sha256': {stage: {name: hashlib.sha256(raw).hexdigest() for name, raw in held.items()}
                                 for stage, held in references.items()}})
        step = 'validating preserved history, exact archive handoffs, retry results, and fresh recovery'; progress(step)
        files = vm.export_guest(); validate_guest(references, files, source, cuts)
        step = 'removing guest service and synthetic state'; progress(step)
        evidence['guest_cleanup'] = vm.guest('cleanup')
        require(evidence['guest_cleanup']['ok'] is True and source_identity() == source,
                'Guest cleanup or exact source revalidation failed.')
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        report['error'] = step + ': ' + vm.redact(error).replace(str(destination), '<report>')
    finally:
        try:
            progress('stopping owned VM and deleting private access credentials and disk')
            evidence['cleanup'] = vm.cleanup()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            evidence['cleanup'] = {'ok': False, 'error': vm.redact(error)}
        report['completed_at_utc'] = timestamp()
    report['ok'] = 'error' not in report and evidence['cleanup']['ok']; report['cleanup'] = evidence['cleanup']
    reboot.write_json(staging / 'REPORT.json', report)
    if not report['ok']:
        raise RuntimeError('Archive power-cut exercise failed: ' + report.get('error', 'Private VM cleanup failed.'))
    for name, raw in files.items():
        (staging / name).write_bytes(raw)
    vm_bytes = (canonical(evidence) + '\n').encode()
    require(len(vm_bytes) <= 64 * 1024 * 1024, 'Host lifecycle evidence exceeds its finite size bound.')
    (staging / 'VM.json').write_bytes(vm_bytes)
    (staging / 'SUMMARY.md').write_text(f'''# Archived monitoring history through abrupt virtual power loss

Source commit `{source['commit']}`. Completed {report['completed_at_utc']}.

The host killed its entire QEMU process with SIGKILL at three observed archive handoff boundaries and cold-started the same disposable disk each time. Four distinct Linux boot identities and QEMU process lifetimes were observed. No guest shutdown or graceful QEMU exit was requested at a cut.

At row 128, the staging file had been flushed but its name had not yet been durably published. At row 256, the final archive file and directory had been flushed but SQLite still held the active prefix. At row 384, the metadata handoff had committed before the caller received its acknowledgement. Every boundary observation was already committed and survived exactly once. Recovery rebuilt the first segment from its exact committed prefix, adopted the exact published second segment, and retained the third without repeating its completed handoff.

After each cold start, the enabled monitor automatically verified its retained history and recorded unknown coverage with the original unresolved incident. Each exact lost-acknowledgement retry returned its original historical result without adding a row or claiming current health. Explicitly reconstructed network rules and fresh connection checks were required to resolve that original incident at row 388. Collection continued through row 520, including a normal fourth archive rollover. The final archive contains four 128-row segments and eight active rows.

VM.json holds the original public fingerprints, stopped-worker boundary records, SIGKILL results, direct-I/O and flush readbacks, four cold boots, and cleanup evidence. Four reports and history exports, four original segments, the enabled service definition, approved policy, and before/after packet captures are covered by MANIFEST.json. No extra persistent-disk sync is issued after the selected boundary is armed. The first staging filename may survive or disappear because its parent directory had not yet been synced; either case must reconstruct the identical committed bytes.

This bounded test uses submitted synthetic network observations, with no continuous collector or missing-data timer. It simulates abrupt guest power loss while the host and physical storage stay powered. It does not test torn sectors, failed storage flushes, physical power loss, or administrator-resistant custody. AWS, real Evidence keys, and trusted history remain outside the exercise. The owned guest services, synthetic network, VM, private credentials, seed, and disk were removed before publication.
''')
    reboot.write_json(staging / 'MANIFEST.json', {name: reboot.sha256_file(staging / name) for name in PUBLIC_FILES})
    publish = destination / 'publish'; publish.mkdir(mode=0o755)
    for name in (*PUBLIC_FILES, 'MANIFEST.json'):
        (staging / name).rename(publish / name); (publish / name).chmod(0o644)
    destination.chmod(0o755)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, help='New report directory with an existing parent')
    arguments = parser.parse_args()
    try:
        report = run(arguments.output)
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        parser.exit(1, 'Archive power-cut VM stopped: ' + str(error) + '\n')
    print(json.dumps({'ok': report['ok'], 'source_commit': report['source']['commit'], 'cleanup': report['cleanup']}, indent=2))


if __name__ == '__main__':
    main()
