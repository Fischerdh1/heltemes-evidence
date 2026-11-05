"""Boot a disposable Ubuntu VM and verify monitoring across a full guest reboot."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import secrets
import select
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts import network_monitoring_lab as monitoring

require, timestamp = monitoring.require, monitoring.timestamp
IMAGE_URL = "https://cloud-images.ubuntu.com/minimal/releases/noble/release-20261103/ubuntu-24.04-minimal-cloudimg-amd64.img"
IMAGE_SHA256 = "bc9237bfdfa42b5f9a4404b6c6cab595d3e57599c6498f6664ad00e6192f9595"
GUEST_ROOT = "/opt/heltemes-reboot-lab"
GUEST_REPORT = "/var/lib/heltemes-reboot-lab/report/publish"
GUEST_SCRIPT = GUEST_ROOT + "/scripts/network_monitor_reboot_guest.py"
SOURCE_FILES = (*monitoring.SOURCE_FILES, "scripts/network_monitor_store.py", "scripts/network_monitor_service.py",
                "scripts/network_monitor_reboot_guest.py", "scripts/network_monitor_reboot_vm.py")
GUEST_FILES = ("BEFORE.json", "AFTER.json", "APPROVED_POLICY.json", "monitor.service",
               *(name for phase in ("before", "after") for zone in ("user", "app", "management")
                 for name in (phase + "-" + zone + ".pcap", phase + "-" + zone + "-packets.txt")))
PUBLIC_FILES = ("REPORT.json", "VM.json", "SUMMARY.md", *GUEST_FILES)
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
TOKEN = re.compile(r"[0-9a-f]{32}\Z")
MAX_EXPORT = 32 * 1024 * 1024


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def preflight():
    require(sys.platform == "linux" and platform.machine() in {"x86_64", "amd64"},
            "The full-reboot exercise requires a disposable x86-64 Linux host; it does not run on macOS.")
    names = ("qemu-system-x86_64", "qemu-img", "cloud-localds", "ssh", "ssh-keygen", "curl", "git")
    tools = {name: shutil.which(name) for name in names}
    require(all(tools.values()), "Install QEMU, cloud-image-utils, OpenSSH client, curl, and Git on the disposable Linux host.")
    return tools


def source_identity(root=ROOT, environment=None):
    root = Path(root).resolve()
    identity = monitoring.source_identity(root, environment)
    for name in SOURCE_FILES[len(monitoring.SOURCE_FILES):]:
        content = (root / name).read_bytes()
        result = subprocess.run(["git", "-c", f"safe.directory={root}", "-C", str(root),
                                 "show", f"{identity['commit']}:{name}"], capture_output=True, timeout=30)
        require(result.returncode == 0 and content == result.stdout, "Reboot lab source differs from its committed version.")
        identity["source_sha256"][name] = hashlib.sha256(content).hexdigest()
    return identity


def source_archive(root=ROOT):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name in SOURCE_FILES[:-1]:
            content = (Path(root) / name).read_bytes()
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode, entry.uid, entry.gid, entry.mtime = len(content), 0o644, 0, 0, 0
            archive.addfile(entry, io.BytesIO(content))
    return output.getvalue()


def cloud_configuration(token, client_public, host_private, host_public):
    require(TOKEN.fullmatch(token), "VM token is invalid.")
    return {
        "users": [{"name": "lab", "groups": "sudo", "shell": "/bin/bash", "lock_passwd": True,
                   "sudo": "ALL=(ALL) NOPASSWD:ALL", "ssh_authorized_keys": [client_public.strip()]}],
        "disable_root": True, "ssh_pwauth": False, "ssh_deletekeys": True, "ssh_genkeytypes": [],
        "ssh_keys": {"ed25519_private": host_private, "ed25519_public": host_public.strip()},
        "package_update": True, "packages": ["python3", "git", "iproute2", "nftables", "tcpdump", "procps"],
        "write_files": [{"path": "/etc/heltemes-reboot-lab.json", "owner": "root:root", "permissions": "0600",
                         "content": json.dumps({"format": "heltemes-disposable-reboot-vm", "version": 1, "token": token}) + "\n"}],
    }


class QMP:
    """Bounded QMP client. Only selected event metadata is exported."""
    def __init__(self, path, started):
        require(len(os.fsencode(path)) < 100, "The owned QMP socket path is too long.")
        self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.buffer, self.events, self.started = bytearray(), [], started
        try:
            self.connection.settimeout(10)
            self.connection.connect(str(path))
            greeting = self.read(10)
            require(isinstance(greeting.get("QMP"), dict), "The VM monitor did not present a QMP greeting.")
            self.command("qmp_capabilities")
        except BaseException:
            self.connection.close()
            raise

    def close(self):
        self.connection.close()

    def read(self, timeout):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.connection], [], [], max(0, remaining))[0]:
                raise TimeoutError("QMP response timed out.")
            block = self.connection.recv(65536)
            require(block, "The owned VM monitor disconnected.")
            self.buffer.extend(block)
            require(len(self.buffer) <= 1024 * 1024, "The VM monitor returned an oversized message.")
        line, _, remainder = self.buffer.partition(b"\n")
        self.buffer = bytearray(remainder)
        value = json.loads(line)
        require(isinstance(value, dict), "The VM monitor returned a malformed message.")
        if "event" in value:
            self.events.append({"event": value["event"], "data": value.get("data", {}),
                                "observed_elapsed_seconds": time.monotonic() - self.started})
        return value

    def command(self, command):
        request_id = secrets.token_hex(8)
        self.connection.sendall((json.dumps({"execute": command, "id": request_id}) + "\n").encode())
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            reply = self.read(deadline - time.monotonic())
            if reply.get("id") == request_id:
                require("return" in reply and "error" not in reply, "The VM monitor rejected a command.")
                return reply["return"]
        raise TimeoutError("The VM monitor command timed out.")

    def drain(self):
        while b"\n" in self.buffer or select.select([self.connection], [], [], 0)[0]:
            self.read(1)


class DisposableVM:
    def __init__(self, tools):
        self.tools, self.token = tools, secrets.token_hex(16)
        self.directory = self.process = self.qmp = self.log = None
        self.started = time.monotonic()
        self.accelerator = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
        self.port = None

    def redact(self, value):
        text = str(value).replace(str(ROOT), "<source>").replace(self.token, "<run-token>")
        return text.replace(str(self.directory), "<private-vm>") if self.directory is not None else text

    def command(self, arguments, *, input=None, timeout=60, check=True):
        result = subprocess.run(arguments, input=input, capture_output=True, timeout=timeout)
        if check:
            require(result.returncode == 0, "A disposable VM setup command failed: " + Path(arguments[0]).name + ": " + self.redact(result.stderr.decode(errors="replace")[-1000:]).strip())
        return result

    def prepare(self):
        self.directory = Path(tempfile.mkdtemp(prefix="he-rb-", dir="/tmp"))
        self.directory.chmod(0o700)
        base_image = self.directory / "base.img"
        self.command([self.tools["curl"], "--fail", "--silent", "--show-error", "--location",
                      "--proto", "=https", "--proto-redir", "=https", "--max-time", "240",
                      "--output", str(base_image), IMAGE_URL], timeout=250)
        require(base_image.stat().st_size < 2 * 1024 ** 3 and sha256_file(base_image) == IMAGE_SHA256,
                "The downloaded Ubuntu image differs from its pinned SHA-256 fingerprint.")
        for key in ("client", "host"):
            self.command([self.tools["ssh-keygen"], "-q", "-t", "ed25519", "-N", "", "-C", "disposable-reboot-lab",
                          "-f", str(self.directory / key)])
        for file in self.directory.iterdir():
            file.chmod(0o600)
        client_public, host_private, host_public = [(self.directory / name).read_text() for name in ("client.pub", "host", "host.pub")]
        config = cloud_configuration(self.token, client_public, host_private, host_public)
        (self.directory / "user-data").write_text("#cloud-config\n" + json.dumps(config, indent=2) + "\n")
        (self.directory / "meta-data").write_text(json.dumps({"instance-id": "he-rb-" + self.token,
                                                            "local-hostname": "heltemes-reboot-lab"}) + "\n")
        self.command([self.tools["cloud-localds"], str(self.directory / "seed.img"),
                      str(self.directory / "user-data"), str(self.directory / "meta-data")])
        self.command([self.tools["qemu-img"], "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base_image),
                      str(self.directory / "disk.qcow2"), "8G"])
        for file in self.directory.iterdir():
            file.chmod(0o600)
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            self.port = reservation.getsockname()[1]
        # An explicit seed-provisioned host key is trusted before the first SSH connection.
        (self.directory / "known_hosts").write_text(f"[127.0.0.1]:{self.port} " + host_public.strip() + "\n")
        (self.directory / "known_hosts").chmod(0o600)
        version = self.command([self.tools["qemu-system-x86_64"], "--version"]).stdout.decode().splitlines()[0]
        return {"accelerator": self.accelerator, "qemu_version": version,
                "ssh_host_key_pinned_before_connect": True, "shared_host_directories": False,
                "host_forward_binding": "127.0.0.1", "guest_network": "qemu_user_networking"}

    def launch(self):
        require(self.directory is not None and self.process is None, "A prepared VM may be launched only once.")
        qmp_path = self.directory / "qmp.sock"
        require(len(os.fsencode(qmp_path)) < 100, "The VM runtime path is too long.")
        self.log = (self.directory / "qemu.log").open("wb")
        arguments = [self.tools["qemu-system-x86_64"], "-m", "2048", "-smp", "2", "-accel", self.accelerator,
                     "-cpu", "host" if self.accelerator == "kvm" else "max", "-display", "none", "-monitor", "none",
                     "-serial", "file:" + str(self.directory / "serial.log"),
                     "-qmp", "unix:" + str(qmp_path) + ",server=on,wait=off",
                     "-drive", "file=" + str(self.directory / "disk.qcow2") + ",if=virtio,format=qcow2",
                     "-drive", "file=" + str(self.directory / "seed.img") + ",if=virtio,format=raw,readonly=on",
                     "-nic", f"user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{self.port}-:22"]
        self.process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 20
        while not qmp_path.exists() and time.monotonic() < deadline:
            self.require_running()
            time.sleep(0.1)
        require(qmp_path.is_socket(), "The owned VM did not expose its private QMP socket.")
        self.qmp = QMP(qmp_path, self.started)
        self.kvm_status = self.qmp.command("query-kvm")
        require(self.kvm_status.get("enabled") is (self.accelerator == "kvm"), "QEMU acceleration differs from the selected mode.")
        self.wait_boot(timeout=360)
        self.ssh("sudo -n cloud-init status --wait", timeout=360)
        self.ssh("sudo -n mkdir -p " + GUEST_ROOT + " && sudo -n tar -xz --no-same-owner -f - -C " + GUEST_ROOT,
                 input=source_archive(), timeout=60)

    def require_running(self):
        require(self.process is not None and self.process.poll() is None, "The owned VM process stopped unexpectedly.")

    def ssh(self, command, *, input=None, timeout=30, check=True):
        require(self.directory is not None and self.port is not None, "A private VM transport is required.")
        arguments = [self.tools["ssh"], "-F", "/dev/null", "-i", str(self.directory / "client"), "-p", str(self.port),
                     "-o", "BatchMode=yes", "-o", "IdentityAgent=none", "-o", "IdentitiesOnly=yes", "-o", "StrictHostKeyChecking=yes",
                     "-o", "UserKnownHostsFile=" + str(self.directory / "known_hosts"),
                     "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=2", "-o", "ConnectionAttempts=1",
                     "-o", "ServerAliveInterval=2", "-o", "ServerAliveCountMax=2", "-o", "LogLevel=ERROR",
                     "lab@127.0.0.1", command]
        result = self.command(arguments, input=input, timeout=timeout, check=False)
        if check and result.returncode:
            error = (result.stderr or result.stdout).decode(errors="replace")[-1500:]
            error = error.replace(str(self.directory), "<private-vm>").replace(str(ROOT), "<source>").replace(self.token, "<run-token>")
            raise RuntimeError("A disposable guest operation failed: " + error.strip())
        return result

    def boot_snapshot(self):
        self.require_running()
        result = self.ssh("cat /proc/sys/kernel/random/boot_id; cut -d ' ' -f 1 /proc/uptime", timeout=8, check=False)
        if result.returncode:
            return None
        values = result.stdout.decode().splitlines()
        require(len(values) == 2 and UUID.fullmatch(values[0]), "The guest returned malformed boot identity.")
        uptime = float(values[1])
        require(0 <= uptime < 10 ** 9, "The guest returned invalid uptime.")
        info = (self.directory / "disk.qcow2").stat()
        return {"boot_id": values[0], "uptime_seconds": uptime, "qemu_pid": self.process.pid,
                "disk_identity": {"device": info.st_dev, "inode": info.st_ino},
                "observed_elapsed_seconds": time.monotonic() - self.started}

    def wait_boot(self, *, timeout=360, previous=None):
        deadline = time.monotonic() + timeout
        unavailable = False
        while time.monotonic() < deadline:
            self.require_running()
            self.qmp.drain()
            try:
                snapshot = self.boot_snapshot()
            except subprocess.TimeoutExpired:
                snapshot = None
            if snapshot is None:
                unavailable = True
            elif previous is None or snapshot["boot_id"] != previous["boot_id"]:
                return snapshot, unavailable
            time.sleep(0.5)
        raise RuntimeError("The guest did not complete a verified Linux boot within the bounded wait.")

    def guest(self, stage):
        require(stage in {"before", "after", "cleanup"}, "Unknown guest stage.")
        result = self.ssh("sudo -n python3 -I -S -B " + GUEST_SCRIPT + " " + stage + " --token " + self.token,
                          timeout=180)
        require(len(result.stdout) <= 1024 * 1024, "The guest returned oversized stage metadata.")
        value = json.loads(result.stdout)
        require(isinstance(value, dict) and value.get("ok") is True, "The guest stage did not succeed.")
        return value

    def reboot(self):
        before = self.boot_snapshot()
        require(before is not None, "The pre-reboot guest is unreachable.")
        self.qmp.drain()
        event_start = len(self.qmp.events)
        requested = time.monotonic() - self.started
        result = self.ssh("sudo -n systemctl reboot", timeout=10, check=False)
        require(result.returncode in {0, 255}, "The guest did not accept the reboot request.")
        after, unavailable = self.wait_boot(previous=before)
        self.qmp.drain()
        events = self.qmp.events[event_start:]
        validate_reboot(before, after, unavailable, events, requested)
        return {"before": before, "after": after, "ssh_unavailable_observed": unavailable,
                "qmp_events": events, "reboot_requested_elapsed_seconds": requested,
                "ready_elapsed_seconds": after["observed_elapsed_seconds"],
                "same_qemu_process": True, "same_disk": True, "reboot_command": "systemctl reboot"}

    def export_guest(self):
        command = "sudo -n tar -cz -C " + GUEST_REPORT + " -- " + " ".join(GUEST_FILES)
        result = self.ssh(command, timeout=60)
        return extract_guest_export(result.stdout)

    def cleanup(self):
        stopped = self.process is None
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=10)
            stopped = self.process.poll() is not None
        if self.qmp is not None:
            self.qmp.close()
        if self.log is not None:
            self.log.close()
        require(stopped, "The owned VM process could not be stopped.")
        if self.directory is not None and self.directory.exists():
            require(self.directory.parent == Path("/tmp") and self.directory.name.startswith("he-rb-")
                    and not self.directory.is_symlink(), "VM cleanup is outside the owned temporary directory.")
            shutil.rmtree(self.directory)
        removed = self.directory is None or not self.directory.exists()
        require(removed, "Disposable VM credentials or storage remain after cleanup.")
        return {"ok": True, "vm_stopped": stopped, "private_runtime_removed": removed,
                "private_ssh_keys_seed_disk_removed": removed}


def validate_reboot(before, after, unavailable, events, requested):
    require(before["boot_id"] != after["boot_id"], "The guest kernel boot identity did not change.")
    require(before["qemu_pid"] == after["qemu_pid"] and before["disk_identity"] == after["disk_identity"],
            "The VM process or persistent disk was replaced during reboot.")
    require(unavailable is True, "No guest SSH outage was observed during reboot.")
    require(before["observed_elapsed_seconds"] <= requested < after["observed_elapsed_seconds"],
            "Reboot observations are out of order.")
    require(any(event["event"] == "RESET" and event.get("data", {}).get("guest") is True
                and requested <= event["observed_elapsed_seconds"] <= after["observed_elapsed_seconds"]
                for event in events), "QEMU did not report a guest-triggered reset during the observed boot change.")


def extract_guest_export(content):
    require(len(content) <= MAX_EXPORT, "The guest export exceeds its size limit.")
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
        entries = archive.getmembers()
        require(len(entries) == len(GUEST_FILES) and {entry.name for entry in entries} == set(GUEST_FILES),
                "The guest export inventory differs from the fixed public allowlist.")
        require(all(entry.isfile() and entry.size <= 8 * 1024 * 1024 for entry in entries)
                and sum(entry.size for entry in entries) <= MAX_EXPORT, "The guest export has unsafe or oversized entries.")
        files = {entry.name: archive.extractfile(entry).read() for entry in entries}
    require(not any(b"PRIVATE KEY" in value or b"/Users/" in value for value in files.values()),
            "The public guest export includes a private marker.")
    return files



def validate_preserved_history(reference, files, source, reboot):
    require(files["BEFORE.json"] == reference, "The guest preboot reference changed during reboot.")
    before, after = json.loads(reference), json.loads(files["AFTER.json"])
    expected_sources = {name: source["source_sha256"][name] for name in SOURCE_FILES[:-1]}
    require(before["source_sha256"] == after["source_sha256"] == expected_sources,
            "Guest source bytes differ from the host-verified source snapshot.")
    require(before["boot"]["boot_id"] == reboot["before"]["boot_id"]
            and after["boot"]["boot_id"] == reboot["after"]["boot_id"], "Guest and host boot records disagree.")
    original, automatic, final = before["journal"], after["automatic_start"]["journal"], after["journal"]
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    require(canonical(original["identity"]) == canonical(automatic["identity"]) == canonical(final["identity"]),
            "The original persistent journal identity was replaced during reboot.")
    require(len(original["rows"]) == 5 and len(automatic["rows"]) == 6 and len(final["rows"]) == 8
            and canonical(original["rows"]) == canonical(automatic["rows"][:5]) == canonical(final["rows"][:5]),
            "The host-held preboot history does not match the reopened journal prefix.")
    require(after["automatic_start"]["no_manual_service_start"] is True
            and after["automatic_start"]["status"]["current_evaluation"]["status"] == "unknown"
            and after["final_status"]["current_evaluation"]["status"] == "healthy",
            "Automatic boot and fresh recovery status do not match the expected sequence.")
    require(before["critical_incident_id"] == after["critical_incident_id"], "The preserved incident identity differs.")


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def run(output):
    tools = preflight()
    source = source_identity()
    destination = monitoring.base.new_output(output)
    staging = destination / "staging"
    staging.mkdir(mode=0o700)
    vm = DisposableVM(tools)
    report = {"format": "heltemes-network-monitor-reboot-lab", "version": 1, "ok": False,
              "started_at_utc": timestamp(), "source": source,
              "scope": {"synthetic_only": True, "aws_deployed": False, "real_evidence_inputs": False,
                        "full_guest_os_reboot_tested": True, "physical_power_loss_tested": False,
                        "administrator_resistant_storage": False, "continuous_monitoring": False}}
    evidence, files = {}, {}
    current_step = "preparing pinned VM image and private boot media"
    try:
        evidence["image"] = {"url": IMAGE_URL, "sha256": IMAGE_SHA256}
        evidence["virtualization"] = vm.prepare()
        current_step = "booting guest and waiting for cloud-init"
        vm.launch()
        evidence["virtualization"]["qmp_kvm"] = vm.kvm_status
        current_step = "collecting preboot evidence"
        before = vm.guest("before")
        before_reference = vm.ssh("sudo -n cat " + GUEST_REPORT + "/BEFORE.json", timeout=15).stdout
        require(len(before_reference) <= 8 * 1024 * 1024, "The preboot reference exceeds its size limit.")
        evidence["preboot_reference_sha256"] = hashlib.sha256(before_reference).hexdigest()
        current_step = "performing and verifying full guest reboot"
        evidence["reboot"] = vm.reboot()
        require(before["boot_id"] == evidence["reboot"]["before"]["boot_id"], "Guest pre-reboot records disagree.")
        current_step = "verifying automatic startup and fresh recovery"
        after = vm.guest("after")
        require(after["boot_id"] == evidence["reboot"]["after"]["boot_id"], "Guest post-reboot records disagree.")
        evidence["guest_stages"] = {"before": before, "after": after}
        current_step = "exporting and comparing preserved evidence"
        files = vm.export_guest()
        validate_preserved_history(before_reference, files, source, evidence["reboot"])
        evidence["preboot_reference_held_outside_guest"] = True
        current_step = "cleaning guest service and state"
        evidence["guest_cleanup"] = vm.guest("cleanup")
        require(source_identity() == source, "Reboot lab source changed during execution.")
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
        report["error"] = current_step + ": " + vm.redact(error).replace(str(destination), "<report>")
    finally:
        try:
            evidence["cleanup"] = vm.cleanup()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            evidence["cleanup"] = {"ok": False, "error": vm.redact(error)}
        report["completed_at_utc"] = timestamp()
    report["ok"] = "error" not in report and evidence["cleanup"]["ok"]
    report["cleanup"] = evidence["cleanup"]
    write_json(staging / "REPORT.json", report)
    if not report["ok"]:
        raise RuntimeError("Full VM reboot exercise failed: " + report.get("error", "Private VM cleanup failed."))
    for name, content in files.items():
        (staging / name).write_bytes(content)
    write_json(staging / "VM.json", evidence)
    (staging / "SUMMARY.md").write_text(f"""# HELTEMES Evidence full Linux VM reboot exercise

Source commit `{source['commit']}`. Completed {report['completed_at_utc']}.

A fresh Ubuntu 24.04 guest booted from a pinned image on a disposable disk. The monitor saved its journal in persistent `/var/lib` storage and enabled its systemd service for boot.

The harness opened a synthetic forbidden-access incident, then requested a full guest OS reboot. QEMU reported a guest-triggered RESET; SSH became unavailable; the Linux kernel boot ID changed while the same QEMU process and disk remained in use. The enabled worker started automatically and reopened the original journal. Its startup gap reported unknown coverage and preserved the unresolved incident. Fresh rules and all three canaries were required before recovery.

Inspect VM.json for image, QEMU, boot and cleanup evidence. BEFORE.json and AFTER.json preserve the committed histories, service observations and actual network checks. Three interface captures for each stage preserve packet evidence.

The guest service and synthetic networks were cleaned up. The VM process stopped, and its private SSH keys, seed image and disk were deleted before publication. This tests a graceful full guest reboot, not physical power loss, hostile-administrator rollback resistance, or continuous production monitoring. AWS and real Evidence keys/history were outside the exercise.
""")
    manifest = {name: sha256_file(staging / name) for name in PUBLIC_FILES}
    write_json(staging / "MANIFEST.json", manifest)
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
        parser.exit(1, "VM reboot lab stopped: " + str(error) + "\n")
    print(json.dumps({"ok": report["ok"], "source_commit": report["source"]["commit"], "cleanup": report["cleanup"]}, indent=2))


if __name__ == "__main__":
    main()
