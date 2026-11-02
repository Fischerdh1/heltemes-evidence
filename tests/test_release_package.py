"""Source release preservation/privacy checks; all output lives in disposable folders."""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts import package_release as release


class ReleasePackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "source"
        self.root.mkdir()
        self.write("pyproject.toml", '[project]\nname = "heltemes-evidence"\nversion = "0.3.2"\n')
        self.write("heltemes/__init__.py", '__version__ = "0.3.2"\n')
        self.write("heltemes/sec.py", 'SOURCE = "current collector"\n')
        self.write("cloud/__init__.py", '"""Prepared cloud source."""\n')
        self.write("cloud/handler.py", 'SOURCE = "current handler"\n')
        self.write("README.md", "Source release fixture, no live archive.\n")
        self.write("Launch.command", "#!/bin/zsh\nexit 0\n")
        self.write("scripts/repair_local_startup.py", '"""Startup repair source fixture."""\n')
        self.write("tests/test_startup_repair.py", '"""Offline test fixture."""\n')
        self.write("heltemes/fixtures/demo_submissions.json", '{"synthetic": true}\n')
        self.destination = self.base / "release.zip"

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode() if isinstance(content, str) else content)
        return path

    def test_release_is_reproducible_manifested_and_dated(self):
        first = release.package(self.destination, root=self.root)
        other = self.base / "second.zip"
        second = release.package(other, root=self.root)
        self.assertEqual(self.destination.read_bytes(), other.read_bytes())
        self.assertEqual(first["sha256"], second["sha256"])
        self.assertEqual(first["sha256"], hashlib.sha256(self.destination.read_bytes()).hexdigest())
        self.assertEqual(self.destination.with_suffix(".zip.sha256").read_text(), first["sha256"] + "  release.zip\n")
        self.assertEqual(first["release_date"], "2026-10-26")
        self.assertFalse(first["installed_service_modified"])
        self.assertFalse(first["aws_deployed"])
        with zipfile.ZipFile(self.destination) as archive:
            manifest = json.loads(archive.read("heltemes-evidence/RELEASE-MANIFEST.json"))
            self.assertEqual(len(manifest), first["files"])
            for name, expected in manifest.items():
                self.assertEqual(hashlib.sha256(archive.read("heltemes-evidence/" + name)).hexdigest(), expected)
            self.assertTrue(all(item.date_time == (2026, 10, 26, 0, 0, 0) for item in archive.infolist()))
            metadata = json.loads(archive.read("heltemes-evidence/RELEASE.json"))
            self.assertEqual(metadata["version"], "0.3.2")
            self.assertTrue(metadata["package_only"])
            self.assertFalse(metadata["updates_installed_local_service"])
            self.assertEqual(stat.S_IMODE(archive.getinfo("heltemes-evidence/Launch.command").external_attr >> 16), 0o755)
            self.assertIn("scripts/repair_local_startup.py", manifest)
            self.assertIn("tests/test_startup_repair.py", manifest)

    def test_runtime_material_and_machine_specs_are_excluded_even_under_source_folders(self):
        forbidden = ["data/settings.json", "data/data.sqlite3", "data/documents/filing.bin",
                     "work/local-account-recovery.json", "work/activation-logs/private.log",
                     "backups/evidence.zip", ".heltemes-keys/archive/signing_key", ".heltemes-trust/archive/anchor.json",
                     "scripts/runtime.json", "scripts/repair-machine-spec.json", "docs/trust-receipt.json",
                     "heltemes/settings.json", "heltemes/fixtures/real_submissions.json", "examples/live_filing.json",
                     "infra/terraform.tfstate", "infra/terraform.tfstate.backup", "infra/terraform.tfvars",
                     "infra/.terraform/provider/config.py", "tests/work/private.py", ".env", ".env.local",
                     "scripts/settings.env", "scripts/signing_key.pem"]
        for name in forbidden:
            self.write(name, b"PRIVATE-RUNTIME-SENTINEL\n")
        release.package(self.destination, root=self.root)
        with zipfile.ZipFile(self.destination) as archive:
            names = set(archive.namelist())
            for name in forbidden:
                self.assertNotIn("heltemes-evidence/" + name, names)
            self.assertTrue(all(b"PRIVATE-RUNTIME-SENTINEL" not in archive.read(name) for name in names))

    def test_nested_cloud_zip_is_rebuilt_from_current_packaged_source(self):
        old = self.write("dist/collector.zip", b"STALE-CLOUD-ARCHIVE")
        release.package(self.destination, root=self.root)
        self.assertEqual(old.read_bytes(), b"STALE-CLOUD-ARCHIVE")
        with zipfile.ZipFile(self.destination) as outer:
            with zipfile.ZipFile(io.BytesIO(outer.read("heltemes-evidence/dist/collector.zip"))) as inner:
                self.assertEqual(set(inner.namelist()), set(release.LAMBDA_SOURCE))
                for name in release.LAMBDA_SOURCE:
                    self.assertEqual(inner.read(name), outer.read("heltemes-evidence/" + name))

    def test_existing_archive_is_not_overwritten(self):
        self.destination.write_bytes(b"HISTORICAL RELEASE")
        with self.assertRaisesRegex(FileExistsError, "historical"):
            release.package(self.destination, root=self.root)
        self.assertEqual(self.destination.read_bytes(), b"HISTORICAL RELEASE")
        self.assertFalse(self.destination.with_suffix(".zip.sha256").exists())

    def test_existing_checksum_and_symlink_are_not_overwritten(self):
        checksum = self.destination.with_suffix(".zip.sha256")
        checksum.write_bytes(b"HISTORICAL CHECKSUM")
        with self.assertRaises(FileExistsError):
            release.package(self.destination, root=self.root)
        self.assertEqual(checksum.read_bytes(), b"HISTORICAL CHECKSUM")
        self.assertFalse(self.destination.exists())
        checksum.unlink()
        self.destination.symlink_to(self.base / "missing-original")
        with self.assertRaises(FileExistsError):
            release.package(self.destination, root=self.root)
        self.assertTrue(self.destination.is_symlink())

    def test_checksum_publication_race_preserves_other_writer(self):
        real_link = os.link
        checksum = self.destination.with_suffix(".zip.sha256")
        def publish(source, target):
            if Path(target) == checksum:
                checksum.write_bytes(b"OTHER WRITER")
            return real_link(source, target)
        with patch.object(release.os, "link", side_effect=publish):
            with self.assertRaises(FileExistsError):
                release.package(self.destination, root=self.root)
        self.assertEqual(checksum.read_bytes(), b"OTHER WRITER")
        self.assertFalse(self.destination.exists())

    def test_mismatched_version_cannot_publish_release(self):
        self.write("heltemes/__init__.py", '__version__ = "0.3.1"\n')
        with self.assertRaisesRegex(ValueError, "versions must match"):
            release.package(self.destination, root=self.root)
        self.assertFalse(self.destination.exists())

    def test_private_key_in_allowed_source_is_refused(self):
        self.write("docs/accidental-key.md", "-----BEGIN OPENSSH PRIVATE KEY-----\nprivate-placeholder\n")
        with self.assertRaisesRegex(ValueError, "private-key"):
            release.package(self.destination, root=self.root)
        self.assertFalse(self.destination.exists())

    def test_symlink_and_hardlink_source_are_refused(self):
        outside = self.base / "private.md"
        outside.write_text("PRIVATE-RUNTIME-SENTINEL")
        linked = self.root / "docs" / "linked.md"
        linked.parent.mkdir()
        linked.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "symbolic links"):
            release.package(self.destination, root=self.root)
        linked.unlink()
        os.link(outside, linked)
        with self.assertRaisesRegex(ValueError, "hard links"):
            release.package(self.destination, root=self.root)
        self.assertFalse(self.destination.exists())

    def test_missing_cloud_source_and_corrupt_archive_are_refused(self):
        (self.root / "cloud/handler.py").unlink()
        with self.assertRaisesRegex(ValueError, "collector source is missing"):
            release.package(self.destination, root=self.root)
        self.assertFalse(self.destination.exists())
        self.write("cloud/handler.py", "pass\n")
        release.package(self.destination, root=self.root)
        with self.assertRaisesRegex(ValueError, "inventory"):
            release.verify_archive(self.destination, {"README.md": b"altered"})


if __name__ == "__main__":
    unittest.main()
