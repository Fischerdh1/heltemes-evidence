"""Create a verified source release without replacing historical artifacts.

This packages source only. It neither updates the installed local service nor
deploys AWS. Runtime archives, private keys, contact settings, and machine-specific
recovery specifications are deliberately outside the source allowlist.
"""
from pathlib import Path
import ast
import hashlib
import io
import json
import os
import re
import stat
import tempfile
import tomllib
import zipfile

ROOT = Path(__file__).resolve().parents[1]
RELEASE_DATE = (2026, 10, 26)
ARCHIVE_ROOT = "heltemes-evidence/"
ALLOW_ROOT = {
    "README.md", "CHANGELOG.md", "pyproject.toml", ".gitignore", ".env.example",
    "Launch.command", "Configure SEC.command", "Activate Local Protection.command",
    "Manage Local Protection.command", "Diagnose Local Protection.command", "Repair Local Protection.command",
    "Review and Back Up Filings.command",
    "Update Local Protection.command",
}
BLOCK_DIRS = {
    "__pycache__", ".terraform", ".git", "data", "backups", "work", "build", ".venv",
    ".heltemes-trust", ".heltemes-keys", "node_modules",
}
LAMBDA_SOURCE = ("cloud/__init__.py", "cloud/handler.py", "heltemes/__init__.py", "heltemes/sec.py")
PRIVATE_KEY = re.compile(br"(?m)^-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----\r?$")
MAX_SOURCE_BYTES = 64 * 1024 * 1024


def allowed(relative):
    """Accept source formats by location, never arbitrary runtime JSON/log files."""
    parts = relative.parts
    if any(part in BLOCK_DIRS for part in parts):
        return False
    if len(parts) == 1:
        return parts[0] in ALLOW_ROOT
    if relative.name.startswith(".env") or any(part.endswith(".egg-info") for part in parts):
        return False
    directory = parts[0]
    if directory in {"scripts", "tests", "cloud"}:
        return relative.suffix == ".py"
    if directory == "heltemes":
        return (relative.suffix == ".py"
                or len(parts) == 3 and parts[1] == "web" and relative.suffix in {".html", ".css", ".js"}
                or relative.as_posix() in {"heltemes/fixtures/demo_submissions.json", "heltemes/web/lessons.json"})
    if directory == "infra":
        return relative.suffix in {".tf", ".hcl"} or relative.name == "terraform.tfvars.example"
    if directory == "docs":
        return relative.suffix == ".md"
    if directory == "examples":
        return relative.as_posix() in {"examples/demo_submissions.json", "examples/lessons.json"}
    return directory == ".github" and relative.suffix in {".yml", ".yaml"}


def source_bytes(root):
    """Capture each source once so its manifest and archived bytes cannot diverge."""
    files, total = {}, 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if not allowed(relative):
            continue
        for ancestor in (path, *path.parents):
            if ancestor == root:
                break
            if ancestor.is_symlink():
                raise ValueError("Release inputs cannot contain symbolic links: " + relative.as_posix())
        if path.is_dir():
            continue
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise ValueError("Release inputs must be ordinary files without hard links: " + relative.as_posix())
            if before.st_size > MAX_SOURCE_BYTES - total:
                raise ValueError("Release source exceeds its size limit.")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                content = handle.read(MAX_SOURCE_BYTES - total + 1)
            after = os.fstat(descriptor)
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or len(content) != before.st_size:
                raise ValueError("Release source changed while reading: " + relative.as_posix())
        finally:
            os.close(descriptor)
        total += len(content)
        if total > MAX_SOURCE_BYTES or PRIVATE_KEY.search(content) or b"openssh-key-v1\x00" in content:
            raise ValueError("Release source contains private-key material or exceeds its size limit.")
        files[relative.as_posix()] = content
    return files


def release_version(files):
    try:
        declared = tomllib.loads(files["pyproject.toml"].decode())["project"]["version"]
        parsed = ast.parse(files["heltemes/__init__.py"].decode())
        versions = [ast.literal_eval(node.value) for node in parsed.body if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets)]
    except (KeyError, ValueError, TypeError, SyntaxError, UnicodeError) as error:
        raise ValueError("Release version metadata is missing or invalid.") from error
    if not isinstance(declared, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", declared) or versions != [declared]:
        raise ValueError("Application and project release versions must match.")
    return declared


def zip_entry(name, date=RELEASE_DATE + (0, 0, 0)):
    entry = zipfile.ZipInfo(name, date)
    entry.compress_type = zipfile.ZIP_DEFLATED
    entry.external_attr = (0o100755 if name.endswith(".command") else 0o100644) << 16
    return entry


def collector_bytes(files):
    """Rebuild the prepared AWS artifact from the exact source being released."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in LAMBDA_SOURCE:
            if name not in files:
                raise ValueError("Required cloud collector source is missing: " + name)
            # Match package_lambda.py's deterministic four-file format.
            archive.writestr(zip_entry(name, (2020, 1, 1, 0, 0, 0)), files[name], compresslevel=9)
    return buffer.getvalue()


def verify_archive(path, files):
    manifest = {name: hashlib.sha256(content).hexdigest() for name, content in sorted(files.items())}
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        expected = {ARCHIVE_ROOT + name for name in files} | {ARCHIVE_ROOT + "RELEASE-MANIFEST.json"}
        if len(names) != len(expected) or set(names) != expected or archive.testzip() is not None:
            raise ValueError("Release archive inventory or ZIP integrity check failed.")
        if json.loads(archive.read(ARCHIVE_ROOT + "RELEASE-MANIFEST.json")) != manifest:
            raise ValueError("Release archive manifest differs from its captured source.")
        for name, digest in manifest.items():
            if hashlib.sha256(archive.read(ARCHIVE_ROOT + name)).hexdigest() != digest:
                raise ValueError("Release archive content differs from its manifest.")
    return manifest


def package(destination=None, *, root=ROOT):
    root = Path(root).resolve()
    files = source_bytes(root)
    version = release_version(files)
    destination = Path(destination) if destination else root.parent / f"HELTEMES-Evidence-v{version}.zip"
    destination = destination.expanduser().absolute()
    checksum = destination.with_suffix(destination.suffix + ".sha256")
    if os.path.lexists(destination) or os.path.lexists(checksum):
        raise FileExistsError("Release archive or checksum already exists; historical artifacts will not be overwritten.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    files["dist/collector.zip"] = collector_bytes(files)
    files["RELEASE.json"] = (json.dumps({"format": "heltemes-source-release", "version": version,
        "release_date": "-".join(f"{part:02d}" for part in RELEASE_DATE), "package_only": True,
        "updates_installed_local_service": False, "deploys_aws": False}, indent=2, sort_keys=True) + "\n").encode()
    manifest = {name: hashlib.sha256(content).hexdigest() for name, content in sorted(files.items())}
    with tempfile.TemporaryDirectory(prefix=".heltemes-release-", dir=destination.parent) as temporary:
        staged = Path(temporary) / "release.zip"
        with zipfile.ZipFile(staged, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, content in sorted(files.items()):
                archive.writestr(zip_entry(ARCHIVE_ROOT + name), content, compresslevel=9)
            archive.writestr(zip_entry(ARCHIVE_ROOT + "RELEASE-MANIFEST.json"),
                             json.dumps(manifest, indent=2, sort_keys=True) + "\n", compresslevel=9)
        verify_archive(staged, files)
        digest = hashlib.sha256(staged.read_bytes()).hexdigest()
        staged_checksum = Path(temporary) / "release.sha256"
        staged_checksum.write_text(f"{digest}  {destination.name}\n")
        for path in (staged, staged_checksum):
            path.chmod(0o644)
            with path.open("rb") as handle:
                os.fsync(handle.fileno())
        # Link exclusively: a concurrent build or historical file is never replaced.
        os.link(staged, destination)
        try:
            os.link(staged_checksum, checksum)
        except BaseException:
            if destination.exists() and os.path.samefile(staged, destination):
                destination.unlink()
            raise
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    return {"archive": str(destination), "checksum": str(checksum), "version": version,
            "release_date": "-".join(f"{part:02d}" for part in RELEASE_DATE),
            "files": len(files), "sha256": digest, "bytes": destination.stat().st_size,
            "installed_service_modified": False, "aws_deployed": False}


if __name__ == "__main__":
    print(json.dumps(package(), indent=2))
