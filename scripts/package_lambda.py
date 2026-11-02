#!/usr/bin/env python3
"""Build a reproducible, source-only Lambda zip. Run from any directory."""

from pathlib import Path
import hashlib
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def package(destination=None):
    destination = Path(destination) if destination else ROOT / "dist" / "collector.zip"
    destination.parent.mkdir(parents=True, exist_ok=True)
    # An explicit allowlist keeps local data, contact settings, dashboard files,
    # Terraform state and unrelated future modules out of the upload.
    files = [ROOT / name for name in ("cloud/__init__.py", "cloud/handler.py", "heltemes/__init__.py", "heltemes/sec.py")]
    if not files or not (ROOT / "heltemes" / "sec.py").is_file():
        raise RuntimeError("SEC collector source is missing")
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            if path.is_symlink() or "__pycache__" in path.parts:
                raise ValueError("Package inputs must be ordinary Python source files")
            info = zipfile.ZipInfo(path.relative_to(ROOT).as_posix(), date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return destination


if __name__ == "__main__":
    artifact = package()
    print(f"Created {artifact}")
    print(f"SHA256 {hashlib.sha256(artifact.read_bytes()).hexdigest()}")
