#!/usr/bin/env python3
"""Prepare an isolated, content-addressed backend from the locked btls-sys crate.

Never edits Cargo's registry cache. Prints only the resulting source path.
The crate checksum is verified by Cargo; git apply fails closed on patch drift.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def prepare():
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version=1"], cwd=ROOT))
    package, = [p for p in metadata["packages"] if p["name"] == "btls-sys"]
    assert package["version"] == "0.5.6", "review the patch before updating btls-sys"
    crate = Path(package["manifest_path"]).parent
    patches = [crate / "patches" / name for name in (
        "boring-pq.patch", "boringssl.patch", "boringssl-loongarch.patch", "boringssl-windows.patch")]
    patches.append(ROOT / "scripts/patches/bridge-tls.patch")
    patches.append(ROOT / "scripts/patches/bridge-hybrid-groups.patch")
    patches.append(ROOT / "scripts/patches/bridge-mldsa.patch")
    digest = hashlib.sha256(b"btls-sys=0.5.6\0" + b"".join(p.read_bytes() for p in patches)).hexdigest()
    parent = Path(metadata["target_directory"]) / "bridge-native"
    destination = parent / digest
    if (destination / ".bridge-ready").is_file():
        return destination
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=parent) as temporary:
        source = Path(temporary) / "source"
        shutil.copytree(crate / "deps/boringssl", source, ignore=shutil.ignore_patterns(".git"))
        subprocess.run(["git", "init", "--quiet"], cwd=source, check=True)
        for patch in patches:
            subprocess.run(["git", "apply", "--check", str(patch)], cwd=source, check=True)
            subprocess.run(["git", "apply", str(patch)], cwd=source, check=True)
        (source / ".bridge-ready").write_text(digest + "\n")
        try:
            source.rename(destination)
        except OSError:
            if not (destination / ".bridge-ready").is_file():
                raise
    return destination


if __name__ == "__main__":
    print(prepare())
