#!/usr/bin/env python3
"""Build release archives from an explicit allowlist; never package runtime state."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SUPPORTED = {("linux", "amd64"), ("linux", "arm64"), ("darwin", "amd64"),
             ("darwin", "arm64"), ("windows", "amd64")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--os", required=True, choices=["linux", "darwin", "windows"])
    parser.add_argument("--arch", required=True, choices=["amd64", "arm64"])
    parser.add_argument("--version", default="dev")
    parser.add_argument("--package-version", default=None)
    parser.add_argument("--commit", default=None)
    parser.add_argument("--output", type=Path, default=ROOT / "dist" / "aissh")
    args = parser.parse_args()
    if (args.os, args.arch) not in SUPPORTED:
        parser.error("unsupported platform")
    package_version = args.package_version or args.version
    for value in [args.version, package_version]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}", value):
            parser.error("invalid version")
    commit = args.commit or subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        parser.error("commit must be a full 40-character Git SHA")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    name = f"aissh_{package_version}_{args.os}_{args.arch}"
    env = dict(os.environ, CGO_ENABLED="0", GOOS=args.os, GOARCH=args.arch)
    ldflags = ("-s -w -X github.com/fatedier/frp/aissh.Version=" + args.version
               + " -X github.com/fatedier/frp/aissh.Commit=" + commit)
    with tempfile.TemporaryDirectory(prefix="aissh-package-") as tmp:
        stage = Path(tmp) / name
        stage.mkdir()
        for binary in ["aisshs", "aisshc"]:
            target = stage / (binary + (".exe" if args.os == "windows" else ""))
            subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-tags", "noweb",
                            "-ldflags", ldflags, "-o", str(target), "./cmd/" + binary],
                           cwd=ROOT, env=env, check=True)
            target.chmod(0o755)
        # Explicit allowlist: no cert private key, admin password, database or user config.
        for source, destination in [("LICENSE", "LICENSE"), ("README.md", "README.md"),
                                    ("doc/aissh/deployment.md", "deployment.md")]:
            shutil.copyfile(ROOT / source, stage / destination)
        if args.os == "linux":
            shutil.copyfile(ROOT / "deploy/aisshs.service", stage / "aisshs.service")
        (stage / "build-info.json").write_text(json.dumps({
            "version": args.version, "commit": commit, "os": args.os, "arch": args.arch,
            "defaultServer": "connect.builderopc.com",
        }, indent=2) + "\n", encoding="utf-8")
        if args.os == "windows":
            archive = output / (name + ".zip")
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
                for path in sorted(stage.iterdir()):
                    z.write(path, arcname=f"{name}/{path.name}")
        else:
            archive = output / (name + ".tar.gz")
            with tarfile.open(archive, "w:gz") as t:
                for path in sorted(stage.iterdir()):
                    t.add(path, arcname=f"{name}/{path.name}", recursive=False)
    with archive.open("rb") as archive_file:
        digest = hashlib.file_digest(archive_file, "sha256").hexdigest()
    archive.with_name(archive.name + ".sha256").write_text(
        f"{digest}  {archive.name}\n", encoding="utf-8")
    print(archive)


if __name__ == "__main__":
    main()
