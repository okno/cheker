"""Package built Linux artifacts; private state and virtualenvs stay outside archives."""

import argparse
import hashlib
import json
import shutil
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

DEV = Path(__file__).resolve().parent
VERSION = "1.0.0"


def package(app: Path, windows: bool = False) -> Path:
    frontend = DEV / "frontend" / "dist"
    source = DEV / "backend" / "integrity_guard"
    wheel = app / "wheels" / f"mcp_integrity_guard-{VERSION}-py3-none-any.whl"
    if not (frontend / "index.html").is_file() or not wheel.is_file():
        raise ValueError("Build frontend and Python wheel before packaging")
    # A stale wheel must never masquerade as the source just tested.
    with zipfile.ZipFile(wheel) as archive:
        expected = {"integrity_guard/" + path.relative_to(source).as_posix(): path
                    for path in source.rglob("*") if path.is_file() and path.suffix in {".py", ".json"}}
        actual = {name for name in archive.namelist()
                  if name.startswith("integrity_guard/") and Path(name).suffix in {".py", ".json"}}
        if actual != set(expected):
            raise ValueError("Stale wheel: package modules differ from current source")
        for name, path in sorted(expected.items()):
            if archive.read(name) != path.read_bytes():
                raise ValueError(f"Stale wheel: rebuild after changing {path.name}")
    app.mkdir(parents=True, exist_ok=True)
    for name, origin in (("ui", frontend), ("examples", DEV / "examples")):
        target = app / name
        if target.is_dir():
            shutil.rmtree(target)
        shutil.copytree(origin, target)
    for path in (DEV / "deploy" / "linux").iterdir():
        if path.is_file():
            shutil.copy2(path, app / path.name)
    shutil.copy2(DEV / "backend" / "requirements-linux.lock", app / "requirements-linux.lock")
    shutil.copy2(DEV / "README.md", app / "README-LINUX.md")
    shutil.copy2(DEV / "CONTRACT.md", app / "CONTRACT.md")
    docs = app / "docs"
    docs.mkdir(exist_ok=True)
    for path in (DEV / "docs").iterdir():
        if path.suffix in {".md", ".service"} and path.name != "REQUISITI_ORIGINALI.md":
            shutil.copy2(path, docs / path.name)
    if windows:
        target = app / "runtime" / "Lib" / "site-packages" / "integrity_guard"
        if not target.parent.is_dir():
            raise ValueError("Optional Windows runtime is not installed")
        if target.is_dir():
            shutil.rmtree(target)
        shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    members = [wheel, app / "requirements-linux.lock", app / "README-LINUX.md", app / "CONTRACT.md"]
    members.extend(app / path.name for path in (DEV / "deploy" / "linux").iterdir() if path.is_file())
    for directory in (app / "ui", app / "examples", docs):
        members.extend(path for path in directory.rglob("*") if path.is_file())
    manifest = {"version": VERSION, "platform": "linux", "built_at": datetime.now(timezone.utc).isoformat(),
                "sha256": {path.relative_to(app).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                           for path in sorted(set(members))}}
    manifest_path = app / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    members.append(manifest_path)
    destination = app / "releases"
    destination.mkdir(exist_ok=True)
    bundle = destination / f"mcp-integrity-guard-{VERSION}-linux.tar.gz"
    with tarfile.open(bundle, "w:gz") as archive:
        # DrvFS often reports 0777 even when Windows ACLs protect the source.
        # Never propagate those writable modes into a native Linux installation.
        root_info = tarfile.TarInfo("mcp-integrity-guard")
        root_info.type = tarfile.DIRTYPE
        root_info.mode = 0o700
        archive.addfile(root_info)
        for path in sorted(set(members)):
            info = archive.gettarinfo(path, arcname=f"mcp-integrity-guard/{path.relative_to(app).as_posix()}")
            info.mode = 0o755 if path.suffix == ".sh" else 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            with path.open("rb") as stream:
                archive.addfile(info, stream)
    checksum = hashlib.sha256(bundle.read_bytes()).hexdigest()
    bundle.with_suffix(bundle.suffix + ".sha256").write_text(f"{checksum}  {bundle.name}\n", encoding="ascii")
    return bundle


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-dir", type=Path, default=DEV.parent / "app")
    parser.add_argument("--with-windows", action="store_true", help="Also update the installed optional Windows package")
    args = parser.parse_args()
    print("Linux application packaged:", package(args.app_dir.resolve(), args.with_windows))
