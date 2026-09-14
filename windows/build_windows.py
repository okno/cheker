"""Build the x64 WinForms/WebView2 package from a verified Linux release in WSL."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile
import zipfile

SDK_VERSION = "1.0.4191.47"
SDK_SHA256 = "f492bbf547d0da329553b6727435b677579b1e9f91cc9e4a1ad029366d5f23d0"
SOURCE = Path(__file__).resolve().parent

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def win(path):
    return subprocess.check_output(["wslpath", "-w", str(path.absolute())], text=True).strip()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-release", type=Path, required=True)
    parser.add_argument("--linux-sha256", required=True)
    parser.add_argument("--sdk-package", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if sha(args.linux_release) != args.linux_sha256:
        raise SystemExit("Linux archive checksum mismatch")
    if sha(args.sdk_package) != SDK_SHA256:
        raise SystemExit("WebView2 SDK checksum mismatch")
    if args.output.exists() or args.output.with_suffix(".zip").exists():
        raise SystemExit("Use a new output directory")
    args.output.mkdir(parents=True, mode=0o700)
    with tarfile.open(args.linux_release, "r:gz") as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if member.isdir() and path == PurePosixPath("mcp-integrity-guard"):
                continue
            if not member.isfile() or path.is_absolute() or ".." in path.parts or len(path.parts) < 2 or path.parts[0] != "mcp-integrity-guard":
                raise SystemExit("Unexpected Linux archive member")
            target = args.output / "linux" / Path(*path.parts[1:])
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.extractfile(member).read())
            target.chmod(0o600)
    subprocess.run(["python3", "-I", str(args.output / "linux/verify-release.py")], check=True)
    mapping = {
        "lib/net462/Microsoft.Web.WebView2.Core.dll": "Microsoft.Web.WebView2.Core.dll",
        "lib/net462/Microsoft.Web.WebView2.WinForms.dll": "Microsoft.Web.WebView2.WinForms.dll",
        "runtimes/win-x64/native/WebView2Loader.dll": "WebView2Loader.dll",
        "LICENSE.txt": "licenze/WebView2-LICENSE.txt",
        "NOTICE.txt": "licenze/WebView2-NOTICE.txt",
    }
    with zipfile.ZipFile(args.sdk_package) as sdk:
        for source, destination in mapping.items():
            target = args.output / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(sdk.read(source))
    for name in ("desktop_bridge.py", "LEGGIMI.html"):
        shutil.copy2(SOURCE / name, args.output / name)
    shutil.copy2(SOURCE.parent / "branding/cheker-logomark.png", args.output / "cheker.png")
    compiler = "/mnt/c/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe"
    command = [compiler, "/nologo", "/target:winexe", "/platform:x64", "/optimize+",
               "/out:" + win(args.output / "Cheker.exe"), "/r:System.Windows.Forms.dll", "/r:System.Drawing.dll",
               "/r:System.Net.Http.dll", "/r:System.Web.Extensions.dll",
               "/r:" + win(args.output / "Microsoft.Web.WebView2.Core.dll"),
               "/r:" + win(args.output / "Microsoft.Web.WebView2.WinForms.dll"), win(SOURCE / "Cheker.cs")]
    subprocess.run(command, check=True)
    (args.output / "Cheker.exe.config").write_text('<?xml version="1.0"?><configuration><startup><supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.8"/></startup></configuration>', encoding="utf-8")
    manifest = {"platform": "windows-x64-wsl2", "native_scanning": False, "authenticode_signed": False,
                "webview2_sdk": SDK_VERSION, "webview2_sdk_sha256": SDK_SHA256,
                "linux_archive_sha256": args.linux_sha256,
                "sha256": {p.relative_to(args.output).as_posix(): sha(p) for p in sorted(args.output.rglob("*")) if p.is_file()}}
    (args.output / "MANIFEST-WINDOWS.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    archive = args.output.with_suffix(".zip")
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(args.output.rglob("*")):
            if path.is_file():
                bundle.write(path, args.output.name + "/" + path.relative_to(args.output).as_posix())
    print(json.dumps({"directory": str(args.output), "exe_sha256": sha(args.output / "Cheker.exe"), "zip": str(archive), "zip_sha256": sha(archive)}))

if __name__ == "__main__":
    main()
