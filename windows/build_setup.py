"""Build the single-file x64 .NET 4.8 Cheker installer, without network access."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import zipfile

SOURCE = Path(__file__).resolve().parent
ZIP_SHA256 = 'b626390c9e169d48706a096e83743b5b81eea8df2370c6a5c83d1690db46fb81'
ROOT = 'cheker-windows-anteprima-4/'
COMPILER = Path('/mnt/c/Windows/Microsoft.NET/Framework64/v4.0.30319/csc.exe')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def win(path):
    return subprocess.check_output(['wslpath', '-w', str(path.absolute())], text=True).strip()

def verify_zip(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16 * 1024**2 or sha(path) != ZIP_SHA256:
        raise SystemExit('Expected the immutable preview-4 ZIP; checksum/type/size differs')
    with zipfile.ZipFile(path) as archive:
        seen, hashes, expanded = set(), {}, 0
        for entry in archive.infolist():
            if not entry.filename.startswith(ROOT):
                raise SystemExit('ZIP root differs')
            relative = entry.filename[len(ROOT):]
            parts = PurePosixPath(relative).parts
            if not parts or '/'.join(parts) != relative or relative.startswith('/') or any(p in {'.','..'} or p.endswith(('.', ' ')) or re.search(r'[\\:<>"|?*\x00-\x1f]', p) for p in parts):
                raise SystemExit('Invalid ZIP path')
            if relative.lower() in seen or entry.is_dir() or (entry.external_attr >> 16) & 0xF000 not in {0, 0x8000}:
                raise SystemExit('Duplicate or non-regular ZIP entry')
            seen.add(relative.lower())
            expanded += entry.file_size
            if entry.file_size > 16 * 1024**2 or expanded > 64 * 1024**2:
                raise SystemExit('ZIP expanded limit exceeded')
            hashes[relative] = hashlib.sha256(archive.read(entry)).hexdigest()
        manifest = json.loads(archive.read(ROOT + 'MANIFEST-WINDOWS.json'))
        if len(hashes) != 42 or manifest['sha256'] != {k:v for k,v in hashes.items() if k != 'MANIFEST-WINDOWS.json'}:
            raise SystemExit('Full Windows manifest mismatch')
        return hashes, expanded

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--zip', type=Path, required=True, help='Unchanged cheker-windows-anteprima-4.zip')
    parser.add_argument('--output', type=Path, required=True, help='New EXE output, never overwritten')
    args = parser.parse_args()
    manifest_path = args.output.with_suffix('.manifest.json')
    if args.output.suffix.lower() != '.exe' or args.output.exists() or manifest_path.exists():
        raise SystemExit('Use a new EXE and manifest path')
    hashes, expanded = verify_zip(args.zip)
    source_sha = sha(SOURCE / 'Setup.cs')
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.cheker-setup-build-', dir=args.output.parent) as temp:
        temporary = Path(temp)
        application_manifest = temporary / 'application.manifest'
        application_manifest.write_text('''<?xml version="1.0" encoding="utf-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<assemblyIdentity version="1.0.0.0" name="Cheker.Setup" processorArchitecture="amd64" type="win32"/>
<trustInfo xmlns="urn:schemas-microsoft-com:asm.v3"><security><requestedPrivileges><requestedExecutionLevel level="asInvoker" uiAccess="false"/></requestedPrivileges></security></trustInfo>
<compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1"><application><supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/></application></compatibility>
</assembly>''', encoding='utf-8')
        executable = temporary / 'Cheker-Setup.exe'
        command = [str(COMPILER), '/nologo', '/target:winexe', '/platform:x64', '/optimize+',
                   '/out:' + win(executable), '/win32manifest:' + win(application_manifest),
                   '/resource:' + win(args.zip) + ',Cheker.Payload.zip',
                   '/r:System.Windows.Forms.dll', '/r:System.Drawing.dll', '/r:System.Core.dll',
                   '/r:System.Web.Extensions.dll', '/r:System.IO.Compression.dll',
                   '/r:System.IO.Compression.FileSystem.dll', win(SOURCE / 'Setup.cs')]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise SystemExit(result.stdout + result.stderr)
        if sha(args.zip) != ZIP_SHA256 or sha(SOURCE / 'Setup.cs') != source_sha:
            raise SystemExit('Build input changed')
        # Exclusive final creation; an existing installer is never replaced.
        with args.output.open('xb') as output:
            output.write(executable.read_bytes())
    manifest = {'platform':'windows-x64', 'framework':'.NET Framework 4.8', 'authenticode_signed':False,
                'network_during_build':False, 'zip':str(args.zip.absolute()), 'zip_sha256':ZIP_SHA256,
                'embedded_file_count':len(hashes), 'embedded_expanded_bytes':expanded,
                'embedded_sha256':hashes, 'source_sha256':source_sha, 'builder_sha256':sha(Path(__file__)),
                'compiler':str(COMPILER), 'compiler_sha256':sha(COMPILER),
                'exe':str(args.output.absolute()), 'exe_sha256':sha(args.output),
                'verification':'Build only; functional extraction evidence is recorded separately.'}
    with manifest_path.open('x', encoding='utf-8') as output:
        json.dump(manifest, output, indent=2); output.write('\n')
    print(json.dumps({'exe':str(args.output), 'exe_sha256':manifest['exe_sha256'], 'manifest':str(manifest_path)}))

if __name__ == '__main__':
    main()
