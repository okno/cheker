"""Verify release checksums before installation; this is not signature verification."""
import hashlib
import json
import sys
from pathlib import Path, PurePosixPath


def verify(root: Path) -> list[str]:
    manifest = json.loads((root / "release-manifest.json").read_text(encoding="utf-8"))
    entries = manifest.get("sha256")
    if not isinstance(entries, dict) or not entries:
        raise ValueError("Manifest contains no checksums")
    failures = []
    for relative, digest in entries.items():
        path = PurePosixPath(relative)
        if path.is_absolute() or ".." in path.parts or "\\" in relative or not path.parts:
            raise ValueError("Invalid manifest path")
        candidate = root.joinpath(*path.parts)
        if candidate.resolve() != candidate.absolute() or candidate.is_symlink():
            failures.append(relative + ": symbolic links are not accepted")
        elif not candidate.is_file():
            failures.append(relative + ": missing")
        elif hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
            failures.append(relative + ": checksum mismatch")
    return failures


if __name__ == "__main__":
    try:
        problems = verify(Path(__file__).resolve().parent)
        if problems:
            print("Release verification failed:\n" + "\n".join(problems), file=sys.stderr)
            raise SystemExit(2)
        print("Release checksums verified.")
    except (OSError, ValueError, TypeError) as exc:
        print("Release verification failed: " + str(exc), file=sys.stderr)
        raise SystemExit(2)
