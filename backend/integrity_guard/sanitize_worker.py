"""One HTML snapshot transformed in a confined Linux process; stdout is protocol only."""
from __future__ import annotations

import base64
import hashlib
import json
import sys


def main() -> int:
    if sys.platform != "linux":
        sys.stderr.write("SANITIZE_LINUX_REQUIRED\n")
        return 70
    try:
        # Reuse the scanner's actual 512 MiB / 10-second CPU limits unchanged.
        from integrity_guard.scan_worker import constrain_memory
        constrain_memory()
        from integrity_guard.linux_sandbox import apply_sandbox
        confinement = apply_sandbox()
    except Exception:
        sys.stderr.write("SANITIZE_SANDBOX_UNAVAILABLE\n")
        return 70
    try:
        from integrity_guard.html_text import HtmlTextError, MAX_INPUT_BYTES, PROTOCOL, transform_html
        from integrity_guard.sanitize_protocol import MAX_WORKER_OUTPUT
        sandbox = {key: confinement[key] for key in ("active", "mechanism", "landlock_abi")}
        # No source byte is read before both confinement and resource limits.
        source = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        envelope = {"protocol": PROTOCOL, "input_sha256": hashlib.sha256(source).hexdigest(),
                    "transformation_complete": False, "sandbox": sandbox}
        try:
            result = transform_html(source)
            envelope.update(transformation_complete=True, output_sha256=hashlib.sha256(result.data).hexdigest(),
                            output_size_bytes=len(result.data), output_utf8_base64=base64.b64encode(result.data).decode("ascii"),
                            omitted_counts=result.omitted_counts)
        except HtmlTextError as exc:
            envelope["error_code"] = exc.code
        output = json.dumps(envelope, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")
        if len(output) > MAX_WORKER_OUTPUT:
            raise ValueError("bounded output")
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        sys.stderr.write("SANITIZE_WORKER_FAILED\n")
        return 70


if __name__ == "__main__":
    sys.exit(main())
