"""Read-only installation check using one real, confined scanner process."""

import json
import platform
import sys

from .linux_sandbox import probe_capabilities
from .reports import worker_environment
from .scan_protocol import validate_worker_report
from .worker_process import run_worker


def check_installation() -> dict:
    capabilities = probe_capabilities()
    result = {"platform": sys.platform, "python": platform.python_version(),
              "capabilities": capabilities, "status": "UNAVAILABLE", "scan_complete": False,
              "sandbox_active": False}
    if not capabilities["available"]:
        result["error"] = capabilities["error"]
        return result
    source = b"Meeting agenda: documentation review on Monday."
    try:
        output = run_worker([sys.executable, "-I", "-m", "integrity_guard.scan_worker", "diagnostic.txt"],
                            input=source, env=worker_environment(), timeout=12)
        report = validate_worker_report(json.loads(output), source)
        if report["status"] != "ALLOWED" or not report["analysis_complete"] or report["findings"]:
            raise RuntimeError("Diagnostic sample could not be fully analyzed")
        result.update(status="READY", scan_complete=True, sandbox_active=True)
    except Exception as exc:
        # No document data or inherited environment is included in diagnostics.
        result["error"] = f"Confined worker check failed: {type(exc).__name__}"
    return result


def main():
    result = check_installation()
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "READY" else 2


if __name__ == "__main__":
    sys.exit(main())
