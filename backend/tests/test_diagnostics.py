import sys

import pytest

from integrity_guard import diagnostics


def test_missing_sandbox_is_actionable_and_does_not_scan(monkeypatch):
    monkeypatch.setattr(diagnostics, "probe_capabilities", lambda: {
        "available": False, "error": "Landlock is disabled", "landlock_abi": None,
        "libseccomp_api": None})
    monkeypatch.setattr(diagnostics, "run_worker", lambda *args, **kwargs: pytest.fail("must not scan"))
    result = diagnostics.check_installation()
    assert result["status"] == "UNAVAILABLE"
    assert not result["sandbox_active"]
    assert result["error"] == "Landlock is disabled"


def test_worker_failure_is_not_reported_as_ready(monkeypatch):
    monkeypatch.setattr(diagnostics, "probe_capabilities", lambda: {"available": True})
    def failed(*args, **kwargs):
        raise RuntimeError("document-secret-must-not-be-in-error")
    monkeypatch.setattr(diagnostics, "run_worker", failed)
    result = diagnostics.check_installation()
    assert result["status"] == "UNAVAILABLE"
    assert "document-secret" not in str(result)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux installation diagnostic")
def test_real_confined_worker_reports_ready():
    result = diagnostics.check_installation()
    if not result["capabilities"]["available"]:
        pytest.skip(result["error"])
    assert result["status"] == "READY", result
    assert result["sandbox_active"] and result["scan_complete"]
