import hashlib
import json

import pytest

from integrity_guard.core import GuardStore
from integrity_guard.reports import Reports
from integrity_guard.scanner import Scanner


@pytest.mark.parametrize("fault", ["null", "array", "empty", "missing-completion", "digest", "nan", "bool-score", "negative", "score-string", "status", "false-completion", "findings-type", "truncated", "layer", "sandbox"])
def test_malformed_worker_never_authorizes_and_is_recorded(tmp_path, monkeypatch, fault):
    source = b"Meeting notes: Monday review."
    report = Scanner().scan_bytes(source, "notes.txt")
    report["sandbox"] = {"active": True, "mechanism": "landlock+seccomp"}
    if fault == "null": report = None
    elif fault == "array": report = []
    elif fault == "empty": report = {}
    elif fault == "missing-completion": report.pop("analysis_complete")
    elif fault == "digest": report["sha256"] = "0" * 64
    elif fault == "nan": report["risk_score"] = float("nan")
    elif fault == "bool-score": report["risk_score"] = False
    elif fault == "negative": report["risk_score"] = -1
    elif fault == "score-string": report["risk_score"] = "0"
    elif fault == "status": report["status"] = "SAFE"
    elif fault == "false-completion": report["analysis_complete"] = False
    elif fault == "findings-type": report["findings"] = {}
    elif fault == "truncated": report["extraction"]["truncated"] = True
    elif fault == "sandbox":
        import sys
        if sys.platform != "linux": pytest.skip("Linux confinement boundary")
        report["sandbox"]["active"] = "true"
    elif fault == "layer":
        report["findings"] = [{"rule_id":"x","title":"x","severity":"LOW","category":"PROMPT_HINT","evidence":"x","location":"file","layer":"INVALID"}]
    monkeypatch.setattr("integrity_guard.reports.run_worker", lambda *a, **k: json.dumps(report).encode())
    store = GuardStore(tmp_path)
    reports = Reports(tmp_path, store)
    try:
        result = reports.scan(source, "notes.txt")
        assert result["status"] == "BLOCKED"
        assert result["verdict"] == "UNSCANNABLE"
        assert result["analysis_complete"] is False
        assert result["sha256"] == hashlib.sha256(source).hexdigest()
        assert reports.stats()["unscannable"] == 1
        assert store.verify_audit()["valid"]
    finally:
        reports.close()
        store.close()
