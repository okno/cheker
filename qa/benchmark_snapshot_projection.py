"""Reproduce the previously observed benchmark; not run when evidence was saved.

Synthetic stores are confined to an automatically deleted temporary directory.
This pins the measured baseline and checks the measured projection's source hash.
"""
import hashlib
import json
import statistics
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path

from integrity_guard import core

repository = Path(__file__).resolve().parents[1]
baseline_commit = "b728fbb3a01354542f8c821ca0f60c28d676dc7d"
source = subprocess.check_output(
    ["git", "-C", str(repository), "show", f"{baseline_commit}:backend/integrity_guard/core.py"]
)
assert hashlib.sha256(source).hexdigest() == "533d46d9fa3f0d496f656cd5aa97719149e9d74050880f05af32efae484d81b8"
assert hashlib.sha256(Path(core.__file__).read_bytes()).hexdigest() == "cf50c080732dfb725c45a030051ee8a4d3e2da9dc0cea5b0546cb43180ffe395"
baseline = types.ModuleType("integrity_guard._projection_baseline")
baseline.__package__ = "integrity_guard"
sys.modules[baseline.__name__] = baseline
exec(compile(source, "<baseline-core>", "exec"), baseline.__dict__)

results = {}
with tempfile.TemporaryDirectory(prefix="cheker-projection-bench-") as directory:
    root = Path(directory)
    config = root / "catalog.json"
    config.write_text(json.dumps({
        "metadata": "safe " * 410,
        "tools": [{"name": f"tool-{index}", "description": "Read inventory"} for index in range(100)],
    }))
    for label, module in (("baseline", baseline), ("projection", core)):
        module.config_findings = lambda *args, **kwargs: []
        store = module.GuardStore(root / label)
        try:
            store.discover(config)
            with store._atomic_updates():
                for index in range(2000):
                    store.append_audit("BENCHMARK", None, {"iteration": index})
            store.verify_audit(fast=True)
            store.list_components()
            timings = []
            for _ in range(15):
                start = time.perf_counter()
                rows = store.list_components()
                timings.append((time.perf_counter() - start) * 1000)
            if label == "projection":
                assert all(row["snapshot_valid"] for row in rows)
            results[label] = {
                "components": len(rows),
                "audit_events": store._db.execute("SELECT COUNT(*) FROM audit").fetchone()[0],
                "snapshot_bytes": store._db.execute("SELECT SUM(length(content)+length(record)) FROM components").fetchone()[0],
                "median_ms": round(statistics.median(timings), 2),
                "max_ms": round(max(timings), 2),
                "iterations": len(timings),
            }
        finally:
            store.close()
print(json.dumps(results, indent=2))
