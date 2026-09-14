"""Strict parent/worker boundary: malformed scanner output never grants access."""

import hashlib
import sys
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Finding(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)
    rule_id: str = Field(min_length=1, max_length=120)
    title: str = Field(min_length=1, max_length=1000)
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    category: str = Field(min_length=1, max_length=120)
    evidence: str = Field(max_length=2000)
    location: str = Field(max_length=4096)
    layer: Literal["VISIBLE_CONTENT", "HIDDEN_CONTENT", "METADATA"]


class Extraction(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    format: str = Field(min_length=1, max_length=32)
    characters: int = Field(ge=0, le=8_000_000)
    segments: int = Field(ge=0, le=20_000)
    truncated: bool


class WorkerReport(BaseModel):
    model_config = ConfigDict(extra="allow", strict=True)
    filename: str = Field(min_length=1, max_length=420)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: Literal["ALLOWED", "FLAGGED", "QUARANTINED", "BLOCKED"]
    risk_score: int = Field(ge=0, le=100)
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    analysis_complete: bool
    findings: list[Finding] = Field(max_length=201)
    extraction: Extraction
    rules_version: str = Field(min_length=1, max_length=100)
    limitations: list[str] = Field(max_length=200)


def validate_worker_report(value, source: bytes) -> dict:
    report = WorkerReport.model_validate(value)
    if sys.platform == "linux":
        sandbox = value.get("sandbox")
        if (not isinstance(sandbox, dict) or sandbox.get("active") is not True or
                sandbox.get("mechanism") != "landlock+seccomp"):
            raise ValueError("Linux worker did not attest required confinement")
    if report.sha256 != hashlib.sha256(source).hexdigest():
        raise ValueError("Worker digest does not match input snapshot")
    if not report.analysis_complete and report.status != "BLOCKED":
        raise ValueError("Incomplete inspection must be blocked")
    if report.analysis_complete and (report.extraction.truncated or
                                   value.get("failure_kind") or
                                   any(f.category == "ANALYSIS_FAILURE" for f in report.findings)):
        raise ValueError("Worker completion contradicts extraction findings")
    if report.analysis_complete:
        severity_order = {name: rank for rank, name in enumerate(("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"))}
        expected_severity = max((finding.severity for finding in report.findings),
                                key=severity_order.get, default="INFO")
        if report.severity != expected_severity:
            raise ValueError("Worker severity contradicts its findings")
        if not report.findings and (report.risk_score != 0 or report.status != "ALLOWED"):
            raise ValueError("Worker decision contradicts an empty findings list")
    return report.model_dump()
