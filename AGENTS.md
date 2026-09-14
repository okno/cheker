# MCP Integrity Guard

All source and application artifacts live under D:\Cheker (WSL /mnt/d/Cheker).
Development source is in dev; distributable application is in app.
Python backend package: backend/integrity_guard. React/TypeScript UI: frontend.
Do not execute scanned files or discovered MCP commands. No external telemetry.
Use real persisted data, fail closed at enforcement boundaries, redact secrets in API responses and audit.
Tests must cover content-bound approvals, tamper detection, scanner limits, and enforcement failures.
