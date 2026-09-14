"""Strict, separate transformation protocol; validated bytes still require scanning.

No scanner report schema or authorization status is extended by this module.
Only the dedicated transformation worker may emit text in this protocol. The
caller must scan the returned data and require a complete VALID/ALLOWED report
for those exact bytes before returning any content to a consumer.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .html_text import ERROR_MESSAGES, MAX_INPUT_BYTES, MAX_NODES, MAX_OUTPUT_BYTES, PROTOCOL

MAX_WORKER_OUTPUT = 1024 * 1024
_MAX_BASE64 = 4 * ((MAX_OUTPUT_BYTES + 2) // 3)


class SanitizeProtocolError(ValueError):
    def __init__(self):
        super().__init__("Invalid transformation worker response.")


class SanitizationRejected(ValueError):
    def __init__(self, code: str):
        self.code = code if code in ERROR_MESSAGES else "TRANSFORM_FAILED"
        super().__init__(ERROR_MESSAGES[self.code])


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _Sandbox(_Strict):
    active: bool
    mechanism: Literal["landlock+seccomp"]
    landlock_abi: int = Field(ge=3, le=1_000_000)


class _Counts(_Strict):
    comments: int = Field(ge=0, le=MAX_NODES)
    hidden_nodes: int = Field(ge=0, le=MAX_NODES)
    metadata_nodes: int = Field(ge=0, le=MAX_NODES)
    active_nodes: int = Field(ge=0, le=MAX_NODES)
    nontext_nodes: int = Field(ge=0, le=MAX_NODES)
    attributes: int = Field(ge=0, le=MAX_NODES * 32)


class _Common(_Strict):
    protocol: Literal["html-text-v1"]
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    transformation_complete: bool
    sandbox: _Sandbox


class _Success(_Common):
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_size_bytes: int = Field(gt=0, le=MAX_OUTPUT_BYTES)
    output_utf8_base64: str = Field(min_length=4, max_length=_MAX_BASE64)
    omitted_counts: _Counts


class _Failure(_Common):
    error_code: str = Field(min_length=1, max_length=64)


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SanitizeProtocolError()
        value[key] = item
    return value


def _nonfinite(_):
    raise SanitizeProtocolError()


def validate_sanitize_output(output: bytes, source: bytes) -> dict:
    """Return verified UTF-8 bytes as result['data'], never an authorization.

    Structured worker refusals raise SanitizationRejected with a fixed code;
    malformed output raises SanitizeProtocolError with no reflected source text.
    Accepted envelopes are bounded, strict and bound to the exact input snapshot.
    """
    if (not isinstance(output, bytes) or not 0 < len(output) <= MAX_WORKER_OUTPUT
            or not isinstance(source, bytes) or len(source) > MAX_INPUT_BYTES):
        raise SanitizeProtocolError()
    try:
        value = json.loads(output.decode("utf-8", errors="strict"), object_pairs_hook=_object, parse_constant=_nonfinite)
        if not isinstance(value, dict) or type(value.get("transformation_complete")) is not bool:
            raise SanitizeProtocolError()
        complete = value["transformation_complete"]
        model = (_Success if complete else _Failure).model_validate(value)
        if model.input_sha256 != hashlib.sha256(source).hexdigest() or model.sandbox.active is not True:
            raise SanitizeProtocolError()
        if not complete:
            if model.error_code not in ERROR_MESSAGES:
                raise SanitizeProtocolError()
            raise SanitizationRejected(model.error_code)
        data = base64.b64decode(model.output_utf8_base64, validate=True)
        if (not 0 < len(data) <= MAX_OUTPUT_BYTES or len(data) != model.output_size_bytes
                or hashlib.sha256(data).hexdigest() != model.output_sha256
                or base64.b64encode(data).decode("ascii") != model.output_utf8_base64):
            raise SanitizeProtocolError()
        text = data.decode("utf-8", errors="strict")
        if (text.startswith("\ufeff") or not text.strip() or not text.endswith("\n") or "\r" in text
                or any(ord(char) < 32 and char not in "\n\t" or ord(char) == 127 for char in text)):
            raise SanitizeProtocolError()
        return {"protocol": PROTOCOL, "input_sha256": model.input_sha256,
                "output_sha256": model.output_sha256, "output_size_bytes": len(data),
                "omitted_counts": model.omitted_counts.model_dump(), "sandbox": model.sandbox.model_dump(),
                "data": data}
    except SanitizationRejected:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, binascii.Error, RecursionError, ValidationError):
        raise SanitizeProtocolError() from None
