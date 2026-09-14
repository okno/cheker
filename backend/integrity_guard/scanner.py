"""Deterministic multilayer prompt-injection scanner. Findings are evidence, not a safety proof."""
from __future__ import annotations

import base64
import binascii
import codecs
import hashlib
import html
import json
import re
import time
import unicodedata
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, unquote_plus

from .extraction import Budget, ExtractionError, Segment, extract, failure_kind

INVISIBLE = re.compile("[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff\U000e0000-\U000e007f]")
# Unicode Emoji 17.0 / UTS #51: only these three tag flags are RGI.
# Exempt complete sequences from the anomaly signal, never surrounding tags.
RGI_TAG_FLAGS = tuple("\U0001f3f4" + "".join(chr(0xE0000 + ord(c)) for c in subdivision) + "\U000e007f"
                      for subdivision in ("gbeng", "gbsct", "gbwls"))
INVISIBLE_OUTSIDE_FLAGS = re.compile("(?:" + "|".join(map(re.escape, RGI_TAG_FLAGS)) + ")|(?P<invisible>" + INVISIBLE.pattern + ")")
BIDI = re.compile("[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
CONFUSABLES = str.maketrans({
    "а": "a", "А": "A", "е": "e", "Е": "E", "о": "o", "О": "O", "р": "p", "Р": "P", "с": "c", "С": "C", "у": "y", "У": "Y", "х": "x", "Х": "X", "і": "i", "І": "I", "ј": "j", "Ј": "J", "ѕ": "s", "Ѕ": "S", "ԁ": "d", "Ԍ": "G", "ӏ": "l", "ԛ": "q", "ѵ": "v", "ԝ": "w", "ԍ": "g", "п": "n", "т": "t",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "ο": "o", "ι": "i", "ρ": "p", "ϲ": "c", "ν": "v",
})
TOKEN = re.compile(r"(?<![\w+/=-])[A-Za-z0-9+/_-]{20,}={0,2}(?![\w+/=-])")
HEX = re.compile(r"(?<!\w)(?:0x)?(?:[0-9a-fA-F]{2}){10,}(?!\w)")
B64_LINES = re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{8,}[ \t]*\r?\n){1,128}[A-Za-z0-9+/]{4,}={0,2}(?![A-Za-z0-9+/=])")
HEX_SPACED = re.compile(r"(?<!\w)(?:[0-9a-fA-F]{2}[ \t:-]){7,}[0-9a-fA-F]{2}(?!\w)")
SEVERITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def redact_evidence(text: str) -> str:
    """Best-effort bounded evidence redaction; original file bytes are never in reports."""
    text = re.sub(r"-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)", "[REDACTED PRIVATE KEY]", text, flags=re.I)
    text = re.sub(r"(?i)(\b(?:[\w.-]*(?:secret|password|passwd|token|api[_-]?key|credential)[\w.-]*|authorization)\b[\"']?\s*[:=]\s*)(?:[\"'][^\"'\r\n]*[\"']|[^\s,;<>]+)", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)\bBearer\s+[^\s\"'<>]+", "Bearer [REDACTED]", text)
    text = re.sub(r"(?i)(https?://)[^\s/@]+:[^\s/@]+@", r"\1[REDACTED]@", text)
    text = re.sub(r"(?i)([?&](?:token|key|secret|password|api_key|access_token)=)[^&\s]+", r"\1[REDACTED]", text)
    text = re.sub(r"\b(?:sk-[\w-]{8,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{12,}|[A-Za-z0-9+/_=-]{28,})\b", "[REDACTED TOKEN]", text)
    return INVISIBLE.sub(lambda m: ("\\u%04x" if ord(m.group()) <= 0xffff else "\\U%08x") % ord(m.group()), text)[:420]


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(CONFUSABLES)
    text = text.translate(str.maketrans({"’": "'", "‘": "'", "“": '"', "”": '"', "‐": "-", "‑": "-"}))
    text = INVISIBLE.sub("", text)
    text = "".join(ch for ch in unicodedata.normalize("NFD", text) if unicodedata.category(ch) != "Mn")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return re.sub(r"[\t\f\v ]+", " ", text).casefold().strip(" ")


def _printable(text: str) -> bool:
    return len(text) >= 8 and sum(ch.isprintable() or ch.isspace() for ch in text) / len(text) >= .93 and "\x00" not in text


def required_literal_alternatives(pattern: str) -> tuple[str, ...]:
    """Return a necessary OR-condition for matching, or disable optimization.

    A sequence must satisfy every required child; we select one useful condition.
    Every branch must supply a condition before branch alternatives can be combined.
    Optional repeats and unknown constructs supply no condition. CPython's parser is
    an optional optimization dependency: unavailable/changed syntax falls back to
    the full regex. Manual keyword lists never exclude a detection.
    """
    try:
        from re import _parser
        parsed = _parser.parse(pattern, re.I | re.S)

        def condition(nodes, depth=0):
            if depth > 24:
                return ()
            choices, run = [], []

            def flush():
                if len(run) >= 3:
                    choices.append(frozenset({"".join(run)}))
                run.clear()

            for operation, argument in nodes:
                name = str(operation)
                if name == "LITERAL":
                    run.append(chr(argument))
                    continue
                flush()
                child = ()
                if name == "SUBPATTERN":
                    child = condition(argument[-1], depth + 1)
                elif name in {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"} and argument[0] > 0:
                    child = condition(argument[-1], depth + 1)
                elif name == "BRANCH":
                    branches = [condition(branch, depth + 1) for branch in argument[1]]
                    if branches and all(branches):
                        child = frozenset().union(*branches)
                elif name == "ATOMIC_GROUP":
                    child = condition(argument, depth + 1)
                if child and len(child) <= 16 and all(len(item) >= 3 for item in child):
                    choices.append(frozenset(child))
            flush()
            return min(choices, key=lambda values: (len(values), -min(map(len, values)), -sum(map(len, values)))) if choices else ()

        return tuple(sorted(condition(parsed)))
    except Exception:
        # If the optional parser cannot prove a condition, run the complete rule.
        return ()


class Scanner:
    def __init__(self, rules_path: Path | None = None, max_input_size: int = 10_485_760, timeout: float = 8.0):
        self.max_input_size = int(max_input_size)
        self.timeout = float(timeout)
        if not 0 < self.max_input_size <= 100_000_000 or not 0 < self.timeout <= 120:
            raise ValueError("Invalid scanner limits")
        self.rules = json.loads((Path(rules_path) if rules_path else Path(__file__).with_name("rules.json")).read_text(encoding="utf-8"))
        if not isinstance(self.rules.get("version"), str) or not isinstance(self.rules.get("rules"), list):
            raise ValueError("Rules require a version and rules array")
        self.compiled = []
        self.literal_filters = {}
        self.literal_patterns = {}
        identifiers = set()
        for rule in self.rules["rules"]:
            if rule["id"] in identifiers or rule["severity"] not in SEVERITY or not 0 <= rule["score"] <= 100:
                raise ValueError("Invalid or duplicate scanner rule")
            identifiers.add(rule["id"])
            for language, patterns in rule["patterns"].items():
                for pattern in patterns:
                    compiled = re.compile(pattern, re.I | re.S)
                    self.compiled.append((rule, language, compiled))
                    literals = required_literal_alternatives(pattern) if self.rules.get("enable_literal_prefilters", True) is True else ()
                    self.literal_filters[compiled] = literals
                    for literal in literals:
                        self.literal_patterns.setdefault(literal, re.compile(re.escape(literal), re.I))
        limits = self.rules.get("limits", {})
        self.max_depth = min(3, max(1, int(limits.get("max_decode_depth", 3))))
        self.max_ratio = min(10, max(1, int(limits.get("max_expansion_ratio", 6))))
        self.max_candidates = min(2048, max(1, int(limits.get("max_candidates", 512))))
        self.max_findings = min(200, max(1, int(limits.get("max_findings", 120))))
        self.thresholds = self.rules.get("thresholds", {"flag": 20, "quarantine": 60, "block": 80})
        if not 1 <= self.thresholds["flag"] < self.thresholds["quarantine"] < self.thresholds["block"] <= 100:
            raise ValueError("Invalid scanner score thresholds")

    def scan_bytes(self, data: bytes, filename: str) -> dict:
        started = time.perf_counter()
        filename = str(filename).replace("\\", "/").rsplit("/", 1)[-1][:200]
        report = {"id": str(uuid.uuid4()), "filename": redact_evidence(filename), "sha256": hashlib.sha256(data).hexdigest(),
                  "status": "BLOCKED", "risk_score": 100, "severity": "CRITICAL", "findings": [],
                  "analysis_complete": False,
                  "extraction": {"format": filename.rsplit(".", 1)[-1].lower() if "." in filename else "unknown", "characters": 0, "segments": 0, "truncated": False},
                  "rules_version": self.rules["version"], "created_at": datetime.now(timezone.utc).isoformat(), "duration_ms": 0,
                  "limitations": ["Heuristic detection can miss novel or contextual attacks. ALLOWED means no configured rule reached the decision threshold; it is not a safety guarantee. Original content is never executed or semantically sanitized."]}
        budget = Budget(self.timeout, max_chars=min(8_000_000, max(100_000, len(data) * 30)))
        try:
            if len(data) > self.max_input_size:
                raise ExtractionError("File exceeds configured input size limit", "INPUT_SIZE_LIMIT")
            extraction = extract(data, filename, budget)
            report["extraction"] = {"format": extraction.format, "characters": extraction.characters, "segments": len(extraction.segments), "truncated": extraction.truncated}
            report["limitations"].extend(extraction.limitations)
            findings, scores = self._analyze(extraction.segments, budget)
            report["findings"] = findings
            score = min(100, sum(scores.values()))
            report["risk_score"] = score
            report["severity"] = max((item["severity"] for item in findings), key=SEVERITY.get, default="INFO")
            report["status"] = ("BLOCKED" if score >= self.thresholds["block"] else "QUARANTINED" if score >= self.thresholds["quarantine"] else "FLAGGED" if score >= self.thresholds["flag"] else "ALLOWED")
            report["analysis_complete"] = True
        except ExtractionError as exc:
            report["failure_kind"] = failure_kind(exc.code)
            report["extraction"]["truncated"] = report["failure_kind"] == "RESOURCE_LIMIT"
            report["findings"].append({"rule_id": exc.code, "title": str(exc), "severity": "CRITICAL", "category": "ANALYSIS_FAILURE", "failure_kind": report["failure_kind"], "evidence": "Inspection did not complete; content is not approved for agent consumption.", "location": "document", "layer": "METADATA"})
            report["limitations"].append(str(exc))
        except Exception as exc:
            report["failure_kind"] = "RESOURCE_LIMIT" if isinstance(exc, (MemoryError, RecursionError)) else "INTERNAL_ERROR"
            if report["failure_kind"] == "RESOURCE_LIMIT":
                report["extraction"]["truncated"] = True
            report["findings"].append({"rule_id": "SCANNER_FAILURE", "title": "Analysis failed closed", "severity": "CRITICAL", "category": "ANALYSIS_FAILURE", "failure_kind": report["failure_kind"], "evidence": type(exc).__name__, "location": "document", "layer": "METADATA"})
            report["limitations"].append("Scanner could not complete inspection.")
        report["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
        return report

    def _analyze(self, segments: list[Segment], budget: Budget):
        findings, scores = [], {}
        seen_findings = set()
        expanded = 0
        candidates_count = 0
        total_source = sum(len(segment.text) for segment in segments)
        max_expansion = min(8_000_000, max(64_000, total_source * self.max_ratio))

        def add(rule_id, title, severity, category, score, text, segment, encoding="plain", start=0, end=None):
            key = (rule_id, segment.location, encoding, segment.layer)
            if key in seen_findings:
                return
            if len(findings) >= self.max_findings:
                raise ExtractionError("Finding count budget exhausted", "FINDINGS_LIMIT")
            seen_findings.add(key)
            end = min(len(text), start + 160) if end is None else end
            evidence = redact_evidence(text[max(0, start - 60): min(len(text), end + 120)])
            findings.append({"rule_id": rule_id, "title": title, "severity": severity, "category": category, "evidence": evidence,
                             "location": segment.location, "layer": segment.layer, "line": text.count("\n", 0, start) + 1, "encoding": encoding})
            scores[rule_id] = max(scores.get(rule_id, 0), score)

        for segment in segments:
            budget.check()
            original = segment.text
            invisible = next((match for match in INVISIBLE_OUTSIDE_FLAGS.finditer(original)
                              if match.lastgroup == "invisible"), None)
            if BIDI.search(original):
                add("BIDI_CONTROL", "Bidirectional controls can conceal or reorder instructions", "MEDIUM", "UNICODE_ANOMALY", 30, original, segment, start=BIDI.search(original).start())
            elif invisible:
                add("INVISIBLE_CHARACTERS", "Invisible Unicode characters in content", "LOW", "UNICODE_ANOMALY", 20, original, segment, start=invisible.start())
            queue = deque([(original, 0, "plain")])
            seen_text = {hashlib.sha256(original.encode("utf-8")).digest()}
            while queue:
                budget.check()
                text, depth, encoding = queue.popleft()
                clean = normalize(text)
                ascii_text = clean.isascii()
                literal_matches = {}

                def contains_literal(literal):
                    if literal not in literal_matches:
                        # For non-ASCII input, use the regex engine's own folding
                        # semantics (e.g. dotless i), never a guessed word fold.
                        literal_matches[literal] = (literal.lower() in clean if ascii_text and literal.isascii()
                                                    else bool(self.literal_patterns[literal].search(clean)))
                    return literal_matches[literal]

                matched = False
                strong_match = False
                for rule, language, pattern in self.compiled:
                    budget.check()
                    literals = self.literal_filters.get(pattern, ())
                    if literals and not any(contains_literal(literal) for literal in literals):
                        continue
                    match = pattern.search(clean)
                    if match:
                        matched = True
                        strong_match |= rule["severity"] in {"HIGH", "CRITICAL"}
                        add(rule["id"], rule["title"], rule["severity"], rule["category"], rule["score"], clean, segment, encoding, match.start(), match.end())
                if matched:
                    if encoding != "plain":
                        add("ENCODED_INSTRUCTION" if strong_match else "ENCODED_PROMPT_HINT", "Instruction or prompt-like text recovered from encoded content", "HIGH" if strong_match else "MEDIUM", "OBFUSCATION" if strong_match else "PROMPT_HINT", 20, clean, segment, encoding)
                    if segment.layer != "VISIBLE_CONTENT" and segment.location != "html:source-markup":
                        add("HIDDEN_INSTRUCTION" if strong_match else "HIDDEN_PROMPT_HINT", "Instruction or prompt-like text appears in hidden content or metadata", "HIGH" if strong_match else "MEDIUM", "HIDDEN_CONTENT" if strong_match else "PROMPT_HINT", 20, clean, segment, encoding)
                    if text.translate(CONFUSABLES) != text or INVISIBLE.search(text) or unicodedata.normalize("NFKC", text) != text:
                        add("UNICODE_INSTRUCTION" if strong_match else "UNICODE_PROMPT_HINT", "Instruction or prompt-like text recovered through Unicode normalization", "HIGH" if strong_match else "MEDIUM", "UNICODE_OBFUSCATION" if strong_match else "PROMPT_HINT", 20, clean, segment, encoding)
                if depth >= self.max_depth:
                    # A pending transform at the boundary is uninspected content,
                    # including mixed encoding + concatenation, not only Base64.
                    for decoded, _ in self._variants(text, budget):
                        budget.check()
                        if hashlib.sha256(decoded.encode("utf-8")).digest() not in seen_text:
                            raise ExtractionError("Maximum nested decoding depth reached", "DECODING_LIMIT")
                    continue
                for decoded, name in self._variants(text, budget):
                    budget.check()
                    candidates_count += 1
                    if candidates_count > self.max_candidates:
                        raise ExtractionError("Decoding candidate budget exhausted", "DECODING_LIMIT")
                    digest = hashlib.sha256(decoded.encode("utf-8")).digest()
                    if digest in seen_text:
                        continue
                    seen_text.add(digest)
                    expanded += len(decoded)
                    if expanded > max_expansion:
                        raise ExtractionError("Decoded content expansion limit exceeded", "EXPANSION_LIMIT")
                    queue.append((decoded, depth + 1, name if encoding == "plain" else encoding + ">" + name))
        return findings, scores

    @staticmethod
    def _variants(text, budget):
        # Whole-string transformations preserve context around encoded words.
        if re.search(r"%[0-9a-fA-F]{2}", text):
            decoded = unquote(text, errors="strict")
            if decoded != text:
                yield decoded, "url"
        if "+" in text and (re.search(r"%[0-9a-fA-F]{2}", text) or re.search(r"(?:[A-Za-z]+\+){3,}[A-Za-z]+", text)):
            decoded = unquote_plus(text, errors="strict")
            if decoded != text:
                yield decoded, "url-form"
        if re.search(r"&(?:#[xX]?[0-9a-fA-F]+|[a-zA-Z]+);", text):
            decoded = html.unescape(text)
            if decoded != text:
                yield decoded, "html-entity"
        if re.search(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|U[0-9a-fA-F]{8})", text):
            def unescape(match):
                codepoint = int(match.group()[2:], 16)
                return chr(codepoint) if codepoint <= 0x10FFFF and not 0xD800 <= codepoint <= 0xDFFF else " "
            yield re.sub(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|U[0-9a-fA-F]{8})", unescape, text), "unicode-escape"
        joined = re.sub(r"[\"'`]\s*\+\s*[\"'`]", "", text)
        if joined != text:
            yield joined, "string-concatenation"
        spaced = re.sub(r"(?<!\w)(?:[A-Za-z][ \t\r\n]){3,}[A-Za-z](?!\w)", lambda m: re.sub(r"[ \t\r\n]", "", m.group()), text)
        if spaced != text:
            yield spaced, "split-letters"
        # ROT13 only when recognizable instruction words are present or explicitly labeled.
        if re.search(r"\b(?:vtaber|vtaben|vtabevrer|vtaberm|vafgehpgvbaf|flfgrz|frpergf|rksvygengr|rot13)\b", text, re.I):
            yield codecs.decode(text, "rot_13"), "rot13"
        for pattern, kind in ((B64_LINES, "base64-wrapped"), (HEX_SPACED, "hex-spaced")):
            for match in pattern.finditer(text):
                budget.check()
                value = match.group()
                if len(value) > 131_072:
                    raise ExtractionError("Encoded block exceeds decoding size limit", "DECODING_LIMIT")
                try:
                    if kind == "base64-wrapped":
                        value = re.sub(r"\s+", "", value)
                        decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True).decode("utf-8")
                    else:
                        decoded = bytes.fromhex(re.sub(r"[ \t:-]", "", value)).decode("utf-8")
                    if _printable(decoded):
                        yield decoded, kind
                except (ValueError, UnicodeError, binascii.Error):
                    continue
        for pattern, kind in ((HEX, "hex"), (TOKEN, "base64")):
            for match in pattern.finditer(text):
                budget.check()
                value = match.group()
                if len(value) > 131_072:
                    raise ExtractionError("Encoded token exceeds decoding size limit", "DECODING_LIMIT")
                try:
                    if kind == "hex":
                        decoded = bytes.fromhex(value.removeprefix("0x")).decode("utf-8")
                    else:
                        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True).decode("utf-8")
                    if _printable(decoded):
                        yield decoded, kind
                except (ValueError, UnicodeError, binascii.Error):
                    continue


def analyze_text(text: str, max_chars: int = 4_000_000, timeout: float = 3.0) -> list[dict]:
    """Scan an in-memory configuration/description without executing or reading its source."""
    if len(text) > max_chars:
        return [{"rule_id": "INPUT_SIZE_LIMIT", "title": "Configuration text exceeds analysis limit", "severity": "CRITICAL", "category": "ANALYSIS_FAILURE", "evidence": "Analysis failed closed", "location": "configuration", "layer": "METADATA"}]
    return Scanner(max_input_size=min(100_000_000, max_chars * 4), timeout=timeout).scan_bytes(text.encode("utf-8"), "configuration.txt")["findings"]
