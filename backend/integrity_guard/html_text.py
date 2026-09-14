"""Deterministic, lossy HTML-to-text profile; this does not authorize its output.

html-text-v1 accepts balanced HTML fragments/documents and ordinary void elements.
It copies text only, decodes HTML character references and uses LF separators for
block elements. Text inside pre is retained with normalized newlines; ordinary
HTML whitespace is collapsed. Comments, attributes, head/title/meta/link content,
script/template/noscript content, and explicitly hidden subtrees are omitted.

There is no browser, scripting, stylesheet evaluation or resource retrieval. Only
the small inline visibility declarations below are understood; style blocks,
external stylesheets, unknown elements and unbalanced/implicit closures fail.
The resulting bytes still require a complete independent security scan.
"""
from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass
from html.parser import HTMLParser

PROTOCOL = "html-text-v1"
MAX_INPUT_BYTES = 10 * 1024**2
MAX_OUTPUT_BYTES = 256 * 1024
MAX_DEPTH = 128
MAX_NODES = 20_000
MAX_TOKEN_CHARS = 64 * 1024
COUNT_KEYS = ("comments", "hidden_nodes", "metadata_nodes", "active_nodes", "nontext_nodes", "attributes")
ERROR_MESSAGES = {
    "INPUT_INVALID": "Transformation input is invalid.",
    "INPUT_SIZE_LIMIT": "HTML exceeds the transformation input limit.",
    "TEXT_ENCODING": "HTML requires valid UTF-8 or BOM-marked UTF-16 text.",
    "TEXT_CONTROL": "HTML contains unsupported text control characters.",
    "MALFORMED_HTML": "HTML structure is outside the balanced transformation profile.",
    "UNSUPPORTED_ELEMENT": "HTML contains an element outside the transformation profile.",
    "UNSUPPORTED_CSS": "Stylesheets or inline CSS exceed the transformation profile.",
    "UNSUPPORTED_DECLARATION": "HTML contains an unsupported declaration.",
    "STRUCTURE_LIMIT": "HTML exceeds the transformation structure limit.",
    "OUTPUT_SIZE_LIMIT": "Text exceeds the 256 KiB transformation output limit.",
    "EMPTY_OUTPUT": "No nonempty text remains in the supported transformation.",
    "TIME_LIMIT": "HTML transformation exceeded its time budget.",
    "TRANSFORM_FAILED": "HTML transformation could not complete.",
}


class HtmlTextError(ValueError):
    """Fixed error codes/messages never include source fragments or parser errors."""

    def __init__(self, code: str):
        self.code = code if code in ERROR_MESSAGES else "TRANSFORM_FAILED"
        super().__init__(ERROR_MESSAGES[self.code])


@dataclass(frozen=True)
class HtmlTextResult:
    data: bytes
    omitted_counts: dict[str, int]


_VOID = {"br", "hr", "img", "meta", "link", "wbr", "col", "source"}
_METADATA = {"head", "title", "meta", "link"}
_ACTIVE = {"script", "template", "noscript"}
_BLOCK = {"html", "body", "address", "article", "aside", "blockquote", "caption", "dd", "details",
          "div", "dl", "dt", "figcaption", "figure", "footer", "h1", "h2", "h3", "h4", "h5", "h6",
          "header", "hr", "li", "main", "nav", "ol", "p", "pre", "section", "summary", "table",
          "tbody", "td", "tfoot", "th", "thead", "tr", "ul"}
_ALLOWED = _VOID | _METADATA | _ACTIVE | _BLOCK | {
    "a", "abbr", "b", "bdi", "bdo", "cite", "code", "colgroup", "data", "del", "dfn", "em", "i",
    "ins", "kbd", "mark", "picture", "q", "rp", "rt", "ruby", "s", "samp", "small", "span",
    "strong", "sub", "sup", "time", "u", "var",
}
_CONTROLS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SPACE = re.compile(r"([ \t\n\r\f]+)")
_INLINE_VALUES = {
    "display": {"none": True, "block": False, "inline": False, "inline-block": False},
    "visibility": {"hidden": True, "collapse": True, "visible": False},
    "opacity": {"0": True, "0.0": True, "1": False, "1.0": False},
    "font-size": {"0": True, "0px": True, "0pt": True, "0em": True, "1px": True, "1pt": True},
}


def _inline_hidden(style: str) -> bool:
    """Recognize literal declarations only; reject general CSS instead of rendering it."""
    hidden = False
    seen = set()
    for declaration in style.split(";"):
        if not declaration.strip():
            continue
        pair = declaration.split(":")
        if len(pair) != 2:
            raise HtmlTextError("UNSUPPORTED_CSS")
        name, value = (part.strip().lower() for part in pair)
        if name in seen or name not in _INLINE_VALUES or value not in _INLINE_VALUES[name]:
            raise HtmlTextError("UNSUPPORTED_CSS")
        seen.add(name)
        hidden |= _INLINE_VALUES[name][value]
    return hidden


class _TextParser(HTMLParser):
    def __init__(self, deadline: float, source: str):
        super().__init__(convert_charrefs=True)
        self.deadline = deadline
        self.source = source
        self.source_line = 1
        self.source_line_start = 0
        self.stack: list[tuple[str, str | None]] = []
        self.counts = dict.fromkeys(COUNT_KEYS, 0)
        self.nodes = 0
        self.parts: list[str] = []
        self.size = 0
        self.pending_space = False
        self.line_start = True

    def check(self):
        if time.perf_counter() >= self.deadline:
            raise HtmlTextError("TIME_LIMIT")

    def node(self):
        self.check()
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise HtmlTextError("STRUCTURE_LIMIT")

    def append(self, value: str):
        if not value:
            return
        if _CONTROLS.search(value):
            raise HtmlTextError("TEXT_CONTROL")
        try:
            self.size += len(value.encode("utf-8", errors="strict"))
        except UnicodeError:
            raise HtmlTextError("TEXT_ENCODING") from None
        if self.size > MAX_OUTPUT_BYTES:
            raise HtmlTextError("OUTPUT_SIZE_LIMIT")
        self.parts.append(value)
        self.line_start = value.endswith("\n")

    def boundary(self):
        self.pending_space = False
        if self.parts and not self.line_start:
            self.append("\n")

    def handle_starttag(self, tag, attrs):
        self.node()
        if len(self.get_starttag_text()) > MAX_TOKEN_CHARS:
            raise HtmlTextError("STRUCTURE_LIMIT")
        if tag == "style":
            raise HtmlTextError("UNSUPPORTED_CSS")
        if tag not in _ALLOWED:
            raise HtmlTextError("UNSUPPORTED_ELEMENT")
        values = {}
        for name, value in attrs:
            if name in values:
                raise HtmlTextError("MALFORMED_HTML")
            values[name] = value
        self.counts["attributes"] += len(attrs)
        if self.counts["attributes"] > MAX_NODES * 32 or len(attrs) > 128:
            raise HtmlTextError("STRUCTURE_LIMIT")
        if tag == "link" and "stylesheet" in (values.get("rel") or "").lower().split():
            raise HtmlTextError("UNSUPPORTED_CSS")
        style_hidden = _inline_hidden(values.get("style") or "")
        inherited = self.stack[-1][1] if self.stack else None
        omission = inherited
        if omission is None:
            if tag in _METADATA:
                omission = "metadata_nodes"
            elif tag in _ACTIVE:
                omission = "active_nodes"
            elif tag in {"img", "source"}:
                omission = "nontext_nodes"
            elif ("hidden" in values or (values.get("aria-hidden") or "").strip().lower() == "true" or style_hidden):
                omission = "hidden_nodes"
            if omission is not None:
                self.counts[omission] += 1
                self.boundary()
        if tag not in _VOID:
            self.stack.append((tag, omission))
            if len(self.stack) > MAX_DEPTH:
                raise HtmlTextError("STRUCTURE_LIMIT")
        if omission is None and (tag in _BLOCK or tag == "br"):
            self.boundary()

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in _VOID:
            self.close_element(tag)

    def handle_endtag(self, tag):
        self.check()
        # getpos() identifies the current token. Advance through source lines
        # once overall, without a line-offset table or rescanning prior text.
        line, column = self.getpos()
        while self.source_line < line:
            self.check()
            self.source_line_start = self.source.index("\n", self.source_line_start) + 1
            self.source_line += 1
        start = self.source_line_start + column
        if self.source.find(">", start, start + MAX_TOKEN_CHARS) < 0:
            raise HtmlTextError("STRUCTURE_LIMIT")
        self.close_element(tag)

    def close_element(self, tag):
        self.node()
        if tag in _VOID or not self.stack or self.stack[-1][0] != tag:
            raise HtmlTextError("MALFORMED_HTML")
        _, omission = self.stack.pop()
        if omission is None and tag in _BLOCK or omission is not None and not (self.stack and self.stack[-1][1]):
            self.boundary()

    def handle_data(self, data):
        self.check()
        if self.stack and self.stack[-1][1] is not None:
            return
        preformatted = any(tag == "pre" for tag, _ in self.stack)
        offset = 0
        # HTMLParser may deliver a whole text node at once. Bound each unit of
        # output processing independently of its feed/callback segmentation.
        while offset < len(data):
            self.check()
            end = min(offset + 8192, len(data))
            if end < len(data) and data[end - 1:end + 1] == "\r\n":
                end += 1
            chunk = data[offset:end].replace("\r\n", "\n").replace("\r", "\n")
            offset = end
            if preformatted:
                self.pending_space = False
                self.append(chunk)
                continue
            for part in _SPACE.split(chunk):
                if not part:
                    continue
                if part[0] in " \t\n\r\f":
                    self.pending_space = not self.line_start
                else:
                    self.append((" " if self.pending_space and not self.line_start else "") + part)
                    self.pending_space = False

    def handle_comment(self, data):
        self.node()
        if len(data) > MAX_TOKEN_CHARS:
            raise HtmlTextError("STRUCTURE_LIMIT")
        self.counts["comments"] += 1

    def handle_decl(self, decl):
        self.node()
        if len(decl) > MAX_TOKEN_CHARS:
            raise HtmlTextError("STRUCTURE_LIMIT")
        if decl.strip().lower() != "doctype html":
            raise HtmlTextError("UNSUPPORTED_DECLARATION")
        self.counts["metadata_nodes"] += 1

    def unknown_decl(self, data):
        raise HtmlTextError("UNSUPPORTED_DECLARATION")

    def handle_pi(self, data):
        raise HtmlTextError("UNSUPPORTED_DECLARATION")

    def finish(self) -> HtmlTextResult:
        self.check()
        if self.rawdata or self.stack:
            raise HtmlTextError("MALFORMED_HTML")
        self.close()
        self.check()
        if self.rawdata or self.stack:
            raise HtmlTextError("MALFORMED_HTML")
        self.boundary()
        value = "".join(self.parts)
        if not value.strip():
            raise HtmlTextError("EMPTY_OUTPUT")
        return HtmlTextResult(value.encode("utf-8"), dict(self.counts))


def transform_html(data: bytes, *, timeout: float = 8.0) -> HtmlTextResult:
    """Convert a bounded snapshot only; no files, networks, scans or authorization.

    Counters describe omitted subtree roots (descendants are not counted twice),
    comments and stripped attributes. The output always ends with LF. No output
    is returned after any unsupported construct, incomplete parse or limit.
    """
    if not isinstance(data, bytes) or type(timeout) not in {int, float} or not math.isfinite(timeout) or not 0 < timeout <= 10:
        raise HtmlTextError("INPUT_INVALID")
    if len(data) > MAX_INPUT_BYTES:
        raise HtmlTextError("INPUT_SIZE_LIMIT")
    deadline = time.perf_counter() + timeout
    try:
        text = data.decode("utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig", errors="strict")
    except UnicodeError:
        raise HtmlTextError("TEXT_ENCODING") from None
    if _CONTROLS.search(text):
        raise HtmlTextError("TEXT_CONTROL")
    parser = _TextParser(deadline, text)
    try:
        parser.check()
        # Feed the bounded snapshot once. Newer HTMLParser implementations can
        # defer successive feeds until more input arrives; inspecting rawdata
        # between feeds would then miss data awaiting the public close() call.
        # Text callbacks enforce their own processing/output budgets above.
        parser.feed(text)
        if len(parser.rawdata) > MAX_TOKEN_CHARS:
            raise HtmlTextError("STRUCTURE_LIMIT")
        return parser.finish()
    except HtmlTextError:
        raise
    except (MemoryError, RecursionError):
        raise HtmlTextError("STRUCTURE_LIMIT") from None
    except Exception:
        raise HtmlTextError("TRANSFORM_FAILED") from None
