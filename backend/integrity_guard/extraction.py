"""Bounded, non-executing document extraction. Unknown/unreadable content fails closed."""
from __future__ import annotations

import csv
import io
import json
import re
import time
import zipfile
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import PurePosixPath
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from .extractor_registry import lookup_extractor


def failure_kind(code: str) -> str:
    """Distinguish malformed bytes from unsupported content and bounded refusals."""
    if code in {"EXTRACTION_FAILED", "INVALID_DOCX", "INVALID_PDF", "TEXT_ENCODING", "BINARY_CONTENT"}:
        return "MALFORMED"
    if code in {"XML_ENTITY_FORBIDDEN", "UNSAFE_YAML_TAG"}:
        return "UNSAFE_CONTENT"
    if code.endswith(("_LIMIT", "_BUDGET")) or code in {"ARCHIVE_BOMB", "RESOURCE_EXHAUSTED"}:
        return "RESOURCE_LIMIT"
    if code in {"SCANNER_FAILURE", "DEPENDENCY_UNAVAILABLE", "EXTRACTOR_FAILURE",
                "EXTRACTOR_RESULT_INVALID", "EXTRACTOR_REGISTRY_UNAVAILABLE", "EXTRACTOR_INCOMPLETE"}:
        return "INTERNAL_ERROR"
    return "UNSUPPORTED"


class ExtractionError(ValueError):
    def __init__(self, message: str, code: str = "EXTRACTION_FAILED"):
        super().__init__(message)
        self.code = code


@dataclass
class Segment:
    text: str
    layer: str = "VISIBLE_CONTENT"
    location: str = "document"


@dataclass
class Extraction:
    format: str
    segments: list[Segment] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    characters: int = 0
    truncated: bool = False


class Budget:
    def __init__(self, timeout: float, max_chars: int = 8_000_000, max_segments: int = 20_000):
        # Python 3.12 on Windows implements monotonic() with GetTickCount64
        # (15.625 ms resolution). QueryPerformanceCounter via perf_counter()
        # preserves monotonic deadlines even for short configured budgets.
        self.deadline = time.perf_counter() + timeout
        self.max_chars = max_chars
        self.max_segments = max_segments
        self.characters = 0
        self.segments = 0

    def check(self):
        if time.perf_counter() >= self.deadline:
            raise ExtractionError("Extraction or analysis time budget exhausted", "TIME_BUDGET")

    def add(self, result: Extraction, text: str, layer="VISIBLE_CONTENT", location="document"):
        self.check()
        if not text or not text.strip():
            return
        self.characters += len(text)
        self.segments += 1
        if self.characters > self.max_chars or self.segments > self.max_segments:
            result.truncated = True
            raise ExtractionError("Document expansion or segment budget exhausted", "EXPANSION_LIMIT")
        result.characters += len(text)
        result.segments.append(Segment(text, layer, location[:300]))


TEXT_FORMATS = {"txt", "md", "json", "json5", "yaml", "yml", "toml", "csv", "html", "htm", "xml", "log", "py", "js", "ts", "sh", "ps1", "env"}
MARKDOWN_FRONTMATTER_MAX_BYTES = 64 * 1024
MARKDOWN_FRONTMATTER_MAX_LINES = 4096
HIDDEN_STYLE = re.compile(r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:[;\s}]|$)|font-size\s*:\s*(?:0(?:px|pt|em)?|1(?:px|pt))\b|color\s*:\s*(?:white|#fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))", re.I)


def decode_text(data: bytes) -> str:
    try:
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return data.decode("utf-16", errors="strict")
        value = data.decode("utf-8-sig", errors="strict")
    except UnicodeError as exc:
        raise ExtractionError("Unsupported or malformed text encoding; use UTF-8 or UTF-16 with BOM", "TEXT_ENCODING") from exc
    if "\x00" in value:
        raise ExtractionError("Binary or NUL-containing input cannot be analyzed as text", "BINARY_CONTENT")
    return value


def _markdown_marker(text: str, start: int, end: int, budget: Budget) -> str | None:
    if end > start and text[end - 1] == "\r":
        end -= 1
    if end - start < 3:
        return None
    marker = text[start:start + 3]
    if marker not in {"---", "...", "+++"}:
        return None
    # A delimiter is at column zero, with only optional horizontal whitespace.
    # Chunk the whitespace check so even an unusually long line stays budgeted.
    for offset in range(start + 3, end, 4096):
        budget.check()
        if text[offset:min(end, offset + 4096)].strip(" \t"):
            return None
    return marker


def _markdown_frontmatter(text: str, result: Extraction, budget: Budget):
    first_end = text.find("\n")
    if first_end < 0:
        return
    opener = _markdown_marker(text, 0, first_end, budget)
    if opener not in {"---", "+++"}:
        return
    kind = "yaml" if opener == "---" else "toml"
    closers = {"---", "..."} if kind == "yaml" else {"+++"}
    content_start = position = first_end + 1
    lines = 0
    while position < len(text):
        budget.check()
        newline = text.find("\n", position)
        line_end = len(text) if newline < 0 else newline
        if _markdown_marker(text, position, line_end, budget) in closers:
            # Check character length before making any potentially large copy;
            # UTF-8 uses at least one byte per decoded character.
            if position - content_start > MARKDOWN_FRONTMATTER_MAX_BYTES or lines > MARKDOWN_FRONTMATTER_MAX_LINES:
                raise ExtractionError("Markdown frontmatter exceeds its byte or line limit", "FRONTMATTER_LIMIT")
            raw = text[content_start:position]
            if len(raw.encode("utf-8")) > MARKDOWN_FRONTMATTER_MAX_BYTES:
                raise ExtractionError("Markdown frontmatter exceeds its byte or line limit", "FRONTMATTER_LIMIT")
            budget.add(result, raw, "METADATA", "markdown:frontmatter:" + kind)
            return
        lines += 1
        if newline < 0:
            return
        position = newline + 1
    # An unmatched opening thematic break remains ordinary Markdown. No source
    # is removed or truncated: extract() always keeps the complete visible text.


class SafeHTML(HTMLParser):
    def __init__(self, result: Extraction, budget: Budget, hidden_selectors: set[str]):
        super().__init__(convert_charrefs=True)
        self.result, self.budget, self.hidden_selectors = result, budget, hidden_selectors
        self.stack: list[tuple[str, bool]] = []
        self.visible: list[str] = []
        self.hidden: list[str] = []

    def handle_starttag(self, tag, attrs):
        self.budget.check()
        a = dict(attrs)
        selectors = {tag, "#" + (a.get("id") or ""), *("." + c for c in (a.get("class") or "").split())}
        hidden = (any(item[1] for item in self.stack) or tag in {"script", "style", "template", "noscript"}
                  or "hidden" in a or (a.get("aria-hidden") or "").lower() == "true"
                  or bool(HIDDEN_STYLE.search(a.get("style") or "")) or bool(selectors & self.hidden_selectors))
        if tag not in {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}:
            self.stack.append((tag, hidden))
            if len(self.stack) > 128:
                raise ExtractionError("HTML nesting budget exhausted", "STRUCTURE_LIMIT")
        if tag == "meta":
            self.budget.add(self.result, a.get("content") or "", "METADATA", "html:meta:" + (a.get("name") or a.get("property") or "unknown"))
        for key, value in attrs:
            if value and (key in {"alt", "title", "aria-label", "value", "srcdoc", "href", "src"} or key.startswith("data-")):
                self.budget.add(self.result, value, "METADATA", "html:" + tag + "@" + key)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break
        if tag in {"p", "div", "li", "section", "h1", "h2", "br"}:
            self.visible.append("\n")
            self.hidden.append("\n")

    def handle_data(self, data):
        self.budget.check()
        if any(item[1] for item in self.stack):
            self.hidden.append(data)
        else:
            self.visible.append(data)

    def handle_comment(self, data):
        self.budget.add(self.result, data, "HIDDEN_CONTENT", "html:comment")

    def finish(self):
        self.close()
        self.budget.add(self.result, "".join(self.visible), "VISIBLE_CONTENT", "html:rendered-text")
        self.budget.add(self.result, "".join(self.hidden), "HIDDEN_CONTENT", "html:hidden-nodes")


def _html(text: str, result: Extraction, budget: Budget):
    selectors: set[str] = set()
    stylesheet = "\n".join(re.findall(r"<style\b[^>]*>(.*?)</style\s*>", text, re.I | re.S))
    stylesheet = re.sub(r"/\*.*?\*/", "", stylesheet, flags=re.S)
    for style in re.finditer(r"([^{}]+)\{([^{}]*)\}", stylesheet):
        budget.check()
        if HIDDEN_STYLE.search(style.group(2)):
            selectors.update(x.strip() for x in style.group(1).split(",") if re.fullmatch(r"[.#]?[\w-]+", x.strip()))
    parser = SafeHTML(result, budget, selectors)
    parser.feed(text)
    parser.finish()
    # Raw markup also captures attribute splitting, SVG text, unusual parsers and CSS selectors.
    budget.add(result, text, "METADATA", "html:source-markup")


def _xml(text: str, result: Extraction, budget: Budget):
    root = SafeET.fromstring(text, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    budget.add(result, " ".join(root.itertext()), location="xml:text")
    for index, node in enumerate(root.iter()):
        budget.check()
        if index > 20_000:
            raise ExtractionError("XML node budget exhausted", "STRUCTURE_LIMIT")
        for key, value in node.attrib.items():
            budget.add(result, value, "METADATA", f"xml:{node.tag}@{key}")
    for comment in re.finditer(r"<!--(.*?)-->", text, re.S):
        budget.add(result, comment.group(1), "HIDDEN_CONTENT", "xml:comment")


def _validate_structured(text: str, fmt: str, budget: Budget):
    if fmt == "json":
        depth = nodes = 0
        quoted = escaped = False
        for index, character in enumerate(text):
            if index % 4096 == 0:
                budget.check()
            if quoted:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    quoted = False
            elif character == '"':
                quoted = True
            elif character in "[{":
                depth += 1
                nodes += 1
            elif character in "]}":
                depth -= 1
            elif character == ",":
                nodes += 1
            if depth > 128 or nodes > 100_000:
                raise ExtractionError("JSON structure budget exhausted", "STRUCTURE_LIMIT")
        json.loads(text)
    elif fmt == "json5":
        import json5
        json5.loads(text)
    elif fmt in {"yaml", "yml"}:
        import yaml
        # Compose validates syntax without constructing objects or traversing aliases.
        # Limit token count/depth first; aliased content is analyzed in original source.
        depth = count = 0
        for token in yaml.scan(text):
            budget.check()
            count += 1
            if isinstance(token, (yaml.tokens.BlockMappingStartToken, yaml.tokens.BlockSequenceStartToken, yaml.tokens.FlowMappingStartToken, yaml.tokens.FlowSequenceStartToken)):
                depth += 1
            elif isinstance(token, (yaml.tokens.BlockEndToken, yaml.tokens.FlowMappingEndToken, yaml.tokens.FlowSequenceEndToken)):
                depth -= 1
            if count > 100_000 or depth > 128:
                raise ExtractionError("YAML structure budget exhausted", "STRUCTURE_LIMIT")
            if isinstance(token, yaml.tokens.TagToken) and "python" in str(token.value).lower():
                raise ExtractionError("Executable YAML tags are not supported", "UNSAFE_YAML_TAG")
        list(yaml.compose_all(text, Loader=yaml.SafeLoader))
    elif fmt == "toml":
        import tomllib
        tomllib.loads(text)
    elif fmt == "csv":
        cells = 0
        for row in csv.reader(io.StringIO(text), strict=True):
            budget.check()
            cells += len(row)
            if cells > 100_000:
                raise ExtractionError("CSV cell budget exhausted", "STRUCTURE_LIMIT")


_DOCX_WORD_NAMESPACES = {
    "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "http://purl.oclc.org/ooxml/wordprocessingml/main",
}
_DOCX_RELATIONSHIP_NAMESPACES = {
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "http://purl.oclc.org/ooxml/officeDocument/relationships",
}
_DOCX_ALTCHUNK_TAGS = {"{" + namespace + "}altChunk" for namespace in _DOCX_WORD_NAMESPACES}
# Word uses aFChunk; the older specification also documents afChunk.
_DOCX_ALTCHUNK_RELATIONSHIPS = {
    namespace + "/" + kind for namespace in _DOCX_RELATIONSHIP_NAMESPACES
    for kind in ("aFChunk", "afChunk")
}
_DOCX_HYPERLINK_RELATIONSHIPS = {namespace + "/hyperlink" for namespace in _DOCX_RELATIONSHIP_NAMESPACES}
_DOCX_PACKAGE_RELATIONSHIPS = "{http://schemas.openxmlformats.org/package/2006/relationships}"


def _check_docx_references(root, relationships: bool, budget: Budget):
    for node in root.iter():
        budget.check()
        if node.tag in _DOCX_ALTCHUNK_TAGS:
            raise ExtractionError("DOCX alternative format import cannot be fully inspected", "DOCX_ALTCHUNK_UNSUPPORTED")
    if not relationships:
        return
    if root.tag != _DOCX_PACKAGE_RELATIONSHIPS + "Relationships":
        raise ExtractionError("DOCX relationship markup is invalid", "INVALID_DOCX")
    for node in root:
        budget.check()
        if (node.tag != _DOCX_PACKAGE_RELATIONSHIPS + "Relationship" or
                any(not node.get(key, "").strip() for key in ("Id", "Type", "Target")) or
                node.get("TargetMode", "Internal") not in {"Internal", "External"}):
            raise ExtractionError("DOCX relationship markup is invalid", "INVALID_DOCX")
        kind = node.get("Type")
        if kind in _DOCX_ALTCHUNK_RELATIONSHIPS:
            raise ExtractionError("DOCX alternative format import cannot be fully inspected", "DOCX_ALTCHUNK_UNSUPPORTED")
        if node.get("TargetMode") == "External" and kind not in _DOCX_HYPERLINK_RELATIONSHIPS:
            raise ExtractionError("DOCX external content cannot be fully inspected", "DOCX_EXTERNAL_CONTENT")


def _docx(data: bytes, result: Extraction, budget: Budget):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > 2048:
            raise ExtractionError("DOCX archive has too many entries", "ARCHIVE_LIMIT")
        names = {item.filename for item in entries}
        if "[Content_Types].xml" not in names or "word/document.xml" not in names:
            raise ExtractionError("ZIP is not a DOCX document", "INVALID_DOCX")
        total = 0
        for info in entries:
            budget.check()
            total += info.file_size
            if info.flag_bits & 1 or ".." in PurePosixPath(info.filename).parts or info.filename.startswith("/"):
                raise ExtractionError("Encrypted or unsafe archive member", "ARCHIVE_UNSAFE")
            if info.file_size > 8_000_000 or total > 24_000_000 or info.file_size / max(1, info.compress_size) > 100:
                raise ExtractionError("DOCX expansion/ratio limit exceeded", "ARCHIVE_BOMB")
            if info.filename.startswith("word/embeddings/") or info.filename.lower().endswith((".bin", ".vba")):
                raise ExtractionError("Embedded executable/object content cannot be fully scanned", "EMBEDDED_CONTENT")
            if info.filename.startswith("word/media/") and not info.is_dir():
                raise ExtractionError("DOCX contains visual media; OCR is not available", "OCR_REQUIRED")
        # Preserve the existing archive/media refusal precedence across all members.
        # Every non-directory part accepted here is parsed below; none are skipped.
        for info in entries:
            budget.check()
            if info.is_dir() and info.file_size == 0:
                continue
            if info.is_dir() or not info.filename.endswith((".xml", ".rels")):
                raise ExtractionError("DOCX contains a part outside the inspected XML profile", "DOCX_UNINSPECTED_PART")
        ns = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
        hidden_styles = set()
        if "word/styles.xml" in names:
            styles = SafeET.fromstring(archive.read("word/styles.xml"), forbid_dtd=True, forbid_entities=True, forbid_external=True)
            for style in styles.iter(ns + "style"):
                if style.find(".//" + ns + "vanish") is not None or style.find(".//" + ns + "webHidden") is not None:
                    hidden_styles.add(style.get(ns + "styleId"))
        for info in entries:
            name = info.filename
            if info.is_dir():
                continue
            content = archive.read(info)
            root = SafeET.fromstring(content, forbid_dtd=True, forbid_entities=True, forbid_external=True)
            _check_docx_references(root, name.endswith(".rels"), budget)
            is_meta = name.startswith("docProps/") or name.endswith(".rels")
            is_hidden = any(marker in name.lower() for marker in ("comments", "footnotes", "endnotes"))
            if name.startswith("word/") and not is_meta:
                # Classify each run before joining text, including hidden/white/tiny typography.
                visible, hidden = [], []
                seen_text = set()
                paragraphs = list(root.iter(ns + "p"))
                # The stream includes explicit paragraph boundaries so split words across
                # adjacent runs are reconstructed as they would be rendered.
                runs = []
                for paragraph in paragraphs:
                    runs.extend((run, False) for run in paragraph.iter(ns + "r"))
                    runs.append((paragraph, True))
                for idx, (run, paragraph_end) in enumerate(runs):
                    budget.check()
                    if idx > 20_000:
                        raise ExtractionError("DOCX run count limit exceeded", "STRUCTURE_LIMIT")
                    if paragraph_end:
                        visible.append("\n")
                        hidden.append("\n")
                        continue
                    props = run.find(ns + "rPr")
                    hide = is_hidden
                    if props is not None:
                        hide |= props.find(ns + "vanish") is not None or props.find(ns + "webHidden") is not None
                        for prop in props:
                            val = prop.get(ns + "val", "")
                            hide |= prop.tag == ns + "color" and val.lower() in {"fff", "ffffff"}
                            hide |= prop.tag == ns + "sz" and val.isdigit() and int(val) <= 2
                            hide |= prop.tag == ns + "rStyle" and val in hidden_styles
                    for child in run.iter():
                        if child.tag in {ns + "t", ns + "instrText", ns + "delText"} and child.text:
                            seen_text.add(id(child))
                            (hidden if hide or child.tag != ns + "t" else visible).append(child.text)
                budget.add(result, "".join(visible), "VISIBLE_CONTENT", "docx:" + name)
                budget.add(result, "".join(hidden), "HIDDEN_CONTENT", "docx:" + name)
                rest = [node.text for node in root.iter() if node.text and node.text.strip() and id(node) not in seen_text]
                budget.add(result, " ".join(rest), "METADATA", "docx:embedded-fields:" + name)
            else:
                budget.add(result, " ".join(root.itertext()), "METADATA", "docx:" + name)
            for node in root.iter():
                budget.check()
                for key, value in node.attrib.items():
                    if len(value) > 3:
                        budget.add(result, value, "METADATA", "docx:" + name + "@" + key.split("}")[-1])
        result.limitations.append("DOCX visual layout is heuristic; image media, embedded objects, non-XML parts and alternative format imports fail closed. External hyperlinks are metadata only; other external relationships are unsupported. OCR is unavailable.")


def _pdf(data: bytes, result: Extraction, budget: Budget):
    from pypdf import PdfReader
    if not data.startswith(b"%PDF-"):
        raise ExtractionError("PDF signature missing", "INVALID_PDF")
    reader = PdfReader(io.BytesIO(data), strict=True)
    if reader.is_encrypted:
        raise ExtractionError("Encrypted PDFs cannot be inspected", "ENCRYPTED_PDF")
    if not len(reader.pages):
        raise ExtractionError("PDF has no analyzable pages", "OCR_REQUIRED")
    if len(reader.pages) > 100:
        raise ExtractionError("PDF page limit exceeded", "PDF_PAGE_LIMIT")
    for key, value in (reader.metadata or {}).items():
        budget.add(result, str(value), "METADATA", "pdf:metadata:" + str(key))
    catalog = reader.trailer["/Root"]
    if catalog.get("/OpenAction") or catalog.get("/AA"):
        raise ExtractionError("PDF active actions are not supported", "PDF_ACTIVE_CONTENT")
    names = catalog.get("/Names")
    if names and any(key in names.get_object() for key in ("/JavaScript", "/EmbeddedFiles")):
        raise ExtractionError("PDF contains scripts or embedded files", "PDF_ACTIVE_CONTENT")
    if catalog.get("/Metadata"):
        metadata = catalog["/Metadata"].get_data()
        if len(metadata) > 1_000_000:
            raise ExtractionError("PDF metadata expansion limit exceeded", "EXPANSION_LIMIT")
        root = SafeET.fromstring(metadata, forbid_dtd=True, forbid_entities=True, forbid_external=True)
        budget.add(result, " ".join(root.itertext()), "METADATA", "pdf:xmp-metadata")
        for node in root.iter():
            for value in node.attrib.values():
                budget.add(result, value, "METADATA", "pdf:xmp-attribute")
    if catalog.get("/AcroForm"):
        form = catalog["/AcroForm"].get_object()
        if form.get("/XFA"):
            raise ExtractionError("PDF XFA content is unsupported", "PDF_ACTIVE_CONTENT")
        pending = list(form.get("/Fields", []))
        processed = 0
        while pending:
            budget.check()
            processed += 1
            if processed > 1000:
                raise ExtractionError("PDF field count limit exceeded", "STRUCTURE_LIMIT")
            field = pending.pop().get_object()
            if field.get("/AA") or field.get("/A"):
                raise ExtractionError("PDF form actions cannot be fully inspected", "PDF_ACTIVE_CONTENT")
            for key in ("/V", "/DV", "/TU", "/T"):
                if field.get(key):
                    budget.add(result, str(field[key]), "HIDDEN_CONTENT", "pdf:form-field:" + key)
            pending.extend(field.get("/Kids", []))
    for index, page in enumerate(reader.pages):
        budget.check()
        if page.get("/AA"):
            raise ExtractionError("PDF page active actions are unsupported", "PDF_ACTIVE_CONTENT")
        pending_resources = [(page.get("/Resources", {}), 0)]
        inspected_resources = 0
        while pending_resources:
            resources, depth = pending_resources.pop()
            resources = resources.get_object() if hasattr(resources, "get_object") else resources
            inspected_resources += 1
            if depth > 16 or inspected_resources > 1000:
                raise ExtractionError("PDF resource nesting limit exceeded", "STRUCTURE_LIMIT")
            xobjects = resources.get("/XObject", {})
            xobjects = xobjects.get_object() if hasattr(xobjects, "get_object") else xobjects
            for ref in xobjects.values():
                budget.check()
                obj = ref.get_object()
                if obj.get("/Subtype") == "/Image":
                    raise ExtractionError("PDF contains image content; OCR is not available", "OCR_REQUIRED")
                if obj.get("/Subtype") == "/Form" and obj.get("/Resources"):
                    pending_resources.append((obj["/Resources"], depth + 1))
        state = {"invisible": False, "white": False, "characters": 0}
        visible, hidden = [], []
        def operand(op, args, cm, tm):
            budget.check()
            if op == b"Tr" and args:
                state["invisible"] = int(args[0]) in {3, 7}
            elif op == b"g" and args:
                state["white"] = float(args[0]) >= 0.99
            elif op == b"rg" and len(args) >= 3:
                state["white"] = all(float(a) >= 0.99 for a in args[:3])
        def visitor(text, cm, tm, font, size):
            budget.check()
            if text:
                (hidden if state["invisible"] or state["white"] or abs(size) <= 1 else visible).append(text)
                state["characters"] += len(text)
                if state["characters"] > budget.max_chars:
                    raise ExtractionError("PDF extracted text limit exceeded", "EXPANSION_LIMIT")
        page.extract_text(visitor_text=visitor, visitor_operand_before=operand)
        budget.add(result, "".join(visible), "VISIBLE_CONTENT", f"pdf:page:{index + 1}")
        budget.add(result, "".join(hidden), "HIDDEN_CONTENT", f"pdf:page:{index + 1}:hidden-text")
        for annotation in page.get("/Annots", []):
            node = annotation.get_object()
            for key in ("/Contents", "/T", "/Subj", "/Alt", "/ActualText"):
                if node.get(key):
                    budget.add(result, str(node[key]), "HIDDEN_CONTENT", f"pdf:page:{index + 1}:annotation")
            if node.get("/AA") or node.get("/FS") or node.get("/RichMediaContent") or node.get("/3DD"):
                raise ExtractionError("PDF annotation active content cannot be fully inspected", "PDF_ACTIVE_CONTENT")
            if node.get("/A"):
                action = node["/A"].get_object()
                if action.get("/S") != "/URI":
                    raise ExtractionError("PDF annotation action is unsupported", "PDF_ACTIVE_CONTENT")
                budget.add(result, str(action.get("/URI", "")), "METADATA", f"pdf:page:{index + 1}:link")
        # Image-only pages have no analyzable text: never report an uninspected PDF as allowed.
        if not "".join(visible + hidden).strip():
            raise ExtractionError("PDF has a textless page; OCR is not available", "OCR_REQUIRED")
    result.limitations.append("PDF text, metadata and annotation extraction is heuristic; PDFs containing images fail closed because OCR is unavailable.")


def _registered(data: bytes, filename: str, fmt: str, budget: Budget) -> Extraction:
    try:
        entry = lookup_extractor(fmt)
    except (ValueError, RuntimeError, OSError, ImportError) as exc:
        raise ExtractionError("Trusted extractor registry is unavailable", "EXTRACTOR_REGISTRY_UNAVAILABLE") from exc
    if entry is None:
        raise ExtractionError("Unsupported file type; content has not been inspected", "UNSUPPORTED_FORMAT")
    characters_before, segments_before = budget.characters, budget.segments
    limits_before = (budget.max_chars, budget.max_segments, budget.deadline)
    try:
        result = entry.handler(data, filename, budget)
    except ExtractionError:
        raise
    except (MemoryError, RecursionError):
        raise
    except Exception as exc:
        raise ExtractionError("Trusted extractor could not complete", "EXTRACTOR_FAILURE") from exc
    invalid = lambda: ExtractionError("Trusted extractor returned an invalid result", "EXTRACTOR_RESULT_INVALID")
    if (type(result) is not Extraction or type(result.format) is not str or result.format != entry.format or
            type(result.characters) is not int or type(result.truncated) is not bool or
            type(budget.characters) is not int or type(budget.segments) is not int or
            (budget.max_chars, budget.max_segments, budget.deadline) != limits_before or
            type(result.segments) is not list or len(result.segments) > budget.max_segments or
            type(result.limitations) is not list or len(result.limitations) > 200 or
            any(type(item) is not str or len(item) > 1000 for item in result.limitations)):
        raise invalid()
    budget.check()
    if result.truncated:
        raise ExtractionError("Trusted extractor reported incomplete coverage", "EXTRACTOR_INCOMPLETE")
    characters = 0
    for segment in result.segments:
        budget.check()
        if (type(segment) is not Segment or type(segment.text) is not str or
                type(segment.layer) is not str or
                segment.layer not in {"VISIBLE_CONTENT", "HIDDEN_CONTENT", "METADATA"} or
                type(segment.location) is not str or len(segment.location) > 300):
            raise invalid()
        characters += len(segment.text)
        if characters > budget.max_chars:
            raise ExtractionError("Trusted extractor exceeded the expansion budget", "EXPANSION_LIMIT")
    if (characters != result.characters or
            budget.characters - characters_before < characters or
            budget.segments - segments_before < len(result.segments) or
            budget.characters > budget.max_chars or budget.segments > budget.max_segments):
        raise invalid()
    if not any(segment.text.strip() for segment in result.segments):
        raise ExtractionError("Trusted extractor returned no inspectable text", "EXTRACTOR_INCOMPLETE")
    return result


def extract(data: bytes, filename: str, budget: Budget) -> Extraction:
    base = filename.replace("\\", "/").rsplit("/", 1)[-1]
    fmt = "env" if base == ".env" or base.startswith(".env.") else base.rsplit(".", 1)[-1].lower() if "." in base else ""
    result = Extraction(fmt or "unknown")
    try:
        if fmt in TEXT_FORMATS:
            text = decode_text(data)
            budget.check()
            if fmt in {"html", "htm"}:
                _html(text, result, budget)
            elif fmt == "xml":
                _xml(text, result, budget)
            else:
                _validate_structured(text, fmt, budget)
                budget.add(result, text, location=fmt + ":source")
                if fmt == "md":
                    _markdown_frontmatter(text, result, budget)
                    for comment in re.finditer(r"<!--(.*?)-->", text, re.S):
                        budget.add(result, comment.group(1), "HIDDEN_CONTENT", "markdown:comment")
                    for alt in re.finditer(r"!\[([^\]]*)\]\([^)]*\)", text):
                        budget.add(result, alt.group(1), "METADATA", "markdown:image-alt")
                    if re.search(r"<(?:div|span|script|style|meta)\b", text, re.I):
                        _html(text, result, budget)
        elif fmt == "docx":
            _docx(data, result, budget)
        elif fmt == "pdf":
            _pdf(data, result, budget)
        else:
            result = _registered(data, filename, fmt, budget)
        budget.check()
        return result
    except ExtractionError:
        raise
    except DefusedXmlException as exc:
        raise ExtractionError("XML declarations or entities were rejected before expansion", "XML_ENTITY_FORBIDDEN") from exc
    except (MemoryError, RecursionError) as exc:
        raise ExtractionError("Parser memory or recursion budget exhausted", "RESOURCE_EXHAUSTED") from exc
    except (ImportError, ModuleNotFoundError) as exc:
        raise ExtractionError("An optional document parser is unavailable", "DEPENDENCY_UNAVAILABLE") from exc
    except Exception as exc:
        # Never include parser exception strings; those can contain original secrets.
        raise ExtractionError(f"Malformed or unreadable {fmt or 'unknown'} document ({type(exc).__name__})") from exc
