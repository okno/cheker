"""Static, bounded SpreadsheetML data profile; formulas and visual parts fail closed."""
from __future__ import annotations

import io
import re
import zipfile
from datetime import datetime
from pathlib import PurePosixPath
from urllib.parse import unquote, urlsplit

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from .extraction import Budget, Extraction, ExtractionError

S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
P = "http://schemas.openxmlformats.org/package/2006/relationships"
T = "http://schemas.openxmlformats.org/package/2006/content-types"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
CORE = "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
APP = "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
CUSTOM = "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
VT = "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"
MAX_ENTRIES = 2048
MAX_PART_BYTES = 8_000_000
MAX_ARCHIVE_BYTES = 24_000_000
MAX_RATIO = 100
MAX_NODES = 200_000
MAX_DEPTH = 64
MAX_SHEETS = 100
MAX_CELLS = 20_000
MAX_STRINGS = 20_000
MAX_RELATIONSHIPS = 4096

_TYPES = {
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml": ("workbook", S, "workbook"),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml": ("worksheet", S, "worksheet"),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml": ("strings", S, "sst"),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml": ("styles", S, "styleSheet"),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml": ("comments", S, "comments"),
    "application/vnd.openxmlformats-officedocument.theme+xml": ("theme", A, "theme"),
    "application/vnd.openxmlformats-package.core-properties+xml": ("core", CORE, "coreProperties"),
    "application/vnd.openxmlformats-officedocument.extended-properties+xml": ("app", APP, "Properties"),
    "application/vnd.openxmlformats-officedocument.custom-properties+xml": ("custom", CUSTOM, "Properties"),
    "application/vnd.openxmlformats-package.relationships+xml": ("relations", P, "Relationships"),
}
_FORMULA = {"f", "formula", "formula1", "formula2", "definedName", "calculatedColumnFormula", "totalsRowFormula"}
_RICH = set("t r rPr rFont charset family b i strike outline shadow condense extend color sz u vertAlign scheme rPh phoneticPr".split())
_ALLOWED = {
    "workbook": set("workbook fileVersion workbookPr bookViews workbookView sheets sheet calcPr workbookProtection definedNames".split()),
    "worksheet": set("worksheet sheetPr tabColor outlinePr pageSetUpPr dimension sheetViews sheetView pane selection sheetFormatPr cols col sheetData row c v is sheetCalcPr sheetProtection protectedRanges protectedRange autoFilter filterColumn filters filter customFilters customFilter dynamicFilter top10 colorFilter iconFilter dateGroupItem sortState sortCondition mergeCells mergeCell dataValidations dataValidation hyperlinks hyperlink printOptions pageMargins pageSetup headerFooter oddHeader oddFooter evenHeader evenFooter firstHeader firstFooter rowBreaks colBreaks brk ignoredErrors ignoredError".split()) | _RICH,
    "strings": {"sst", "si"} | _RICH,
    "comments": {"comments", "authors", "author", "commentList", "comment", "text"} | _RICH,
    "styles": set("styleSheet numFmts numFmt fonts font name fills fill patternFill fgColor bgColor borders border left right top bottom diagonal start end cellStyleXfs cellXfs xf alignment protection cellStyles cellStyle dxfs dxf tableStyles tableStyle colors indexedColors rgbColor mruColors".split()) | _RICH,
}
_RELATIONS = {
    "": {R + "/officeDocument": "workbook", P + "/metadata/core-properties": "core",
         R + "/extended-properties": "app", R + "/custom-properties": "custom"},
    "workbook": {R + "/worksheet": "worksheet", R + "/sharedStrings": "strings",
                 R + "/styles": "styles", R + "/theme": "theme"},
    "worksheet": {R + "/comments": "comments", R + "/hyperlink": "hyperlink"},
}
_MESSAGES = {
    "INVALID_XLSX": "The XLSX package is malformed or has inconsistent references.",
    "XLSX_UNINSPECTED_PART": "The XLSX package contains content outside the inspected static profile.",
    "XLSX_FORMULA_UNSUPPORTED": "XLSX formulas are outside the inspected static data profile.",
    "XLSX_EXTERNAL_CONTENT": "External XLSX content cannot be inspected.",
    "XLSX_EMBEDDED_CONTENT": "XLSX macros or embedded objects cannot be inspected.",
    "OCR_REQUIRED": "XLSX visual media requires unavailable OCR.",
    "ARCHIVE_LIMIT": "The XLSX archive entry limit was exceeded.",
    "ARCHIVE_BOMB": "The XLSX archive expansion limit was exceeded.",
    "ARCHIVE_UNSAFE": "The XLSX archive member profile is unsupported.",
    "STRUCTURE_LIMIT": "The XLSX structure limit was exceeded.",
    "XML_ENTITY_FORBIDDEN": "XML declarations or entities were rejected before expansion.",
}
_ESCAPE = re.compile(r"_x([0-9a-fA-F]{4})_")
_CELL = re.compile(r"([A-Z]{1,3})([1-9][0-9]{0,6})\Z")
_NUMERIC = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[Ee][+-]?[0-9]+)?\Z")


def _fail(code="INVALID_XLSX"):
    raise ExtractionError(_MESSAGES[code], code)


def _tag(node):
    if not isinstance(node.tag, str) or not node.tag.startswith("{"):
        _fail("XLSX_UNINSPECTED_PART")
    namespace, local = node.tag[1:].split("}", 1)
    return namespace, local


def _number(value, minimum=0, maximum=1_048_576):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,10}", value):
        _fail()
    number = int(value)
    if not minimum <= number <= maximum:
        _fail()
    return number


def _boolean(value):
    if value not in {None, "0", "1", "false", "true"}:
        _fail()
    return value in {"1", "true"}


def _resolve(source, target):
    """Resolve an OPC reference within the ZIP, never as an OS path."""
    if not isinstance(target, str) or not target or "\\" in target:
        _fail()
    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        _fail()
    try:
        decoded = unquote(parsed.path, errors="strict")
    except (UnicodeError, ValueError):
        _fail()
    if "\\" in decoded or any(ord(char) < 32 for char in decoded):
        _fail()
    parts = [] if decoded.startswith("/") else source.split("/")[:-1]
    for part in decoded.split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                _fail()
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        _fail()
    return "/".join(parts)


class _Reader:
    def __init__(self, budget):
        self.budget = budget
        self.result = Extraction("xlsx")
        self.nodes = self.cells = 0
        self.consumed_text = set()

    def add(self, text, layer, location):
        if text is None:
            return
        self.budget.check()
        # SpreadsheetML string escapes are decoded once; an escaped underscore
        # must not trigger another decoding pass. Preserve the literal view too.
        if _ESCAPE.search(text):
            try:
                decoded = _ESCAPE.sub(lambda match: chr(int(match[1], 16)), text)
                decoded = decoded.encode("utf-16-le", "surrogatepass").decode("utf-16-le")
            except UnicodeError:
                _fail()
            self.budget.add(self.result, text, "METADATA", location + ":literal")
            text = decoded
        self.budget.add(self.result, text, layer, location)

    def parse(self, content, name):
        depth = 0
        root = None
        for event, node in SafeET.iterparse(io.BytesIO(content), events=("start", "end", "comment", "pi"),
                                           forbid_dtd=True, forbid_entities=True, forbid_external=True):
            self.budget.check()
            if event == "end":
                depth -= 1
                continue
            self.nodes += 1
            if self.nodes > MAX_NODES:
                _fail("STRUCTURE_LIMIT")
            if event in {"comment", "pi"}:
                self.add(node.text, "HIDDEN_CONTENT", "xlsx:" + name + ":xml-" + event)
                continue
            depth += 1
            if depth > MAX_DEPTH:
                _fail("STRUCTURE_LIMIT")
            if root is None:
                root = node
        if root is None:
            _fail()
        return root

    def metadata(self, root, name):
        texts = []
        for node in root.iter():
            self.budget.check()
            if id(node) not in self.consumed_text and node.text:
                texts.append(node.text)
            if node.tail:
                texts.append(node.tail)
            texts.extend(node.attrib.values())
        self.add(" ".join(texts), "METADATA", "xlsx:" + name + ":metadata")

    def rich(self, node):
        text, hidden = [], False
        for child in node:
            self.budget.check()
            if child.tag == "{" + S + "}t":
                if len(child):
                    _fail()
                text.append(child.text or "")
                self.consumed_text.add(id(child))
            elif child.tag == "{" + S + "}r":
                hidden |= _hidden_font(child.find("{" + S + "}rPr"))
                if any(item.tag not in {"{" + S + "}rPr", "{" + S + "}t"} for item in child):
                    _fail()
                for run_text in child.findall("{" + S + "}t"):
                    text.append(run_text.text or "")
                    self.consumed_text.add(id(run_text))
            elif child.tag not in {"{" + S + "}rPh", "{" + S + "}phoneticPr"}:
                _fail()
        return "".join(text), hidden


def _hidden_font(font):
    if font is None:
        return False
    for child in font:
        if child.tag == "{" + S + "}color" and child.get("rgb", "").upper() in {"FFFFFF", "FFFFFFFF"}:
            return True
        if child.tag == "{" + S + "}sz":
            try:
                size = float(child.get("val", ""))
            except ValueError:
                _fail()
            if not 0 < size <= 4096:
                _fail()
            if size <= 1:
                return True
    return False


def _validate_nodes(root, kind, reader):
    for node in root.iter():
        reader.budget.check()
        ns, local = _tag(node)
        if ns == S and local in _FORMULA:
            _fail("XLSX_FORMULA_UNSUPPORTED")
        if local in {"extLst", "AlternateContent"}:
            _fail("XLSX_UNINSPECTED_PART")
        if kind in _ALLOWED and (ns != S or local not in _ALLOWED[kind]):
            _fail("XLSX_UNINSPECTED_PART")
        if kind == "theme" and ns != A:
            _fail("XLSX_UNINSPECTED_PART")
        if kind == "theme" and local in {"blip", "hlinkClick", "hlinkHover", "graphic", "graphicData"}:
            _fail("XLSX_UNINSPECTED_PART")
        if kind in {"core", "app", "custom"} and ns not in {
                CORE, APP, CUSTOM, VT, "http://purl.org/dc/elements/1.1/",
                "http://purl.org/dc/terms/", "http://purl.org/dc/dcmitype/"}:
            _fail("XLSX_UNINSPECTED_PART")
        if ns == VT and local in {"blob", "oblob", "stream", "ostream", "storage", "ostorage", "vstream"}:
            _fail("XLSX_EMBEDDED_CONTENT")


def _styles(root, budget):
    if root is None:
        return [False]
    fonts = root.findall("{" + S + "}fonts/{" + S + "}font")
    font_hidden = []
    for font in fonts:
        budget.check()
        font_hidden.append(_hidden_font(font))
    custom_formats = {_number(node.get("numFmtId")) for node in root.findall("{" + S + "}numFmts/{" + S + "}numFmt")}
    bases = root.findall("{" + S + "}cellStyleXfs/{" + S + "}xf")

    def hidden(style):
        font_id = _number(style.get("fontId", "0"))
        if font_id >= len(font_hidden):
            _fail()
        return font_hidden[font_id] or _number(style.get("numFmtId", "0")) in custom_formats

    result = []
    for style in root.findall("{" + S + "}cellXfs/{" + S + "}xf"):
        budget.check()
        hide = hidden(style)
        if style.get("xfId") is not None:
            index = _number(style.get("xfId"))
            if index >= len(bases):
                _fail()
            hide |= hidden(bases[index])
        result.append(hide)
    return result or [False]


def _column(label):
    value = 0
    for char in label:
        value = value * 26 + ord(char) - 64
    if value > 16384:
        _fail()
    return value


def _column_label(number):
    if not 1 <= number <= 16384:
        _fail()
    result = ""
    while number:
        number, char = divmod(number - 1, 26)
        result = chr(65 + char) + result
    return result


def _worksheet(reader, root, name, sheet_hidden, strings, styles):
    ns = "{" + S + "}"
    hidden_columns = []
    for column in root.findall(ns + "cols/" + ns + "col"):
        lower = _number(column.get("min"), 1, 16384)
        upper = _number(column.get("max"), lower, 16384)
        style_index = _number(column.get("style", "0"))
        if style_index >= len(styles):
            _fail()
        if _boolean(column.get("hidden")) or column.get("width") == "0" or styles[style_index]:
            hidden_columns.append((lower, upper))
    # Intervals stay compressed; at most the nodes already covered by MAX_NODES.
    # A fixed-size column map avoids repeated cells*intervals traversal.
    hidden_map = bytearray(16385)
    for lower, upper in hidden_columns:
        reader.budget.check()
        hidden_map[lower:upper + 1] = b"\1" * (upper - lower + 1)
    row_number = 0
    seen, seen_rows = set(), set()
    data_nodes = root.findall(ns + "sheetData")
    if len(data_nodes) != 1:
        _fail()
    for row in data_nodes[0]:
        if row.tag != ns + "row":
            _fail()
        row_number = _number(row.get("r", str(row_number + 1)), 1)
        if row_number in seen_rows:
            _fail()
        seen_rows.add(row_number)
        row_style = _number(row.get("s", "0"))
        if row_style >= len(styles):
            _fail()
        hide_row = sheet_hidden or _boolean(row.get("hidden")) or row.get("ht") == "0" or styles[row_style]
        column_number = 0
        for cell in row:
            reader.budget.check()
            if cell.tag != ns + "c":
                _fail()
            reader.cells += 1
            if reader.cells > MAX_CELLS:
                _fail("STRUCTURE_LIMIT")
            reference = cell.get("r")
            if reference is None:
                reference = _column_label(column_number + 1) + str(row_number)
            match = _CELL.fullmatch(reference)
            if match is None or _number(match[2], 1) != row_number or reference in seen:
                _fail()
            seen.add(reference)
            column_number = _column(match[1])
            style_index = _number(cell.get("s", "0"))
            if style_index >= len(styles):
                _fail()
            hidden = hide_row or bool(hidden_map[column_number]) or styles[style_index]
            values = cell.findall(ns + "v")
            inline = cell.findall(ns + "is")
            if any(child.tag not in {ns + "v", ns + "is"} for child in cell):
                _fail()
            if any(len(value) for value in values):
                _fail()
            kind = cell.get("t", "n")
            if kind not in {"n", "b", "d", "e", "s", "str", "inlineStr"} or len(values) > 1 or len(inline) > 1:
                _fail()
            if kind == "inlineStr":
                if values or len(inline) != 1:
                    _fail()
                text, rich_hidden = reader.rich(inline[0])
                hidden |= rich_hidden
            elif inline:
                _fail()
            elif not values or values[0].text is None:
                # A structurally present, empty cell has no value to invent.
                text = ""
                if kind == "s":
                    _fail()
            else:
                value = values[0]
                text = value.text
                reader.consumed_text.add(id(value))
                if kind == "s":
                    index = _number(text, 0, MAX_STRINGS)
                    if index >= len(strings):
                        _fail()
                    text, rich_hidden = strings[index]
                    hidden |= rich_hidden
                elif kind == "b" and text not in {"0", "1"}:
                    _fail()
                elif kind == "n" and not _NUMERIC.fullmatch(text):
                    _fail()
                elif kind == "d":
                    try:
                        datetime.fromisoformat(text)
                    except ValueError:
                        _fail()
            reader.add(text, "HIDDEN_CONTENT" if hidden else "VISIBLE_CONTENT", "xlsx:" + name + ":cell:" + reference)


def _package(data, reader):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_ENTRIES:
            _fail("ARCHIVE_LIMIT")
        total = 0
        names = set()
        files = {}
        for info in entries:
            reader.budget.check()
            name = info.filename
            path = PurePosixPath(name)
            if (info.flag_bits & 1 or name.startswith("/") or "\\" in name or
                    any(part in {".", ".."} for part in name.split("/")) or
                    any(ord(char) < 32 for char in name) or not path.parts or
                    info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}):
                _fail("ARCHIVE_UNSAFE")
            if name.casefold() in names:
                _fail()
            names.add(name.casefold())
            total += info.file_size
            if (info.file_size > MAX_PART_BYTES or total > MAX_ARCHIVE_BYTES or
                    info.file_size / max(1, info.compress_size) > MAX_RATIO):
                _fail("ARCHIVE_BOMB")
            if info.is_dir():
                if info.file_size:
                    _fail("XLSX_UNINSPECTED_PART")
                continue
            if name.lower().endswith((".bin", ".vba")) or any(part in name.lower().split("/") for part in ("embeddings", "activex", "macrosheets")):
                _fail("XLSX_EMBEDDED_CONTENT")
            if "media" in name.lower().split("/") or name.lower().endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".svg", ".emf", ".wmf")):
                _fail("OCR_REQUIRED")
            if not name.endswith((".xml", ".rels")):
                _fail("XLSX_UNINSPECTED_PART")
            files[name] = info
        if "[Content_Types].xml" not in files or "_rels/.rels" not in files:
            _fail()
        roots = {name: reader.parse(archive.read(info), name) for name, info in files.items()}
    content_types = roots["[Content_Types].xml"]
    if content_types.tag != "{" + T + "}Types":
        _fail()
    defaults, overrides = {}, {}
    for node in content_types:
        if node.tag == "{" + T + "}Default":
            key, target = node.get("Extension"), defaults
        elif node.tag == "{" + T + "}Override":
            if not (node.get("PartName") or "").startswith("/"):
                _fail()
            key, target = _resolve("", node.get("PartName")), overrides
            if key not in roots:
                _fail()
        else:
            _fail()
        if not key or key in target or not node.get("ContentType"):
            _fail()
        target[key] = node.get("ContentType")
    kinds = {}
    for name, root in roots.items():
        if name == "[Content_Types].xml":
            continue
        content_type = overrides.get(name, defaults.get(name.rsplit(".", 1)[-1], ""))
        if "macroEnabled" in content_type or "vba" in content_type.lower():
            _fail("XLSX_EMBEDDED_CONTENT")
        if content_type.startswith("image/"):
            _fail("OCR_REQUIRED")
        if content_type not in _TYPES:
            _fail("XLSX_UNINSPECTED_PART")
        kind, ns, local = _TYPES[content_type]
        if root.tag != "{" + ns + "}" + local:
            if _tag(root)[0] != ns:
                _fail("XLSX_UNINSPECTED_PART")
            _fail()
        kinds[name] = kind
        _validate_nodes(root, kind, reader)
    relationships = {}
    relation_count = 0
    for name, kind in kinds.items():
        if kind != "relations":
            continue
        parts = name.split("/")
        if name == "_rels/.rels":
            source = ""
        elif len(parts) >= 2 and parts[-2] == "_rels" and name.endswith(".rels"):
            source = "/".join(parts[:-2] + [parts[-1][:-5]])
            if source not in kinds:
                _fail()
        else:
            _fail()
        if source in relationships:
            _fail()
        links = {}
        for node in roots[name]:
            reader.budget.check()
            relation_count += 1
            if relation_count > MAX_RELATIONSHIPS:
                _fail("STRUCTURE_LIMIT")
            if node.tag != "{" + P + "}Relationship":
                _fail()
            identifier, relation_type, target = node.get("Id"), node.get("Type"), node.get("Target")
            mode = node.get("TargetMode", "Internal")
            if not identifier or identifier in links or not relation_type or not target or mode not in {"Internal", "External"}:
                _fail()
            source_kind = kinds.get(source, "")
            expected = _RELATIONS.get(source_kind, {}).get(relation_type)
            if mode == "External":
                if expected != "hyperlink":
                    _fail("XLSX_EXTERNAL_CONTENT")
                links[identifier] = ("hyperlink", None)
            else:
                if expected is None or expected == "hyperlink":
                    _fail("XLSX_UNINSPECTED_PART")
                destination = _resolve(source, target)
                if kinds.get(destination) != expected:
                    _fail()
                links[identifier] = (expected, destination)
        relationships[source] = links
    main = [target for kind, target in relationships.get("", {}).values() if kind == "workbook"]
    if len(main) != 1 or list(kinds.values()).count("workbook") != 1:
        _fail()
    workbook = main[0]
    referenced = {target for links in relationships.values() for _, target in links.values() if target is not None}
    if referenced != {name for name, kind in kinds.items() if kind != "relations"}:
        _fail()
    for name, root in roots.items():
        for node in root.iter():
            reader.budget.check()
            for attr, value in node.attrib.items():
                if attr.startswith("{" + R + "}") and value not in relationships.get(name, {}):
                    _fail()
    links = relationships.get(workbook, {})
    dependencies = {}
    for kind in ("strings", "styles", "theme"):
        selected = [target for item_kind, target in links.values() if item_kind == kind]
        if len(selected) > 1:
            _fail()
        if set(selected) != {name for name, item_kind in kinds.items() if item_kind == kind}:
            _fail()
        dependencies[kind] = roots[selected[0]] if selected else None
    strings = []
    if dependencies["strings"] is not None:
        for item in dependencies["strings"]:
            if item.tag != "{" + S + "}si":
                _fail()
            if len(strings) >= MAX_STRINGS:
                _fail("STRUCTURE_LIMIT")
            value = reader.rich(item)
            strings.append(value)
            reader.add(value[0], "METADATA", "xlsx:shared-string:" + str(len(strings) - 1))
    styles = _styles(dependencies["styles"], reader.budget)
    sheets = roots[workbook].findall("{" + S + "}sheets/{" + S + "}sheet")
    if len(sheets) > MAX_SHEETS:
        _fail("STRUCTURE_LIMIT")
    if not sheets:
        _fail()
    visited, ids, sheet_names = set(), set(), set()
    for sheet in sheets:
        reader.budget.check()
        sheet_id = _number(sheet.get("sheetId"), 1)
        sheet_name = sheet.get("name")
        state = sheet.get("state", "visible")
        kind, name = links.get(sheet.get("{" + R + "}id"), (None, None))
        if (kind != "worksheet" or name in visited or sheet_id in ids or not sheet_name or
                sheet_name.casefold() in sheet_names or state not in {"visible", "hidden", "veryHidden"}):
            _fail()
        visited.add(name)
        ids.add(sheet_id)
        sheet_names.add(sheet_name.casefold())
        _worksheet(reader, roots[name], name, state != "visible", strings, styles)
    if visited != {name for name, kind in kinds.items() if kind == "worksheet"}:
        _fail()
    for name, root in roots.items():
        if kinds.get(name) == "comments":
            authors = root.findall("{" + S + "}authors/{" + S + "}author")
            for comment in root.findall("{" + S + "}commentList/{" + S + "}comment"):
                author = _number(comment.get("authorId"))
                reference = comment.get("ref", "")
                match = _CELL.fullmatch(reference)
                if match is None or author >= len(authors):
                    _fail()
                _column(match[1])
                _number(match[2], 1)
                for text in comment.findall("{" + S + "}text"):
                    value, _ = reader.rich(text)
                    reader.add(value, "HIDDEN_CONTENT", "xlsx:" + name + ":comment:" + reference)
        reader.metadata(root, name)
    reader.result.limitations.append(
        "XLSX static data profile: Transitional XML cells, shared strings and metadata only; formulas, visual media, VML, unknown parts and external data fail closed. No Office execution, recalculation or OCR. Hidden typography is heuristic; custom number formats are conservatively hidden.")
    return reader.result


def extract_xlsx(data: bytes, filename: str, budget: Budget) -> Extraction:
    """Trusted registry handler: all failures are fixed, content-free diagnostics."""
    budget.check()
    try:
        return _package(data, _Reader(budget))
    except ExtractionError:
        raise
    except DefusedXmlException:
        _fail("XML_ENTITY_FORBIDDEN")
    except (MemoryError, RecursionError):
        raise
    except Exception:
        _fail()
