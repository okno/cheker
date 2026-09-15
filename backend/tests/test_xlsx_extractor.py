"""Ordinary SpreadsheetML examples for the bounded static-data profile."""
import hashlib
import io
import sys
import struct
import zlib
import zipfile
from xml.etree import ElementTree as ET

import pytest

from integrity_guard import xlsx_extractor as module
from integrity_guard.core import GuardStore
from integrity_guard.extraction import Budget, ExtractionError, extract
from integrity_guard.extractor_registry import get_registry
from integrity_guard.reports import Reports, classify_report
from integrity_guard.scanner import Scanner

def png_chunk(kind, data):
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


# A complete ordinary 1x1 RGB PNG, with no instructions or active content.
PNG = (b"\x89PNG\r\n\x1a\n" + png_chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
       + png_chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff")) + png_chunk(b"IEND", b""))
S, R, P, T = module.S, module.R, module.P, module.T
KIND_TYPES = {value[0]: key for key, value in module._TYPES.items()}


def xml(root):
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def element(name, attrs=None, text=None, ns=S):
    node = ET.Element(f"{{{ns}}}{name}", attrs or {})
    node.text = text
    return node


def links(entries):
    root = element("Relationships", ns=P)
    for entry in entries:
        root.append(element("Relationship", entry, ns=P))
    return root


def rel(identifier, kind, target, mode=None):
    attrs = {"Id": identifier, "Type": R + "/" + kind, "Target": target}
    if mode:
        attrs["TargetMode"] = mode
    return attrs


def cell(reference="A1", text="Meeting notes.", kind="inlineStr", style=None):
    attrs = {"r": reference, "t": kind}
    if style is not None:
        attrs["s"] = str(style)
    node = element("c", attrs)
    if text is not None:
        if kind == "inlineStr":
            value = element("is")
            value.append(element("t", text=text))
        else:
            value = element("v", text=text)
        node.append(value)
    return node


def sheet(*cells, hidden_row=False, hidden_column=False):
    root = element("worksheet")
    if hidden_column:
        columns = element("cols")
        columns.append(element("col", {"min": "1", "max": "16384", "hidden": "1"}))
        root.append(columns)
    data = element("sheetData")
    row = element("row", {"r": "1", **({"hidden": "1"} if hidden_row else {})})
    for item in cells or (cell(),):
        row.append(item)
    data.append(row)
    root.append(data)
    return root


def rich(*texts):
    root = element("si")
    for text in texts:
        run = element("r")
        run.append(element("t", {"{http://www.w3.org/XML/1998/namespace}space": "preserve"}, text))
        root.append(run)
    return root


def styles(*, white=False, tiny=False, custom=False):
    root = element("styleSheet")
    if custom:
        formats = element("numFmts")
        formats.append(element("numFmt", {"numFmtId": "164", "formatCode": ";;;"}))
        root.append(formats)
    fonts = element("fonts")
    font = element("font")
    font.append(element("sz", {"val": "1" if tiny else "11"}))
    font.append(element("color", {"rgb": "FFFFFFFF" if white else "FF000000"}))
    fonts.append(font)
    root.append(fonts)
    xfs = element("cellXfs")
    xfs.append(element("xf", {"fontId": "0", "numFmtId": "164" if custom else "0"}))
    root.append(xfs)
    return root


def parts(*, worksheet=None, state="visible", strings=None, style=None, comments=None):
    root = element("workbook")
    sheets = element("sheets")
    sheets.append(element("sheet", {"name": "Notes", "sheetId": "1", "state": state, "{" + R + "}id": "sheet"}))
    root.append(sheets)
    relations = [rel("sheet", "worksheet", "worksheets/sheet1.xml")]
    content = {
        "xl/workbook.xml": ("workbook", root),
        "xl/worksheets/sheet1.xml": ("worksheet", worksheet if worksheet is not None else sheet()),
        "_rels/.rels": ("relations", links([rel("main", "officeDocument", "xl/workbook.xml")])),
    }
    for name, kind, value, target in (("xl/sharedStrings.xml", "strings", strings, "sharedStrings.xml"),
                                     ("xl/styles.xml", "styles", style, "styles.xml")):
        if value is not None:
            content[name] = (kind, value)
            relations.append(rel(kind, "sharedStrings" if kind == "strings" else kind, target))
    if comments is not None:
        content["xl/comments1.xml"] = ("comments", comments)
        content["xl/worksheets/_rels/sheet1.xml.rels"] = ("relations", links([rel("comments", "comments", "../comments1.xml")]))
    content["xl/_rels/workbook.xml.rels"] = ("relations", links(relations))
    return content


def package(content=None, extras=None, *, compressed=False):
    content = parts() if content is None else content
    types = element("Types", ns=T)
    for name, (kind, _) in content.items():
        types.append(element("Override", {"PartName": "/" + name, "ContentType": KIND_TYPES[kind]}, ns=T))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED) as archive:
        archive.writestr("[Content_Types].xml", xml(types))
        for name, (_, root) in content.items():
            archive.writestr(name, xml(root) if isinstance(root, ET.Element) else root)
        for name, data in (extras or {}).items():
            archive.writestr(name, data)
    return out.getvalue()


def extracted(data):
    return extract(data, "notes.xlsx", Budget(8))


def assert_refusal(data, code, failure="UNSUPPORTED"):
    with pytest.raises(ExtractionError) as error:
        extracted(data)
    assert error.value.code == code
    report = Scanner().scan_bytes(data, "notes.xlsx")
    assert report["status"] == "BLOCKED" and report["analysis_complete"] is False
    assert report["failure_kind"] == failure
    assert report["findings"][0]["rule_id"] == code
    assert classify_report(report) == ("CORRUPTED" if failure == "MALFORMED" else "UNSCANNABLE")
    return report


def test_static_cells_empty_cells_and_exact_locations():
    data = package(parts(worksheet=sheet(cell(), cell("B1", "12.5", "n"), cell("C1", "1", "b"),
                                                cell("D1", None, "n"), cell("E1", "", "inlineStr"))))
    result = extracted(data)
    visible = [(s.text, s.location) for s in result.segments if s.layer == "VISIBLE_CONTENT"]
    assert visible == [("Meeting notes.", "xlsx:xl/worksheets/sheet1.xml:cell:A1"),
                       ("12.5", "xlsx:xl/worksheets/sheet1.xml:cell:B1"),
                       ("1", "xlsx:xl/worksheets/sheet1.xml:cell:C1")]
    assert result.characters == sum(len(s.text) for s in result.segments)
    report = Scanner().scan_bytes(data, "notes.XLSX")
    assert report["status"] == "ALLOWED" and report["analysis_complete"] is True
    assert classify_report(report) == "VALID"


def test_blank_workbook_is_structurally_inspected_without_inventing_cells():
    worksheet = element("worksheet")
    worksheet.append(element("sheetData"))
    result = extracted(package(parts(worksheet=worksheet)))
    assert not any(s.layer == "VISIBLE_CONTENT" for s in result.segments)
    assert any("Notes" in s.text and s.layer == "METADATA" for s in result.segments)


def test_shared_strings_rich_runs_and_unused_string_keep_coverage():
    strings = element("sst")
    strings.extend([rich("Meeting", " notes."), rich("Unused", " reference.")])
    result = extracted(package(parts(worksheet=sheet(cell(text="0", kind="s")), strings=strings)))
    assert any(s.text == "Meeting notes." and s.layer == "VISIBLE_CONTENT" for s in result.segments)
    assert any(s.text == "Unused reference." and s.layer == "METADATA" and s.location == "xlsx:shared-string:1" for s in result.segments)


@pytest.mark.parametrize("state,row,column,style", [
    ("hidden", False, False, None), ("veryHidden", False, False, None),
    ("visible", True, False, None), ("visible", False, True, None),
    ("visible", False, False, {"white": True}), ("visible", False, False, {"tiny": True}),
    ("visible", False, False, {"custom": True}),
])
def test_hidden_data_is_present_and_classified(state, row, column, style):
    result = extracted(package(parts(worksheet=sheet(hidden_row=row, hidden_column=column), state=state,
                                     style=styles(**style) if style else None)))
    assert any(s.text == "Meeting notes." and s.layer == "HIDDEN_CONTENT" and s.location.endswith(":cell:A1") for s in result.segments)
    assert not any(s.text == "Meeting notes." and s.layer == "VISIBLE_CONTENT" for s in result.segments)


def test_inline_rich_text_hidden_font_is_not_lost():
    value = cell()
    inline = value[0]
    inline.clear()
    run = element("r")
    props = element("rPr")
    props.append(element("sz", {"val": "1"}))
    run.extend([props, element("t", text="Meeting notes.")])
    inline.append(run)
    result = extracted(package(parts(worksheet=sheet(value))))
    assert any(s.text == "Meeting notes." and s.layer == "HIDDEN_CONTENT" for s in result.segments)


def test_comment_properties_headers_attributes_and_xml_tail():
    comments = element("comments")
    authors = element("authors")
    authors.append(element("author", text="Editor"))
    items = element("commentList")
    comment = element("comment", {"ref": "A1", "authorId": "0"})
    text = element("text")
    text.append(element("t", text="Editorial note."))
    comment.append(text)
    items.append(comment)
    comments.extend([authors, items])
    content = parts(comments=comments)
    header = element("headerFooter")
    header.append(element("oddHeader", text="Annual notes."))
    content["xl/worksheets/sheet1.xml"][1].append(header)
    properties = element("Properties", ns=module.CUSTOM)
    prop = element("property", {"name": "Topic", "pid": "2"}, ns=module.CUSTOM)
    prop.append(element("lpwstr", text="Meeting summary.", ns=module.VT))
    prop[0].tail = "Supplement."
    properties.append(prop)
    content["docProps/custom.xml"] = ("custom", properties)
    content["_rels/.rels"][1].append(element("Relationship", rel("properties", "custom-properties", "docProps/custom.xml"), ns=P))
    result = extracted(package(content))
    assert any(s.text == "Editorial note." and s.layer == "HIDDEN_CONTENT" and s.location.endswith(":comment:A1") for s in result.segments)
    for value in ("Editor", "Annual notes.", "Topic", "Meeting summary.", "Supplement."):
        assert any(value in s.text and s.layer == "METADATA" for s in result.segments), value


def test_literal_spreadsheet_escapes_decode_once_and_preserve_raw_view():
    result = extracted(package(parts(worksheet=sheet(cell(text="Notes_x000A_Second line_x005F_x0041_")))))
    assert any(s.text == "Notes\nSecond line_x0041_" and s.layer == "VISIBLE_CONTENT" for s in result.segments)
    assert any(s.text == "Notes_x000A_Second line_x005F_x0041_" and s.layer == "METADATA" for s in result.segments)


def test_xml_comments_and_processing_instructions_are_inspected():
    content = parts()
    body = xml(content["xl/worksheets/sheet1.xml"][1]).replace(b"?>", b"?><!--Editorial note.--><?notes ordinary?>", 1)
    content["xl/worksheets/sheet1.xml"] = ("worksheet", body)
    result = extracted(package(content))
    assert any(s.text == "Editorial note." and s.layer == "HIDDEN_CONTENT" for s in result.segments)
    assert any(s.text == "notes ordinary" and s.layer == "HIDDEN_CONTENT" for s in result.segments)


def test_hyperlink_is_metadata_only():
    content = parts()
    hyperlinks = element("hyperlinks")
    hyperlinks.append(element("hyperlink", {"ref": "A1", "{" + R + "}id": "link"}))
    content["xl/worksheets/sheet1.xml"][1].append(hyperlinks)
    content["xl/worksheets/_rels/sheet1.xml.rels"] = ("relations", links([rel("link", "hyperlink", "https://example.org/notes", "External")]))
    result = extracted(package(content))
    assert any("https://example.org/notes" in s.text and s.layer == "METADATA" for s in result.segments)


@pytest.mark.parametrize("place", ["cell", "validation", "name"])
def test_ordinary_formulas_are_explicitly_unsupported(place):
    content = parts()
    if place == "cell":
        content["xl/worksheets/sheet1.xml"][1].find(".//{" + S + "}c").append(element("f", text="SUM(A2:A3)"))
    elif place == "validation":
        content["xl/worksheets/sheet1.xml"][1].append(element("formula1", text="1"))
    else:
        content["xl/workbook.xml"][1].append(element("definedName", {"name": "Total"}, "SUM(Notes!A2:A3)"))
    assert_refusal(package(content), "XLSX_FORMULA_UNSUPPORTED")


@pytest.mark.parametrize("name,data,code", [
    ("xl/appendix.txt", b"Meeting appendix.", "XLSX_UNINSPECTED_PART"),
    ("xl/drawings/comments.vml", b"<xml>Editorial note.</xml>", "XLSX_UNINSPECTED_PART"),
    ("xl/media/diagram.png", PNG, "OCR_REQUIRED"),
    ("xl/embeddings/notes.bin", b"ordinary attachment placeholder", "XLSX_EMBEDDED_CONTENT"),
])
def test_parts_outside_profile_are_not_silently_skipped(name, data, code):
    assert_refusal(package(extras={name: data}), code)


def test_external_relationship_has_fixed_message_without_target():
    content = parts()
    target = "https://example.org/ordinary-workbook.xlsx"
    content["xl/_rels/workbook.xml.rels"][1].append(element("Relationship", rel("external", "externalLink", target, "External"), ns=P))
    report = assert_refusal(package(content), "XLSX_EXTERNAL_CONTENT")
    assert target not in str(report["findings"])


@pytest.mark.parametrize("case", ["not_zip", "missing_part", "bad_xml", "missing_sheet", "bad_shared_index", "wrong_root", "duplicate_cell", "unknown_type"])
def test_ordinary_incomplete_or_inconsistent_files_fail_closed(case):
    content = parts()
    code = "INVALID_XLSX"
    failure = "MALFORMED"
    if case == "not_zip":
        data = b"Meeting notes."
    else:
        if case == "missing_part":
            del content["xl/worksheets/sheet1.xml"]
        elif case == "bad_xml":
            content["xl/worksheets/sheet1.xml"] = ("worksheet", b"<worksheet>")
        elif case == "missing_sheet":
            content["xl/workbook.xml"][1].clear()
        elif case == "bad_shared_index":
            strings = element("sst")
            strings.append(rich("Meeting notes."))
            content = parts(worksheet=sheet(cell(text="2", kind="s")), strings=strings)
        elif case == "wrong_root":
            content["xl/worksheets/sheet1.xml"] = ("worksheet", element("workbook"))
        elif case == "duplicate_cell":
            content = parts(worksheet=sheet(cell(), cell()))
        elif case == "unknown_type":
            content["xl/worksheets/sheet1.xml"][1].append(element("extLst"))
            code, failure = "XLSX_UNINSPECTED_PART", "UNSUPPORTED"
        data = package(content)
    assert_refusal(data, code, failure)


@pytest.mark.parametrize("limit,value,code", [
    ("MAX_ENTRIES", 2, "ARCHIVE_LIMIT"), ("MAX_PART_BYTES", 20, "ARCHIVE_BOMB"),
    ("MAX_ARCHIVE_BYTES", 20, "ARCHIVE_BOMB"), ("MAX_NODES", 3, "STRUCTURE_LIMIT"),
    ("MAX_DEPTH", 2, "STRUCTURE_LIMIT"), ("MAX_SHEETS", 0, "STRUCTURE_LIMIT"),
    ("MAX_CELLS", 0, "STRUCTURE_LIMIT"), ("MAX_RELATIONSHIPS", 0, "STRUCTURE_LIMIT"),
])
def test_limits_on_small_neutral_documents(monkeypatch, limit, value, code):
    monkeypatch.setattr(module, limit, value)
    assert_refusal(package(), code, "RESOURCE_LIMIT")


def test_shared_string_limit_and_common_budget_are_preserved(monkeypatch):
    strings = element("sst")
    strings.append(rich("Meeting notes."))
    data = package(parts(strings=strings))
    monkeypatch.setattr(module, "MAX_STRINGS", 0)
    assert_refusal(data, "STRUCTURE_LIMIT", "RESOURCE_LIMIT")
    with pytest.raises(ExtractionError) as error:
        extract(package(), "notes.xlsx", Budget(8, max_chars=5))
    assert error.value.code == "EXPANSION_LIMIT"
    with pytest.raises(ExtractionError) as error:
        extract(package(), "notes.xlsx", Budget(0))
    assert error.value.code == "TIME_BUDGET"


def test_registry_manifest_includes_only_explicit_packaged_xlsx():
    manifest = get_registry().descriptors()
    assert [item["format"] for item in manifest["extractors"]] == ["xlsx"]
    descriptor = manifest["extractors"][0]
    assert descriptor["extensions"] == [".xlsx"]
    assert descriptor["handler"]["module"] == "integrity_guard.xlsx_extractor"
    assert descriptor["handler"]["qualname"] == "extract_xlsx"
    assert descriptor["dependencies"] == {"defusedxml": "0.7.1"}


@pytest.mark.skipif(sys.platform != "linux", reason="The real worker requires the Linux sandbox")
@pytest.mark.parametrize("case,verdict,code", [
    ("static", "VALID", None), ("formula", "UNSCANNABLE", "XLSX_FORMULA_UNSUPPORTED"),
    ("appendix", "UNSCANNABLE", "XLSX_UNINSPECTED_PART"),
])
def test_real_worker_reports_persistence_statistics_and_audit(tmp_path, case, verdict, code):
    content = parts()
    if case == "formula":
        content["xl/worksheets/sheet1.xml"][1].find(".//{" + S + "}c").append(element("f", text="1+2"))
    data = package(content, {"xl/appendix.txt": b"Meeting appendix."} if case == "appendix" else None)
    state = tmp_path / "state"
    store = reports = None
    try:
        store = GuardStore(state)
        reports = Reports(state, store)
        before = store.verify_audit()
        report = reports.scan(data, "notes.xlsx")
        assert report["sandbox"]["active"] is True
        assert report["sandbox"]["mechanism"] == "landlock+seccomp"
        assert report["sha256"] == hashlib.sha256(data).hexdigest()
        assert report["verdict"] == verdict
        assert report["status"] == ("ALLOWED" if verdict == "VALID" else "BLOCKED")
        assert report["analysis_complete"] is (verdict == "VALID")
        if code:
            assert report["findings"][0]["rule_id"] == code
        assert reports.get(report["id"]) == report
        stats = reports.stats()
        assert stats["analyzed"] == stats["unique_files"] == stats["matched"] == 1
        assert stats["valid"] == int(verdict == "VALID")
        assert stats["unscannable"] == stats["blocked"] == int(verdict == "UNSCANNABLE")
        after = store.verify_audit()
        assert after["valid"] is True and after["checked"] == before["checked"] + 1
        event = store.audit_events()[0]
        assert event["event_type"] == "FILE_SCANNED" and event["details"]["scan_id"] == report["id"]
    finally:
        try:
            if reports is not None:
                reports.close()
        finally:
            if store is not None:
                store.close()


@pytest.mark.parametrize("scope", ["row", "column"])
def test_inherited_typography_is_conservatively_hidden(scope):
    style = styles()
    fonts = style.find("{" + S + "}fonts")
    font = element("font")
    font.append(element("color", {"rgb": "FFFFFFFF"}))
    fonts.append(font)
    style.find("{" + S + "}cellXfs").append(element("xf", {"fontId": "1", "numFmtId": "0"}))
    worksheet = sheet()
    if scope == "row":
        worksheet.find(".//{" + S + "}row").set("s", "1")
    else:
        columns = element("cols")
        columns.append(element("col", {"min": "1", "max": "2", "style": "1"}))
        worksheet.insert(0, columns)
    result = extracted(package(parts(worksheet=worksheet, style=style)))
    assert any(s.text == "Meeting notes." and s.layer == "HIDDEN_CONTENT" for s in result.segments)


def test_two_sheets_preserve_names_relations_and_locations():
    content = parts()
    content["xl/workbook.xml"][1].find("{" + S + "}sheets").append(
        element("sheet", {"name": "Archive", "sheetId": "2", "state": "hidden", "{" + R + "}id": "archive"}))
    content["xl/_rels/workbook.xml.rels"][1].append(element("Relationship", rel("archive", "worksheet", "/xl/worksheets/archive.xml"), ns=P))
    content["xl/worksheets/archive.xml"] = ("worksheet", sheet(cell(text="Previous notes.")))
    result = extracted(package(content, compressed=True))
    assert any(s.text == "Meeting notes." and s.layer == "VISIBLE_CONTENT" for s in result.segments)
    assert any(s.text == "Previous notes." and s.layer == "HIDDEN_CONTENT" and s.location == "xlsx:xl/worksheets/archive.xml:cell:A1" for s in result.segments)


@pytest.mark.parametrize("kind,text", [("n", "twelve"), ("b", "yes"), ("d", "next week")])
def test_cell_type_mismatch_is_malformed(kind, text):
    assert_refusal(package(parts(worksheet=sheet(cell(text=text, kind=kind)))), "INVALID_XLSX", "MALFORMED")


def test_serialized_iso_date_and_error_values_are_preserved_as_text():
    result = extracted(package(parts(worksheet=sheet(cell(text="2026-09-15", kind="d"), cell("B1", "#DIV/0!", "e")))))
    assert [s.text for s in result.segments if s.layer == "VISIBLE_CONTENT"] == ["2026-09-15", "#DIV/0!"]


def test_strict_namespace_is_explicitly_outside_initial_profile():
    content = parts()
    content["xl/workbook.xml"] = ("workbook", xml(content["xl/workbook.xml"][1]).replace(S.encode(), b"http://purl.oclc.org/ooxml/spreadsheetml/main"))
    assert_refusal(package(content), "XLSX_UNINSPECTED_PART")


@pytest.mark.parametrize("extension", ["doc", "xls", "xlsm", "xlsb"])
def test_legacy_and_macro_extensions_remain_unsupported(extension):
    report = Scanner().scan_bytes(package(), "notes." + extension)
    assert report["status"] == "BLOCKED" and report["analysis_complete"] is False
    assert report["findings"][0]["rule_id"] == "UNSUPPORTED_FORMAT"


def test_theme_and_core_properties_are_metadata_with_real_relationships():
    content = parts()
    theme = element("theme", {"name": "Plain theme"}, ns=module.A)
    theme.append(element("themeElements", ns=module.A))
    content["xl/theme/theme1.xml"] = ("theme", theme)
    content["xl/_rels/workbook.xml.rels"][1].append(element("Relationship", rel("theme", "theme", "theme/theme1.xml"), ns=P))
    props = element("coreProperties", ns=module.CORE)
    props.append(element("title", text="Annual meeting.", ns="http://purl.org/dc/elements/1.1/"))
    content["docProps/core.xml"] = ("core", props)
    content["_rels/.rels"][1].append(element("Relationship", {"Id": "core", "Type": P + "/metadata/core-properties", "Target": "docProps/core.xml"}, ns=P))
    result = extracted(package(content))
    assert any("Plain theme" in s.text and s.layer == "METADATA" for s in result.segments)
    assert any("Annual meeting." in s.text and s.layer == "METADATA" for s in result.segments)


def test_unlinked_known_part_is_an_incomplete_package():
    content = parts()
    content["docProps/custom.xml"] = ("custom", element("Properties", ns=module.CUSTOM))
    assert_refusal(package(content), "INVALID_XLSX", "MALFORMED")


def test_empty_zip_directory_and_implicit_cell_coordinates():
    worksheet = sheet(cell(), cell("B1", "Second note."))
    row = worksheet.find(".//{" + S + "}row")
    del row.attrib["r"]
    for item in row:
        del item.attrib["r"]
    result = extracted(package(parts(worksheet=worksheet), {"xl/": b""}))
    assert [(s.text, s.location.rsplit(":", 1)[-1]) for s in result.segments if s.layer == "VISIBLE_CONTENT"] == [
        ("Meeting notes.", "A1"), ("Second note.", "B1")]
