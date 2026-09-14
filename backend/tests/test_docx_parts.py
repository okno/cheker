"""Neutral DOCX coverage checks: unsupported parts cannot be silently omitted."""
import hashlib
import io
import sys
import urllib.request
import zipfile
from xml.etree import ElementTree as ET

import pytest

from integrity_guard.core import GuardStore
from integrity_guard.extraction import Budget, ExtractionError, extract
from integrity_guard.reports import Reports, classify_report
from integrity_guard.scanner import Scanner


W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
P = "http://schemas.openxmlformats.org/package/2006/relationships"
T = "http://schemas.openxmlformats.org/package/2006/content-types"
MAIN_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"


def xml_bytes(root):
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def paragraph(text):
    paragraph = ET.Element(f"{{{W}}}p")
    run = ET.SubElement(paragraph, f"{{{W}}}r")
    ET.SubElement(run, f"{{{W}}}t").text = text
    return paragraph


def document(*, anchor=False):
    root = ET.Element(f"{{{W}}}document")
    body = ET.SubElement(root, f"{{{W}}}body")
    body.append(paragraph("Verbale della riunione."))
    if anchor:
        ET.SubElement(body, f"{{{W}}}altChunk", {f"{{{R}}}id": "appendix"})
    return xml_bytes(root)


def relationships(*entries):
    root = ET.Element(f"{{{P}}}Relationships")
    for attrs in entries:
        ET.SubElement(root, f"{{{P}}}Relationship", attrs)
    return xml_bytes(root)


def relation(kind="hyperlink", target="https://example.org/appendix", mode="External"):
    attrs = {"Id": "appendix", "Type": f"{R}/{kind}", "Target": target}
    if mode is not None:
        attrs["TargetMode"] = mode
    return attrs


def package(extra=None, *, main=None, compressed=False):
    parts = {
        "word/document.xml": document() if main is None else main,
        "_rels/.rels": relationships({"Id": "document", "Type": f"{R}/officeDocument",
                                     "Target": "word/document.xml"}),
        **(extra or {}),
    }
    types = ET.Element(f"{{{T}}}Types")
    for extension, content_type in (("xml", "application/xml"),
                                    ("rels", "application/vnd.openxmlformats-package.relationships+xml"),
                                    ("html", "text/html"), ("txt", "text/plain"),
                                    ("rtf", "application/rtf")):
        ET.SubElement(types, f"{{{T}}}Default", {"Extension": extension, "ContentType": content_type})
    ET.SubElement(types, f"{{{T}}}Override", {"PartName": "/word/document.xml", "ContentType": MAIN_TYPE})
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_DEFLATED if compressed else zipfile.ZIP_STORED) as archive:
        archive.writestr("[Content_Types].xml", xml_bytes(types))
        for name, content in parts.items():
            archive.writestr(name, content)
    return data.getvalue()


def assert_unsupported(data, code):
    with pytest.raises(ExtractionError) as error:
        extract(data, "meeting.docx", Budget(8))
    assert error.value.code == code
    report = Scanner().scan_bytes(data, "meeting.docx")
    assert report["status"] == "BLOCKED"
    assert report["analysis_complete"] is False
    assert report["failure_kind"] == "UNSUPPORTED"
    assert classify_report(report) == "UNSCANNABLE"
    assert report["findings"][0]["rule_id"] == code
    return str(error.value), report


def test_normal_xml_parts_preserve_text_layers_and_completion():
    comments = ET.Element(f"{{{W}}}comments")
    comment = ET.SubElement(comments, f"{{{W}}}comment", {f"{{{W}}}id": "1"})
    comment.append(paragraph("Nota editoriale."))
    footnotes = ET.Element(f"{{{W}}}footnotes")
    note = ET.SubElement(footnotes, f"{{{W}}}footnote", {f"{{{W}}}id": "1"})
    note.append(paragraph("Riferimento bibliografico."))
    data = package({
        "word/comments.xml": xml_bytes(comments),
        "word/footnotes.xml": xml_bytes(footnotes),
        "word/styles.xml": f'<w:styles xmlns:w="{W}"/>'.encode(),
        "docProps/core.xml": b"<properties><title>Verbale annuale.</title></properties>",
    })
    result = extract(data, "meeting.docx", Budget(8))
    segments = {(part.text, part.layer, part.location) for part in result.segments}
    assert ("Verbale della riunione.\n", "VISIBLE_CONTENT", "docx:word/document.xml") in segments
    assert ("Nota editoriale.\n", "HIDDEN_CONTENT", "docx:word/comments.xml") in segments
    assert ("Riferimento bibliografico.\n", "HIDDEN_CONTENT", "docx:word/footnotes.xml") in segments
    assert ("Verbale annuale.", "METADATA", "docx:docProps/core.xml") in segments
    report = Scanner().scan_bytes(data, "meeting.docx")
    assert report["analysis_complete"] is True
    assert report["status"] == "ALLOWED"
    assert classify_report(report) == "VALID"


def test_empty_directory_entries_do_not_change_extracted_content():
    plain = extract(package(), "meeting.docx", Budget(8))
    directories = extract(package({"word/": b"", "docProps/": b""}), "meeting.docx", Budget(8))
    assert directories.segments == plain.segments


@pytest.mark.parametrize("name,content", [
    ("word/appendix.html", b"<p>Appendice del progetto.</p>"),
    ("word/appendix.txt", b"Appendice del progetto."),
    ("word/appendix.rtf", br"{\rtf1 Appendice del progetto.}"),
    ("appendix/", b"Appendice del progetto."),
])
def test_uninspected_parts_fail_closed(name, content):
    assert_unsupported(package({name: content}), "DOCX_UNINSPECTED_PART")


@pytest.mark.parametrize("kind", ["aFChunk", "afChunk"])
def test_alternative_import_relationship_to_xml_is_explicitly_unsupported(kind):
    data = package({
        "word/appendix.xml": b"<appendix>Appendice del progetto.</appendix>",
        "word/_rels/document.xml.rels": relationships(relation(kind, "appendix.xml", "Internal")),
    })
    assert_unsupported(data, "DOCX_ALTCHUNK_UNSUPPORTED")


def test_altchunk_anchor_without_resolved_relationship_fails_closed():
    assert_unsupported(package(main=document(anchor=True)), "DOCX_ALTCHUNK_UNSUPPORTED")


@pytest.mark.parametrize("part,root_name", [("word/footnotes.xml", "footnotes"),
                                           ("word/header1.xml", "hdr")])
def test_altchunk_in_secondary_document_parts_is_not_omitted(part, root_name):
    # A different prefix still denotes the same qualified WordprocessingML element.
    xml = f'<q:{root_name} xmlns:q="{W}" xmlns:r="{R}"><q:altChunk r:id="appendix"/></q:{root_name}>'
    assert_unsupported(package({part: xml.encode()}), "DOCX_ALTCHUNK_UNSUPPORTED")


@pytest.mark.parametrize("target", ["https://example.org/appendix", "../references/appendix.html"])
def test_ordinary_external_hyperlinks_are_only_metadata(monkeypatch, target):
    def no_fetch(*args, **kwargs):
        pytest.fail("DOCX extraction must not retrieve hyperlink targets")
    monkeypatch.setattr(urllib.request, "urlopen", no_fetch)
    data = package({"word/_rels/document.xml.rels": relationships(relation(target=target))})
    result = extract(data, "meeting.docx", Budget(8))
    assert any(part.text == target and part.layer == "METADATA"
               and part.location == "docx:word/_rels/document.xml.rels@Target" for part in result.segments)
    report = Scanner().scan_bytes(data, "meeting.docx")
    assert report["analysis_complete"] is True
    assert report["status"] == "ALLOWED"


@pytest.mark.parametrize("kind,target", [
    ("image", "https://example.org/diagram.png"),
    ("image", "../references/diagram.png"),
    ("attachedTemplate", "https://example.org/template.dotx"),
    ("projectReference", "../references/appendix.xml"),
])
def test_external_content_relationships_are_incomplete_without_retrieval(monkeypatch, kind, target):
    def no_fetch(*args, **kwargs):
        pytest.fail("DOCX extraction must not retrieve external content")
    monkeypatch.setattr(urllib.request, "urlopen", no_fetch)
    data = package({"word/_rels/document.xml.rels": relationships(relation(kind, target))})
    assert_unsupported(data, "DOCX_EXTERNAL_CONTENT")


@pytest.mark.parametrize("mode", [None, "Internal"])
def test_normal_internal_relationships_keep_the_xml_content(mode):
    header = ET.Element(f"{{{W}}}hdr")
    header.append(paragraph("Riepilogo annuale."))
    data = package({"word/header1.xml": xml_bytes(header),
                    "word/_rels/document.xml.rels": relationships(relation("header", "header1.xml", mode))})
    result = extract(data, "meeting.docx", Budget(8))
    assert any(part.text == "Riepilogo annuale.\n" and part.location == "docx:word/header1.xml"
               for part in result.segments)


@pytest.mark.parametrize("missing", ["Id", "Type", "Target"])
def test_missing_relationship_fields_are_malformed(missing):
    attrs = relation()
    del attrs[missing]
    report = Scanner().scan_bytes(package({"word/_rels/document.xml.rels": relationships(attrs)}), "meeting.docx")
    assert report["analysis_complete"] is False
    assert report["status"] == "BLOCKED"
    assert report["failure_kind"] == "MALFORMED"
    assert classify_report(report) == "CORRUPTED"
    assert report["findings"][0]["rule_id"] == "INVALID_DOCX"


def test_unknown_target_mode_is_malformed():
    attrs = relation(mode="Unspecified")
    report = Scanner().scan_bytes(package({"word/_rels/document.xml.rels": relationships(attrs)}), "meeting.docx")
    assert report["analysis_complete"] is False
    assert classify_report(report) == "CORRUPTED"
    assert report["findings"][0]["rule_id"] == "INVALID_DOCX"


@pytest.mark.parametrize("name,code", [("word/media/diagram.png", "OCR_REQUIRED"),
                                     ("word/embeddings/appendix.bin", "EMBEDDED_CONTENT")])
def test_specific_existing_part_refusals_keep_precedence(name, code):
    # The general unsupported part occurs first in archive order.
    data = package({"word/appendix.txt": b"Appendice.", name: b"Ordinary attachment bytes."})
    assert_unsupported(data, code)


def test_existing_expansion_limit_precedes_general_unsupported_part():
    data = package({"word/appendix.txt": b"Appendice.",
                    "word/summary.xml": b"<summary>" + b"Ordinary summary. " * 12_000 + b"</summary>"}, compressed=True)
    with pytest.raises(ExtractionError) as error:
        extract(data, "meeting.docx", Budget(8))
    assert error.value.code == "ARCHIVE_BOMB"


def test_refusal_messages_do_not_include_part_names_or_targets():
    message, report = assert_unsupported(package({"word/meeting-notes.txt": b"Meeting notes."}), "DOCX_UNINSPECTED_PART")
    assert "meeting-notes" not in message
    assert "meeting-notes" not in report["findings"][0]["title"]
    target = "https://example.org/meeting-notes.xml"
    message, report = assert_unsupported(
        package({"word/_rels/document.xml.rels": relationships(relation("projectReference", target))}),
        "DOCX_EXTERNAL_CONTENT",
    )
    assert target not in message
    assert target not in report["findings"][0]["title"]


@pytest.mark.skipif(sys.platform != "linux", reason="The real document worker requires the Linux sandbox")
@pytest.mark.parametrize("case,verdict,status,code", [
    ("normal", "VALID", "ALLOWED", None),
    ("text_part", "UNSCANNABLE", "BLOCKED", "DOCX_UNINSPECTED_PART"),
    ("external_image", "UNSCANNABLE", "BLOCKED", "DOCX_EXTERNAL_CONTENT"),
], ids=["normal-xml", "uninspected-text", "external-image"])
def test_real_worker_report_persistence_and_audit(tmp_path, case, verdict, status, code):
    extra = {}
    if case == "text_part":
        extra["word/appendix.txt"] = b"Appendice del progetto."
    elif case == "external_image":
        extra["word/_rels/document.xml.rels"] = relationships(
            relation("image", "https://example.org/diagram.png"))
    data = package(extra)
    state = tmp_path / "guard-state"
    store = registry = None
    try:
        store = GuardStore(state)
        registry = Reports(state, store)
        audit_before = store.verify_audit()
        assert audit_before["valid"] is True
        report = registry.scan(data, "meeting.docx")
        assert report["status"] == status
        assert report["verdict"] == verdict
        assert report["analysis_complete"] is (verdict == "VALID")
        assert report["sha256"] == hashlib.sha256(data).hexdigest()
        assert report["sandbox"]["active"] is True
        assert report["sandbox"]["mechanism"] == "landlock+seccomp"
        if code is not None:
            assert report["failure_kind"] == "UNSUPPORTED"
            assert report["findings"][0]["rule_id"] == code
        else:
            assert report["findings"] == []
        assert registry.get(report["id"]) == report
        assert registry.list() == [report]
        assert registry.count() == 1
        stats = registry.stats()
        assert stats["analyzed"] == stats["unique_files"] == stats["matched"] == 1
        assert stats["blocked"] == int(status == "BLOCKED")
        assert stats["valid"] == int(verdict == "VALID")
        assert stats["unscannable"] == int(verdict == "UNSCANNABLE")
        assert stats["infected"] == stats["corrupted"] == stats["review_required"] == 0
        audit_after = store.verify_audit()
        assert audit_after["valid"] is True
        assert audit_after["checked"] == audit_before["checked"] + 1
        event = store.audit_events()[0]
        assert event["event_type"] == "FILE_SCANNED"
        assert event["details"] == {
            "scan_id": report["id"], "filename": "meeting.docx", "sha256": report["sha256"],
            "status": status, "risk_score": report["risk_score"], "verdict": verdict,
        }
    finally:
        try:
            if registry is not None:
                registry.close()
        finally:
            if store is not None:
                store.close()
