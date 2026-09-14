"""Neutral Unicode documents verify review decisions and readable evidence."""
import pytest

from integrity_guard.core import GuardStore
from integrity_guard.reports import Reports
from integrity_guard.scanner import Scanner, normalize, redact_evidence


FLAGS = (
    "\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f",
    "\U0001f3f4\U000e0067\U000e0062\U000e0073\U000e0063\U000e0074\U000e007f",
    "\U0001f3f4\U000e0067\U000e0062\U000e0077\U000e006c\U000e0073\U000e007f",
)


@pytest.mark.parametrize("codepoint", [0xE0000, 0xE0001, 0xE0020, 0xE0041, 0xE0061, 0xE007F])
def test_tag_in_ordinary_text_requires_review(codepoint):
    text = "Verbale della riunione " + chr(codepoint) + " del lunedi."
    report = Scanner().scan_bytes(text.encode(), "verbale.txt")
    assert report["analysis_complete"] is True
    assert report["status"] == "FLAGGED"
    assert report["risk_score"] == 20
    finding, = report["findings"]
    assert finding["rule_id"] == "INVISIBLE_CHARACTERS"
    assert "\\U%08x" % codepoint in finding["evidence"]
    assert chr(codepoint) not in finding["evidence"]


@pytest.mark.parametrize("flag", FLAGS)
def test_complete_rgi_flag_is_ordinary_content(flag):
    report = Scanner().scan_bytes(("Destinazione " + flag).encode(), "viaggio.md")
    assert report["analysis_complete"] is True
    assert report["status"] == "ALLOWED"
    assert report["findings"] == []


@pytest.mark.parametrize("text", [
    FLAGS[0] + "\U000e0061",
    "\U000e0061" + FLAGS[1],
    FLAGS[2][:-1],
    FLAGS[0][1:],
    FLAGS[1][:3] + " " + FLAGS[1][3:],
    FLAGS[0] + "\u200b",
])
def test_flag_exception_does_not_cover_other_invisibles(text):
    report = Scanner().scan_bytes(("Destinazione " + text).encode(), "viaggio.txt")
    assert report["status"] == "FLAGGED"
    assert any(item["rule_id"] == "INVISIBLE_CHARACTERS" for item in report["findings"])


def test_bidi_signal_keeps_precedence_and_tags_are_visible_in_evidence():
    report = Scanner().scan_bytes("Verbale \u202e\U000e0061 concluso".encode(), "verbale.txt")
    assert report["status"] == "FLAGGED"
    finding, = report["findings"]
    assert finding["rule_id"] == "BIDI_CONTROL"
    assert "\\U000e0061" in finding["evidence"]


def test_normalization_removes_tag_separators_without_changing_source():
    text = "Ver\U000e0061bale\U000e007f della RIUNIONE"
    assert normalize(text) == "verbale della riunione"
    assert "\U000e0061" in text


def test_report_evidence_uses_complete_non_bmp_escapes_and_existing_bmp_form():
    assert redact_evidence("A\U000e0061B\u200bC") == "A\\U000e0061B\\u200bC"
    assert len(redact_evidence("\U000e0061" * 100)) <= 420


@pytest.mark.parametrize("text,verdict,review_required", [
    ("Verbale della riunione", "VALID", False),
    ("Verbale \U000e0061 della riunione", "REVIEW_REQUIRED", True),
    ("Destinazione " + FLAGS[0], "VALID", False),
])
def test_installed_worker_persists_the_decision_and_counter(tmp_path, text, verdict, review_required):
    store = GuardStore(tmp_path)
    reports = Reports(tmp_path, store)
    try:
        result = reports.scan(text.encode(), "verbale.txt")
        assert result["analysis_complete"] is True, result
        assert result["sandbox"]["active"] is True
        assert result["verdict"] == verdict
        assert result["status"] == ("FLAGGED" if review_required else "ALLOWED")
        assert reports.get(result["id"]) == result
        stats = reports.stats()
        assert stats["analyzed"] == 1
        assert stats["review_required"] == int(review_required)
        assert stats["valid"] == int(not review_required)
        assert store.verify_audit()["valid"] is True
    finally:
        reports.close()
        store.close()
