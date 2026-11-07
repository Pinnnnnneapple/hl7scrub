"""Residual-PHI scanner contracts: useful locations with no matched values."""

import json
from datetime import date

import pytest

from hl7scrub.engine import Scrubber
from hl7scrub.model import parse
from hl7scrub.scanner import scan


def segment(tag, fields):
    start = 2 if tag == "MSH" else 1
    return tag + "|" + "|".join(str(fields.get(i, "")) for i in range(start, max(fields) + 1))


def message(note="", *, names="Quillridge^Zorina", extra=()):
    segments = [
        segment("MSH", {2: "^~\\&", 9: "ORU^R01", 10: "test-message", 11: "T", 12: "2.5.1"}),
        segment("PID", {3: "MRN-482719^^^Hospital^MR", 5: names, 7: "19820716"}),
        segment("NTE", {1: 1, 3: note}),
        *extra,
    ]
    return "\r".join(segments) + "\r"


@pytest.mark.parametrize("category,real,fake", [
    ("ssn", "123-45-6789", "900-12-3456"),
    ("phone", "617-234-9876", "617-555-0101"),
    ("email", "patient@clinic.test", "patient@example.invalid"),
])
def test_real_contact_patterns_flagged_but_reserved_synthetic_patterns_ignored(category, real, fake):
    findings = scan(message("Contact: " + real))
    assert {f["category"] for f in findings} == {category}
    assert all(f["path"] == "NTE-3" for f in findings)
    assert scan(message("Contact: " + fake)) == []


def test_reserved_pattern_boundaries_and_formatted_international_phone():
    source = message("899-12-3456; 999-12-3456; +1 (617) 555-0101; "
                     "patient@EXAMPLE.INVALID; patient@sub.example.invalid; +1 (617) 234-9876")
    findings = scan(source)
    assert {f["category"] for f in findings} == {"ssn", "email", "phone"}
    # Only one location/category is emitted even when several patterns occur.
    assert len(findings) == 3


def test_names_in_structured_pid_name_fields_are_excluded_but_other_fields_flagged():
    source = message(extra=[
        segment("PID", {5: "Quillridge^Zorina", 6: "Maidenridge^Coralie", 9: "Aliasridge^Tamsin"}),
        segment("OBX", {1: 1, 2: "TX", 5: "coralie met TAMSIN and Zorina Quillridge"}),
        segment("NK1", {1: 1, 2: "Quillridge^Zorina"}),
    ])
    findings = scan(source)
    assert {(f["path"], f["category"]) for f in findings} == {
        ("OBX-5", "patient_name"),
    }
    assert not any(f["path"] in {"PID-5", "PID-6", "PID-9", "NK1-2"} for f in findings)


def test_ten_digit_provider_ids_are_not_phones_but_narrative_phones_are():
    source = message("Call 617-234-9876", extra=[
        segment("PV1", {7: "1472583690^Kestrelstone^Yara"}),
        segment("OBR", {16: "1472583690^Kestrelstone^Yara"}),
    ])
    assert [(f["path"], f["category"]) for f in scan(source)] == [("NTE-3", "phone")]


@pytest.mark.parametrize("punctuation", [".", ","])
def test_emails_adjacent_to_sentence_punctuation_are_detected(punctuation):
    findings = scan(message("Write unlisted.person@outside.test" + punctuation + " Result normal."))
    assert [(f["path"], f["category"]) for f in findings] == [("NTE-3", "email")]


def test_name_matching_uses_word_boundaries_not_embedded_substrings():
    assert scan(message("annular findings unchanged", names="Quillridge^Ann")) == []
    findings = scan(message("ANN's symptoms improved", names="Quillridge^Ann"))
    assert [(f["path"], f["category"]) for f in findings] == [("NTE-3", "patient_name")]


def test_message_local_tokens_do_not_bleed_into_other_patients():
    source = message("") + message("Zorina reviewed the result", names="Otherfamily^Othergiven")
    assert scan(source) == []
    with_match = source + message("Zorina reviewed the result")
    assert [(f["message"], f["path"], f["category"]) for f in scan(with_match)] == [
        (3, "NTE-3", "patient_name"),
    ]


def test_escaped_phi_repetitions_and_repeated_segments_have_precise_locations():
    source = message("normal", extra=[
        segment("OBX", {1: 1, 2: "TX", 5: r"safe~\X5A6F72696E61\ improved"}),
        segment("OBX", {1: 2, 2: "TX", 5: "123-45-6789^617-234-9876"}),
    ])
    findings = scan(source)
    assert {(f["message"], f["segment"], f["path"], f["category"]) for f in findings} == {
        (1, 4, "OBX-5", "patient_name"),
        (1, 5, "OBX-5", "ssn"),
        (1, 5, "OBX-5", "phone"),
    }


def test_input_forms_agree_scan_is_nonmutating_and_findings_never_include_values():
    source = message("Zorina 123-45-6789 phone 617-234-9876 email patient@clinic.test")
    document = parse(source)
    expected = scan(source)
    assert len(expected) == 4
    assert scan(source.encode()) == scan(document) == expected
    assert document.serialize() == source
    for finding in expected:
        assert set(finding) == {"message", "segment", "path", "category"}
        assert finding["message"] == 1 and finding["segment"] == 3
        assert finding["path"] == "NTE-3"
    serialized = json.dumps(expected)
    for original in ("Zorina", "123-45-6789", "617-234-9876", "patient@clinic.test", "MRN-482719"):
        assert original not in serialized


def test_default_scrub_removes_scanner_findings_while_preserving_clinical_text():
    source = message("Zorina Quillridge 123-45-6789, 617-234-9876, patient@clinic.test. Glucose stable.")
    assert {f["category"] for f in scan(source)} == {"patient_name", "ssn", "phone", "email"}
    result = Scrubber("scanner-integration-secret", reference_date=date(2026, 6, 15)).scrub(source)
    assert scan(result) == []
    assert "Glucose stable." in result.messages[0].get("NTE-3")
    assert "[REDACTED]" in result.messages[0].get("NTE-3")
