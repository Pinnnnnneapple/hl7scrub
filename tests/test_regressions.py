"""Privacy and standards edge cases discovered during integration review."""
from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path

import pytest

from hl7scrub import Scrubber, Message, default_policy, patient_identity, parse
from hl7scrub.cli import main
from hl7scrub.transforms import Transformer


def segment(tag, fields, separator="|"):
    first = 2 if tag == "MSH" else 1
    return tag + separator + separator.join(str(fields.get(i, "")) for i in range(first, max(fields) + 1))


def source(*extras, birth="19200115", mrn="ID123^^^HOSP&1.2.3&ISO^MR"):
    return ("MSH|^~\\&|S|F|R|F|20260101120000||ADT^A01|X|T|2.5.1\r"
            + segment("PID", {3: mrn, 5: "FAMILY^GIVEN", 7: birth, 11: "10 Main St^^Town^CA^02139"})
            + "\r" + "\r".join(extras) + ("\r" if extras else ""))


def test_default_cap_after_shift_never_exceeds_89_at_reference_boundary():
    reference = date(2026, 1, 1)
    for key in range(70):
        value = Scrubber(str(key), reference_date=reference).scrub(source()).messages[0].get("PID-7")
        born = datetime.strptime(value, "%Y%m%d").date()
        age = reference.year - born.year - ((reference.month, reference.day) < (born.month, born.day))
        assert age <= 89, (key, value)


def test_identity_is_independent_of_declared_structural_delimiters():
    standard = Message.parse(source())
    custom = Message.parse("MSH!$%?@#!S!F!R!F!20260101120000!!ADT$A01!X!T!2.7\r"
                           "PID!!!ID123$$$HOSP@1.2.3@ISO$MR!!FAMILY$GIVEN!!19200115\r")
    assert patient_identity(standard) == patient_identity(custom)
    one, two = [Scrubber("same-secret").scrub(m.serialize()).messages[0] for m in (standard, custom)]
    assert one.get("MSH-7") == two.get("MSH-7")


def test_fallback_identity_is_independent_of_component_delimiters():
    standard = Message.parse(source(mrn=""))
    custom = Message.parse("MSH!$%?@!S!F!R!F!20260101120000!!ADT$A01!X!T!2.5\r"
                           "PID!!!!!FAMILY$GIVEN!!19200115\r")
    assert patient_identity(standard) == patient_identity(custom)


def test_component_overrides_use_original_and_specificity_not_insertion_order():
    policy = {"version": 1, "fields": {
        "PID-11.5": {"action": "zip3"},
        "PID-11": {"action": "pseudonym", "kind": "street"},
        "PID-5.1": {"action": "hash"},
        "PID-5": {"action": "pseudonym", "kind": "person_name"},
    }}
    result = Scrubber("key", policy).scrub(source()).messages[0]
    assert result.get("PID-11.5") == "021"
    assert result.get("PID-5.1") == Transformer(b"key").hash("FAMILY")
    assert result.get("PID-5.2") != "GIVEN"


@pytest.mark.parametrize("value_type,value", [("DT", "20260101"), ("TS", "20260101123000-0500"),
                                              ("DTM", "20260101123000.125+0100"),
                                              ("DR", "20260101^20260103")])
def test_date_valued_observations_shift_with_patient(value_type, value):
    raw = source(segment("OBX", {1: 1, 2: value_type, 3: "DATE", 5: value}))
    engine = Scrubber("date-observations")
    patient = patient_identity(Message.parse(raw))
    expected = "^".join(engine.transformer.shift_date(x, patient) for x in value.split("^"))
    assert engine.scrub(raw).messages[0].get("OBX-5") == expected


def test_ppn_authentication_timestamp_is_component_15_not_surname():
    ppn = "^".join(["PROVIDER123", "SURNAME", "GIVEN"] + [""] * 11 + ["20260101123000"])
    raw = source(segment("TXA", {1: 1, 22: ppn}))
    engine = Scrubber("authentication")
    result = engine.scrub(raw).messages[0]
    expected = engine.transformer.shift_date("20260101123000", patient_identity(Message.parse(raw)))
    assert result.get("TXA-22.15") == expected
    assert result.get("TXA-22.2") != "SURNAME"
    assert not engine.report.warnings


@pytest.mark.parametrize("tag,number", [("TXA", 5), ("FT1", 20), ("DG1", 16), ("PV2", 13)])
def test_extended_provider_fields_receive_npi_like_ids(tag, number):
    raw = source(segment(tag, {number: "PR123^FAMILY^GIVEN"}))
    message = Scrubber("providers").scrub(raw).messages[0]
    value = message.get(tag + "-" + str(number) + ".1")
    assert value.isdecimal() and len(value) == 10


def test_invalid_direct_library_policy_cannot_silently_keep_phi():
    with pytest.raises(ValueError):
        Scrubber("key", {"version": 1, "fields": {"PID-5": {"action": "typo"}}})


def test_malformed_date_generates_warning_without_value():
    engine = Scrubber("key")
    raw = source(segment("PV1", {44: "20260230"}))
    assert engine.scrub(raw).messages[0].get("PV1-44") == "20260230"
    assert engine.report.warnings
    assert "20260230" not in json.dumps(engine.report.to_dict())


def test_calendar_overflow_is_reported():
    for key in range(70):
        engine = Scrubber(str(key), date_shift_days=30)
        raw = source(segment("PV1", {44: "00010101"}))
        identity = patient_identity(Message.parse(raw))
        if engine.transformer.patient_offset(identity) < 0:
            result = engine.scrub(raw)
            assert result.messages[0].get("PV1-44") == "00010101"
            assert any("calendar bounds" in w for w in engine.report.warnings)
            break
    else:
        pytest.fail("No negative test offset found")


def test_committed_scrubbed_outputs_and_report_are_reproducible(tmp_path):
    sources = sorted(Path("examples").glob("*.hl7"))
    report = tmp_path / "report.json"
    assert main(["scrub"] + [str(p) for p in sources] + ["--key", "demo-key-do-not-use",
                "--reference-date", "2026-01-01", "--out-dir", str(tmp_path), "--report", str(report)]) == 0
    for source_file in sources:
        actual = parse((tmp_path / source_file.name).read_bytes()).to_bytes(mllp=False)
        committed = parse((Path("examples/scrubbed") / source_file.name).read_bytes()).to_bytes(mllp=False)
        assert actual == committed, source_file.name
    assert json.loads(report.read_text()) == json.loads(Path("examples/scrubbed/report.json").read_text())


@pytest.mark.parametrize("control", ["0B", "1C", "00"])
def test_decoded_controls_are_reescaped_before_serialization(control):
    raw = source(segment("NTE", {3: "Clinical note " + "\\X" + control + "\\ end"}))
    clean = Scrubber("control-escapes").scrub(raw)
    wire = clean.to_bytes()
    assert bytes([int(control, 16)]) not in wire
    assert parse(wire).messages[0].get("NTE-3") == "Clinical note " + chr(int(control, 16)) + " end"


def test_orphan_z_segments_are_scrubbed_and_scanned():
    from hl7scrub import scan
    raw = "ZPH|123-45-6789|FAMILY\r" + source()
    assert scan(raw)
    clean = Scrubber("orphans").scrub(raw)
    assert "123-45-6789" not in clean.serialize()
    assert clean.segments[0].field(2).raw == "***"
    assert not scan(clean)


def test_explicit_null_identifier_does_not_merge_patients():
    first = Message.parse(source(mrn='""^^^HOSP^MR'))
    second = Message.parse(source(mrn='""^^^HOSP^MR').replace('FAMILY^GIVEN','OTHER^PERSON'))
    assert patient_identity(first) != patient_identity(second)
    assert patient_identity(first).startswith("fallback:")


def test_identity_literal_separators_cannot_collide_with_authority_structure():
    escaped = Message.parse(source(mrn="ID123^^^HOSP\\T\\OID^MR"))
    structured = Message.parse(source(mrn="ID123^^^HOSP&OID^MR"))
    assert patient_identity(escaped) != patient_identity(structured)


def test_specific_occurrence_redaction_is_not_reversed_by_wildcard_keep():
    policy = {"version": 1, "fields": {
        "NTE[1]-3": {"action": "redact"},
        "NTE[*]-3": {"action": "keep"},
    }}
    raw = source(segment("NTE", {3: "PRIVATE"}), segment("NTE", {3: "allowed"}))
    clean = Scrubber("specific", policy).scrub(raw).messages[0]
    assert clean.get("NTE[1]-3") == "***"
    assert clean.get("NTE[2]-3") == "allowed"


def test_provider_metadata_survives_action_pipeline_and_numeric_id_is_scrubbed_in_notes():
    policy = default_policy()
    policy['fields']['PV1-7'] = {"identifier": "provider", "actions": [{"action": "pseudonym", "kind": "person_name"}]}
    raw = source(segment("PV1", {7: "123456^HEALER^PERSON"}), segment("NTE", {3: "Provider 123456 approved result."}))
    engine = Scrubber("provider-pipeline", policy)
    clean = engine.scrub(raw).messages[0]
    assert clean.get("PV1-7.1").isdecimal() and len(clean.get("PV1-7.1")) == 10
    assert "123456" not in clean.get("NTE-3")


def test_legacy_ts_degree_of_precision_survives_without_false_malformed_warning():
    engine = Scrubber("precision")
    result = engine.scrub(source(segment("PV1", {44: "20260101120000^S"})))
    assert result.messages[0].get("PV1-44.2") == "S"
    assert not engine.report.warnings
