"""Public-API privacy contracts, using independently assembled ER7 messages.

Expected results describe privacy and clinical invariants, rather than reproducing
the engine's token generation, policy traversal, or date-offset algorithm.
"""

import json
import re
from datetime import date, datetime
from pathlib import Path

import pytest

from hl7scrub.engine import Scrubber, patient_identity, scrub
from hl7scrub.model import Message, parse


KEY = "integration-secret-not-for-production"
REFERENCE = date(2026, 6, 15)


def segment(tag, fields, separator="|"):
    start = 2 if tag in {"MSH", "FHS", "BHS"} else 1
    return tag + separator + separator.join(
        str(fields.get(i, "")) for i in range(start, max(fields, default=start) + 1)
    )


def header(control="visit-one", separator="|", encoding="^~\\&"):
    return segment("MSH", {
        2: encoding, 3: "ClinicalSender", 4: "OriginHospital",
        5: "Receiver", 6: "Destination", 7: "20240131101530-0500",
        9: encoding[0].join(["ADT", "A01"]), 10: control, 11: "T", 12: "2.5.1",
    }, separator)


def patient(overrides=None):
    fields = {
        1: "1", 3: "MRN-482719^^^NorthAuthority^MR",
        5: "Quillridge^Zorina", 7: "19820716", 8: "F",
        11: "741 Lantern Court^^Cedarvale^MA^02139^USA",
        13: "617-234-9876^PRN^PH~^NET^Internet^zorina@clinic.test",
        18: "ACCOUNT-78292", 19: "123-45-6789",
    }
    fields.update(overrides or {})
    return segment("PID", fields)


def transmission(*extras, pid_overrides=None, control="visit-one"):
    return "\r".join([header(control), patient(pid_overrides), *extras]) + "\r"


def custom_policy(fields, unknown="redact"):
    return {"version": 1, "unknown_segments": unknown, "fields": fields}


def run(data, **kwargs):
    return Scrubber(KEY, reference_date=REFERENCE, **kwargs).scrub(data)


def ts(value):
    return datetime.strptime(value, "%Y%m%d%H%M%S%z")


def test_default_scrubs_structured_and_narrative_identifiers():
    note = ("Zorina Quillridge MRN MRN-482719 phone 617-234-9876; "
            "SSN 123-45-6789 email zorina@clinic.test. Glucose stable.")
    source = transmission(segment("NTE", {1: 1, 3: note}))
    result = run(source)
    wire = result.serialize()
    for original in ("Zorina", "Quillridge", "MRN-482719", "617-234-9876",
                     "123-45-6789", "zorina@clinic.test", "NorthAuthority",
                     "ACCOUNT-78292", "741 Lantern Court", "Cedarvale"):
        assert original.casefold() not in wire.casefold(), original
    assert "[REDACTED]" in result.messages[0].get("NTE-3")
    assert "Glucose stable." in result.messages[0].get("NTE-3")
    assert result.messages[0].get("PID-3.1")


def test_default_preserves_clinical_codes_and_broad_address_context():
    observations = [
        segment("OBX", {1: 1, 2: "NM", 3: "2345-7^Glucose^LN", 5: "95.2",
                        6: "mg/dL", 7: "70-99", 8: "N", 11: "F"}),
        segment("OBX", {1: 2, 2: "CE", 3: "94500-6^Result^LN",
                        5: "260373001^Detected^SCT", 11: "F"}),
    ]
    message = run(transmission(*observations)).messages[0]
    assert message.get("OBX[1]-5") == "95.2"
    assert message.get("OBX[1]-3") == "2345-7^Glucose^LN"
    assert message.get("OBX[1]-6") == "mg/dL"
    assert message.get("OBX[1]-7") == "70-99"
    assert message.get("OBX[1]-8") == "N"
    assert message.get("OBX[2]-5") == "260373001^Detected^SCT"
    assert message.get("PID-8") == "F"
    assert message.get("PID-11.4") == "MA"
    assert message.get("PID-11.6") == "USA"
    assert message.get("MSH-9") == "ADT^A01"


@pytest.mark.parametrize("as_bytes", [False, True], ids=["text", "bytes"])
def test_same_key_reproduces_full_output_across_fresh_instances(as_bytes):
    source = transmission(segment("PV1", {44: "20240131101530-0500"}))
    data = source.encode() if as_bytes else source
    first = run(data).serialize()
    second = run(data).serialize()
    assert first == second
    assert first != source
    assert scrub(data, KEY).messages[0].get("PID-3.1") == run(data).messages[0].get("PID-3.1")
    assert Scrubber(KEY.encode(), reference_date=REFERENCE).scrub(data).serialize() == first


def test_different_secrets_separate_stable_identifiers():
    source = transmission()
    messages = [Scrubber(k, reference_date=REFERENCE).scrub(source).messages[0]
                for k in ("secret-alpha", "secret-beta", "secret-gamma")]
    for path in ("PID-3.1", "PID-18", "MSH-10"):
        values = [m.get(path) for m in messages]
        assert len(set(values)) == 3
        assert parse(source).messages[0].get(path) not in values


def test_patient_date_shift_is_stable_across_files_and_preserves_intervals():
    admission = "20240131101530-0500"
    discharge = "20240203114530-0500"
    encounter = segment("PV1", {44: admission, 45: discharge})
    first = run(transmission(encounter, control="file-a"), date_shift_days=60).messages[0]
    # Encounter/control changes and surrounding messages must not seed the offset.
    other = transmission(pid_overrides={3: "OTHER-72^^^OtherAuthority^MR"})
    batch = other + transmission(encounter, control="file-b")
    second = run(batch, date_shift_days=60).messages[1]
    shifted_admit, shifted_discharge = first.get("PV1-44"), first.get("PV1-45")
    assert (shifted_admit, shifted_discharge) == (second.get("PV1-44"), second.get("PV1-45"))
    assert ts(shifted_discharge) - ts(shifted_admit) == ts(discharge) - ts(admission)
    offset = (ts(shifted_admit) - ts(admission)).days
    assert -60 <= offset <= 60
    assert shifted_admit[8:] == admission[8:]
    assert shifted_discharge[8:] == discharge[8:]
    assert first.get("MSH-7") == shifted_admit
    born = datetime.strptime(first.get("PID-7"), "%Y%m%d").date()
    assert (born - date(1982, 7, 16)).days == offset


def test_date_offset_varies_by_patient_rather_than_one_global_shift():
    source = "".join(transmission(pid_overrides={3: f"PATIENT-{i}^^^Hospital^MR"})
                     for i in range(16))
    values = [m.get("MSH-7") for m in run(source).messages]
    offsets = {(ts(v) - ts("20240131101530-0500")).days for v in values}
    assert len(offsets) > 1
    assert offsets <= set(range(-30, 31))


def test_fallback_identity_uses_name_and_dob_independently_of_file_context():
    first = transmission(pid_overrides={3: "UNQUALIFIED"}, control="first-file")
    second = transmission(pid_overrides={3: "DIFFERENT-LOCAL-ID"}, control="second-file")
    one, two = Message.parse(first), Message.parse(second)
    assert patient_identity(one) == patient_identity(two)
    changed_dob = Message.parse(transmission(pid_overrides={3: "", 7: "19820717"}))
    assert patient_identity(one) != patient_identity(changed_dob)
    prefix = transmission(pid_overrides={3: "OTHER^^^Elsewhere^MR"})
    assert run(first).messages[0].get("MSH-7") == run(prefix + second).messages[1].get("MSH-7")


def test_identity_uses_first_qualified_repetition_and_assigning_authority():
    identity_a = Message.parse(transmission(pid_overrides={3: "LOCAL~SHARED^^^HospitalA^MR"}))
    identity_b = Message.parse(transmission(pid_overrides={3: "SHARED^^^HospitalB^MR"}))
    same = Message.parse(transmission(pid_overrides={3: "SHARED^^^HospitalA^MR", 5: "Other^Name"}))
    assert patient_identity(identity_a) == patient_identity(same)
    assert patient_identity(identity_a) != patient_identity(identity_b)


def test_provider_identifier_and_name_remain_linkable_across_roles_and_files():
    provider = "1472583690^Kestrelstone^Yara"
    first = run(transmission(segment("PV1", {7: provider}),
                             segment("OBR", {16: provider}))).messages[0]
    second = run(transmission(segment("ORC", {12: provider}), control="next-file")).messages[0]
    values = [first.get("PV1-7"), first.get("OBR-16"), second.get("ORC-12")]
    assert values[0] == values[1] == values[2]
    assert first.get("PV1-7.1") != "1472583690"
    assert first.get("PV1-7.1")
    assert "Kestrelstone" not in values[0]
    assert "Yara" not in values[0]


@pytest.mark.parametrize("value_type", ["TX", "FT", "ST"])
def test_obx_narrative_redacts_phi_and_retains_clinical_sentence(value_type):
    note = "Zorina Quillridge called 617-234-9876. Potassium normal."
    result = run(transmission(segment("OBX", {1: 1, 2: value_type, 5: note}))).messages[0]
    assert result.get("OBX-5") == "[REDACTED] [REDACTED] called [REDACTED]. Potassium normal."


def test_narrative_email_not_present_in_structured_fields_is_redacted_at_sentence_end():
    note = "Write unlisted.person@outside.test. Potassium normal."
    result = run(transmission(segment("NTE", {1: 1, 3: note}))).messages[0]
    assert result.get("NTE-3") == "Write [REDACTED]. Potassium normal."


@pytest.mark.parametrize("value_type,payload", [
    ("ED", "OriginHospital^TEXT^PLAIN^Base64^Wm9yaW5hIFF1aWxscmlkZ2U="),
    ("RP", "https://clinic.test/patients/MRN-482719^OriginHospital^AP^PDF"),
])
def test_opaque_obx_payloads_are_removed(value_type, payload):
    result = run(transmission(segment("OBX", {1: 1, 2: value_type, 5: payload, 11: "F"})))
    assert result.messages[0].get("OBX-5") == ""
    assert result.messages[0].get("OBX-11") == "F"
    assert payload not in result.serialize()


def test_unknown_z_segments_redact_every_field_and_warn_without_values():
    unknown = segment("ZPX", {1: "PRIVATE-MARKER-8234", 2: "Zorina^Quillridge~MRN-482719", 4: "secret"})
    worker = Scrubber(KEY, reference_date=REFERENCE)
    result = worker.scrub(transmission(unknown))
    z = result.messages[0].find("ZPX")[0]
    assert z.field(1).raw != ""
    assert z.field(2).raw != ""
    assert z.field(3).raw == ""
    for value in ("PRIVATE-MARKER-8234", "Zorina", "Quillridge", "MRN-482719", "secret"):
        assert value not in z.serialize()
        assert value not in json.dumps(worker.report.to_dict())
    report = worker.report.to_dict()
    assert report["unknown_z_segments"] == {"ZPX": 1}
    assert any("ZPX" in warning for warning in report["warnings"])


def test_explicit_unknown_keep_policy_retains_segment_and_reports_choice():
    unknown = segment("ZPX", {1: "explicit-retention", 2: "a^b~c"})
    worker = Scrubber(KEY, policy=custom_policy({}, unknown="keep"))
    result = worker.scrub(transmission(unknown))
    assert result.messages[0].find("ZPX")[0].serialize() == unknown
    assert any("keep" in warning and "ZPX" in warning for warning in worker.report.to_dict()["warnings"])


def test_custom_delimiters_escaped_literals_and_framing_survive_transformation():
    source = "\x0b" + "\r".join([
        header(separator="!", encoding="$%?@#"),
        segment("PID", {3: "MRN-482719$$$NorthAuthority$MR", 5: "Quillridge$Zorina"}, "!"),
        segment("NTE", {1: 1, 3: "Zorina improved; literals ?F? ?S? ?R? ?T? ?E? ?P? ?X4142?."}, "!"),
    ]) + "\r\x1c\r"
    result = run(source.encode())
    wire = result.serialize()
    reparsed = parse(result.to_bytes())
    assert wire.startswith("\x0bMSH!$%?@#!") and wire.endswith("\x1c\r")
    assert reparsed.messages[0].find("MSH")[0].field(2).raw == "$%?@#"
    assert reparsed.messages[0].get("PID-3.1") != "MRN-482719"
    assert len(reparsed.messages[0].find("NTE")[0].field(3).repetitions()) == 1
    assert reparsed.messages[0].get("NTE-3") == "[REDACTED] improved; literals ! $ % @ ? # AB."
    assert "Quillridge" not in wire
    assert reparsed.serialize() == wire


def test_audit_aggregates_multiple_calls_without_original_or_replacement_values():
    policy = custom_policy({"PID-3.1": {"action": "hash"}})
    worker = Scrubber(KEY, policy=policy)
    source = transmission(pid_overrides={3: "AUDIT-ORIGINAL-8237^^^Authority^MR"})
    transformed = worker.scrub(source).messages[0].get("PID-3.1")
    worker.scrub(source)
    report = worker.report.to_dict()
    assert report["messages"] == 2
    assert report["fields"]["PID-3.1"]["hash"] == 2
    assert report["segments_seen"]["PID"] == 2
    encoded = json.dumps(report)
    assert "AUDIT-ORIGINAL-8237" not in encoded
    assert transformed not in encoded
    assert KEY not in encoded


def test_repetition_and_component_rules_only_touch_selected_leaves():
    source = transmission(pid_overrides={3: "FIRST^^^HospitalA^MR~SECOND^^^HospitalB^SS"})
    policy = custom_policy({"PID-3[*].1": {"action": "hash"},
                            "PID-3[2].4": {"action": "remove"},
                            "NTE[2]-3.2": {"action": "redact"}})
    source += segment("NTE", {1: 1, 3: "first^unchanged"}) + "\r"
    source += segment("NTE", {1: 2, 3: "second^private^retained"}) + "\r"
    message = run(source, policy=policy).messages[0]
    identifiers = message.get("PID-3[*].1")
    assert len(identifiers) == 2 and all(identifiers)
    assert identifiers[0] != "FIRST" and identifiers[1] != "SECOND"
    assert identifiers[0] != identifiers[1]
    assert message.get("PID-3[1].4") == "HospitalA"
    assert message.get("PID-3[2].4") == ""
    assert message.get("PID-3[*].5") == ["MR", "SS"]
    assert message.get("NTE[1]-3") == "first^unchanged"
    assert message.get("NTE[2]-3.1") == "second"
    assert message.get("NTE[2]-3.2") not in ("", "private")
    assert message.get("NTE[2]-3.3") == "retained"


def test_keep_remove_redact_and_hash_actions_apply_without_policy_merging():
    policy = custom_policy({
        "PID-8": {"action": "keep"}, "PID-12": {"action": "remove"},
        "PID-23": {"action": "redact"}, "PID-18": {"action": "hash", "length": 24},
    })
    source = transmission(pid_overrides={12: "private-area~second", 23: "private-birthplace^ward"})
    result = run(source, policy=policy).messages[0]
    assert result.get("PID-8") == "F"
    assert result.get("PID-12") == ""
    assert result.get("PID-23") not in ("", "private-birthplace^ward")
    assert "private" not in result.get("PID-23")
    assert re.fullmatch(r"[A-Z2-7]{24}", result.get("PID-18"))
    assert result.get("PID-5") == "Quillridge^Zorina"


def test_age_cap_then_date_shift_pipeline_uses_fixed_reference_date():
    policy = custom_policy({"PID-7": {"actions": [{"action": "age_cap"}, {"action": "date_shift"}]}})
    # June 15 has passed the May 20 birthday; age 89 corresponds to 1937.
    result = run(transmission(pid_overrides={7: "19000520"}), policy=policy, date_shift_days=0)
    assert result.messages[0].get("PID-7") == "19370520"
    boundary = run(transmission(pid_overrides={7: "19370520"}), policy=policy, date_shift_days=0)
    younger = run(transmission(pid_overrides={7: "20000520"}), policy=policy, date_shift_days=0)
    assert boundary.messages[0].get("PID-7") == "19370520"
    assert younger.messages[0].get("PID-7") == "20000520"


def test_zip3_and_year_generalization_preserve_sibling_components():
    policy = custom_policy({"PID-11[*].5": {"action": "zip3"},
                            "PID-7": {"action": "generalize_year"}})
    address = "Street^^Town^MA^02139-1234^USA~Road^^Village^AK^03612^USA"
    result = run(transmission(pid_overrides={11: address, 7: "19820716123456-0500"}), policy=policy).messages[0]
    assert result.get("PID-11[*].5") == ["021", "000"]
    assert result.get("PID-11[*].4") == ["MA", "AK"]
    assert result.get("PID-11[*].6") == ["USA", "USA"]
    assert result.get("PID-7") == "1982"


def test_null_and_empty_fields_are_preserved_in_fields_and_repetitions():
    policy = custom_policy({"PID-3": {"action": "pseudonym", "kind": "mrn"},
                            "PID-5": {"action": "pseudonym", "kind": "person_name"},
                            "PID-7": {"action": "date_shift"}, "PID-8": {"action": "redact"}})
    source = transmission(pid_overrides={3: '""~MRN-482719^^^Authority^MR',
                                         5: '""^Zorina', 7: '""', 8: ""})
    worker = Scrubber(KEY, policy=policy)
    result = worker.scrub(source).messages[0]
    assert result.get("PID-3[1]") == '""'
    assert result.get("PID-3[2].1") not in ("", "MRN-482719")
    assert result.get("PID-5.1") == '""'
    assert result.get("PID-5.2") not in ("", "Zorina")
    assert result.get("PID-7") == '""'
    assert result.get("PID-8") == ""
    assert "PID-7" not in worker.report.to_dict()["fields"]


def test_batch_wrappers_scrubbed_and_counts_and_transport_retained():
    fields = {2: "^~\\&", 3: "WRAPPER-PRIVATE-SENDER", 4: "WRAPPER-PRIVATE-FACILITY",
              7: "20240131101530", 8: "WRAPPER-PRIVATE-SECURITY", 11: "WRAPPER-PRIVATE-FILE"}
    source = ("\x0b" + segment("FHS", fields) + "\r" + segment("BHS", fields) + "\r"
              + transmission() + transmission(control="second")
              + segment("BTS", {1: 2, 2: "WRAPPER-PRIVATE-COMMENT"}) + "\r"
              + segment("FTS", {1: 1, 2: "WRAPPER-PRIVATE-COMMENT"}) + "\r\x1c\r")
    result = run(source)
    assert "WRAPPER-PRIVATE" not in result.serialize()
    assert len(result.messages) == 2
    wrappers = {s.name: s for s in result.segments if s.name in {"FHS", "BHS", "BTS", "FTS"}}
    assert wrappers["BTS"].field(1).raw == "2"
    assert wrappers["FTS"].field(1).raw == "1"
    assert wrappers["FHS"].field(7).raw == "2024"
    assert wrappers["BHS"].field(7).raw == "2024"
    assert result.serialize().startswith("\x0b") and result.serialize().endswith("\x1c\r")
    assert len(parse(result.to_bytes()).messages) == 2


def test_bundled_examples_contain_no_original_patient_names_mrn_or_phone_after_scrub():
    examples = Path(__file__).resolve().parents[1] / "examples"
    originals = ("SYNTH001", "SYNTH002", "SAMPLE", "ALICE", "EXAMPLE", "BOB",
                 "202-555-0101", "202-555-0102")
    for filename in ("adt_sequence.hl7", "oru_lab.hl7", "siu.hl7",
                     "clinical_misc.hl7", "batch_mllp.hl7", "custom_delimiters.hl7"):
        source = (examples / filename).read_bytes()
        assert b"MSH" in source, filename
        result = run(source).serialize()
        # The reserved email domain may contain the same word as a surname.
        searchable = re.sub(r"(?:@|\?T\?)example\.invalid\b", "@reserved.invalid", result, flags=re.I)
        for original in originals:
            assert not re.search(r"(?<!\w)" + re.escape(original) + r"(?!\w)", searchable, re.I), (filename, original)
