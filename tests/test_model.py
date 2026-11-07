"""Lossless transport/model behavior and structural addressing."""
from __future__ import annotations

import pytest

from hl7scrub.model import Delimiters, Field, Message, ParseError, Segment, parse, parse_messages

HEADER = r"MSH|^~\&|TEST|SYNTHETIC|LAB|DEMO|202601011200||ADT^A01|X1|P|2.5.1"
BASE = HEADER + "\r" + r"PID|1||AB123^^^LAB^MR~CD456^^^LAB2^MR||SAMPLE^ALICE||19800101|F|||123 Fake St^^Testville^CA^03601||202-555-0100" + "\r"


@pytest.mark.parametrize("ending", ["\r", "\n", "\r\n"])
@pytest.mark.parametrize("framed", [False, True])
def test_lossless_segment_endings_and_mllp(ending, framed):
    data = BASE.replace("\r", ending).encode()
    if framed:
        data = b"\x0b" + data + b"\x1c\r"
    assert parse(data).to_bytes() == data


@pytest.mark.parametrize("name", ["adt_sequence", "oru_lab", "siu", "clinical_misc", "batch_mllp", "custom_delimiters"])
def test_committed_examples_roundtrip(name):
    from pathlib import Path
    data = Path("examples", name + ".hl7").read_bytes()
    assert parse(data).to_bytes() == data


def test_mixed_endings_empty_fields_and_no_final_separator():
    data = (HEADER + "\r\nPID|1|||\nNTE|1||hello\rOBX|1|NM|||").encode()
    assert parse(data).to_bytes() == data


def test_bytes_with_non_utf8_content_roundtrip():
    data = BASE.encode() + b"NTE|1||caf\xe9\r"
    assert parse(data).to_bytes() == data


def test_msh_numbering():
    message = Message.parse(BASE)
    assert message.get("MSH-1") == "|"
    assert message.get("MSH-2") == r"^~\&"
    assert message.get("MSH-9.1") == "ADT"
    assert message.get("MSH-10") == "X1"


def test_path_components_and_repetitions():
    message = Message.parse(BASE)
    assert message.get("PID-5.1") == "SAMPLE"
    assert message.get("PID-3[*].1") == ["AB123", "CD456"]
    assert message.get("PID-3[2].4") == "LAB2"
    message.set("PID-3[2].1", "EF789")
    assert message.get("PID-3[*].1") == ["AB123", "EF789"]


def test_path_subcomponents_padded_set():
    message = Message.parse(BASE)
    message.set("PID-3[3].4.2", "namespace")
    assert message.get("PID-3[3].4.2") == "namespace"
    assert message.get("PID-3[3].1") == ""
    assert len(message.get("PID-3[*].1")) == 3


def test_path_scalar_escape_and_raw_compound_set():
    message = Message.parse(BASE)
    message.set("PID-5.1", "Last|Name^Value&Other~Test\\")
    assert message.get("PID-5.1") == "Last|Name^Value&Other~Test\\"
    assert message.get("PID-5.2") == "ALICE"
    message.set("PID-5", "DOE^JANE", raw=True)
    assert message.get("PID-5.1") == "DOE"
    assert message.get("PID-5.2") == "JANE"
    assert parse(message.to_bytes()).messages[0].get("PID-5.2") == "JANE"


def test_wildcard_sets_all_repetitions_and_segments():
    message = Message.parse(BASE + "NK1|1|A^B\rNK1|2|C^D\r")
    message.set("NK1[*]-2.1", "Family")
    assert message.get("NK1[*]-2.1") == ["Family", "Family"]
    message.set("PID-3[*].1", "X")
    assert message.get("PID-3[*].1") == ["X", "X"]


def test_segment_occurrence():
    message = Message.parse(BASE + "NK1|1|A^B\rNK1|2|C^D\r")
    assert message.get("NK1[2]-2.2") == "D"
    message.set("NK1[2]-2.2", "E")
    assert message.get("NK1[1]-2.2") == "B"
    assert message.get("NK1[2]-2.2") == "E"


@pytest.mark.parametrize("path", ["PID-0", "PID-5.0", "PID-5[0]", "bad", "PID5", "PID-5.1.0"])
def test_invalid_paths(path):
    with pytest.raises(ValueError):
        Message.parse(BASE).get(path)


def test_missing_fields_and_segments():
    message = Message.parse(BASE)
    assert message.get("PID-99") == ""
    assert message.get("NK1-2", "missing") == "missing"
    with pytest.raises(KeyError):
        message.set("NK1-2", "x")


def test_cannot_edit_encoding_without_reparse():
    with pytest.raises(ValueError):
        Message.parse(BASE).set("MSH-2", "1234")


@pytest.mark.parametrize("encoded,decoded", [('\\F\\', '|'), ('\\S\\', '^'), ('\\T\\', '&'), ('\\R\\', '~'), ('\\E\\', '\\'), ('\\X4142\\', 'AB'), ('\\.br\\', '\n'), ('\\Zlocal\\', '\\Zlocal\\'), ('\\XZZ\\', '\\XZZ\\')])
def test_escape_decode(encoded, decoded):
    assert Delimiters().decode(encoded) == decoded


def test_escape_encode_decode_literal_value():
    d = Delimiters()
    value = "a|b^c~d&e\\f\ng\rh"
    assert d.decode(d.encode(value)) == value


def test_custom_encoding_and_truncation():
    raw = "MSH!$%?@#!S!F!R!T!20260101!!ADT$A01!1!P!2.7\nPID!1!!A01$$$F$MR!!FAMILY$GIVEN\nNTE!1!!literal?F?field?.br?next?X4142?\n"
    doc = parse(raw)
    assert doc.serialize() == raw
    message = doc.messages[0]
    assert message.delimiters.truncation == "#"
    assert message.get("MSH-2") == "$%?@#"
    assert message.get("NTE-3") == "literal!field\nnextAB"
    message.set("PID-5.1", "With!Delimiter#")
    assert message.get("PID-5.1") == "With!Delimiter#"
    assert "?F?" in message.find("PID")[0].field(5).raw
    assert "?P?" in message.find("PID")[0].field(5).raw


def test_multi_message_delimiters_are_independent():
    second = "MSH!$%?@!S!F!R!T!20260101!!ADT$A01!2!P!2.5\rPID!1!!SECOND$$$F$MR\r"
    doc = parse(BASE + second)
    assert len(doc) == 2
    assert doc.messages[0].get("PID-3.1") == "AB123"
    assert doc.messages[1].get("PID-3.1") == "SECOND"
    assert doc.serialize() == BASE + second


def test_batch_wrappers_and_transport_controls():
    text = "\x0bFHS|^~\\&|FILE\rBHS|^~\\&|BATCH\r" + BASE + "BTS|1\rFTS|1\r\x1c\r"
    doc = parse(text)
    assert [s.name for s in doc.segments][0:3] == ["FHS", "BHS", "MSH"]
    assert len(doc) == 1
    assert doc.serialize() == text
    assert doc.serialize(mllp=False).endswith("FTS|1\r")
    assert doc.serialize(mllp=True) == text


@pytest.mark.parametrize("data", [b"", b"bad", b"PID|1||123\r", b"MSH|^^\\&|x", b"MSH|^~\\|x"])
def test_invalid_input(data):
    with pytest.raises(ParseError):
        parse(data)


def test_single_message_api_rejects_multiple_messages():
    with pytest.raises(ParseError):
        Message.parse(BASE + BASE)
    assert len(parse_messages(BASE + BASE)) == 2


def test_parse_warnings_are_value_free():
    doc = parse(BASE + "ZAB|unpaired\\SECRET\r")
    assert doc.warnings
    assert "SECRET" not in repr(doc.warnings)


def test_field_and_segment_public_helpers():
    field = Field("a^b~c^d")
    assert field.get(2, 2) == "d"
    field.set("x", 2, 2)
    assert field.raw == "a^b~c^x"
    segment = Segment.parse("PID|1||ID")
    segment.set(5, "Family")
    assert segment.get(5) == "Family"
    with pytest.raises(ValueError):
        segment.get("NK1-2")
    with pytest.raises(ValueError):
        field.get(0)
