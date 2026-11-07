"""Generate 100% fictitious HL7 fixtures; no package or third-party dependency.

All identities, addresses, organizations, and identifiers are invented. Email
uses example.invalid, phone uses 555-01xx, and SSNs use invalid area 900.
The fixed event dates and byte writes make every run identical on every OS.
"""

from __future__ import annotations

from pathlib import Path


HERE = Path(__file__).resolve().parent
PATIENTS = (
    dict(mrn="SYNTH001", family="SAMPLE", given="ALICE", dob="19200115",
         sex="F", street="101 Fictional Lantern Lane", city="Imaginaryville",
         phone="202-555-0101", ssn="900-12-0001", email="alice.sample@example.invalid"),
    dict(mrn="SYNTH002", family="EXAMPLE", given="BOB", dob="19850620",
         sex="M", street="202 Invented Comet Road", city="Pretendburg",
         phone="202-555-0102", ssn="900-12-0002", email="bob.example@example.invalid"),
)


def segment(tag: str, fields: dict[int, object], separator: str = "|") -> str:
    """Build by HL7 field index, including the special MSH-1 separator rule."""
    if tag in ("MSH", "FHS", "BHS"):
        if fields.get(1, separator) != separator:
            raise ValueError("MSH-1 must equal the selected separator")
        first = 2
    else:
        first = 1
    last = max(fields, default=first)
    return tag + separator + separator.join(str(fields.get(i, "")) for i in range(first, last + 1))


def header(kind: str, control: str, separator: str = "|", encoding: str = "^~\\&", timestamp: str = "20260105100000", version: str = "2.5.1") -> str:
    """Build an explicitly synthetic MSH header."""
    component = encoding[0]
    return segment("MSH", {
        1: separator, 2: encoding, 3: "SYNTHETIC", 4: "NOT_REAL",
        5: "SYNTHETIC_RECEIVER", 6: "NOT_REAL", 7: timestamp,
        9: kind.replace("^", component), 10: control, 11: "T", 12: version,
    }, separator)


def pid(patient: dict, separator: str = "|", component: str = "^", repetition: str = "~") -> str:
    """Build identifiers, names, addresses and contacts for one invented patient."""
    p = patient
    c = component
    email = p['email'].replace('@', '?T?') if component == '$' else p['email']
    return segment("PID", {
        1: "1", 3: c.join([p['mrn'], '', '', 'SYNTHETIC', 'MR']),
        5: c.join([p['family'], p['given']]), 7: p['dob'], 8: p['sex'],
        11: c.join([p['street'], '', p['city'], 'ZZ', '00000', 'USA']),
        13: c.join([p['phone'], 'PRN', 'PH']) + repetition + c.join(['', 'NET', 'Internet', email]),
        18: "ACCOUNT-" + p['mrn'], 19: p['ssn'],
    }, separator)


def narrative(p: dict) -> str:
    """Return a synthetic note containing deliberately planted identity tokens."""
    return ("100% SYNTHETIC NOT_REAL patient " + p['given'] + " " + p['family']
            + "; given name " + p['given'] + "; family name " + p['family']
            + "; MRN " + p['mrn'] + "; phone " + p['phone'] + "; SSN " + p['ssn']
            + "; email " + p['email'] + "; visit date 2026-01-05.")


def adt(p: dict, event: str, ordinal: int) -> list[str]:
    """Build one event in a linked synthetic admission sequence."""
    timestamp = {"A01": "20260105100000", "A08": "20260106110000", "A03": "20260107120000"}[event]
    return [
        header("ADT^" + event + "^" + ("ADT_A03" if event == "A03" else "ADT_A01"),
               "SYNTH-ADT-%02d" % ordinal, timestamp=timestamp),
        segment("EVN", {1: event, 2: timestamp, 5: "OP900^OPERATOR^FICTITIOUS"}),
        pid(p),
        segment("PD1", {3: "SYNTHETIC CLINIC^^^^^SYNTHETIC", 4: "PR900^PROVIDER^PRETEND"}),
        segment("NK1", {1: 1, 2: "KINEXAMPLE^CASEY", 3: "SPO^Spouse^HL70063",
                        4: "303 Imaginary Way^^Pretendburg^ZZ^00000", 5: "202-555-0103"}),
        segment("PV1", {1: 1, 2: "I", 3: "SYNTHWARD^101^A^NOT_REAL",
                        7: "PR901^HEALER^HARPER", 8: "PR902^REFERRER^ROBIN",
                        9: "PR903^CONSULTANT^CAMERON", 17: "PR904^ATTENDER^AVERY",
                        19: "VISIT-" + p['mrn'] + "^^^SYNTHETIC^VN",
                        44: "20260105100000", 45: timestamp if event == 'A03' else ''}),
        segment("PV2", {3: "SYNTH^Synthetic observation^L", 8: "20260105100000", 9: "20260107120000"}),
        segment("GT1", {1: 1, 2: "GUAR-" + p['mrn'], 3: p['family'] + '^' + p['given'],
                        5: p['street'] + '^^' + p['city'] + '^ZZ^00000',
                        6: p['phone'], 8: p['dob'], 12: p['ssn']}),
        segment("IN1", {1: 1, 2: "SYNTHPLAN", 3: "INS900", 4: "NOT_REAL INSURANCE",
                        16: p['family'] + '^' + p['given'], 18: p['dob'],
                        19: p['street'] + '^^' + p['city'] + '^ZZ^00000', 36: "POLICY-" + p['mrn']}),
        segment("IN2", {1: "EMP-" + p['mrn'], 2: p['ssn'], 3: "EMP900^EMPLOYER^FICTITIOUS"}),
        # Repeated PID identity tokens exercise residual own-name detection even
        # when scanners correctly ignore the reserved fake contact identifiers.
        segment("NTE", {1: 1, 3: narrative(p)}),
        segment("ZSY", {1: "SYNTHETIC/NOT_REAL", 2: narrative(p)}),
    ]


def laboratory() -> list[str]:
    """Build numeric results, a narrative and opaque attachment examples."""
    p = PATIENTS[0]
    return [header("ORU^R01^ORU_R01", "SYNTH-ORU-001"), pid(p),
            segment("OBR", {1: 1, 2: "ORDER-SYNTH001", 3: "LAB-SYNTH001",
                            4: "2345-7^Glucose^LN", 7: "20260105103000",
                            16: "PR901^HEALER^HARPER"}),
            segment("OBX", {1: 1, 2: "NM", 3: "2345-7^Glucose^LN", 5: "95", 6: "mg/dL", 7: "70-99", 8: "N", 11: "F"}),
            segment("OBX", {1: 2, 2: "NM", 3: "2951-2^Sodium^LN", 5: "140", 6: "mmol/L", 7: "135-145", 8: "N", 11: "F"}),
            segment("OBX", {1: 3, 2: "TX", 3: "SYNTHNOTE^Synthetic narrative^L", 5: narrative(p), 11: "F"}),
            segment("NTE", {1: 1, 3: narrative(p)}),
            segment("OBX", {1: 4, 2: "ED", 3: "SYNTHDOC^Synthetic attachment^L", 5: "SYNTHETIC^TEXT^PLAIN^Base64^U1lOVEhFVElDIE5PVF9SRUFM", 11: "F"}),
            segment("OBX", {1: 5, 2: "RP", 3: "SYNTHLINK^Synthetic reference^L", 5: "https://example.invalid/SYNTH001^NOT_REAL^AP^PDF", 11: "F"})]


def scheduling() -> list[str]:
    """Build synthetic SIU timing, personnel and location segments."""
    return [header("SIU^S12^SIU_S12", "SYNTH-SIU-001"),
            segment("SCH", {1: "APPT-SYNTH001", 2: "FILL-SYNTH001", 6: "SYNTH^Synthetic visit^L",
                            11: "^^^20260110140000^20260110143000", 12: "PR901^HEALER^HARPER",
                            16: "CONTACT900^COORDINATOR^QUINN", 20: "ENTER900^SCHEDULER^SKY"}),
            pid(PATIENTS[0]), segment("RGS", {1: 1}),
            segment("AIP", {1: 1, 3: "PR901^HEALER^HARPER", 4: "SYNTH^Provider^L", 6: "20260110140000"}),
            segment("AIL", {1: 1, 3: "SYNTHROOM^201^B^NOT_REAL", 4: "SYNTH^Room^L", 6: "20260110140000"})]


def clinical_misc() -> list[str]:
    """Build synthetic MDM and DFT messages."""
    p = PATIENTS[1]
    return [header("MDM^T02^MDM_T02", "SYNTH-MDM-001"), pid(p),
            segment("PV1", {1: 1, 2: "O", 19: "VISIT-SYNTH002^^^SYNTHETIC^VN"}),
            segment("TXA", {1: 1, 2: "SYNTHNOTE", 4: "20260106110000", 5: "PR901^HEALER^HARPER",
                            9: "PR902^REFERRER^ROBIN", 12: "DOC-SYNTH002", 16: "NOT_REAL.txt", 17: "AU"}),
            segment("OBX", {1: 1, 2: "TX", 3: "SYNTHDOC^Synthetic document^L", 5: narrative(p), 11: "F"}),
            header("DFT^P03^DFT_P03", "SYNTH-DFT-001"), pid(p),
            segment("PV1", {1: 1, 2: "O", 19: "VISIT-SYNTH002^^^SYNTHETIC^VN"}),
            segment("FT1", {1: 1, 2: "TXN-SYNTH002", 4: "20260106110000", 6: "CG",
                            7: "SYNTH^Synthetic charge^L", 10: "1", 11: "25.00",
                            20: "PR901^HEALER^HARPER"}),
            segment("NTE", {1: 1, 3: narrative(p)})]


def custom_delimiters() -> list[str]:
    """Build a v2.7 example with custom delimiters and escaped scalar text."""
    return [header("ORU^R01^ORU_R01", "SYNTH-CUSTOM-001", "!", "$%?@#", version="2.7"),
            pid(PATIENTS[0], "!", "$", "%"),
            segment("OBR", {1: 1, 2: "ORDER-SYNTH001$$$SYNTHETIC", 4: "SYNTH$Synthetic report$L"}, "!"),
            segment("OBX", {1: 1, 2: "TX", 3: "SYNTHNOTE$Synthetic narrative$L",
                            5: narrative(PATIENTS[0]).replace('%', '?R?').replace('@', '?T?') + " Escaped literals ?F? ?S? ?T? ?R? ?E? ?X4142? ?.br? END.",
                            11: "F"}, "!"),
            segment("NTE", {1: 1, 3: "SYNTHETIC/NOT_REAL custom escapes ?F? ?S? ?T? ?R? ?E? ?X4142? ?.br?"}, "!")]


def write(name: str, segments: list[str], mllp: bool = False) -> None:
    """Write deterministic ER7 bytes with optional MLLP framing."""
    content = ("\r".join(segments) + "\r").encode("ascii")
    if mllp:
        content = b"\x0b" + content + b"\x1c\r"
    (HERE / name).write_bytes(content)


def main() -> None:
    """Regenerate every committed synthetic input fixture."""
    sequence = []
    ordinal = 0
    for p in PATIENTS:
        for event in ("A01", "A08", "A03"):
            ordinal += 1
            sequence.extend(adt(p, event, ordinal))
    write("adt_sequence.hl7", sequence)
    write("oru_lab.hl7", laboratory())
    write("siu.hl7", scheduling())
    write("clinical_misc.hl7", clinical_misc())
    envelope = {1: "|", 2: "^~\\&", 3: "SYNTHETIC", 4: "NOT_REAL",
                5: "SYNTHETIC_RECEIVER", 6: "NOT_REAL", 7: "20260105100000"}
    batch = [segment("FHS", envelope), segment("BHS", envelope)]
    batch.extend(adt(PATIENTS[0], "A01", 101))
    batch.extend(adt(PATIENTS[1], "A01", 102))
    batch.extend([segment("BTS", {1: 2}), segment("FTS", {1: 1})])
    write("batch_mllp.hl7", batch, mllp=True)
    write("custom_delimiters.hl7", custom_delimiters())


if __name__ == "__main__":
    main()
