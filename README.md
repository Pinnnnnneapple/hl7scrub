# hl7scrub

**Realistic HL7 v2 test messages, with consistent fake identities across messages and files.**

[![CI](https://github.com/Pinnnnnneapple/hl7scrub/actions/workflows/ci.yml/badge.svg)](https://github.com/Pinnnnnneapple/hl7scrub/actions/workflows/ci.yml)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10–3.14](https://img.shields.io/badge/python-3.10%E2%80%933.14-blue.svg)](pyproject.toml)

`hl7scrub` is a Python library and command-line toolkit for structure-aware HL7 v2 anonymisation and pseudonymisation. It has **no runtime dependencies**. Give it the same secret and patient identifiers, and an ADT admission, subsequent update, discharge, and laboratory result retain their relationships after scrubbing.

## Why

Hospital integration engineers need useful messages for interface development, vendor tickets, and CI. Production messages carry names, identifiers, contact details, and identifying narratives. Regex replacements alone can damage delimiter structure or give one patient several unrelated identities.

hl7scrub parses the message's own encoding characters, applies a field policy, and writes ER7 with the original segment separators. It supports ADT, ORM, ORU, SIU, MDM, DFT and other MSH-led messages without needing an interface engine.

**Expert review is required before sharing output.** The default is a linkable test-data pseudonymisation policy informed by HIPAA's 18 Safe Harbor identifier categories. It preserves shifted dates and clinical content; it does **not** implement or certify HIPAA Safe Harbor. Pseudonymised data may remain PHI or personal data, including under GDPR. See [limitations](#limitations-and-disclaimer) and the [Safe Harbor reference](docs/safe-harbor.md).

## Features

- Lossless parse/serialize for unchanged bytes: CR, LF, CRLF, mixed endings, trailing empty fields, multi-message files, FHS/BHS/BTS/FTS wrappers and MLLP framing.
- MSH-declared separators, custom encodings, the optional v2.7 truncation character, repetitions, components, subcomponents, and standard/hexadecimal/line-break escapes.
- HMAC-derived pseudonyms, provider IDs, format-preserving MRNs/phones, case-preserving names, invalid-area SSNs, and non-deliverable email addresses.
- Patient-consistent date shifts with timestamp precision, time of day, fractional seconds and UTC offset retained. Admission-to-discharge intervals survive full-date shifts.
- A bundled policy with 406 field rules, editable JSON, safe-default Z-segment redaction, text scrubbing and opaque OBX ED/RP removal.
- `show` for labelled field trees, `diff` for field changes, `scan` for residual-PHI checks, and aggregate JSON auditing without original values.

The bundled pools contain 200 common given names, 200 family names, 101 street names and 60 invented city names. They contain no records about real people; a generated name can still coincide with a real person's name.

## Install

Python 3.10 or newer:

```sh
pip install git+https://github.com/Pinnnnnneapple/hl7scrub
```

From a checkout:

```sh
git clone https://github.com/Pinnnnnneapple/hl7scrub
cd hl7scrub
python3 -m pip install -e '.[dev]'
python3 -m pytest -q
```

For an offline checkout with pytest already available, no installation is needed:

```sh
PYTHONPATH=src python3 -m pytest -q
PYTHONPATH=src python3 -m hl7scrub --help
```

 The `hl7scrub` executable and `python -m hl7scrub` expose the same interface.

## Quickstart

All committed examples are **100% synthetic**. The following public key is for these examples only:

```sh
hl7scrub scrub examples/adt_sequence.hl7 \
  --key demo-key-do-not-use --reference-date 2026-01-01 \
  -o clean.hl7 --report report.json
hl7scrub scan clean.hl7
hl7scrub show clean.hl7
hl7scrub diff examples/adt_sequence.hl7 clean.hl7
```

Scrubbing reports this expected warning on stderr because the fixture includes a local Z segment:

```text
hl7scrub: warning: Unknown segment ZSY: redact
```

Actual `show` output, excerpted from that run:

```text
  PID
    PID-1 Set ID - PID: 1
    PID-3 Patient Identifier List
      PID-3.1: DJMHB030
      PID-3.4: W72TKT6EWJLD35UX
      PID-3.5: MR
    PID-5 Patient Name
      PID-5.1: MASON
      PID-5.2: VIOLET
    PID-7 Date/Time of Birth: 19360104
    PID-8 Administrative Sex: F
```

Actual `diff` output, excerpted from the same run:

```text
1:PID[1]-3	"SYNTH001^^^SYNTHETIC^MR" -> "DJMHB030^^^W72TKT6EWJLD35UX^MR"
1:PID[1]-5	"SAMPLE^ALICE" -> "MASON^VIOLET"
```

Here `\t` represents the tab separating path and values. Diff paths identify message number, segment occurrence and field. `diff` exits 0 when it successfully compares files, including when differences exist.

`scan` prints no output and exits 0 for `clean.hl7`. Scanning the original exits 1; its findings contain positions and categories rather than matched values:

```text
input=1 message=1 segment=11 NTE-3 patient_name
```

`show` and `diff` display input values. Run them within the source data's protected environment and keep their output out of public logs.

## Commands

| Command | Purpose |
| --- | --- |
| `hl7scrub scrub IN [IN...]` | Scrub to stdout, one output file, or an output directory. |
| `hl7scrub show FILE` | Print message → segment → field → repetition/component trees, with common v2.5.1 field names. |
| `hl7scrub diff A B` | Compare fields, including added and removed fields, across messages. |
| `hl7scrub policy --dump-default` | Print the complete built-in JSON policy. |
| `hl7scrub scan FILE [FILE...]` | Flag likely residual SSNs, phones, emails, and copies of PID names outside structured name fields. |

```sh
# One secret across several files preserves identities across files.
hl7scrub scrub incoming/*.hl7 --out-dir fixtures --key-file /secure/hl7scrub.key \
  --date-shift-days 30 --report report.json

# '-' means stdin/stdout; framing is stripped unless --mllp is selected.
hl7scrub scrub - --key-file /secure/hl7scrub.key --mllp > framed.hl7

# Inspect/edit a complete policy, then apply it.
hl7scrub policy --dump-default > site-policy.json
hl7scrub scrub incoming.hl7 --policy site-policy.json --key-file /secure/hl7scrub.key

# CI guard for a folder of fixtures.
hl7scrub scan fixtures/*.hl7
```

`-o`/`--output` and `--out-dir` are mutually exclusive. Multiple inputs with `-o` or stdout form one transmission; `--out-dir` preserves basenames and rejects collisions. Existing input files are never overwritten. All inputs are read and transformed before output starts. Each output file is replaced atomically; the full directory/report operation is not transactional. Processing is in memory.

`--mllp` adds one MLLP envelope per output transmission. Library serialization preserves existing transport by default. `--strict` on `scrub` returns 1 for parse or policy warnings, including unknown Z segments; it still writes the transformed output. Malformed inputs or I/O errors return 2.

| Exit code | Meaning |
| --- | --- |
| 0 | Successful operation; `scan` found no recognized residual patterns. |
| 1 | `scan` found likely PHI, or a strict command encountered warnings. |
| 2 | Invalid command/configuration, missing key, parse failure, or I/O failure. |

## Secrets and reproducibility

Choose one of `--key`, `HL7SCRUB_KEY`, or `--key-file`. An explicit command-line source takes precedence over the environment; key options are mutually exclusive. Empty keys are refused. A key file contains raw secret bytes, with trailing CR/LF removed. Prefer a protected key file or environment injection to placing a secret in shell history or process arguments.

Without a secret, `scrub` refuses to run. `--random-key` explicitly chooses an ephemeral random secret; the program never prints or stores it. That run cannot be reproduced later, and subsequent invocations will not link to it.

Use at least 32 randomly generated secret bytes for real workflows. Keep the key separate from shared output. Anyone who learns it can reproduce mappings from guessed originals; stable pseudonyms and preserved timing can also enable linkage without the key. Small name pools and short hashes can collide. Pseudonyms are not globally unique identifiers, and the public demo key offers no protection.

Age capping depends on the reference date, captured once per `Scrubber`. Set `--reference-date YYYY-MM-DD` (or the library's `reference_date`) to make capped DOBs reproducible over time. Same key, policy, window and reference date produce the same outputs; changing policy or package data can change mappings. Already scrubbed messages should not be scrubbed again: transformations are deterministic, not idempotent.

## Library usage

```python
from datetime import date
from pathlib import Path
from hl7scrub import Message, Scrubber, parse

original = Path("examples/oru_lab.hl7").read_bytes()
document = parse(original)
assert document.to_bytes() == original
message = document.messages[0]
assert message.get("PID-3[*].1") == ["SYNTH001"]

# Literal setters escape separators; raw=True accepts an ER7 composite.
message.set("PID-5.1", "SYNTHETIC FAMILY")
message.set("PID-5", "SYNTHETIC^PERSON", raw=True)

scrubber = Scrubber(b"demo-key-do-not-use", reference_date=date(2026, 1, 1))
clean = scrubber.scrub(original)  # Each Document passed here is modified in place.
Path("clean.hl7").write_bytes(clean.to_bytes(mllp=False))
report = scrubber.report.to_dict()  # Accumulates across this instance's calls.
```

`Message.parse()` requires exactly one MSH-led message. `parse()` returns a `Document` containing all messages and wrappers; `parse_messages()` returns only the message list. `Segment.field(number)` returns a `Field` with raw ER7 and decoded access. Paths are one-based: `PID-5.1`, `PID-3[2].1`, `PID-3[*].1`, `NK1[2]-2.1`, `NK1[*]-2.1`, and subcomponents such as `PID-3.4.2`. In library access an omitted repetition/segment selector means the first; wildcard getters return lists. In policy rules omitted selectors apply to all occurrences/repetitions.

Parsing uses reversible UTF-8 with `surrogateescape` and preserves arbitrary input bytes. It does not transcode according to MSH-18; review legacy encodings and character-set escapes before transforming them. The model validates structural headers and paths, rather than a full HL7 message grammar or every datatype constraint.

## Policy reference

A custom JSON file **replaces** the default policy; start with `--dump-default` to retain its coverage. Whole-field rules run before more specific component overrides, which read the original field. Ordered `actions` pipelines run sequentially within one rule.

| Action | Example use |
| --- | --- |
| `keep` | Retain numeric clinical observations and message controls. |
| `remove` | Empty a field or selected leaf. |
| `redact` | Replace with `***`, or a configured `text` marker. |
| `pseudonym` | Generate a stable name, MRN, contact or address value. |
| `hash` | Uppercase base32 HMAC-SHA256 token; default 16 characters, maximum 52. |
| `date_shift` | Apply one patient-specific offset within ±N days. |
| `age_cap` | Replace DOBs implying age above 89 with a synthetic capped DOB. |
| `zip3` | Keep the first three digits; return `000` for restricted prefixes. |
| `generalize_year` | Retain year precision from a valid timestamp. |

Pseudonym kinds: `person_name`, `given_name`, `family_name`, `mrn`, `account`, `ssn`, `phone`, `email`, `street`, `city`, `zip`, `free_text`, and `provider_id`.

| Field group | Default treatment |
| --- | --- |
| MSH | Keep routing application/message-type/version fields; hash facilities/control ID, shift message date, remove security. |
| PID / NK1 / GT1 / IN1 / IN2 | Replace names/contact details, transform identifiers, cap/shift DOBs and remove identifying context. |
| PD1 / PV1 / ORC / OBR providers | Consistent synthetic names and NPI-like identifiers; remove identifying provider metadata. |
| Visit, order, document, appointment and account IDs | Keyed hashes or format-preserving pseudonyms, depending on the field. |
| Encounter, order, observation and appointment dates | Patient-specific shifts; timing components preserve durations. |
| OBX-5 | Scrub TX/FT/ST, remove ED/RP, shift date-valued DT/DTM/TS/DR, retain numeric/coded results. |
| NTE-3 and selected descriptions | Replace collected PHI tokens and SSN/phone/email/date patterns; keep remaining prose. |
| Unknown Z segments | Redact with a value-free warning; configurable `keep`. |

The [complete default-policy table](docs/default-policy.md) lists every configured path and its identifier mapping. Unconfigured non-Z fields/segments remain unchanged and need local review. The [methodology](docs/methodology.md) explains context handling and boundaries.

## Methodology

Normalize an original value by collapsing whitespace and case-folding. Given secret `K`, kind `k`, and value `v`:

```text
D(k, v) = HMAC-SHA256(K, UTF8(k + NUL + normalize(v)))
pool_index = integer(D(k, v)) mod pool_size
hash(v) = BASE32(D("hash", v))[:length]
offset(patient) = integer(D("date_shift", patient_identity)) mod (2*N + 1) - N
shifted_date = original_date + offset(patient) days
```

MRNs/accounts substitute each letter/digit while retaining punctuation and character classes. Name selection preserves upper/lower/title style. Telephone punctuation is retained; recognizable North American numbers use fictional `555-01xx` values. SSNs use invalid 900–999 area prefixes. Provider IDs are synthetic 10-digit values with an NPI-style check digit; they are not licensed-provider records.

Patient identity uses the first PID-3 repetition with both an identifier and assigning authority. Otherwise it uses PID-5 plus PID-7. The authority participates in the date identity, so identical local MRNs from different authorities remain distinct. Missing identifiers share a warned fallback offset; identifier changes and cross-facility merges need upstream reconciliation.

Date shifts preserve YYYY, YYYYMM, YYYYMMDD and hour/minute/second precision, fractions, and numeric timezone suffixes. Reduced-precision dates use January/day 1 anchors; only their original number of date digits is emitted. Timezone offsets and times of day are not converted. Malformed dates and calendar-overflow shifts are retained for review, so warnings matter. DOB capping deliberately changes age and is separate from interval preservation.

The `zip3` data file cites the 17 restricted prefixes in historical HHS guidance. That list uses 2000 Census data; current population eligibility must be verified separately. The fixed list is not a current Census determination.

## Examples and audit

| Input | Contents |
| --- | --- |
| [adt_sequence.hl7](examples/adt_sequence.hl7) | A01 → A08 → A03 for two fictitious patients, providers, guarantor/insurance data, notes and a Z segment. |
| [oru_lab.hl7](examples/oru_lab.hl7) | Numeric labs, PHI-bearing synthetic narrative, NTE, and opaque ED/RP examples. |
| [siu.hl7](examples/siu.hl7) | SCH timing, AIP provider and AIL location. |
| [clinical_misc.hl7](examples/clinical_misc.hl7) | MDM/TXA and DFT/FT1. |
| [batch_mllp.hl7](examples/batch_mllp.hl7) | FHS/BHS/BTS/FTS and MLLP around two messages. |
| [custom_delimiters.hl7](examples/custom_delimiters.hl7) | Custom separators, fifth truncation character and escaped literals. |

Regenerate inputs and committed outputs:

```sh
python3 examples/generate_examples.py
PYTHONPATH=src python3 examples/scrub_examples.py
```

[examples/scrubbed/](examples/scrubbed/) contains CLI-generated outputs using `demo-key-do-not-use` and reference date `2026-01-01`, plus the [aggregate report](examples/scrubbed/report.json). Reports contain action counts by path, segment counts, unknown Z-segment names and generic warnings. They contain neither original/replacement values nor keys, patient identities, offsets or input filenames. The report is aggregate audit metadata, not an anonymisation certificate.

## Limitations and disclaimer

De-identification needs expert review. Free text is hard: token/regex scrubbing cannot reliably find unrelated names, misspellings, rare facts, every language, URLs/IPs, or every local identifier. The scanner is a CI heuristic with false positives and false negatives; it deliberately ignores recognizable fake contact formats and structured names. A clean scan does not prove anonymity.

The default retains day/month dates, linkable IDs, broad geographic context and clinical content. Its synthetic DOB cap is not Safe Harbor's required 90-or-older aggregation. Year generalization and the historical ZIP list alone do not make a dataset Safe Harbor compliant. Review all 18 identifier categories, local fields and re-identification risks against [45 CFR §164.514(b)(2)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.514) and [HHS OCR's 2012 de-identification guidance](https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html).

ED/RP values are emptied; no OCR, image or document-content sanitizer is provided. Clinical codes and unconfigured fields may still identify people. Some receivers require local constraints, routable facilities, full ZIPs or mandatory attachments; adapt the policy and validate it with their interface profile. Parsing/escaping preserves ER7 structure, not arbitrary receiver conformance. Pseudonymised output may remain regulated PHI or personal data under applicable law, including GDPR. This software provides no legal or clinical assurance.

## Development and roadmap

The suite covers byte-identical parsing, custom encoding/escapes, paths, all actions, time precision and intervals, formats, cross-file determinism, narratives, providers, opaque payload removal, reports, scanning and direct `main(argv)` CLI calls. CI tests Python 3.10–3.14 on Linux, Windows and macOS and exercises every synthetic fixture through the CLI.

Potential next releases: interface-profile validation, site-specific identity reconciliation hooks, richer multilingual narrative detection, and versioned policy migration tools. These are roadmap items, not current guarantees.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Use synthetic fixtures in issues; never submit PHI. See [CHANGELOG.md](CHANGELOG.md) for releases and [LICENSE](LICENSE) for the MIT license.
