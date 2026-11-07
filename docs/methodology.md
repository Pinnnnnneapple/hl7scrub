# Methodology and limits

hl7scrub uses explicit field policies to replace identifying values while retaining useful HL7 structure. The bundled policy targets common HL7 v2.5.1 fields; deployments must compare it with their interface specifications. A successful parse or an empty residual report does not establish de-identification.

## Field selection

Paths use one-based HL7 field numbering, including the special MSH-1 field separator and MSH-2 encoding characters. `PID-5` selects a field, `PID-5.1` selects its first component, and `PID-5.1.2` selects a subcomponent. A rule applies to every occurrence of its segment and every field repetition unless an occurrence or repetition selector narrows it. For example, `NK1[2]-2[*].1` selects the first name component in all repetitions of the second NK1 segment. Whole-field rules run before more specific component/subcomponent rules. Each rule reads the original field; a component override therefore does not transform its parent rule's pseudonym a second time. An ordered actions pipeline within one rule is sequential. Timing composites use component rules so durations and units can remain useful while their dates change.

Field names are display labels, not datatype declarations or a complete HL7 schema. The reference dictionary has the shape `{"PID": {"3": "Patient Identifier List"}}`. Missing labels and later-version additions require local review. The structural conventions follow [HL7 v2.5.1 chapter 2](https://www.hl7.eu/HL7v2x/v251/std251/ch02.html); patient and encounter fields follow [chapter 3](https://www.hl7.eu/HL7v2x/v251/std251/ch03.html). Financial, order, observation, document and scheduling labels use chapters [6](https://www.hl7.eu/HL7v2x/v251/std251/ch06.html), [4](https://www.hl7.eu/HL7v2x/v251/std251/ch04.html), [7](https://www.hl7.eu/HL7v2x/v251/std251/ch07.html), [9](https://www.hl7.eu/HL7v2x/v251/std251/ch09.html) and [10](https://www.hl7.eu/HL7v2x/v251/std251/ch10.html).

## Transformation boundaries

The policy describes intended actions. The engine and transformer implement repetition handling, datatype-aware component treatment, deterministic mappings and date arithmetic. Names, addresses, XTN contact details and provider composites need that context: treating a complete composite as an ordinary string can retain identifying metadata or produce unusable output. Provider fields include IDs as well as names. Address rules replace streets and cities with synthetic values and retain broad state, country and address-type components. A component-5 `zip3` rule returns exactly three digits, either a permitted prefix or `000`. Component overrides read the original source field, so ZIP generalization uses the source ZIP rather than its synthetic replacement.

The default uses `date_shift`. DOB pipelines apply `age_cap` after shifting, preventing a shift across the reference birthday from exceeding the cap. The current cap produces a synthetic DOB at a maximum completed age, default 89, relative to the configured reference date. It does not implement the Safe Harbor 90-or-older age category. A stable shift can retain time intervals within the engine's chosen patient scope, but boundary dates, malformed values and age handling need explicit verification. A fixed shift can also be inferred from outside information. Shifting preserves month/day detail and therefore does not satisfy Safe Harbor's date rule. A custom policy can use `generalize_year`, including after a shift; DOB age protection must remain in place. Review the reference date used for age calculations and any retained admission dates that could reveal an older person's birth year.

The `hash` action uses keyed HMAC-SHA256 over a domain label, a NUL separator and a whitespace/case-normalized value. Its deterministic byte stream is encoded as uppercase base32 without padding and truncated to the requested length, default 16 characters. Sixteen base32 characters represent 80 output bits; requesting a longer output cannot exceed the 256-bit seed entropy. Key strength and source-value predictability remain relevant. Short tokens increase collision risk, and normalization intentionally maps some distinct spellings to the same token. Keep keys and mapping files separate from released messages. A recipient with the same key and normalized input can reproduce the token.

## Narrative and observation values

`pseudonym` with `kind: "free_text"` asks the engine to process narrative text. This includes NTE-3, selected clinical descriptions, comments and administrative prose. Rules and residual patterns cannot reliably recognize arbitrary personal names, rare diagnoses used as identifiers, or every local identifier format. Escaped text and repeated notes need the same review as visible prose.

For OBX-5, the engine uses OBX-2 to distinguish values. TX, FT and ST values pass through narrative scrubbing; numeric and coded observations remain intact under the bundled `free_text` rule. ED and RP values are emptied because embedded data and referenced documents are not inspected. Identifiers in observation labels or clinical codes still require review. No OCR, image analysis or general document sanitization is provided.

## Unknown and unconfigured data

`unknown_segments: "redact"` redacts fields in segments whose names begin with Z. Setting it to `keep` preserves those segments and reports them for review. Z-segment handling takes place before field rules, so an explicit Z-field rule does not bypass it. The engine preserves unconfigured non-Z segments and fields; this option does not redact every segment missing from the field-name dictionary.

Review added fields, coded text components, assigning authorities, extensions, embedded dates and local uses of standard fields. Even `keep` fields such as diagnoses or observation labels can contain locally entered identifying text. The field-name dictionary supplies labels and does not define an allowlist.

The parser reads bytes through UTF-8 with `surrogateescape`, preserving undecodable legacy bytes for reversible output. Digest encoding uses the same error handler. Format-preserving MRN/account transformations can retain non-ASCII or undecodable characters; inspect those identifiers under the source encoding and choose a hash/redaction rule if complete replacement is required. Name replacement uses synthetic name pools.

The residual scanner is a final heuristic check on output. It can flag recognizable patterns, but it cannot prove that all identifiers were found. Review representative synthetic fixtures for every message type and local extension, compare input/output structure, and inspect flagged output inside the same protected environment as the originals. Keep originals, logs, temporary files and mappings under the same access controls as the source messages.

The [default policy reference](default-policy.md) lists every configured path. The [Safe Harbor reference](safe-harbor.md) maps those transformations to identifier categories and identifies coverage that needs local review.

## Deterministic derivation

For a nonempty secret K, kind k and value v, the transformer computes:

```text
normalize(v) = casefold(collapse_whitespace(v))
D(k, v) = HMAC-SHA256(K, UTF8(k + NUL + normalize(v)))
pseudonym_index = integer(D(k, v)) mod pool_size
hash(v, L) = BASE32(D("hash", v))[:L]        # 1 <= L <= 52; no '=' padding
offset(p) = integer(D("date_shift", patient_identity(p))) mod (2*N + 1) - N
shifted_date = original_date + offset(p) days
```

The default 16-character hash carries 80 output bits. Pool-backed names have far
fewer possible outputs and can collide; neither output is a uniqueness registry.
For n independent 80-bit tokens the approximate collision probability is
`n*(n-1)/(2*2**80)` when that probability is small. Domain separation prevents
an MRN and an account value from sharing the same mapping merely because their
original text matches. Small domains still permit guessing attacks if a key is
compromised. There is no persisted original-to-pseudonym table.

Identity hashing uses the first qualified PID-3 repetition, including its assigning
authority; it falls back to PID-5 and PID-7. Structural delimiter declarations are
canonicalized before hashing. Reconciliation of changed IDs is outside this model.

Full dates receive calendar-day arithmetic; their time, fraction and timezone are
retained verbatim. Reduced precision uses January/day 1 anchors and emits only
original precision. The DOB cap uses a captured local reference date (or an explicit
fixed date) after the shift. Malformed dates and calendar overflow are retained with
value-free warnings during date shifting. Keep those warnings in review workflows.

## References

- [45 CFR §164.514(b)(2)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.514).
- [HHS OCR, Guidance Regarding Methods for De-identification of PHI (2012)](https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html).
- [HL7 v2.5.1 chapter 2, Control](https://www.hl7.eu/HL7v2x/v251/std251/ch02.html) and [chapter 3, Patient Administration](https://www.hl7.eu/HL7v2x/v251/std251/ch03.html).
- [HL7 v2.5.1 chapter 2A, PPN.15](https://www.hl7.eu/HL7v2x/v251/std251/ch02a.html): TXA-22's authentication timestamp is component 15, alongside the transformed provider identity.
