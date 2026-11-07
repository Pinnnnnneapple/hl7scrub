# Default policy

The bundled version 1 policy supports pseudonymisation for test messages. It replaces common identifying fields, shifts dates, and preserves selected clinical content. Shifted day/month values remain outside HIPAA Safe Harbor's date rule. The [Safe Harbor reference](safe-harbor.md) explains the identifier categories and release considerations; [methodology](methodology.md) describes engine responsibilities and residual gaps.

## Python API

```python
from hl7scrub.policy import default_policy, load_policy

policy = default_policy()       # Fresh dictionary on every call.
policy = load_policy()          # Same bundled policy.
policy = load_policy("site.json")
```

`load_policy(path: Optional[Union[str, Path]] = None) -> dict` reads UTF-8 JSON with the standard library. A custom file replaces the complete default policy. An empty `fields` object is valid and provides no explicit field transformations. Invalid JSON or schema values raise `ValueError`; filesystem errors retain their `OSError` subclasses.

## Schema

```json
{
  "version": 1,
  "unknown_segments": "redact",
  "fields": {
    "PID-3": {
      "action": "pseudonym",
      "kind": "mrn",
      "identifier": "medical_record_number"
    },
    "PID-7": {
      "actions": [{"action": "date_shift"}, {"action": "age_cap"}],
      "identifier": "date_of_birth"
    },
    "MSH-10": {"action": "hash", "length": 32}
  }
}
```

`version` must be the integer `1`. `unknown_segments` accepts `redact` or `keep`, defaults to `redact` when omitted, and governs segments beginning with Z. Unconfigured non-Z segments remain intact. `fields` maps paths to rule objects. Unknown keys and duplicate JSON keys are rejected. Paths use the same parser as `model.Path`: uppercase three-character segment IDs, a positive field number, and optional component/subcomponent numbers. `PID-3[*].1` selects the first component in every repetition; `PID-3[2].1` selects repetition 2. `NK1[2]-2.1` selects segment occurrence 2; `NK1[*]-2[*].1` explicitly selects all occurrences and repetitions. Omitted occurrence/repetition selectors also apply to all. Component wildcards are unsupported.

A rule contains either `action` or an ordered `actions` list of 1 to 16 objects. Pipeline steps contain `action` and applicable options: `kind`, `length`, `text`, `value` or `cap`. `identifier` records the coverage category on the outer rule. The values `provider` and `address` also supply compound-field context to the engine; it is not a path selector or a compliance determination. The loader rejects `then`, nested pipelines, and simultaneous `action` and `actions` keys.

`kind` is valid only for `pseudonym` and must be one of `person_name`, `given_name`, `family_name`, `mrn`, `account`, `ssn`, `phone`, `email`, `street`, `city`, `zip`, `free_text` or `provider_id`. The engine recognizes common provider/address fields and also uses the outer `identifier` category when the kind is `person_name` or `street`. Retain that category when customizing a provider or address pipeline. `length` is valid only for `hash` and must be an integer from 1 to 52. Short lengths increase collision risk.

`redact` accepts a string `text` or its alias `value` as the replacement marker; supply at most one. An empty marker is allowed. `age_cap` accepts a nonnegative integer `cap`, defaulting to 89. It produces a synthetic capped DOB relative to the transformer's reference date, which differs from Safe Harbor's required 90-or-older aggregation. Options may appear on an individual action or inside a pipeline step, never beside the outer `actions` list.

| Action | Intended effect |
| --- | --- |
| keep | Preserve the selected value, subject to engine context handling such as OBX payload rules. |
| remove | Empty the selected value while retaining its position in the message structure. |
| redact | Replace identifying content with a redaction marker. |
| pseudonym | Replace a structured value with a synthetic value of the requested kind. `free_text` invokes narrative handling. |
| hash | Replace an identifier with a keyed HMAC-SHA256 token encoded as truncated uppercase base32; default length 16. |
| date_shift | Shift a date using the engine's configured offset and patient context. |
| age_cap | Replace DOBs above a configurable completed-age cap with a synthetic DOB; defaults to cap 89. |
| zip3 | Generalize a postal code with population-threshold handling appropriate to the deployment. |
| generalize_year | Retain only year precision from a date, subject to age protection. |

The default DOB pipeline runs `age_cap` after `date_shift` so a negative shift cannot push a capped DOB back above the cap. A custom year profile can change each `date_shift` to `generalize_year`, including every pipeline step and component-specific rule. If a pipeline both shifts and generalizes, `generalize_year` must come last. For DOBs, apply `age_cap` after shifting and before any year generalization. The loader validates actions and ordering syntax but cannot determine whether a chosen sequence meets a privacy objective. There is no top-level `date_mode` option.

MSH-3 and MSH-5 retain sending and receiving application names. MSH-4 and MSH-6 hash facility identifiers by default; they can be changed to `keep` in a full custom policy when required for routing in a trusted test setting. Review facility metadata in other composites as well. Providers and contacts are transformed even where their identities may be operational metadata.

A field rule applies throughout its repetitions and components using the engine's datatype context. Whole-field rules run before more specific component rules, and those component rules determine their selected output using the original source field. Avoid duplicate whole-field/component date shifts. Address rules replace street/city values, retain broad state/country/address-type components, and apply `zip3` to the original component 5. The result is exactly three digits, a permitted prefix or `000`. Timing fields retain durations while their start and end date components shift. Unconfigured non-Z fields and segments still require local review. For OBX-5, the engine scrubs TX/FT/ST text, retains numeric/coded values under the bundled rule, and empties ED/RP payloads.

## Configured fields

Labels cover common HL7 v2.5.1 fields and are not a complete standard dictionary. References: HL7 chapters [2](https://www.hl7.eu/HL7v2x/v251/std251/ch02.html), [3](https://www.hl7.eu/HL7v2x/v251/std251/ch03.html), [4](https://www.hl7.eu/HL7v2x/v251/std251/ch04.html), [6](https://www.hl7.eu/HL7v2x/v251/std251/ch06.html), [7](https://www.hl7.eu/HL7v2x/v251/std251/ch07.html), [9](https://www.hl7.eu/HL7v2x/v251/std251/ch09.html) and [10](https://www.hl7.eu/HL7v2x/v251/std251/ch10.html).

| Path | Field | Action or ordered actions | Identifier |
| --- | --- | --- | --- |
| `AIL-1` | Set ID - AIL | keep |  |
| `AIL-2` | Segment Action Code | keep |  |
| `AIL-3` | Location Resource ID | redact | identifying_context |
| `AIL-4` | Location Type - AIL | keep |  |
| `AIL-6` | Start Date/Time | date_shift | date |
| `AIL-12` | Filler Status Code | keep |  |
| `AIP-1` | Set ID - AIP | keep |  |
| `AIP-2` | Segment Action Code | keep |  |
| `AIP-3` | Personnel Resource ID | pseudonym (person_name) | provider |
| `AIP-4` | Resource Type | keep |  |
| `AIP-6` | Start Date/Time | date_shift | date |
| `AIP-12` | Filler Status Code | keep |  |
| `AL1-1` | Set ID - AL1 | keep |  |
| `AL1-2` | Allergen Type Code | keep |  |
| `AL1-3` | Allergen Code/Mnemonic/Description | pseudonym (free_text) | free_text |
| `AL1-4` | Allergy Severity Code | keep |  |
| `AL1-5` | Allergy Reaction Code | pseudonym (free_text) | free_text |
| `AL1-6` | Identification Date | date_shift | date |
| `DG1-1` | Set ID - DG1 | keep |  |
| `DG1-2` | Diagnosis Coding Method | keep |  |
| `DG1-3` | Diagnosis Code - DG1 | keep |  |
| `DG1-4` | Diagnosis Description | pseudonym (free_text) | free_text |
| `DG1-5` | Diagnosis Date/Time | date_shift | date |
| `DG1-6` | Diagnosis Type | keep |  |
| `DG1-16` | Diagnosing Clinician | pseudonym (person_name) | provider |
| `DG1-18` | Confidential Indicator | keep |  |
| `DG1-19` | Attestation Date/Time | date_shift | date |
| `DG1-20` | Diagnosis Identifier | hash | linkable_identifier |
| `EVN-1` | Event Type Code | keep |  |
| `EVN-2` | Recorded Date/Time | date_shift | date |
| `EVN-3` | Date/Time Planned Event | date_shift | date |
| `EVN-5` | Operator ID | pseudonym (person_name) | provider |
| `EVN-6` | Event Occurred | date_shift | date |
| `EVN-7` | Event Facility | hash | linkable_identifier |
| `FT1-1` | Set ID - FT1 | keep |  |
| `FT1-2` | Transaction ID | hash | linkable_identifier |
| `FT1-3` | Transaction Batch ID | hash | linkable_identifier |
| `FT1-4.1` | Transaction Date / Range start date/time | date_shift | date |
| `FT1-4.2` | Transaction Date / Range end date/time | date_shift | date |
| `FT1-5` | Transaction Posting Date | date_shift | date |
| `FT1-6` | Transaction Type | keep |  |
| `FT1-7` | Transaction Code | keep |  |
| `FT1-8` | Transaction Description | pseudonym (free_text) | free_text |
| `FT1-9` | Transaction Description - Alt | pseudonym (free_text) | free_text |
| `FT1-16` | Assigned Patient Location | redact | identifying_context |
| `FT1-20` | Performed By Code | pseudonym (person_name) | provider |
| `FT1-21` | Ordered By Code | pseudonym (person_name) | provider |
| `FT1-23` | Filler Order Number | hash | linkable_identifier |
| `FT1-24` | Entered By Code | pseudonym (person_name) | provider |
| `FT1-25` | Procedure Code | keep |  |
| `FT1-30` | Payment Reference ID | hash | linkable_identifier |
| `FT1-31` | Transaction Reference Key | hash | linkable_identifier |
| `GT1-1` | Set ID - GT1 | keep |  |
| `GT1-2` | Guarantor Number | hash | linkable_identifier |
| `GT1-3` | Guarantor Name | pseudonym (person_name) | name |
| `GT1-4` | Guarantor Spouse Name | pseudonym (person_name) | name |
| `GT1-5` | Guarantor Address | pseudonym (street) | address |
| `GT1-5.5` | Guarantor Address / ZIP or postal code | zip3 | postal_code |
| `GT1-6` | Guarantor Ph Num - Home | pseudonym (phone) | telephone_or_email |
| `GT1-7` | Guarantor Ph Num - Business | pseudonym (phone) | telephone_or_email |
| `GT1-8` | Guarantor Date/Time Of Birth | date_shift then age_cap | date_of_birth |
| `GT1-9` | Guarantor Administrative Sex | keep |  |
| `GT1-10` | Guarantor Type | keep |  |
| `GT1-11` | Guarantor Relationship | keep |  |
| `GT1-12` | Guarantor SSN | pseudonym (ssn) | social_security_number |
| `GT1-13` | Guarantor Date - Begin | date_shift | date |
| `GT1-14` | Guarantor Date - End | date_shift | date |
| `GT1-16` | Guarantor Employer Name | hash | linkable_identifier |
| `GT1-17` | Guarantor Employer Address | pseudonym (street) | address |
| `GT1-17.5` | Guarantor Employer Address / ZIP or postal code | zip3 | postal_code |
| `GT1-18` | Guarantor Employer Phone Number | pseudonym (phone) | telephone_or_email |
| `GT1-19` | Guarantor Employee ID Number | hash | linkable_identifier |
| `GT1-21` | Guarantor Organization Name | hash | linkable_identifier |
| `GT1-24` | Guarantor Death Date and Time | date_shift | date |
| `GT1-29` | Guarantor Employer ID Number | hash | linkable_identifier |
| `GT1-31` | Guarantor Hire Effective Date | date_shift | date |
| `GT1-32` | Employment Stop Date | date_shift | date |
| `GT1-35` | Citizenship | keep |  |
| `GT1-42` | Mother's Maiden Name | pseudonym (person_name) | name |
| `GT1-44` | Ethnic Group | keep |  |
| `GT1-45` | Contact Person's Name | pseudonym (person_name) | name |
| `GT1-46` | Contact Person's Telephone Number | pseudonym (phone) | phone |
| `GT1-47` | Contact Reason | keep |  |
| `GT1-49` | Job Title | redact | identifying_context |
| `GT1-51` | Guarantor Employer's Organization Name | hash | linkable_identifier |
| `GT1-56` | Guarantor Birth Place | redact | identifying_context |
| `GT1-57` | VIP Indicator | redact | identifying_context |
| `IN1-1` | Set ID - IN1 | keep |  |
| `IN1-2` | Insurance Plan ID | keep |  |
| `IN1-3` | Insurance Company ID | hash | linkable_identifier |
| `IN1-4` | Insurance Company Name | hash | linkable_identifier |
| `IN1-5` | Insurance Company Address | pseudonym (street) | address |
| `IN1-5.5` | Insurance Company Address / ZIP or postal code | zip3 | postal_code |
| `IN1-6` | Insurance Co Contact Person | pseudonym (person_name) | name |
| `IN1-7` | Insurance Co Phone Number | pseudonym (phone) | telephone_or_email |
| `IN1-8` | Group Number | hash | linkable_identifier |
| `IN1-9` | Group Name | hash | linkable_identifier |
| `IN1-10` | Insured's Group Emp ID | hash | linkable_identifier |
| `IN1-11` | Insured's Group Emp Name | hash | linkable_identifier |
| `IN1-12` | Plan Effective Date | date_shift | date |
| `IN1-13` | Plan Expiration Date | date_shift | date |
| `IN1-14` | Authorization Information | redact | identifying_context |
| `IN1-15` | Plan Type | keep |  |
| `IN1-16` | Name Of Insured | pseudonym (person_name) | name |
| `IN1-17` | Insured's Relationship To Patient | keep |  |
| `IN1-18` | Insured's Date Of Birth | date_shift then age_cap | date_of_birth |
| `IN1-19` | Insured's Address | pseudonym (street) | address |
| `IN1-19.5` | Insured's Address / ZIP or postal code | zip3 | postal_code |
| `IN1-24` | Notice Of Admission Date | date_shift | date |
| `IN1-26` | Report Of Eligibility Date | date_shift | date |
| `IN1-28` | Pre-Admit Cert (PAC) | hash | linkable_identifier |
| `IN1-29` | Verification Date/Time | date_shift | date |
| `IN1-30` | Verification By | pseudonym (person_name) | provider |
| `IN1-35` | Company Plan Code | keep |  |
| `IN1-36` | Policy Number | hash | linkable_identifier |
| `IN1-44` | Insured's Employer's Address | pseudonym (street) | address |
| `IN1-44.5` | Insured's Employer's Address / ZIP or postal code | zip3 | postal_code |
| `IN1-46` | Prior Insurance Plan ID | hash | linkable_identifier |
| `IN1-49` | Insured's ID Number | hash | linkable_identifier |
| `IN1-51` | Signature Code Date | date_shift | date |
| `IN2-1` | Insured's Employee ID | hash | linkable_identifier |
| `IN2-2` | Insured's Social Security Number | pseudonym (ssn) | social_security_number |
| `IN2-3` | Insured's Employer's Name and ID | hash | linkable_identifier |
| `IN2-6` | Medicare Health Ins Card Number | hash | linkable_identifier |
| `IN2-7` | Medicaid Case Name | pseudonym (person_name) | name |
| `IN2-8` | Medicaid Case Number | hash | linkable_identifier |
| `IN2-9` | Military Sponsor Name | pseudonym (person_name) | name |
| `IN2-10` | Military ID Number | hash | linkable_identifier |
| `IN2-12` | Military Organization | hash | linkable_identifier |
| `IN2-13` | Military Station | redact | identifying_context |
| `IN2-17` | Military Retire Date | date_shift | date |
| `IN2-22` | Special Coverage Approval Name | pseudonym (person_name) | name |
| `IN2-25` | Payor ID | hash | linkable_identifier |
| `IN2-26` | Payor Subscriber ID | hash | linkable_identifier |
| `IN2-40` | Mother's Maiden Name | pseudonym (person_name) | name |
| `IN2-44` | Insured's Employment Start Date | date_shift | date |
| `IN2-45` | Employment Stop Date | date_shift | date |
| `IN2-46` | Job Title | redact | identifying_context |
| `IN2-49` | Employer Contact Person Name | pseudonym (person_name) | name |
| `IN2-50` | Employer Contact Person Phone Number | pseudonym (phone) | telephone_or_email |
| `IN2-52` | Insured's Contact Person's Name | pseudonym (person_name) | name |
| `IN2-53` | Insured's Contact Person Phone Number | pseudonym (phone) | telephone_or_email |
| `IN2-55` | Relationship to the Patient Start Date | date_shift | date |
| `IN2-56` | Relationship to the Patient Stop Date | date_shift | date |
| `IN2-58` | Insurance Co Contact Phone Number | pseudonym (phone) | telephone_or_email |
| `IN2-61` | Patient Member Number | hash | linkable_identifier |
| `IN2-63` | Insured's Phone Number - Home | pseudonym (phone) | telephone_or_email |
| `IN2-64` | Insured's Employer Phone Number | pseudonym (phone) | telephone_or_email |
| `IN2-69` | Insured Organization Name and ID | hash | linkable_identifier |
| `IN2-70` | Insured Employer Organization Name and ID | hash | linkable_identifier |
| `MSH-1` | Field Separator | keep |  |
| `MSH-2` | Encoding Characters | keep |  |
| `MSH-3` | Sending Application | keep |  |
| `MSH-4` | Sending Facility | hash | linkable_identifier |
| `MSH-5` | Receiving Application | keep |  |
| `MSH-6` | Receiving Facility | hash | linkable_identifier |
| `MSH-7` | Date/Time of Message | date_shift | date |
| `MSH-8` | Security | remove | identifying_context |
| `MSH-9` | Message Type | keep |  |
| `MSH-10` | Message Control ID | hash | linkable_identifier |
| `MSH-11` | Processing ID | keep |  |
| `MSH-12` | Version ID | keep |  |
| `MSH-21` | Message Profile Identifier | keep |  |
| `NK1-1` | Set ID - NK1 | keep |  |
| `NK1-2` | Name | pseudonym (person_name) | name |
| `NK1-3` | Relationship | keep |  |
| `NK1-4` | Address | pseudonym (street) | address |
| `NK1-4.5` | Address / ZIP or postal code | zip3 | postal_code |
| `NK1-5` | Phone Number | pseudonym (phone) | telephone_or_email |
| `NK1-6` | Business Phone Number | pseudonym (phone) | telephone_or_email |
| `NK1-7` | Contact Role | keep |  |
| `NK1-8` | Start Date | date_shift | date |
| `NK1-9` | End Date | date_shift | date |
| `NK1-10` | Next of Kin / Associated Parties Job Title | redact | identifying_context |
| `NK1-12` | Next of Kin / Associated Parties Employee Number | hash | linkable_identifier |
| `NK1-13` | Organization Name - NK1 | hash | linkable_identifier |
| `NK1-16` | Date/Time of Birth | date_shift then age_cap | date_of_birth |
| `NK1-26` | Mother's Maiden Name | pseudonym (person_name) | name |
| `NK1-30` | Contact Person's Name | pseudonym (person_name) | name |
| `NK1-31` | Contact Person's Telephone Number | pseudonym (phone) | telephone_or_email |
| `NK1-32` | Contact Person's Address | pseudonym (street) | address |
| `NK1-32.5` | Contact Person's Address / ZIP or postal code | zip3 | postal_code |
| `NK1-33` | Next of Kin/Associated Party's Identifiers | hash | linkable_identifier |
| `NK1-34` | Job Status | keep |  |
| `NK1-35` | Race | keep |  |
| `NK1-37` | Contact Person Social Security Number | pseudonym (ssn) | social_security_number |
| `NK1-38` | Next of Kin Birth Place | redact | identifying_context |
| `NK1-39` | VIP Indicator | redact | identifying_context |
| `NTE-1` | Set ID - NTE | keep |  |
| `NTE-2` | Source of Comment | keep |  |
| `NTE-3` | Comment | pseudonym (free_text) | free_text |
| `NTE-4` | Comment Type | keep |  |
| `OBR-1` | Set ID - OBR | keep |  |
| `OBR-2` | Placer Order Number | hash | linkable_identifier |
| `OBR-3` | Filler Order Number | hash | linkable_identifier |
| `OBR-4` | Universal Service Identifier | keep |  |
| `OBR-6` | Requested Date/Time | date_shift | date |
| `OBR-7` | Observation Date/Time | date_shift | date |
| `OBR-8` | Observation End Date/Time | date_shift | date |
| `OBR-10` | Collector Identifier | pseudonym (person_name) | provider |
| `OBR-13` | Relevant Clinical Information | pseudonym (free_text) | free_text |
| `OBR-14` | Specimen Received Date/Time | date_shift | date |
| `OBR-16` | Ordering Provider | pseudonym (person_name) | provider |
| `OBR-17` | Order Callback Phone Number | pseudonym (phone) | telephone_or_email |
| `OBR-18` | Placer Field 1 | redact | identifying_context |
| `OBR-19` | Placer Field 2 | redact | identifying_context |
| `OBR-20` | Filler Field 1 | redact | identifying_context |
| `OBR-21` | Filler Field 2 | redact | identifying_context |
| `OBR-22` | Results Rpt/Status Chng - Date/Time | date_shift | date |
| `OBR-24` | Diagnostic Serv Sect ID | keep |  |
| `OBR-25` | Result Status | keep |  |
| `OBR-27` | Quantity/Timing | keep |  |
| `OBR-27.4` | Quantity/Timing / Start date/time | date_shift | date |
| `OBR-27.5` | Quantity/Timing / End date/time | date_shift | date |
| `OBR-28` | Result Copies To | pseudonym (person_name) | provider |
| `OBR-29` | Parent | hash | linkable_identifier |
| `OBR-31` | Reason for Study | pseudonym (free_text) | free_text |
| `OBR-32` | Principal Result Interpreter | pseudonym (person_name) | provider |
| `OBR-33` | Assistant Result Interpreter | pseudonym (person_name) | provider |
| `OBR-34` | Technician | pseudonym (person_name) | provider |
| `OBR-35` | Transcriptionist | pseudonym (person_name) | provider |
| `OBR-36` | Scheduled Date/Time | date_shift | date |
| `OBR-39` | Collector's Comment | pseudonym (free_text) | free_text |
| `OBR-43` | Planned Patient Transport Comment | pseudonym (free_text) | free_text |
| `OBX-1` | Set ID - OBX | keep |  |
| `OBX-2` | Value Type | keep |  |
| `OBX-3` | Observation Identifier | keep |  |
| `OBX-4` | Observation Sub-ID | keep |  |
| `OBX-5` | Observation Value | pseudonym (free_text) | free_text |
| `OBX-6` | Units | keep |  |
| `OBX-7` | References Range | keep |  |
| `OBX-8` | Abnormal Flags | keep |  |
| `OBX-11` | Observation Result Status | keep |  |
| `OBX-12` | Effective Date of Reference Range | date_shift | date |
| `OBX-13` | User Defined Access Checks | redact | identifying_context |
| `OBX-14` | Date/Time of the Observation | date_shift | date |
| `OBX-15` | Producer's ID | hash | linkable_identifier |
| `OBX-16` | Responsible Observer | pseudonym (person_name) | provider |
| `OBX-18` | Equipment Instance Identifier | hash | linkable_identifier |
| `OBX-19` | Date/Time of the Analysis | date_shift | date |
| `ORC-1` | Order Control | keep |  |
| `ORC-2` | Placer Order Number | hash | linkable_identifier |
| `ORC-3` | Filler Order Number | hash | linkable_identifier |
| `ORC-4` | Placer Group Number | hash | linkable_identifier |
| `ORC-5` | Order Status | keep |  |
| `ORC-7` | Quantity/Timing | keep |  |
| `ORC-7.4` | Quantity/Timing / Start date/time | date_shift | date |
| `ORC-7.5` | Quantity/Timing / End date/time | date_shift | date |
| `ORC-8` | Parent | hash | linkable_identifier |
| `ORC-9` | Date/Time of Transaction | date_shift | date |
| `ORC-10` | Entered By | pseudonym (person_name) | provider |
| `ORC-11` | Verified By | pseudonym (person_name) | provider |
| `ORC-12` | Ordering Provider | pseudonym (person_name) | provider |
| `ORC-13` | Enterer's Location | redact | identifying_context |
| `ORC-14` | Call Back Phone Number | pseudonym (phone) | telephone_or_email |
| `ORC-15` | Order Effective Date/Time | date_shift | date |
| `ORC-16` | Order Control Code Reason | pseudonym (free_text) | free_text |
| `ORC-17` | Entering Organization | hash | linkable_identifier |
| `ORC-18` | Entering Device | hash | linkable_identifier |
| `ORC-19` | Action By | pseudonym (person_name) | provider |
| `ORC-21` | Ordering Facility Name | hash | linkable_identifier |
| `ORC-22` | Ordering Facility Address | pseudonym (street) | address |
| `ORC-22.5` | Ordering Facility Address / ZIP or postal code | zip3 | postal_code |
| `ORC-23` | Ordering Facility Phone Number | pseudonym (phone) | telephone_or_email |
| `ORC-24` | Ordering Provider Address | pseudonym (street) | address |
| `ORC-24.5` | Ordering Provider Address / ZIP or postal code | zip3 | postal_code |
| `PD1-1` | Living Dependency | keep |  |
| `PD1-2` | Living Arrangement | keep |  |
| `PD1-3` | Patient Primary Facility | hash | linkable_identifier |
| `PD1-4` | Patient Primary Care Provider Name & ID No. | pseudonym (person_name) | provider |
| `PD1-9` | Separate Bill | keep |  |
| `PD1-10` | Duplicate Patient | hash | linkable_identifier |
| `PD1-13` | Protection Indicator Effective Date | date_shift | date |
| `PD1-17` | Immunization Registry Status Effective Date | date_shift | date |
| `PD1-18` | Publicity Code Effective Date | date_shift | date |
| `PID-1` | Set ID - PID | keep |  |
| `PID-2` | Patient ID | pseudonym (mrn) | medical_record_number |
| `PID-3` | Patient Identifier List | pseudonym (mrn) | medical_record_number |
| `PID-4` | Alternate Patient ID - PID | pseudonym (mrn) | medical_record_number |
| `PID-5` | Patient Name | pseudonym (person_name) | name |
| `PID-6` | Mother's Maiden Name | pseudonym (person_name) | name |
| `PID-7` | Date/Time of Birth | date_shift then age_cap | date_of_birth |
| `PID-8` | Administrative Sex | keep |  |
| `PID-9` | Patient Alias | pseudonym (person_name) | name |
| `PID-10` | Race | keep |  |
| `PID-11` | Patient Address | pseudonym (street) | address |
| `PID-11.5` | Patient Address / ZIP or postal code | zip3 | postal_code |
| `PID-12` | County Code | redact | identifying_context |
| `PID-13` | Phone Number - Home | pseudonym (phone) | telephone_or_email |
| `PID-14` | Phone Number - Business | pseudonym (phone) | telephone_or_email |
| `PID-15` | Primary Language | keep |  |
| `PID-16` | Marital Status | keep |  |
| `PID-17` | Religion | keep |  |
| `PID-18` | Patient Account Number | hash | linkable_identifier |
| `PID-19` | SSN Number - Patient | pseudonym (ssn) | social_security_number |
| `PID-20` | Driver's License Number - Patient | hash | linkable_identifier |
| `PID-21` | Mother's Identifier | hash | linkable_identifier |
| `PID-22` | Ethnic Group | keep |  |
| `PID-23` | Birth Place | redact | identifying_context |
| `PID-24` | Multiple Birth Indicator | keep |  |
| `PID-25` | Birth Order | keep |  |
| `PID-26` | Citizenship | keep |  |
| `PID-27` | Veterans Military Status | keep |  |
| `PID-28` | Nationality | keep |  |
| `PID-29` | Patient Death Date and Time | date_shift | date |
| `PID-30` | Patient Death Indicator | keep |  |
| `PID-33` | Last Update Date/Time | date_shift | date |
| `PID-34` | Last Update Facility | hash | linkable_identifier |
| `PV1-1` | Set ID - PV1 | keep |  |
| `PV1-2` | Patient Class | keep |  |
| `PV1-3` | Assigned Patient Location | redact | identifying_context |
| `PV1-4` | Admission Type | keep |  |
| `PV1-5` | Preadmit Number | hash | linkable_identifier |
| `PV1-6` | Prior Patient Location | redact | identifying_context |
| `PV1-7` | Attending Doctor | pseudonym (person_name) | provider |
| `PV1-8` | Referring Doctor | pseudonym (person_name) | provider |
| `PV1-9` | Consulting Doctor | pseudonym (person_name) | provider |
| `PV1-10` | Hospital Service | keep |  |
| `PV1-11` | Temporary Location | redact | identifying_context |
| `PV1-16` | VIP Indicator | redact | identifying_context |
| `PV1-17` | Admitting Doctor | pseudonym (person_name) | provider |
| `PV1-19` | Visit Number | hash | linkable_identifier |
| `PV1-25` | Contract Effective Date | date_shift | date |
| `PV1-30` | Transfer to Bad Debt Date | date_shift | date |
| `PV1-35` | Delete Account Date | date_shift | date |
| `PV1-37` | Discharged to Location | redact | identifying_context |
| `PV1-39` | Servicing Facility | hash | linkable_identifier |
| `PV1-40` | Bed Status | keep |  |
| `PV1-42` | Pending Location | redact | identifying_context |
| `PV1-43` | Prior Temporary Location | redact | identifying_context |
| `PV1-44` | Admit Date/Time | date_shift | date |
| `PV1-45` | Discharge Date/Time | date_shift | date |
| `PV1-50` | Alternate Visit ID | hash | linkable_identifier |
| `PV1-52` | Other Healthcare Provider | pseudonym (person_name) | provider |
| `PV2-1` | Prior Pending Location | redact | identifying_context |
| `PV2-3` | Admit Reason | pseudonym (free_text) | free_text |
| `PV2-6` | Patient Valuables Location | redact | identifying_context |
| `PV2-8` | Expected Admit Date/Time | date_shift | date |
| `PV2-9` | Expected Discharge Date/Time | date_shift | date |
| `PV2-12` | Visit Description | pseudonym (free_text) | free_text |
| `PV2-13` | Referral Source Code | pseudonym (person_name) | provider |
| `PV2-14` | Previous Service Date | date_shift | date |
| `PV2-16` | Purge Status Code | keep |  |
| `PV2-17` | Purge Status Date | date_shift | date |
| `PV2-21` | Visit Publicity Code | keep |  |
| `PV2-23` | Clinic Organization Name | hash | linkable_identifier |
| `PV2-24` | Patient Status Code | keep |  |
| `PV2-26` | Previous Treatment Date | date_shift | date |
| `PV2-28` | Signature on File Date | date_shift | date |
| `PV2-29` | First Similar Illness Date | date_shift | date |
| `PV2-33` | Expected Surgery Date and Time | date_shift | date |
| `PV2-46` | Patient Status Effective Date | date_shift | date |
| `PV2-47` | Expected LOA Return Date/Time | date_shift | date |
| `PV2-48` | Expected Preadmission Testing Date/Time | date_shift | date |
| `SCH-1` | Placer Appointment ID | hash | linkable_identifier |
| `SCH-2` | Filler Appointment ID | hash | linkable_identifier |
| `SCH-3` | Occurrence Number | keep |  |
| `SCH-4` | Placer Group Number | hash | linkable_identifier |
| `SCH-6` | Event Reason | pseudonym (free_text) | free_text |
| `SCH-7` | Appointment Reason | pseudonym (free_text) | free_text |
| `SCH-8` | Appointment Type | keep |  |
| `SCH-11` | Appointment Timing Quantity | keep |  |
| `SCH-11.4` | Appointment Timing Quantity / Start date/time | date_shift | date |
| `SCH-11.5` | Appointment Timing Quantity / End date/time | date_shift | date |
| `SCH-12` | Placer Contact Person | pseudonym (person_name) | provider |
| `SCH-13` | Placer Contact Phone Number | pseudonym (phone) | telephone_or_email |
| `SCH-14` | Placer Contact Address | pseudonym (street) | address |
| `SCH-14.5` | Placer Contact Address / ZIP or postal code | zip3 | postal_code |
| `SCH-15` | Placer Contact Location | redact | identifying_context |
| `SCH-16` | Filler Contact Person | pseudonym (person_name) | provider |
| `SCH-17` | Filler Contact Phone Number | pseudonym (phone) | telephone_or_email |
| `SCH-18` | Filler Contact Address | pseudonym (street) | address |
| `SCH-18.5` | Filler Contact Address / ZIP or postal code | zip3 | postal_code |
| `SCH-19` | Filler Contact Location | redact | identifying_context |
| `SCH-20` | Entered by Person | pseudonym (person_name) | provider |
| `SCH-21` | Entered by Phone Number | pseudonym (phone) | telephone_or_email |
| `SCH-22` | Entered by Location | redact | identifying_context |
| `SCH-23` | Parent Placer Appointment ID | hash | linkable_identifier |
| `SCH-24` | Parent Filler Appointment ID | hash | linkable_identifier |
| `SCH-25` | Filler Status Code | keep |  |
| `SCH-26` | Placer Order Number | hash | linkable_identifier |
| `SCH-27` | Filler Order Number | hash | linkable_identifier |
| `TXA-1` | Set ID - TXA | keep |  |
| `TXA-2` | Document Type | keep |  |
| `TXA-3` | Document Content Presentation | keep |  |
| `TXA-4` | Activity Date/Time | date_shift | date |
| `TXA-5` | Primary Activity Provider Code/Name | pseudonym (person_name) | provider |
| `TXA-6` | Origination Date/Time | date_shift | date |
| `TXA-7` | Transcription Date/Time | date_shift | date |
| `TXA-8` | Edit Date/Time | date_shift | date |
| `TXA-9` | Originator Code/Name | pseudonym (person_name) | provider |
| `TXA-10` | Assigned Document Authenticator | pseudonym (person_name) | provider |
| `TXA-11` | Transcriptionist Code/Name | pseudonym (person_name) | provider |
| `TXA-12` | Unique Document Number | hash | linkable_identifier |
| `TXA-13` | Parent Document Number | hash | linkable_identifier |
| `TXA-14` | Placer Order Number | hash | linkable_identifier |
| `TXA-15` | Filler Order Number | hash | linkable_identifier |
| `TXA-16` | Unique Document File Name | hash | linkable_identifier |
| `TXA-17` | Document Completion Status | keep |  |
| `TXA-18` | Document Confidentiality Status | keep |  |
| `TXA-19` | Document Availability Status | keep |  |
| `TXA-20` | Document Storage Status | keep |  |
| `TXA-21` | Document Change Reason | pseudonym (free_text) | free_text |
| `TXA-22` | Authentication Person, Time Stamp (set) | pseudonym (person_name) | provider |
| `TXA-22.15` | Authentication Person, Time Stamp (set) / Date/time action performed | date_shift | date |
| `TXA-23` | Distributed Copies | pseudonym (person_name) | provider |
