# Safe Harbor reference

hl7scrub's default policy supports pseudonymisation for development and testing. It shifts dates and retains clinical information. Its output is not certified as HIPAA de-identified. A date with a shifted month or day still falls outside the Safe Harbor date requirement.

Safe Harbor removes specified identifiers of the individual and of relatives, employers, or household members. It also requires the covered entity to have no actual knowledge that the remaining information could identify an individual. See [45 CFR 164.514(b)(2)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.514#p-164.514(b)(2)).

| Category | Common message locations and policy coverage |
| --- | --- |
| 1. Names | PID-5/6/9, NK1-2, GT1-3/4, IN1-16, IN2-7/9/40; provider and contact fields also receive pseudonyms. |
| 2. Geography below state | XAD addresses are replaced, with `.5` ZIP generalization; PID-12/23 and patient locations are redacted. Review local geography fields. |
| 3. Dates and ages | Dates shift by default; DOB uses a synthetic `date_shift` then `age_cap`; this does not provide the 90-or-older aggregation. For a stricter profile, use year generalization and remove details that reveal ages above 89. |
| 4. Telephone numbers | PID-13/14, NK1-5/6, and contact fields receive replacement values. |
| 5. Fax numbers | XTN fields may carry fax numbers; verify all local fax locations. |
| 6. Email addresses | XTN fields and free text may contain email; review detection coverage. |
| 7. Social security numbers | PID-19, NK1-37, GT1-12, IN2-2 receive replacement values. |
| 8. Medical record numbers | PID-2/3/4 receive pseudonyms; identifiers can also occur in prose. |
| 9. Health plan beneficiary numbers | IN1-36/49, IN2-6/8/26 and related identifiers are hashed. |
| 10. Account numbers | PID-18, GT1-2 and payment references are hashed. |
| 11. Certificate and license numbers | PID-20 and provider identifiers are transformed; review local credential fields. |
| 12. Vehicle identifiers | No dedicated universal field mapping; inspect local fields and narratives. |
| 13. Device identifiers | OBX-18 and ORC-18 are hashed; review serial numbers in values and attachments. |
| 14. Web URLs | May appear in text or references; residual detection is incomplete. |
| 15. IP addresses | May appear in text, application IDs, or local fields; review retained metadata. |
| 16. Biometrics | Remove biometric payloads, including voice recordings and fingerprints. No biometric recognition is provided. |
| 17. Identifying photographs and comparable images | Encapsulated payloads need removal; no image inspection or OCR is provided. |
| 18. Other identifying numbers, characteristics, or codes | Order, visit, appointment and document IDs are hashed; rare clinical combinations and local codes need review. |

The category mapping follows [HHS OCR de-identification guidance (2012)](https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html). The default keeps linkable transformed identifiers. A hash or synthetic replacement alone does not establish that a retained code meets the re-identification-code conditions of [45 CFR 164.514(c)](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164/subpart-E/section-164.514#p-164.514(c)).

For ZIP codes, Safe Harbor permits three digits only when the combined geographic area exceeds 20,000 people using current publicly available Census data; otherwise it requires `000`. Validate any population reference and update process used by `zip3`. The example prefix list in HHS guidance uses 2000 Census data; it is not a current population reference. Keeping a prefix without that check is insufficient. Ages above 89 and dates that reveal those ages require aggregation into a 90-or-older category. These conditions also apply to identifiers embedded in narratives. See [HHS guidance](https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html).

A year profile can replace each `date_shift` action, including nested pipeline steps, with `generalize_year`; keep DOB's `age_cap` first while separately addressing the required 90-or-older aggregation. This is a policy customization, not a compliance switch. Review dates in unconfigured components, free text, attachments, retained codes, and all other categories before release. [Methodology](methodology.md) describes the scope of those checks.
