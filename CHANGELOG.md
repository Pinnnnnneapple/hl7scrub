# Changelog

## Unreleased

- Require Python 3.10+ and test on Python 3.10–3.14; normalize text checkouts
  to LF for consistent example outputs across platforms.

## 0.1.0 — 2026-11-07

- Added a lossless HL7 v2 model with declared delimiters, repetitions, components,
  escape handling, batch wrappers, multiple messages and MLLP transport.
- Added deterministic HMAC pseudonyms, format preservation, patient-specific date
  shifts, age capping, ZIP3 and year generalization with a configurable JSON policy.
- Added provider/contact/address handling, narrative token and regex scrubbing,
  opaque OBX removal, Z-segment redaction and aggregate auditing.
- Added scrub, show, diff, policy and residual scan commands with CI-friendly exits.
- Added synthetic message sequences, generated scrubbed outputs, policy and Safe
  Harbor documentation, packaging, tests and a cross-platform Python CI matrix.
