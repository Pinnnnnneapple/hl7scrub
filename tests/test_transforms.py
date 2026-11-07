"""Contract tests for deterministic substitutions and HL7 timestamp handling."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import unittest
from datetime import date, timedelta
from importlib.resources import files

from hl7scrub.transforms import Transformer


class TransformerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.transformer = Transformer(b"test-secret", reference_date=date(2025, 6, 15))

    def test_constructor_validation(self) -> None:
        with self.assertRaises(ValueError):
            Transformer(b"")
        for key in ("text", None, bytearray(b"secret")):
            with self.subTest(key=key), self.assertRaises(TypeError):
                Transformer(key)
        with self.assertRaises(ValueError):
            Transformer(b"secret", date_shift_days=-1)
        for window in (True, 1.5, "30"):
            with self.subTest(window=window), self.assertRaises(TypeError):
                Transformer(b"secret", date_shift_days=window)
        with self.assertRaises(TypeError):
            Transformer(b"secret", reference_date="20250101")
        self.assertIsInstance(Transformer(b"secret").reference_date, date)

    def test_digest_exact_contract_and_normalization(self) -> None:
        expected = hmac.new(b"test-secret", b"mrn\0alice smith", hashlib.sha256).digest()
        self.assertEqual(self.transformer.digest("mrn", "  ALICE\tSmith\n"), expected)
        self.assertEqual(self.transformer.digest("mrn", "Straße"), self.transformer.digest("mrn", "STRASSE"))
        self.assertNotEqual(expected, self.transformer.digest("account", "Alice Smith"))
        self.assertNotEqual(expected, Transformer(b"different").digest("mrn", "Alice Smith"))
        self.assertEqual(self.transformer.digest("mrn", "Alice\u2003Smith"), expected)

    def test_digest_reversible_invalid_utf8(self) -> None:
        value = b"Person-\xff\x80".decode("utf-8", "surrogateescape")
        expected = hmac.new(b"test-secret", b"mrn\0person-\xff\x80", hashlib.sha256).digest()
        self.assertEqual(self.transformer.digest("mrn", value), expected)
        self.assertRegex(self.transformer.hash(value), r"^[A-Z2-7]{16}$")
        self.assertTrue(self.transformer.pseudonym("email", value).endswith("@example.invalid"))

    def test_hash_base32_and_lengths(self) -> None:
        expected = base64.b32encode(self.transformer.digest("hash", "a")).decode().rstrip("=")
        self.assertEqual(self.transformer.hash("a"), expected[:16])
        self.assertEqual(self.transformer.hash("a", 52), expected)
        for length in (1, 16, 32, 52):
            with self.subTest(length=length):
                token = self.transformer.hash("a", length)
                self.assertEqual(len(token), length)
                self.assertRegex(token, r"^[A-Z2-7]+$")
                self.assertEqual(token, self.transformer.hash(" A ", length))
        for length in (0, -1, 53, 100, 257):
            with self.assertRaises(ValueError):
                self.transformer.hash("a", length)
        for length in (True, 2.5, "3"):
            with self.assertRaises(TypeError):
                self.transformer.hash("a", length)

    def test_every_pseudonym_kind_is_deterministic(self) -> None:
        examples = {
            "person_name": "Alice Mary Smith", "given_name": "Alice", "family_name": "Smith",
            "mrn": "Ab-123:xy", "account": "ACC/123456", "ssn": "123-45-6789",
            "phone": "+1 (212) 123-4567", "email": "person@hospital.example",
            "street": "123 Main Street", "city": "Chicago", "zip": "60601",
            "free_text": "A private clinical narrative.", "provider_id": "1234567893",
        }
        second = Transformer(b"test-secret", reference_date=date(2025, 6, 15))
        for kind, value in examples.items():
            with self.subTest(kind=kind):
                result = self.transformer.pseudonym(kind, value)
                self.assertNotEqual(result, value)
                self.assertEqual(result, second.pseudonym(kind, value))
                self.assertEqual(self.transformer.pseudonym(kind, ""), "")
                self.assertEqual(self.transformer.pseudonym(kind, " \t"), " \t")
        with self.assertRaises(ValueError):
            self.transformer.pseudonym("provider", "1234")
        with self.assertRaises(ValueError):
            self.transformer.pseudonym("unknown", "")

    def test_names_preserve_case_and_components(self) -> None:
        for kind in ("given_name", "family_name", "person_name"):
            for source, case_check in (("ALICE SMITH", str.isupper), ("alice smith", str.islower), ("Alice Smith", str.istitle)):
                with self.subTest(kind=kind, source=source):
                    self.assertTrue(case_check(self.transformer.pseudonym(kind, source)))
        full = self.transformer.pseudonym("person_name", "Alice Mary Smith")
        expected = " ".join((self.transformer.pseudonym("given_name", "Alice"),
                             self.transformer.pseudonym("given_name", "Mary"),
                             self.transformer.pseudonym("family_name", "Smith")))
        self.assertEqual(full, expected)
        self.assertEqual(self.transformer.pseudonym("person_name", "Alice"), self.transformer.pseudonym("given_name", "Alice"))
        self.assertEqual(len(self.transformer.pseudonym("person_name", " Alice  Smith ").split()), 2)

    def test_identifiers_preserve_character_classes_and_long_lengths(self) -> None:
        for kind in ("mrn", "account"):
            for value in ("A1-b2/C3_456.7", "000000000", "abcXYZ", "Z", "5", "-/:", "Ab9-" * 200):
                with self.subTest(kind=kind, value=value[:20]):
                    result = self.transformer.pseudonym(kind, value)
                    self.assertEqual(len(result), len(value))
                    for original, replacement in zip(value, result):
                        if original.isdigit():
                            self.assertTrue(replacement.isdigit())
                        elif original.isupper():
                            self.assertTrue(replacement.isupper())
                        elif original.islower():
                            self.assertTrue(replacement.islower())
                        else:
                            self.assertEqual(original, replacement)
                    if any(c.isalnum() for c in value):
                        self.assertNotEqual(result.casefold(), value.casefold())
        self.assertNotEqual(self.transformer.pseudonym("mrn", "123456789"), self.transformer.pseudonym("account", "123456789"))

    def test_ssn_uses_invalid_area_and_retains_format(self) -> None:
        for value in ("123456789", "123-45-6789", "123 45 6789", "999-99-9999"):
            with self.subTest(value=value):
                result = self.transformer.pseudonym("ssn", value)
                digits = re.sub(r"[^0-9]", "", result)
                self.assertEqual(len(digits), 9)
                self.assertTrue(900 <= int(digits[:3]) <= 999)
                self.assertEqual(len(result), len(value))
                self.assertEqual(re.sub(r"[0-9]", "", result), re.sub(r"[0-9]", "", value))
                self.assertNotEqual(result, value)

    def test_phone_formats_prefixes_and_extensions(self) -> None:
        examples = (("2121234567", 0), ("(212) 123-4567", 0),
                    ("1-212-123-4567", 1), ("+1 (212) 123-4567", 1),
                    ("001-212-123-4567", 3), ("0111 212 123 4567", 4),
                    ("+1 (212) 123-4567 ext. 1234", 1),
                    ("2121234567x1234", 0), ("212-123-4567 #1234", 0))
        for value, prefix_len in examples:
            with self.subTest(value=value):
                result = self.transformer.pseudonym("phone", value)
                digits = re.sub(r"[^0-9]", "", result)
                original_digits = re.sub(r"[^0-9]", "", value)
                self.assertEqual(digits[:prefix_len], original_digits[:prefix_len])
                self.assertEqual(digits[prefix_len + 3:prefix_len + 6], "555")
                self.assertEqual(digits[prefix_len + 6:prefix_len + 8], "01")
                self.assertEqual(re.sub(r"[0-9]", "", result), re.sub(r"[0-9]", "", value))
                self.assertEqual(len(value), len(result))
        for value in ("12345", "+44 20 7123 4567", "+33 1 23 45 67 89"):
            result = self.transformer.pseudonym("phone", value)
            self.assertEqual(re.sub(r"[0-9]", "", result), re.sub(r"[0-9]", "", value))
            self.assertNotEqual(result, value)

    def test_email_zip_and_free_text(self) -> None:
        for value in ("A@REAL.COM", "Malformed private text"):
            self.assertRegex(self.transformer.pseudonym("email", value), r"^[a-z2-7]{16}@example\.invalid$")
        self.assertEqual(self.transformer.pseudonym("email", " ALICE@REAL.COM "), self.transformer.pseudonym("email", "alice@real.com"))
        self.assertRegex(self.transformer.pseudonym("zip", "12345-6789"), r"^000[0-9]{2}$")
        redacted = self.transformer.pseudonym("free_text", "Alice's confidential narrative")
        self.assertRegex(redacted, r"^REDACTED-[A-Z2-7]{16}$")
        self.assertNotIn("Alice", redacted)

    def test_provider_id_has_npi_luhn_digit(self) -> None:
        for value in ("1234567893", "hospital/provider-a", "1234567893 " * 5):
            output = self.transformer.pseudonym("provider_id", value)
            self.assertRegex(output, r"^[12][0-9]{9}$")
            full = "80840" + output
            total = 0
            for index, char in enumerate(reversed(full)):
                digit = int(char)
                if index % 2:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                total += digit
            self.assertEqual(total % 10, 0)
        self.assertEqual(self.transformer.pseudonym("provider_id", " ID 001 "), self.transformer.pseudonym("provider_id", "id 001"))

    def test_no_unchanged_output_when_a_key_collides(self) -> None:
        # Across tiny domains a raw keyed substitution can coincide with its input.
        for number in range(100):
            transformer = Transformer(str(number).encode())
            for value in ("0", "A", "a"):
                self.assertNotEqual(transformer.pseudonym("mrn", value), value)

    def test_patient_offset_bounds_normalization_and_zero_window(self) -> None:
        offsets = {self.transformer.patient_offset(str(i)) for i in range(300)}
        self.assertGreater(len(offsets), 20)
        self.assertGreater(max(offsets), 0)
        self.assertLess(min(offsets), 0)
        self.assertTrue(all(-30 <= offset <= 30 for offset in offsets))
        self.assertEqual(self.transformer.patient_offset(" PATIENT  ONE "), self.transformer.patient_offset("patient one"))
        zero = Transformer(b"secret", date_shift_days=0)
        self.assertEqual(zero.patient_offset("patient"), 0)
        self.assertEqual(zero.shift_date("20240229123456.1234-0500", "patient"), "20240229123456.1234-0500")

    def test_shift_date_all_precisions_and_zones(self) -> None:
        formats = ("2024", "202402", "20240229", "2024022912", "202402291234", "20240229123456",
                   "20240229123456.1234", "20240229123456.123456+0530",
                   "20240229123456-0500", "2024022912+0100", "2024-0500", "202402+0000")
        offset = self.transformer.patient_offset("patient-a")
        for value in formats:
            with self.subTest(value=value):
                core = re.match(r"[0-9]+", value).group()
                day = date(int(core[:4]), int(core[4:6]) if len(core) >= 6 else 1,
                           int(core[6:8]) if len(core) >= 8 else 1)
                shifted = day + timedelta(days=offset)
                expected_date = f"{shifted.year:04d}{shifted.month:02d}{shifted.day:02d}"[:min(len(core), 8)]
                result = self.transformer.shift_date(value, "patient-a")
                self.assertEqual(result, expected_date + value[min(len(core), 8):])
                self.assertEqual(len(result), len(value))

    def test_shift_uses_one_offset_across_calendar_boundaries(self) -> None:
        for patient in ("alpha", "beta", "gamma", "delta"):
            for day in (date(2023, 12, 31), date(2024, 2, 28), date(2024, 2, 29), date(2024, 3, 1)):
                value = day.strftime("%Y%m%d")
                result = self.transformer.shift_date(value, patient)
                shifted = date(int(result[:4]), int(result[4:6]), int(result[6:8]))
                self.assertEqual((shifted - day).days, self.transformer.patient_offset(patient))
        for edge in ("00010101", "99991231"):
            result = self.transformer.shift_date(edge, "alpha")
            date(int(result[:4]), int(result[4:6]), int(result[6:8]))

    def test_invalid_dates_are_unchanged_everywhere(self) -> None:
        malformed = ("", " ", "202", "20241", "202413", "202400", "0000", "00000101", "20230229",
                     "19000229", "20240431", "20240100", "2024010124", "202401011260",
                     "20240101123460", "202401011234561", "202401011234.12", "20240101123456.",
                     "20240101+2460", "20240101123456Z", "2024-01-01", "20240101junk", "20240101\n")
        for value in malformed:
            with self.subTest(value=value):
                self.assertEqual(self.transformer.shift_date(value, "patient"), value)
                self.assertEqual(self.transformer.age_cap(value), value)
                self.assertEqual(self.transformer.generalize_year(value), value)

    def test_age_cap_exact_completed_age_boundary(self) -> None:
        self.assertEqual(self.transformer.age_cap("19350616"), "19350616")  # Still 89.
        self.assertEqual(self.transformer.age_cap("19350615"), "19360615")  # Turns 90 today.
        self.assertEqual(self.transformer.age_cap("19360615"), "19360615")  # Exactly 89.
        self.assertEqual(self.transformer.age_cap("19360616"), "19360616")  # Still 88.
        self.assertEqual(self.transformer.age_cap("19001231"), "19351231")  # Preserve birthday; age 89.
        self.assertEqual(self.transformer.age_cap("19000101"), "19360101")
        self.assertEqual(self.transformer.age_cap("20300101"), "20300101")

    def test_age_cap_preserves_precision_and_time(self) -> None:
        values = ("1900", "190001", "19000101", "1900010112", "190001011234", "19000101123456",
                  "19000101123456.9876+0530")
        for value in values:
            with self.subTest(value=value):
                result = self.transformer.age_cap(value)
                self.assertEqual(result, "1936" + value[4:])
                self.assertEqual(len(result), len(value))
        self.assertEqual(self.transformer.age_cap("19500101", cap=65), "19600101")
        self.assertEqual(self.transformer.age_cap("20240101", cap=0), "20250101")
        with self.assertRaises(ValueError):
            self.transformer.age_cap("19000101", cap=-1)
        with self.assertRaises(TypeError):
            self.transformer.age_cap("19000101", cap=True)

    def test_age_cap_leap_birthdays_are_valid_and_exact(self) -> None:
        for reference in (date(2024, 2, 28), date(2024, 2, 29), date(2025, 2, 27), date(2025, 2, 28), date(2025, 3, 1)):
            transformer = Transformer(b"secret", reference_date=reference)
            for original in ("19040229", "19000228", "19000301"):
                result = transformer.age_cap(original)
                born = date(int(result[:4]), int(result[4:6]), int(result[6:8]))
                try:
                    birthday = born.replace(year=reference.year)
                except ValueError:
                    birthday = date(reference.year, 2, 28)
                age = reference.year - born.year - (reference < birthday)
                self.assertEqual(age, 89, (reference, original, result))
        self.assertEqual(Transformer(b"s", reference_date=date(2025, 2, 28)).age_cap("19360229"), "19360229")
        leap_reference = Transformer(b"s", reference_date=date(2024, 2, 28))
        self.assertEqual(leap_reference.age_cap("19040229", cap=88), "19360228")
        self.assertEqual(leap_reference.age_cap("19040229", cap=0), "20240228")

    def test_reference_date_makes_age_cap_reproducible(self) -> None:
        early = Transformer(b"s", reference_date=date(2024, 6, 15))
        late = Transformer(b"s", reference_date=date(2025, 6, 15))
        self.assertEqual(early.age_cap("19350615"), "19350615")
        self.assertEqual(late.age_cap("19350615"), "19360615")

    def test_generalize_year(self) -> None:
        for value in ("2024", "202402", "20240229", "2024022912", "202402291234", "20240229123456.123-0500"):
            with self.subTest(value=value):
                self.assertEqual(self.transformer.generalize_year(value), "2024")
        self.assertEqual(self.transformer.generalize_year("20000229"), "2000")

    def test_zip3_restrictions_and_valid_formats(self) -> None:
        restricted = "036 059 063 102 203 556 692 790 821 823 830 831 878 879 884 890 893".split()
        for prefix in restricted:
            for value in (prefix, prefix + "12", prefix + "12-3456", prefix + "123456"):
                with self.subTest(value=value):
                    self.assertEqual(self.transformer.zip3(value), "000")
        for source, expected in (("02139", "021"), ("10001-1234", "100"), ("606011234", "606"), ("012", "012")):
            self.assertEqual(self.transformer.zip3(source), expected)
        for invalid in ("", "1234", "123456", "ABCDE", "12345-12", " 02139", "02139\n"):
            self.assertEqual(self.transformer.zip3(invalid), invalid)

    def test_packaged_pools_and_restriction_citation(self) -> None:
        root = files("hl7scrub").joinpath("data")
        for filename, minimum in (("given_names.json", 200), ("family_names.json", 200), ("streets.json", 100), ("cities.json", 60)):
            with self.subTest(filename=filename):
                values = json.loads(root.joinpath(filename).read_text(encoding="utf-8"))
                self.assertGreaterEqual(len(values), minimum)
                self.assertEqual(len(values), len(set(values)))
                self.assertTrue(all(isinstance(item, str) and item.strip() for item in values))
        restricted = json.loads(root.joinpath("zip3_restricted.json").read_text(encoding="utf-8"))
        self.assertEqual(len(restricted["restricted_prefixes"]), 17)
        self.assertIn("hhs.gov", restricted["source"]["url"])
        self.assertIn("Historical", restricted["description"])


if __name__ == "__main__":
    unittest.main()
