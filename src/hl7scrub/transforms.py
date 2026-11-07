"""Deterministic keyed substitutions for individual HL7 field values.

These helpers implement synthetic substitutions, not a de-identification guarantee.
Date shifting retains date detail and is not Safe Harbor date generalization.
``age_cap`` is a configurable synthetic DOB cap evaluated against ``reference_date``;
it is not the Safe Harbor aggregation of ages over 89 into the category ``90+``.
A custom policy may instead apply ``generalize_year`` to dates and ``zip3`` to ZIPs;
policy selection and validation belong to the caller.
"""

from __future__ import annotations

import base64
import calendar
import hashlib
import hmac
import json
import re
from datetime import date, timedelta
from functools import lru_cache
from importlib.resources import files
from typing import Any, Iterator, Optional, Tuple

__all__ = ["Transformer"]


def _normalize(value: str) -> str:
    """Collapse Unicode whitespace and case-fold a value for keyed lookup."""
    return " ".join(value.split()).casefold()


@lru_cache(maxsize=None)
def _data(filename: str) -> Any:
    """Read an installed UTF-8 data resource once."""
    return json.loads(files("hl7scrub").joinpath("data").joinpath(filename).read_text(encoding="utf-8"))


def _style(replacement: str, original: str) -> str:
    """Retain uppercase, lowercase, or title-case spelling."""
    if original.isupper():
        return replacement.upper()
    if original.islower():
        return replacement.lower()
    return replacement.title()


def _parse_ts(value: str) -> Optional[Tuple[date, str, str]]:
    """Validate an HL7 TS; anchor missing months/days to January/one."""
    match = re.fullmatch(r"([0-9]{4}(?:[0-9]{2}){0,5})(\.[0-9]+)?([+-][0-9]{4})?", value)
    if match is None:
        return None
    core, fraction, zone = match.groups()
    if fraction and len(core) != 14:
        return None
    if zone and (int(zone[1:3]) > 23 or int(zone[3:5]) > 59):
        return None
    try:
        parsed = date(int(core[:4]), int(core[4:6]) if len(core) >= 6 else 1,
                      int(core[6:8]) if len(core) >= 8 else 1)
    except ValueError:
        return None
    if len(core) >= 10 and int(core[8:10]) > 23:
        return None
    if len(core) >= 12 and int(core[10:12]) > 59:
        return None
    if len(core) >= 14 and int(core[12:14]) > 59:
        return None
    return parsed, core, (fraction or "") + (zone or "")


def _render_date(parsed: date, core: str, suffix: str) -> str:
    """Replace only the available date digits, retaining time and zone."""
    digits = f"{parsed.year:04d}{parsed.month:02d}{parsed.day:02d}"
    return digits[:min(len(core), 8)] + core[8:] + suffix


def _birthday(year: int, month: int, day: int) -> date:
    """Treat a February 29 anniversary as February 28 in common years."""
    return date(year, month, min(day, calendar.monthrange(year, month)[1]))


def _npi_check(body: str) -> str:
    """Compute the Luhn digit including the NPI's 80840 prefix."""
    total = 0
    for index, char in enumerate(reversed("80840" + body), 1):
        digit = int(char) * (2 if index % 2 else 1)
        total += digit // 10 + digit % 10
    return str((-total) % 10)


class Transformer:
    """Apply stable, domain-separated pseudonyms using a caller-held secret.

    ``date_shift_days`` is the inclusive symmetric shift bound. ``reference_date``
    defaults to today's local date, captured at construction for reproducible age
    calculations within this instance. Supply it explicitly for repeatable runs.
    """

    def __init__(self, key: bytes, date_shift_days: int = 30,
                 reference_date: Optional[date] = None) -> None:
        """Validate the secret, integral shift window, and optional age reference."""
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")
        if not key:
            raise ValueError("key must not be empty")
        if not isinstance(date_shift_days, int) or isinstance(date_shift_days, bool):
            raise TypeError("date_shift_days must be an integer")
        if date_shift_days < 0:
            raise ValueError("date_shift_days must be nonnegative")
        if reference_date is not None and type(reference_date) is not date:
            raise TypeError("reference_date must be a date")
        self._key = key
        self.date_shift_days = date_shift_days
        self.reference_date = reference_date if reference_date is not None else date.today()

    def digest(self, kind: str, value: str) -> bytes:
        """Return HMAC-SHA256 of kind, NUL, and whitespace/case-normalized value."""
        message = (kind + "\0" + _normalize(value)).encode("utf-8", "surrogateescape")
        return hmac.new(self._key, message, hashlib.sha256).digest()

    def _bytes(self, kind: str, value: str) -> Iterator[int]:
        """Expand a domain-separated digest into deterministic random bytes."""
        seed = self.digest(kind, value)
        yield from seed
        counter = 1
        while True:
            yield from hmac.new(self._key, seed + counter.to_bytes(8, "big"), hashlib.sha256).digest()
            counter += 1

    def hash(self, value: str, length: int = 16) -> str:
        """Return a positive-length uppercase base32 token without padding."""
        if not isinstance(length, int) or isinstance(length, bool):
            raise TypeError("length must be an integer")
        if not 1 <= length <= 52:
            raise ValueError("length must be from 1 to 52 for SHA-256 base32")
        return base64.b32encode(self.digest("hash", value)).decode("ascii").rstrip("=")[:length]

    def _token(self, kind: str, value: str) -> str:
        """Return a compact token from the requested pseudonym domain."""
        return base64.b32encode(self.digest(kind, value)).decode("ascii").rstrip("=")[:16]

    def _choice(self, kind: str, value: str, filename: str) -> str:
        """Select a pool entry, avoiding an unchanged normalized value."""
        choices = _data(filename)
        index = int.from_bytes(self.digest(kind, value), "big") % len(choices)
        result = choices[index]
        if _normalize(result) == _normalize(value):
            result = choices[(index + 1) % len(choices)]
        return _style(result, value)

    def _pattern(self, kind: str, value: str) -> str:
        """Substitute letters/digits while retaining length, case and punctuation."""
        stream = self._bytes(kind, value)
        result = []
        for char in value:
            if char.isdecimal():
                result.append(str(next(stream) % 10))
            elif char.isalpha():
                base = ord("A" if char.isupper() else "a")
                result.append(chr(base + next(stream) % 26))
            else:
                result.append(char)
        output = "".join(result)
        if _normalize(output) == _normalize(value):
            for index, char in enumerate(result):
                if char.isdecimal():
                    result[index] = str((int(char) + 1) % 10)
                    break
                if char.isalpha():
                    base = ord("A" if char.isupper() else "a")
                    result[index] = chr(base + (ord(char) - base + 1) % 26)
                    break
            output = "".join(result)
        return output

    def _phone(self, value: str) -> str:
        """Keep formatting, using US fictional 555-01xx numbers when recognizable."""
        stream = self._bytes("phone", value)
        result = [str(next(stream) % 10) if char in "0123456789" else char for char in value]
        extension = re.search(r"(?:ext\.?|[x#])\s*[0-9]+\s*$", value, re.IGNORECASE)
        end = extension.start() if extension else len(value)
        positions = [i for i, char in enumerate(value[:end]) if char in "0123456789"]
        digits = "".join(value[i] for i in positions)
        prefix_length = None
        if len(digits) == 10 and not value.lstrip().startswith("+"):
            prefix_length = 0
        for prefix in ("1", "001", "0111"):
            if len(digits) == len(prefix) + 10 and digits.startswith(prefix):
                prefix_length = len(prefix)
                break
        if prefix_length is not None:
            for position in positions[:prefix_length]:
                result[position] = value[position]
            national = positions[prefix_length:]
            result[national[0]] = str(2 + int(result[national[0]]) % 8)
            for position, char in zip(national[3:8], "55501"):
                result[position] = char
            if "".join(result) == value:
                result[national[-1]] = str((int(result[national[-1]]) + 1) % 10)
        if "".join(result) == value:
            all_positions = [i for i, char in enumerate(value) if char in "0123456789"]
            if all_positions:
                last = all_positions[-1]
                result[last] = str((int(result[last]) + 1) % 10)
        return "".join(result)

    def pseudonym(self, kind: str, value: str) -> str:
        """Substitute a supported semantic kind; leave blank values unchanged.

        Supported kinds: person_name, given_name, family_name, mrn, account, ssn,
        phone, email, street, city, zip, free_text, provider_id. Scalar person names
        use given-name tokens followed by a family-name token; the engine handles
        HL7 composite components. Names retain upper/lower/title style.
        """
        supported = {"person_name", "given_name", "family_name", "mrn", "account",
                     "ssn", "phone", "email", "street", "city", "zip", "free_text", "provider_id"}
        if kind not in supported:
            raise ValueError(f"unsupported pseudonym kind: {kind}")
        if not value.strip():
            return value
        pools = {"given_name": "given_names.json", "family_name": "family_names.json",
                 "street": "streets.json", "city": "cities.json"}
        if kind in pools:
            return self._choice(kind, value, pools[kind])
        if kind == "person_name":
            parts = re.split(r"(\s+)", value)
            indices = [i for i, part in enumerate(parts) if part and not part.isspace()]
            for index in indices:
                name_kind = "family_name" if len(indices) > 1 and index == indices[-1] else "given_name"
                parts[index] = self.pseudonym(name_kind, parts[index])
            return "".join(parts)
        if kind in {"mrn", "account"}:
            return self._pattern(kind, value)
        if kind == "phone":
            return self._phone(value)
        if kind == "email":
            return self._token(kind, value).lower() + "@example.invalid"
        if kind == "free_text":
            return "REDACTED-" + self._token(kind, value)
        if kind == "provider_id":
            stream = self._bytes(kind, value)
            body = "2" + "".join(str(next(stream) % 10) for _ in range(8))
            output = body + _npi_check(body)
            if output == value:
                body = body[:-1] + str((int(body[-1]) + 1) % 10)
                output = body + _npi_check(body)
            return output
        if kind == "zip":
            stream = self._bytes(kind, value)
            output = "000" + "".join(str(next(stream) % 10) for _ in range(2))
            if output == value:
                output = output[:-1] + str((int(output[-1]) + 1) % 10)
            return output
        # SSN: preserve punctuation and ensure an invalid 900--999 area for nine digits.
        result = list(self._pattern(kind, value))
        positions = [i for i, char in enumerate(value) if char in "0123456789"]
        if len(positions) == 9:
            result[positions[0]] = "9"
            if "".join(result) == value:
                result[positions[-1]] = str((int(result[positions[-1]]) + 1) % 10)
        return "".join(result)

    def patient_offset(self, patient_key: str) -> int:
        """Return one stable integer day offset within the inclusive shift window."""
        return int.from_bytes(self.digest("date_shift", patient_key), "big") % (2 * self.date_shift_days + 1) - self.date_shift_days

    def shift_date(self, value: str, patient_key: str) -> str:
        """Shift a valid HL7 TS, preserving precision and the time/fraction/zone.

        Missing months/days are anchored to January/one before shifting. Invalid
        values or shifts outside years 0001--9999 are returned unchanged.
        """
        parsed = _parse_ts(value)
        if parsed is None:
            return value
        day, core, suffix = parsed
        try:
            shifted = day + timedelta(days=self.patient_offset(patient_key))
        except (OverflowError, ValueError):
            return value
        return _render_date(shifted, core, suffix)

    def age_cap(self, value: str, cap: int = 89) -> str:
        """Set DOBs with completed age above cap to that age at reference_date.

        This is a synthetic DOB cap, not the Safe Harbor ``90+`` age category.
        Missing month/day components use January/one; February 29 birthdays use
        February 28 in common years. Retain timestamp precision and time suffix.
        Invalid dates and DOBs already at or below the cap are returned unchanged.
        """
        if not isinstance(cap, int) or isinstance(cap, bool):
            raise TypeError("cap must be an integer")
        if cap < 0:
            raise ValueError("cap must be nonnegative")
        parsed = _parse_ts(value)
        if parsed is None:
            return value
        born, core, suffix = parsed
        today = self.reference_date
        anniversary = _birthday(today.year, born.month, born.day)
        age = today.year - born.year - (today < anniversary)
        if age <= cap:
            return value
        year = today.year - cap
        adjusted = _birthday(year, born.month, born.day)
        if today < _birthday(today.year, adjusted.month, adjusted.day):
            adjusted = _birthday(year - 1, born.month, born.day)
            anniversary = _birthday(today.year, adjusted.month, adjusted.day)
            if today.year - adjusted.year - (today < anniversary) > cap:
                # A leap-day DOB can become February 28 in the previous year,
                # moving its anniversary across today's date. Keep the exact cap.
                adjusted = date(year, 2, 28)
        return _render_date(adjusted, core, suffix)

    def zip3(self, value: str) -> str:
        """Return the first three ZIP digits, or 000 for restricted prefixes.

        Accept three/five digits or ZIP+4 (with or without its hyphen); malformed
        input is unchanged. Uses the bundled historical HHS restricted-prefix list.
        """
        if re.fullmatch(r"(?:[0-9]{3}|[0-9]{5}(?:-?[0-9]{4})?)", value) is None:
            return value
        prefix = value[:3]
        restricted = _data("zip3_restricted.json")["restricted_prefixes"]
        return "000" if prefix in restricted else prefix

    def generalize_year(self, value: str) -> str:
        """Return only the year of a valid HL7 TS; preserve malformed input."""
        return value[:4] if _parse_ts(value) is not None else value
