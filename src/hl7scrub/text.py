"""Conservative regex and message-token scrubbing for clinical narratives."""
from __future__ import annotations

import re
from typing import Iterable, List, Tuple

from .model import Message, Segment, split_escaped

SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
EMAIL = re.compile(r"(?<![\w.+-])[\w.!#$%&'*+/=?^`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![\w-])")
PHONE = re.compile(r"(?<![\w])(?:\+?1[-. ]?)?(?:\(\d{3}\)|\d{3})[-. ]?\d{3}[-. ]?\d{4}(?:\s*(?:ext\.?|x)\s*\d+)?(?!\d)", re.I)
DATES = re.compile(r"(?<!\w)(?:\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|(?:19|20)\d{6}(?:\d{2}){0,3}(?:\.\d+)?(?:[+-]\d{4})?)(?!\w)")
MONTH_DATES = re.compile(r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?\s+\d{1,2}(?:,?\s+\d{4})?\b", re.I)


def scalar_values(segment: Segment, number: int) -> Iterable[str]:
    """Yield decoded nonempty scalar leaves from one field."""
    d = segment.delimiters
    for rep in segment.field(number).repetitions():
        for comp in split_escaped(rep, d.component, d.escape):
            for sub in split_escaped(comp, d.subcomponent, d.escape):
                value = d.decode(sub)
                if value and value != '""':
                    yield value


def patient_names(message: Message) -> List[str]:
    """Collect PID name components for residual-name matching in other fields."""
    names = []
    for segment in message.find("PID"):
        for number in (5, 6, 9):
            d = segment.delimiters
            for rep in segment.field(number).repetitions():
                comps = split_escaped(rep, d.component, d.escape)
                for comp in comps[:3]:
                    value = d.decode(comp.split(d.subcomponent)[0]).strip()
                    if len(value) >= 2:
                        names.append(value)
    return sorted(set(names), key=lambda x: (-len(x), x.casefold()))


def scrub_text(value: str, tokens: Iterable[str] = ()) -> str:
    """Replace known message PHI plus SSN/phone/email/date patterns with markers.

    Clinical facts outside these patterns are retained. This is deliberately not
    a natural-language entity recognizer and cannot certify anonymous free text.
    """
    patterns = []
    for token in sorted(set(tokens), key=lambda x: (-len(x), x.casefold())):
        if len(token.strip()) >= 2:
            patterns.append(r"(?<!\w)" + re.escape(token) + r"(?!\w)")
    if patterns:
        value = re.sub("|".join(patterns), "[REDACTED]", value, flags=re.I)
    for pattern in (SSN, EMAIL, PHONE, DATES, MONTH_DATES):
        value = pattern.sub("[REDACTED]", value)
    return value


def is_fake_phone(value: str) -> bool:
    """Recognize the reserved exchange emitted by the pseudonym generator."""
    value = re.split(r"(?:ext\.?|[x#])\s*\d+\s*$", value, flags=re.I)[0]
    digits = re.sub(r"\D", "", value)
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    return len(digits) == 10 and digits[3:6] == "555"


def is_fake_email(value: str) -> bool:
    """Recognize RFC 2606 non-deliverable placeholder addresses."""
    return value.casefold().endswith("@example.invalid")


def regex_findings(value: str) -> Iterable[str]:
    """Yield value-free finding categories, excluding recognizable fake formats."""
    for match in SSN.finditer(value):
        if int(match.group(0)[:3]) < 900:
            yield "ssn"
    for match in EMAIL.finditer(value):
        if not is_fake_email(match.group(0)):
            yield "email"
    for match in PHONE.finditer(value):
        if not is_fake_phone(match.group(0)):
            yield "phone"
