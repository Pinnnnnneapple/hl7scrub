"""Value-free heuristic residual-PHI scanning for HL7 test fixtures."""
from __future__ import annotations

import re
from typing import Dict, List, Union

from .model import Document, Message, parse
from .policy import default_policy
from .text import patient_names, regex_findings, scalar_values


def scan(data: Union[str, bytes, Document]) -> List[Dict[str, Union[int, str]]]:
    """Flag SSNs, phones, emails and PID names repeated elsewhere in a message.

    Findings identify positions and categories without including matched values.
    Reserved fake formats (900+ SSN areas, 555 telephone exchange, and
    example.invalid email addresses) are ignored. Absence is not proof of safety.
    """
    document = data if isinstance(data, Document) else parse(data)
    findings: List[Dict[str, Union[int, str]]] = []
    rules = default_policy()["fields"]
    owned = {id(s) for message in document for s in message.segments}
    orphans = [s for s in document.segments if id(s) not in owned and s.name not in ("FHS", "BHS", "BTS", "FTS")]
    scopes = list(enumerate(document, 1))
    if orphans:
        scopes.append((0, Message(orphans)))
    all_names = [n for message in document for n in patient_names(message)]
    for message_index, message in scopes:
        names = patient_names(message) if message_index else all_names
        for segment_index, segment in enumerate(message.segments, 1):
            for number in range(1, len(segment.fields) + 1):
                if segment.name == "MSH" and number <= 2:
                    continue
                categories = set()
                rule = rules.get(segment.name + "-" + str(number), {})
                name_field = rule.get("kind") == "person_name"
                identifier_field = rule.get("kind") in ("mrn", "account") or rule.get("action") == "hash"
                for value in scalar_values(segment, number):
                    kinds = set(regex_findings(value))
                    # A ten-digit XCN identifier is not an unformatted phone.
                    if (name_field or identifier_field) and value.isdecimal():
                        kinds.discard("phone")
                    categories.update(kinds)
                    if name_field or (segment.name == "PID" and number in (5, 6, 9)):
                        continue
                    if any(re.search(r"(?<!\w)" + re.escape(n) + r"(?!\w)", value, re.I) for n in names):
                        categories.add("patient_name")
                for category in sorted(categories):
                    findings.append({"message": message_index, "segment": segment_index,
                                     "path": segment.name + "-" + str(number), "category": category})
    return findings
