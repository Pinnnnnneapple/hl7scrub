"""Policy-driven, deterministic HL7 v2 pseudonymisation."""
from __future__ import annotations

import copy
import re
from collections import Counter
from datetime import date
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote

from .model import Document, Field, Message, Path, Segment, parse, split_escaped
from .policy import default_policy, _validate
from .text import patient_names, scalar_values, scrub_text
from .transforms import Transformer, _parse_ts


class AuditReport:
    """Accumulate aggregate metadata; never retain original or replacement values."""

    def __init__(self) -> None:
        self.messages = 0
        self.fields: Counter = Counter()
        self.segments: Counter = Counter()
        self.unknown_segments: Counter = Counter()
        self.warnings: List[str] = []

    def warn(self, text: str) -> None:
        """Add a library-generated warning, without message values or file names."""
        if text not in self.warnings:
            self.warnings.append(text)

    def record(self, path: str, action: str) -> None:
        """Record one action application to one nonempty field/repetition."""
        self.fields[(path, action)] += 1

    def to_dict(self) -> Dict[str, Any]:
        """Return a stable, JSON-ready report containing metadata only."""
        fields: Dict[str, Dict[str, int]] = {}
        for (path, action), count in sorted(self.fields.items()):
            fields.setdefault(path, {})[action] = count
        return {"version": 1, "messages": self.messages, "fields": fields,
                "segments_seen": dict(sorted(self.segments.items())),
                "unknown_z_segments": dict(sorted(self.unknown_segments.items())),
                "warnings": list(self.warnings)}


def _identity_scalar(value: str) -> str:
    return quote(" ".join(value.split()).casefold(), safe="", encoding="utf-8", errors="surrogateescape")


def _canonical(raw: str, segment: Segment) -> str:
    """Normalize structural characters before identity hashing across encodings."""
    d = segment.delimiters
    return "^".join("&".join(_identity_scalar(d.decode(sub))
                             for sub in split_escaped(comp, d.subcomponent, d.escape))
                    for comp in split_escaped(raw, d.component, d.escape))


def patient_identity(message: Message) -> str:
    """Resolve first PID-3 identifier with authority, then name plus birth date.

    Authorities participate in the identity key so different hospitals' identical
    local identifiers do not automatically merge. Encoding delimiters themselves
    do not change identity. Identifier changes need upstream reconciliation.
    """
    for pid in message.find("PID"):
        f = pid.field(3)
        for index in range(1, len(f.repetitions()) + 1):
            identifier = f.get(index, 1)
            authority = f.get(index, 4, decoded=False)
            if identifier and identifier != '""' and authority and authority != '""':
                return "pid3:" + _identity_scalar(identifier) + "|" + _canonical(authority, pid)
    patients = message.find("PID")
    if not patients:
        return "fallback:|"
    pid = patients[0]
    name = _canonical(pid.field(5).get(decoded=False), pid)
    birth = _canonical(pid.field(7).get(decoded=False), pid)
    return "fallback:" + name + "|" + birth


# Compound data types require semantic transforms: don't turn a name's type
# code or a telephone's country/area components into random identifiers.
_ADDRESS_FIELDS = {"PID": {11}, "NK1": {4, 32}, "GT1": {5}, "IN1": {5, 19}, "IN2": {4}}
_PROVIDER_FIELDS = {"EVN": {5}, "PD1": {4}, "PV1": {7, 8, 9, 17, 52},
                    "ORC": {10, 11, 12, 19}, "OBR": {10, 16, 28, 32, 33, 34, 35},
                    "AIP": {3}, "TXA": {9, 10, 22}, "SCH": {12, 16, 20, 24}}
# The identifier portion is transformed; authority/type metadata is redacted
# when it contains identifying local institution text.
_ID_FIELDS = {"PID": {2, 3, 4, 18, 21}, "PV1": {19, 50}, "IN1": {36, 49},
              "GT1": {2, 19}, "ORC": {2, 3, 4}, "OBR": {2, 3}, "TXA": {12, 13, 14, 15}, "SCH": {1, 2}, "FT1": {2, 23}}


class Scrubber:
    """Apply a policy in place, sharing one secret across messages and files."""

    def __init__(self, key: Union[str, bytes], policy: Optional[dict] = None,
                 date_shift_days: int = 30, reference_date: Optional[date] = None) -> None:
        self.transformer = Transformer(key.encode("utf-8") if isinstance(key, str) else key,
                                       date_shift_days=date_shift_days, reference_date=reference_date)
        self.policy = _validate(copy.deepcopy(policy if policy is not None else default_policy()))
        self.report = AuditReport()
        self._rules = [(Path.parse(p), p, rule) for p, rule in self.policy["fields"].items()]
        # Parent rules run before component/subcomponent and repetition overrides.
        self._rules.sort(key=lambda item: (item[0].component is not None,
                                          item[0].subcomponent is not None,
                                          item[0].occurrence not in (None, "*"),
                                          item[0].repetition not in (None, "*")))

    def scrub(self, data: Union[str, bytes, Document]) -> Document:
        """Transform all messages and wrappers, preserving their wire structure."""
        document = data if isinstance(data, Document) else parse(data)
        for warning in document.warnings:
            self.report.warn(warning)
        for segment in document.segments:
            self.report.segments[segment.name] += 1
        for message in document:
            self._scrub_message(message)
        owned = {id(s) for message in document for s in message.segments}
        for segment in document.segments:
            if id(segment) not in owned and segment.name.startswith("Z"):
                self.report.unknown_segments[segment.name] += 1
                self.report.warn("Unknown segment " + segment.name + ": " + self.policy["unknown_segments"])
                if self.policy["unknown_segments"] == "redact":
                    for number, field in enumerate(segment.fields, 1):
                        if field.raw:
                            field.raw = segment.delimiters.encode("***")
                            self.report.record(segment.name + "-" + str(number), "redact")
            if segment.name in ("FHS", "BHS"):
                # These headers can contain identifying paths, facilities,
                # comments and file/batch identifiers; retain only control data.
                for number in range(3, len(segment.fields) + 1):
                    if number == 7:
                        value = segment.field(number).value
                        if value:
                            segment.field(number).raw = segment.delimiters.encode(self.transformer.generalize_year(value))
                            self.report.record(segment.name + "-7", "generalize_year")
                    elif segment.field(number).raw:
                        segment.field(number).raw = ""
                        self.report.record(segment.name + "-" + str(number), "remove")
            elif segment.name in ("BTS", "FTS") and len(segment.fields) >= 2:
                if segment.field(2).raw:
                    segment.field(2).raw = ""
                    self.report.record(segment.name + "-2", "remove")
        return document

    def _tokens(self, message: Message) -> List[str]:
        tokens = patient_names(message)
        for p, _, rule in self._rules:
            actions = rule.get("actions", [rule])
            if all(a.get("action") == "keep" for a in actions):
                continue
            # Narrative contents are not identity tokens: replacing the entire
            # narrative would discard the clinical detail we intend to keep.
            if any(a.get("kind") == "free_text" for a in actions):
                continue
            for segment in message.find(p.segment):
                if p.field > len(segment.fields):
                    continue
                if p.segment == "OBX" and p.field == 5:
                    continue
                for token in scalar_values(segment, p.field):
                    if len(token.strip()) >= 3 and not token.isdecimal():
                        tokens.append(token)
                # Numeric identifiers and phones, but not clinical numeric data.
                numeric_identity = (
                    rule.get("identifier") == "provider"
                    or p.field in _PROVIDER_FIELDS.get(p.segment, set())
                    or p.field in _ID_FIELDS.get(p.segment, set())
                    or any(a.get("kind") in ("ssn", "phone", "mrn", "account")
                           or a.get("action") in ("date_shift", "age_cap", "generalize_year")
                           for a in actions)
                )
                if numeric_identity:
                    tokens.extend(v for v in scalar_values(segment, p.field) if len(v) >= 3)
        return tokens

    def _scrub_message(self, message: Message) -> None:
        self.report.messages += 1
        identity = patient_identity(message)
        if identity == "fallback:|":
            self.report.warn("No PID identity; dates share the missing-patient fallback offset")
        tokens = self._tokens(message)
        occurrences: Counter = Counter()
        for segment in message.segments:
            occurrences[segment.name] += 1
            if segment.name.startswith("Z"):
                self.report.unknown_segments[segment.name] += 1
                self.report.warn("Unknown segment " + segment.name + ": " + self.policy.get("unknown_segments", "redact"))
                if self.policy.get("unknown_segments", "redact") == "redact":
                    for number, field in enumerate(segment.fields, 1):
                        if field.raw:
                            field.raw = segment.delimiters.encode("***")
                            self.report.record(segment.name + "-" + str(number), "redact")
                continue
            originals = {number: field.raw for number, field in enumerate(segment.fields, 1)}
            for p, path, rule in self._rules:
                if p.segment != segment.name or p.field > len(segment.fields):
                    continue
                if p.occurrence not in (None, "*") and int(p.occurrence) != occurrences[segment.name]:
                    continue
                if segment.name in ("MSH", "FHS", "BHS") and p.field <= 2:
                    continue
                # OBX-5 action depends on OBX-2. Clinical numeric/coded values
                # stay untouched, text is scrubbed, opaque ED/RP is removed.
                value_type = str(segment.get(2)) if segment.name == "OBX" else ""
                if segment.name == "OBX" and p.field == 5:
                    if value_type in ("ED", "RP"):
                        if segment.field(5).raw:
                            segment.field(5).raw = ""
                            self.report.record(path, "remove")
                        continue
                    if value_type in ("DT", "DTM", "TS", "DR") and rule.get("kind") == "free_text":
                        rule = {"action": "date_shift"}
                    elif value_type not in ("TX", "FT", "ST"):
                        # An explicitly customized action still takes effect.
                        if rule.get("kind") == "free_text":
                            continue
                field = segment.field(p.field)
                if not originals[p.field] or originals[p.field] == '""':
                    continue
                # Every rule reads original input. This prevents a component
                # override from hashing a pseudonym or generalizing a fake ZIP.
                work = Field(originals[p.field], segment.delimiters)
                for action in rule.get("actions", [rule]):
                    step = dict(action)
                    if "identifier" in rule:
                        step.setdefault("identifier", rule["identifier"])
                    self._apply(work, segment, p, path, step, identity, tokens)
                if p.component is None and p.repetition in (None, "*"):
                    field.raw = work.raw
                else:
                    indices = range(1, len(work.repetitions()) + 1) if p.repetition in (None, "*") else [int(p.repetition)]
                    for index in indices:
                        field.set(work.get(index, p.component, p.subcomponent, decoded=False),
                                  index, p.component, p.subcomponent, raw=True)

    def _apply(self, field: Field, segment: Segment, p: Path, path: str,
               rule: dict, identity: str, tokens: List[str]) -> None:
        action = rule["action"]
        if action == "keep":
            self.report.record(path, action)
            return
        # Whole-field remove/redact eliminate all repetitions and leaves.
        if action in ("remove", "redact") and p.repetition is None and p.component is None:
            field.raw = "" if action == "remove" else segment.delimiters.encode(str(rule.get("text", rule.get("value", "***"))))
            self.report.record(path, action)
            return
        indices = range(1, len(field.repetitions()) + 1) if p.repetition in (None, "*") else [int(p.repetition)]
        for index in indices:
            original = field.get(index, p.component, p.subcomponent, decoded=False)
            if not original or original == '""':
                continue
            if p.component is None and action == "pseudonym":
                replacement = self._compound(original, segment, p.field, rule.get("kind", "mrn"), identity, tokens,
                                             provider=rule.get("identifier") == "provider",
                                             address=rule.get("identifier") == "address")
            elif p.component is None and action == "hash" and p.field in _ID_FIELDS.get(segment.name, set()):
                replacement = self._identifier(original, segment, action, rule, identity, tokens)
            else:
                replacement = self._leaves(original, segment, rule, identity, tokens)
            field.set(replacement, index, p.component, p.subcomponent, raw=True)
            self.report.record(path, action)

    def _leaves(self, raw: str, segment: Segment, rule: dict, identity: str, tokens: List[str]) -> str:
        d = segment.delimiters
        comps = split_escaped(raw, d.component, d.escape)
        output = []
        for ci, comp in enumerate(comps):
            subs = split_escaped(comp, d.subcomponent, d.escape)
            encoded = []
            for si, sub in enumerate(subs):
                # Legacy TS.2 is a precision code, not a second timestamp.
                precision = rule["action"] in ("date_shift", "age_cap", "generalize_year") and (ci > 0 or si > 0) and sub in ("Y", "L", "D", "H", "M", "S")
                if not sub or sub == '""' or precision:
                    encoded.append(sub)
                else:
                    encoded.append(d.encode(self._scalar(d.decode(sub), rule, identity, tokens)))
            output.append(d.subcomponent.join(encoded))
        return d.component.join(output)

    def _scalar(self, value: str, rule: dict, identity: str, tokens: List[str]) -> str:
        action = rule["action"]
        t = self.transformer
        if action == "remove":
            return ""
        if action == "redact":
            return str(rule.get("text", rule.get("value", "***")))
        if action == "hash":
            return t.hash(value, int(rule.get("length", 16)))
        if action == "pseudonym":
            kind = rule.get("kind", "mrn")
            return scrub_text(value, tokens) if kind == "free_text" else t.pseudonym(kind, value)
        if action == "date_shift":
            result = t.shift_date(value, identity)
            if _parse_ts(value) is None:
                self.report.warn("Malformed date retained by date_shift; review source fields")
            elif result == value and t.patient_offset(identity) != 0 and len(_parse_ts(value)[1]) >= 8:
                self.report.warn("Date shift exceeds calendar bounds; original date retained")
            return result
        if action == "age_cap":
            return t.age_cap(value, int(rule.get("cap", 89)))
        if action == "zip3":
            return t.zip3(value)
        if action == "generalize_year":
            return t.generalize_year(value)
        return value

    def _identifier(self, raw: str, segment: Segment, action: str, rule: dict,
                    identity: str, tokens: List[str]) -> str:
        d = segment.delimiters
        comps = split_escaped(raw, d.component, d.escape)
        if comps and comps[0]:
            comps[0] = self._leaves(comps[0], segment, rule, identity, tokens)
        # EI and CX place assigning authorities in different positions. Keep
        # identifier-type and universal-ID-type codes while hiding authority text.
        is_ei = segment.name in ("ORC", "OBR", "SCH", "TXA", "FT1")
        if is_ei:
            for i in (1, 2):
                if i < len(comps) and comps[i]:
                    comps[i] = self._leaves(comps[i], segment, {"action": "hash"}, identity, tokens)
        else:
            for i in (3, 5):
                if i < len(comps) and comps[i]:
                    authority = split_escaped(comps[i], d.subcomponent, d.escape)
                    for j in range(min(len(authority), 2)):
                        if authority[j]:
                            authority[j] = d.encode(self.transformer.hash(d.decode(authority[j])))
                    comps[i] = d.subcomponent.join(authority)
            # CX.7/.8 effective/expiration dates are patient-related too.
            for i in (6, 7):
                if i < len(comps) and comps[i]:
                    comps[i] = self._leaves(comps[i], segment, {"action": "date_shift"}, identity, tokens)
        return d.component.join(comps)

    def _compound(self, raw: str, segment: Segment, number: int, kind: str,
                  identity: str, tokens: List[str], provider: bool = False,
                  address: bool = False) -> str:
        d = segment.delimiters
        comps = split_escaped(raw, d.component, d.escape)
        if kind in ("mrn", "account") and number in _ID_FIELDS.get(segment.name, set()):
            return self._identifier(raw, segment, "pseudonym", {"action": "pseudonym", "kind": kind}, identity, tokens)
        if kind == "person_name":
            provider = provider or number in _PROVIDER_FIELDS.get(segment.name, set())
            for i, comp in enumerate(comps):
                if not comp or comp == '""':
                    continue
                if provider and i == 0:
                    k = "provider_id"
                elif i == (1 if provider else 0):
                    k = "family_name"
                elif i in ((2, 3) if provider else (1, 2)):
                    k = "given_name"
                else:
                    # Suffix, prefix, authority, credentials can identify a
                    # provider. Keep datatype codes only at known positions.
                    if i >= (4 if provider else 3):
                        comps[i] = ""
                        continue
                    k = "person_name"
                comps[i] = self._leaves(comp, segment, {"action": "pseudonym", "kind": k}, identity, tokens)
            return d.component.join(comps)
        if kind in ("street", "address") and (address or number in _ADDRESS_FIELDS.get(segment.name, set())):
            for i, comp in enumerate(comps):
                if not comp:
                    continue
                if i == 0:
                    k = "street"
                elif i == 2:
                    k = "city"
                elif i == 4:
                    k = "zip"
                elif i in (3, 5, 6):
                    # State, country and address type are useful broad context.
                    continue
                else:
                    comps[i] = ""
                    continue
                comps[i] = self._leaves(comp, segment, {"action": "pseudonym", "kind": k}, identity, tokens)
            return d.component.join(comps)
        if kind == "phone" and len(comps) > 1:
            # XTN.1 legacy number; XTN.4 email; XTN.5 country, .6 area,
            # .7 local number, .8 extension. Retain use/equipment codes.
            for i, comp in enumerate(comps):
                if not comp:
                    continue
                if i == 0:
                    k = "phone"
                elif i == 3:
                    k = "email"
                elif i in (1, 2):
                    continue
                elif i in (4, 5, 6, 7):
                    k = "phone" if i == 6 else "mrn"
                else:
                    comps[i] = ""
                    continue
                comps[i] = self._leaves(comp, segment, {"action": "pseudonym", "kind": k}, identity, tokens)
            return d.component.join(comps)
        return self._leaves(raw, segment, {"action": "pseudonym", "kind": kind}, identity, tokens)


def scrub(data: Union[str, bytes], key: Union[str, bytes], policy: Optional[dict] = None,
          date_shift_days: int = 30) -> Document:
    """Convenience function for one transmission; Scrubber also exposes auditing."""
    return Scrubber(key, policy, date_shift_days).scrub(data)
