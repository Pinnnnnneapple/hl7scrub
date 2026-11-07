"""Lossless HL7 v2 ER7 model, paths, escaping, and transmission parsing.

Text uses UTF-8 with surrogateescape at the byte boundary. Unmodified input is
never normalized; even mixed line endings and transport framing survive.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator, List, Optional, Union


class ParseError(ValueError):
    """An input cannot be interpreted safely as HL7 v2."""


@dataclass(frozen=True)
class Delimiters:
    """Delimiters declared in MSH-1/MSH-2 (including optional truncation)."""

    field: str = "|"
    component: str = "^"
    repetition: str = "~"
    escape: str = "\\"
    subcomponent: str = "&"
    truncation: str = ""

    @classmethod
    def from_header(cls, text: str) -> Delimiters:
        """Read delimiters from MSH, FHS or BHS without hardcoded separators."""
        if len(text) < 8:
            raise ParseError("Incomplete HL7 header")
        field = text[3]
        encoding = text[4:].split(field, 1)[0]
        if len(encoding) not in (4, 5):
            raise ParseError("Encoding characters must contain four or five characters")
        chars = field + encoding
        if len(set(chars)) != len(chars) or any(ord(c) < 33 or ord(c) > 126 for c in chars):
            raise ParseError("HL7 delimiters must be distinct printable ASCII characters")
        return cls(field, *encoding[:4], encoding[4:])

    @property
    def encoding(self) -> str:
        """Return MSH-2 in its original order."""
        return self.component + self.repetition + self.escape + self.subcomponent + self.truncation

    def decode(self, value: str) -> str:
        """Decode standard, hexadecimal and line-break escapes; retain unknown ones."""
        mapping = {"F": self.field, "S": self.component, "R": self.repetition,
                   "T": self.subcomponent, "E": self.escape, ".br": "\n"}
        if self.truncation:
            mapping["P"] = self.truncation
        def replace(match: re.Match) -> str:
            token = match.group(1)
            if token in mapping:
                return mapping[token]
            if token.startswith("X"):
                try:
                    return bytes.fromhex(token[1:]).decode("utf-8", "surrogateescape")
                except ValueError:
                    return match.group(0)
            return match.group(0)
        return re.sub(re.escape(self.escape) + r"(.*?)" + re.escape(self.escape), replace, value)

    def encode(self, value: str) -> str:
        """Encode a literal scalar so delimiter characters cannot change its structure."""
        mapping = {self.field: "F", self.component: "S", self.repetition: "R",
                   self.subcomponent: "T", self.escape: "E", "\n": ".br", "\r": "X0D"}
        if self.truncation:
            mapping[self.truncation] = "P"
        return "".join(self.escape + mapping[c] + self.escape if c in mapping else
                       self.escape + "X" + format(ord(c), "02X") + self.escape if ord(c) < 32 else c
                       for c in value)


def split_escaped(value: str, separator: str, escape: str) -> List[str]:
    """Split ER7 at structural separators, ignoring paired escape sequences."""
    result: List[str] = []
    start = 0
    i = 0
    while i < len(value):
        if value[i] == escape:
            close = value.find(escape, i + 1)
            if close != -1:
                i = close + 1
                continue
        if value[i] == separator:
            result.append(value[start:i])
            start = i + 1
        i += 1
    result.append(value[start:])
    return result


class Field:
    """One raw ER7 field with decoded scalar access; repetitions are one-based."""

    def __init__(self, raw: str = "", delimiters: Optional[Delimiters] = None) -> None:
        self.raw = raw
        self.delimiters = delimiters or Delimiters()

    @property
    def value(self) -> str:
        """Return a decoded view of this field; structural separators remain visible."""
        return self.delimiters.decode(self.raw)

    def repetitions(self) -> List[str]:
        """Return raw repetitions, preserving empty entries."""
        d = self.delimiters
        return split_escaped(self.raw, d.repetition, d.escape)

    def get(self, repetition: int = 1, component: Optional[int] = None,
            subcomponent: Optional[int] = None, decoded: bool = True) -> str:
        """Get a scalar or compound repetition; missing positions return empty text."""
        if repetition < 1 or (component is not None and component < 1) or (subcomponent is not None and subcomponent < 1):
            raise ValueError("HL7 indices are one-based")
        d = self.delimiters
        parts = self.repetitions()
        value = parts[repetition - 1] if repetition <= len(parts) else ""
        if component is not None:
            parts = split_escaped(value, d.component, d.escape)
            value = parts[component - 1] if component <= len(parts) else ""
        if subcomponent is not None:
            if component is None:
                raise ValueError("Subcomponents require a component")
            parts = split_escaped(value, d.subcomponent, d.escape)
            value = parts[subcomponent - 1] if subcomponent <= len(parts) else ""
        return d.decode(value) if decoded else value

    def set(self, value: str, repetition: int = 1, component: Optional[int] = None,
            subcomponent: Optional[int] = None, raw: bool = False) -> None:
        """Set a literal value, or an ER7 compound when raw=True, padding as needed."""
        if repetition < 1 or (component is not None and component < 1) or (subcomponent is not None and subcomponent < 1):
            raise ValueError("HL7 indices are one-based")
        if subcomponent is not None and component is None:
            raise ValueError("Subcomponents require a component")
        d = self.delimiters
        encoded = value if raw else d.encode(str(value))
        reps = self.repetitions()
        while len(reps) < repetition:
            reps.append("")
        if component is None:
            reps[repetition - 1] = encoded
        else:
            comps = split_escaped(reps[repetition - 1], d.component, d.escape)
            while len(comps) < component:
                comps.append("")
            if subcomponent is None:
                comps[component - 1] = encoded
            else:
                subs = split_escaped(comps[component - 1], d.subcomponent, d.escape)
                while len(subs) < subcomponent:
                    subs.append("")
                subs[subcomponent - 1] = encoded
                comps[component - 1] = d.subcomponent.join(subs)
            reps[repetition - 1] = d.component.join(comps)
        self.raw = d.repetition.join(reps)

    def __str__(self) -> str:
        return self.raw


_PATH = re.compile(r"^([A-Z][A-Z0-9]{2})(?:\[([1-9][0-9]*|\*)\])?-([1-9][0-9]*)(?:\[([1-9][0-9]*|\*)\])?(?:\.([1-9][0-9]*))?(?:\.([1-9][0-9]*))?$")


@dataclass(frozen=True)
class Path:
    """A parsed HL7 path; field, repetition and component indices are one-based."""

    segment: str
    occurrence: Optional[str]
    field: int
    repetition: Optional[str]
    component: Optional[int]
    subcomponent: Optional[int]

    @classmethod
    def parse(cls, path: str) -> Path:
        """Validate a path such as PID-3[*].1 or NK1[2]-2.1."""
        match = _PATH.fullmatch(path)
        if not match or int(match.group(3)) < 1:
            raise ValueError("Invalid HL7 path: " + path)
        s, occurrence, field, repetition, component, subcomponent = match.groups()
        return cls(s, occurrence, int(field), repetition,
                   int(component) if component else None, int(subcomponent) if subcomponent else None)


class Segment:
    """An HL7 segment; MSH/FHS/BHS field 1 is the field separator itself."""

    def __init__(self, name: str, fields: Optional[List[Field]] = None,
                 delimiters: Optional[Delimiters] = None) -> None:
        self.name = name
        self.delimiters = delimiters or Delimiters()
        self.fields = fields or []

    @classmethod
    def parse(cls, raw: str, delimiters: Optional[Delimiters] = None) -> Segment:
        """Parse a single segment while retaining each original raw field."""
        name = raw[:3]
        if not re.fullmatch(r"[A-Z][A-Z0-9]{2}", name):
            raise ParseError("Invalid segment identifier")
        header = name in ("MSH", "FHS", "BHS")
        d = Delimiters.from_header(raw) if header else (delimiters or Delimiters())
        if len(raw) > 3 and raw[3] != d.field:
            raise ParseError("Segment has inconsistent field separator: " + name)
        if header:
            tail = raw[4:].split(d.field, 1)
            values = [d.field, tail[0]]
            if len(tail) == 2:
                values.extend(split_escaped(tail[1], d.field, d.escape))
        else:
            values = split_escaped(raw[4:], d.field, d.escape) if len(raw) > 3 else []
        return cls(name, [Field(v, d) for v in values], d)

    def field(self, number: int, create: bool = False) -> Field:
        """Access a numbered field, optionally extending this segment."""
        if number < 1:
            raise ValueError("HL7 fields are one-based")
        if create:
            while len(self.fields) < number:
                self.fields.append(Field("", self.delimiters))
        return self.fields[number - 1] if number <= len(self.fields) else Field("", self.delimiters)

    def get(self, path: Union[str, int], decoded: bool = True) -> Union[str, List[str]]:
        """Get a field by number or complete path (including repetition wildcard)."""
        p = Path.parse(self.name + "-" + str(path) if isinstance(path, int) else path)
        if p.segment != self.name:
            raise ValueError("Path names a different segment")
        f = self.field(p.field)
        if self.name in ("MSH", "FHS", "BHS") and p.field <= 2:
            return f.raw
        if p.repetition == "*":
            return [f.get(i, p.component, p.subcomponent, decoded) for i in range(1, len(f.repetitions()) + 1)]
        return f.get(int(p.repetition or 1), p.component, p.subcomponent, decoded)

    def set(self, path: Union[str, int], value: str, raw: bool = False) -> None:
        """Set a field/path; wildcard repeats set each existing repetition."""
        p = Path.parse(self.name + "-" + str(path) if isinstance(path, int) else path)
        if p.segment != self.name:
            raise ValueError("Path names a different segment")
        if self.name in ("MSH", "FHS", "BHS") and p.field <= 2:
            raise ValueError("Delimiter declarations cannot be edited through paths")
        f = self.field(p.field, create=True)
        indices = range(1, len(f.repetitions()) + 1) if p.repetition == "*" else [int(p.repetition or 1)]
        for index in indices:
            f.set(value, index, p.component, p.subcomponent, raw)

    def serialize(self) -> str:
        """Serialize exactly, retaining trailing empty fields."""
        d = self.delimiters
        if self.name in ("MSH", "FHS", "BHS"):
            return self.name + d.field + d.field.join(f.raw for f in self.fields[1:])
        return self.name + (d.field + d.field.join(f.raw for f in self.fields) if self.fields else "")

    def __str__(self) -> str:
        return self.serialize()


class Message:
    """One MSH-led message with structured access to repeated segments."""

    def __init__(self, segments: Optional[List[Segment]] = None) -> None:
        self.segments = segments or []
        self._chunks: List[Union[str, Segment]] = []
        self.warnings: List[str] = []

    @classmethod
    def parse(cls, data: Union[str, bytes]) -> Message:
        """Parse exactly one message; use parse() for a multi-message transmission."""
        doc = parse(data)
        if len(doc.messages) != 1:
            raise ParseError("Expected exactly one MSH message")
        return doc.messages[0]

    @property
    def delimiters(self) -> Delimiters:
        """Return the encoding declared by this message's MSH."""
        return self.segments[0].delimiters if self.segments else Delimiters()

    def find(self, name: str) -> List[Segment]:
        """Return all segments with the requested identifier, in wire order."""
        return [s for s in self.segments if s.name == name]

    def get(self, path: str, default: str = "") -> Union[str, List[str]]:
        """Get the first matching segment, or all occurrences using SEG[*]."""
        p = Path.parse(path)
        segments = self.find(p.segment)
        if p.occurrence == "*":
            values = [s.get(path) for s in segments]
            return [v for item in values for v in (item if isinstance(item, list) else [item])]
        index = int(p.occurrence or 1) - 1
        return segments[index].get(path) if index < len(segments) else default

    def set(self, path: str, value: str, raw: bool = False) -> None:
        """Set an existing segment path, optionally across all occurrences."""
        p = Path.parse(path)
        segments = self.find(p.segment)
        if p.occurrence == "*":
            for segment in segments:
                segment.set(path, value, raw)
            return
        index = int(p.occurrence or 1) - 1
        if index >= len(segments):
            raise KeyError("Segment does not exist: " + p.segment)
        segments[index].set(path, value, raw)

    def serialize(self, mllp: bool = False) -> str:
        """Serialize this message, excluding transmission wrappers by default."""
        text = "".join(str(x) for x in self._chunks) if self._chunks else "\r".join(str(s) for s in self.segments) + "\r"
        text = _without_mllp(text)
        return "\x0b" + text + "\x1c\r" if mllp else text

    def to_bytes(self, mllp: bool = False) -> bytes:
        """Encode this message with reversible UTF-8/surrogateescape."""
        return self.serialize(mllp).encode("utf-8", "surrogateescape")

    def __str__(self) -> str:
        return self.serialize()


def _without_mllp(text: str) -> str:
    return text.replace("\x0b", "").replace("\x1c\r", "").replace("\x1c", "")


class Document:
    """Lossless transmission: messages, batch wrappers, framing and separators."""

    def __init__(self) -> None:
        self.messages: List[Message] = []
        self.chunks: List[Union[str, Segment]] = []
        self.warnings: List[str] = []

    @property
    def segments(self) -> List[Segment]:
        """Return all segments, including batch/file wrappers."""
        return [x for x in self.chunks if isinstance(x, Segment)]

    def serialize(self, mllp: Optional[bool] = None) -> str:
        """Retain original transport by default; False strips, True adds one frame."""
        text = "".join(str(x) for x in self.chunks)
        if mllp is None:
            return text
        text = _without_mllp(text)
        return "\x0b" + text + "\x1c\r" if mllp else text

    def to_bytes(self, mllp: Optional[bool] = None) -> bytes:
        """Serialize with reversible byte encoding; unchanged inputs are byte-identical."""
        return self.serialize(mllp).encode("utf-8", "surrogateescape")

    def __iter__(self) -> Iterator[Message]:
        return iter(self.messages)

    def __len__(self) -> int:
        return len(self.messages)

    def __str__(self) -> str:
        return self.serialize()


def parse(data: Union[str, bytes]) -> Document:
    """Parse ER7 bytes/text, multi-message files, batch wrappers and MLLP frames.

    Invalid segment text raises ParseError without echoing the input. A segment
    outside an MSH-led message is retained with a value-free warning.
    """
    text = data.decode("utf-8", "surrogateescape") if isinstance(data, bytes) else data
    document = Document()
    current: Optional[Message] = None
    delimiters = Delimiters()
    for match in re.finditer(r"[^\r\n\x0b\x1c]+|\r\n|[\r\n\x0b\x1c]", text):
        chunk = match.group(0)
        if chunk[0] in "\r\n\x0b\x1c":
            document.chunks.append(chunk)
            if current is not None:
                current._chunks.append(chunk)
            continue
        segment = Segment.parse(chunk, delimiters)
        if segment.name in ("MSH", "FHS", "BHS"):
            delimiters = segment.delimiters
        if segment.name == "MSH":
            current = Message()
            document.messages.append(current)
        elif segment.name in ("FHS", "BHS", "BTS", "FTS"):
            current = None
        document.chunks.append(segment)
        if current is not None:
            current.segments.append(segment)
            current._chunks.append(segment)
        elif segment.name not in ("FHS", "BHS", "BTS", "FTS"):
            document.warnings.append("Segment outside an MSH message: " + segment.name)
        if segment.name not in ("FHS", "BHS", "MSH"):
            for field in segment.fields:
                if field.raw.count(delimiters.escape) % 2:
                    document.warnings.append("Unpaired escape delimiter in " + segment.name)
                    break
    if not document.messages:
        raise ParseError("No MSH-led messages found")
    # Detect unbalanced framing without exposing message content.
    if text.count("\x0b") != text.count("\x1c"):
        document.warnings.append("Unbalanced MLLP framing")
    return document


def parse_messages(data: Union[str, bytes]) -> List[Message]:
    """Convenience interface returning only MSH-led messages."""
    return parse(data).messages
