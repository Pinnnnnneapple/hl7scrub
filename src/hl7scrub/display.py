"""Human-readable inspection and structural field diffs."""
from __future__ import annotations

import json
from importlib import resources
from typing import Dict, List, Union

from .model import Document, parse, split_escaped


def field_names() -> dict:
    """Load common HL7 v2.5.1 field labels shipped with this package."""
    return json.loads(resources.files("hl7scrub").joinpath("data/field_names.json").read_text(encoding="utf-8"))


def _visible(value: str) -> str:
    return value.encode("unicode_escape").decode("ascii")


def show(data: Union[str, bytes, Document]) -> str:
    """Render messages as a field/repetition/component tree (contains input PHI)."""
    document = data if isinstance(data, Document) else parse(data)
    names = field_names()
    lines: List[str] = []
    for index, message in enumerate(document, 1):
        lines.append("Message " + str(index))
        for segment in message.segments:
            lines.append("  " + segment.name)
            d = segment.delimiters
            for number, field in enumerate(segment.fields, 1):
                if not field.raw:
                    continue
                label = names.get(segment.name, {}).get(str(number), "Field " + str(number))
                path = segment.name + "-" + str(number)
                if segment.name == "MSH" and number <= 2:
                    lines.append("    " + path + " " + label + ": " + _visible(field.raw))
                    continue
                reps = field.repetitions()
                if len(reps) == 1 and d.component not in field.raw:
                    lines.append("    " + path + " " + label + ": " + _visible(field.value))
                    continue
                lines.append("    " + path + " " + label)
                for r, rep in enumerate(reps, 1):
                    rpath = path + ("[" + str(r) + "]" if len(reps) > 1 else "")
                    comps = split_escaped(rep, d.component, d.escape)
                    for c, comp in enumerate(comps, 1):
                        if comp:
                            lines.append("      " + rpath + "." + str(c) + ": " + _visible(d.decode(comp)))
    return "\n".join(lines) + "\n"


def _flatten(document: Document) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for index, message in enumerate(document, 1):
        counts: Dict[str, int] = {}
        for segment in message.segments:
            counts[segment.name] = counts.get(segment.name, 0) + 1
            prefix = str(index) + ":" + segment.name + "[" + str(counts[segment.name]) + "]-"
            for number, field in enumerate(segment.fields, 1):
                result[prefix + str(number)] = field.raw
    return result


def diff(a: Union[str, bytes, Document], b: Union[str, bytes, Document]) -> List[dict]:
    """Return ordered field-level differences with path, old and new raw values."""
    left = _flatten(a if isinstance(a, Document) else parse(a))
    right = _flatten(b if isinstance(b, Document) else parse(b))
    keys = list(left) + [k for k in right if k not in left]
    return [{"path": k, "old": left.get(k, ""), "new": right.get(k, "")}
            for k in keys if left.get(k, "") != right.get(k, "")]
