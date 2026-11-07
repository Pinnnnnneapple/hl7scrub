"""Load and validate version 1 field transformation policies.

Custom policies replace the bundled policy. They are never implicitly merged.
Validation checks configuration syntax, not de-identification or HL7 conformance.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any, Optional, Union

from .model import Path as FieldPath

__all__ = ["default_policy", "load_policy"]

_ACTIONS = frozenset({
    "keep", "remove", "redact", "pseudonym", "hash", "date_shift",
    "age_cap", "zip3", "generalize_year",
})
_KINDS = frozenset({
    "person_name", "given_name", "family_name", "mrn", "account", "ssn",
    "phone", "email", "street", "city", "zip", "free_text", "provider_id",
})
_ACTION_KEYS = frozenset({"action", "kind", "length", "text", "value", "cap"})
_RULE_KEYS = _ACTION_KEYS | {"actions", "identifier"}


def _object(pairs: list) -> dict:
    """Reject duplicate JSON keys before a later value can hide an earlier rule."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate policy key: {!r}".format(key))
        result[key] = value
    return result


def _constant(value: str) -> Any:
    raise ValueError("Non-finite JSON value is not allowed: " + value)


def _validate_action(rule: dict, location: str) -> None:
    action = rule.get("action")
    if not isinstance(action, str) or action not in _ACTIONS:
        raise ValueError("{}: unsupported or missing action".format(location))
    if "kind" in rule:
        kind = rule["kind"]
        if action != "pseudonym" or not isinstance(kind, str) or kind not in _KINDS:
            raise ValueError("{}: kind requires pseudonym and a supported kind".format(location))
    if "length" in rule:
        length = rule["length"]
        if (action != "hash" or type(length) is not int
                or not 1 <= length <= 52):
            raise ValueError("{}: length requires hash and an integer from 1 to 52".format(location))
    for option in ("text", "value"):
        if option in rule and (action != "redact" or not isinstance(rule[option], str)):
            raise ValueError("{}: {} requires redact and a string".format(location, option))
    if "text" in rule and "value" in rule:
        raise ValueError("{}: choose text or value, not both".format(location))
    if "cap" in rule:
        if action != "age_cap" or type(rule["cap"]) is not int or rule["cap"] < 0:
            raise ValueError("{}: cap requires age_cap and a nonnegative integer".format(location))


def _validate(policy: Any) -> dict:
    if not isinstance(policy, dict):
        raise ValueError("Policy must be a JSON object")
    extra = policy.keys() - {"version", "unknown_segments", "fields"}
    if extra:
        raise ValueError("Unknown policy keys: " + ", ".join(sorted(extra)))
    if type(policy.get("version")) is not int or policy["version"] != 1:
        raise ValueError("Policy version must be the integer 1")
    unknown = policy.get("unknown_segments", "redact")
    if not isinstance(unknown, str) or unknown not in {"keep", "redact"}:
        raise ValueError("unknown_segments must be 'keep' or 'redact'")
    fields = policy.get("fields")
    if not isinstance(fields, dict):
        raise ValueError("Policy fields must be a JSON object")
    for path, rule in fields.items():
        if not isinstance(path, str):
            raise ValueError("Invalid field path: {!r}".format(path))
        FieldPath.parse(path)
        if not isinstance(rule, dict):
            raise ValueError("{}: rule must be a JSON object".format(path))
        extra = rule.keys() - _RULE_KEYS
        if extra:
            raise ValueError("{}: unknown rule keys: {}".format(path, ", ".join(sorted(extra))))
        if "identifier" in rule:
            identifier = rule["identifier"]
            if not isinstance(identifier, str) or not identifier.strip():
                raise ValueError("{}: identifier must be a nonempty string".format(path))
        if "actions" in rule:
            if rule.keys() & _ACTION_KEYS:
                raise ValueError("{}: actions cannot be combined with outer action options".format(path))
            actions = rule["actions"]
            if not isinstance(actions, list) or not 1 <= len(actions) <= 16:
                raise ValueError("{}: actions must contain 1 to 16 action objects".format(path))
            for index, step in enumerate(actions):
                location = "{}.actions[{}]".format(path, index)
                if not isinstance(step, dict) or step.keys() - _ACTION_KEYS:
                    raise ValueError("{}: expected action object with supported options".format(location))
                _validate_action(step, location)
        else:
            _validate_action(rule, path)
    policy["unknown_segments"] = unknown
    return policy


def default_policy() -> dict:
    """Return a fresh, validated copy of the bundled pseudonymisation policy."""
    content = resources.files("hl7scrub").joinpath("data/default_policy.json").read_text(encoding="utf-8")
    return _validate(json.loads(content, object_pairs_hook=_object, parse_constant=_constant))


def load_policy(path: Optional[Union[str, Path]] = None) -> dict:
    """Read a complete UTF-8 JSON policy, or return the bundled policy.

    Invalid JSON or policy syntax raises ValueError. Filesystem errors retain
    their OSError subclasses. No policy file or caller-visible cache is modified.
    """
    if path is None:
        return default_policy()
    content = Path(path).read_text(encoding="utf-8")
    return _validate(json.loads(content, object_pairs_hook=_object, parse_constant=_constant))
