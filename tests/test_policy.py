"""Policy schema, resource and reference checks using only the standard library."""

from __future__ import annotations

import json
import tempfile
import unittest
from importlib import resources
from pathlib import Path

from hl7scrub.policy import default_policy, load_policy


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "policy.json"

    def load(self, fields=None, **options):
        value = {"version": 1, "unknown_segments": "redact", "fields": fields or {}}
        value.update(options)
        self.path.write_text(json.dumps(value), encoding="utf-8")
        return load_policy(self.path)

    def test_default_is_fresh_and_matches_load_without_path(self):
        expected = default_policy()
        changed = default_policy()
        changed["fields"]["PID-3"]["kind"] = "changed"
        changed["fields"]["PID-7"]["actions"][0]["action"] = "remove"
        self.assertEqual(expected, load_policy())
        self.assertNotEqual(changed, default_policy())

    def test_default_coverage_and_date_intent(self):
        policy = default_policy()
        self.assertEqual(policy["unknown_segments"], "redact")
        fields = policy["fields"]
        expected = {"MSH", "EVN", "PID", "PD1", "NK1", "PV1", "PV2", "GT1", "IN1", "IN2",
                    "ORC", "OBR", "OBX", "NTE", "AL1", "DG1", "SCH", "AIP", "AIL", "TXA", "FT1"}
        self.assertTrue(expected <= {path.split("-")[0] for path in fields})
        self.assertEqual(fields["MSH-10"]["action"], "hash")
        for field in ("MSH-3", "MSH-5"):
            self.assertEqual(fields[field], {"action": "keep"})
        for field in ("MSH-4", "MSH-6"):
            self.assertEqual(fields[field]["action"], "hash")
        self.assertNotIn("FT1-4", fields)
        for field in ("FT1-4.1", "FT1-4.2"):
            self.assertEqual(fields[field]["action"], "date_shift")
        self.assertEqual(fields["PID-5"]["kind"], "person_name")
        self.assertEqual(fields["PV1-7"]["kind"], "person_name")
        self.assertEqual(fields["PID-11"]["kind"], "street")
        self.assertEqual(fields["NTE-3"]["kind"], "free_text")
        self.assertEqual(fields["PID-7"]["actions"], [{"action": "date_shift"}, {"action": "age_cap"}])
        for field in ("MSH-7", "EVN-2", "PV1-44", "PV1-45", "OBX-14", "SCH-11.4"):
            self.assertEqual(fields[field]["action"], "date_shift")

    def test_bundled_labels_cover_every_rule(self):
        content = resources.files("hl7scrub").joinpath("data/field_names.json").read_text(encoding="utf-8")
        names = json.loads(content)
        for path in default_policy()["fields"]:
            segment, field = path.split("-")
            label = names[segment][field.split(".")[0]]
            self.assertIsInstance(label, str)
            self.assertTrue(label.strip())
        self.assertEqual(names["PV2"]["16"], "Purge Status Code")
        self.assertEqual(names["PV2"]["17"], "Purge Status Date")
        self.assertEqual(names["GT1"]["45"], "Contact Person's Name")
        self.assertEqual(names["GT1"]["46"], "Contact Person's Telephone Number")

    def test_custom_policy_replaces_default_and_accepts_string_path(self):
        self.load({"Z01-2": {"action": "redact"}}, unknown_segments="keep")
        result = load_policy(str(self.path))
        self.assertEqual(set(result["fields"]), {"Z01-2"})
        self.assertEqual(result["unknown_segments"], "keep")

    def test_missing_unknown_segment_option_defaults_to_redact(self):
        self.path.write_text('{"version":1,"fields":{}}', encoding="utf-8")
        self.assertEqual(load_policy(self.path)["unknown_segments"], "redact")

    def test_component_and_subcomponent_rules(self):
        fields = {"PID-5.1": {"action": "pseudonym", "kind": "family_name", "identifier": "name"},
                  "Z99-12.2.3": {"action": "hash", "length": 32}}
        self.assertEqual(self.load(fields)["fields"], fields)

    def test_all_supported_actions_and_sequential_dob_rule(self):
        actions = ["keep", "remove", "redact", "pseudonym", "hash", "date_shift", "age_cap", "zip3", "generalize_year"]
        fields = {"PID-" + str(index): {"action": action} for index, action in enumerate(actions, 1)}
        fields["PID-7"] = {"actions": [{"action": "age_cap"}, {"action": "generalize_year"}], "identifier": "date_of_birth"}
        self.assertEqual(self.load(fields)["fields"], fields)

    def test_rejects_malformed_paths(self):
        for path in ("PID", "pid-3", "PID-0", "PID-03", "PID--3", "PID-3.0", "PID-3.*", "PID-3[0]", "PID-3.1.1.1", "PID-3\n"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.load({path: {"action": "keep"}})

    def test_path_syntax_matches_model_selectors(self):
        from hl7scrub.model import Path as FieldPath
        for path in ("PID-3[1]", "PID-3[*].1", "NK1[2]-2.1", "NK1[*]-2[*].1.2"):
            with self.subTest(path=path):
                FieldPath.parse(path)
                self.assertIn(path, self.load({path: {"action": "keep"}})["fields"])

    def test_supported_pseudonym_kinds(self):
        for kind in ("person_name", "given_name", "family_name", "mrn", "account", "ssn",
                     "phone", "email", "street", "city", "zip", "free_text", "provider_id"):
            with self.subTest(kind=kind):
                self.load({"PID-3": {"action": "pseudonym", "kind": kind}})
        for kind in ("name", "provider", "address", "last_name", "unknown"):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.load({"PID-3": {"action": "pseudonym", "kind": kind}})

    def test_redaction_markers_and_age_cap_options(self):
        for option in ("text", "value"):
            self.load({"NTE-3": {"action": "redact", option: "[REMOVED]"}})
            self.load({"NTE-3": {"actions": [{"action": "redact", option: ""}]}})
        self.load({"PID-7": {"actions": [{"action": "age_cap", "cap": 89}, {"action": "date_shift"}]}})
        self.load({"PID-7": {"action": "age_cap", "cap": 0}})
        invalid = [{"action": "redact", "text": 1}, {"action": "redact", "value": None},
                   {"action": "redact", "text": "x", "value": "y"},
                   {"action": "keep", "text": "x"}, {"action": "hash", "value": "x"},
                   {"action": "age_cap", "cap": True}, {"action": "age_cap", "cap": -1},
                   {"action": "age_cap", "cap": 89.0}, {"action": "date_shift", "cap": 89}]
        for rule in invalid:
            for outer in (rule, {"actions": [rule]}):
                with self.subTest(rule=outer), self.assertRaises(ValueError):
                    self.load({"PID-7": outer})
        for option in ("text", "value", "cap"):
            with self.subTest(option=option), self.assertRaises(ValueError):
                self.load({"PID-7": {"actions": [{"action": "keep"}], option: "x"}})

    def test_rejects_unknown_actions_and_keys(self):
        for rule in ({"action": "free_text"}, {"action": "pseudonym", "lenght": 8},
                     {"action": "age_cap", "then": "date_shift"}, {"action": ["keep"]}, {}, "keep", None):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                self.load({"PID-3": rule})
        with self.assertRaises(ValueError):
            self.load(unknown_segment="redact")

    def test_rejects_invalid_top_level_types_and_versions(self):
        for value in ([], None, 1, {"version": True, "fields": {}}, {"version": 1.0, "fields": {}},
                      {"version": 2, "fields": {}}, {"fields": {}}, {"version": 1},
                      {"version": 1, "fields": []}, {"version": 1, "fields": {}, "unknown_segments": []}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.path.write_text(json.dumps(value), encoding="utf-8")
                load_policy(self.path)
        with self.assertRaises(ValueError):
            self.load(unknown_segments="remove")

    def test_validates_action_sequences(self):
        for rule in ({"actions": []}, {"actions": "redact"}, {"actions": [{"action": "keep"}] * 17},
                     {"actions": [{"action": "unknown"}]}, {"actions": ["keep"]},
                     {"actions": [{"actions": [{"action": "keep"}]}]},
                     {"actions": [{"action": "keep"}], "action": "keep"},
                     {"actions": [{"action": "pseudonym"}], "kind": "mrn"},
                     {"actions": [{"action": "hash"}], "length": 8},
                     {"actions": [{"action": "keep", "identifier": "nested"}]}):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                self.load({"PID-7": rule})

    def test_validates_kind_identifier_and_length(self):
        for rule in ({"action": "hash", "length": True}, {"action": "hash", "length": 0},
                     {"action": "hash", "length": 65}, {"action": "hash", "length": 8.0},
                     {"action": "keep", "length": 8}, {"action": "pseudonym", "length": 8}, {"action": "hash", "kind": "mrn"},
                     {"action": "pseudonym", "kind": []}, {"action": "pseudonym", "kind": ""},
                     {"action": "pseudonym", "kind": "Free Text"},
                     {"action": "redact", "identifier": " "}, {"action": "redact", "identifier": 1}):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                self.load({"PID-3": rule})
        for length in (1, 52):
            self.load({"PID-3": {"action": "hash", "length": length}})

    def test_rejects_duplicate_keys_nonfinite_values_and_invalid_json(self):
        for text in ('{"version":1,"version":1,"fields":{}}',
                     '{"version":1,"fields":{"PID-3":{"action":"keep"},"PID-3":{"action":"hash"}}}',
                     '{"version":1,"fields":{"PID-3":{"action":"hash","action":"keep"}}}',
                     '{"version":1,"fields":{"PID-3":{"action":"hash","length":NaN}}}',
                     '{"version":Infinity,"fields":{}}', '{'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.path.write_text(text, encoding="utf-8")
                load_policy(self.path)

    def test_missing_file_preserves_filesystem_error(self):
        with self.assertRaises(FileNotFoundError):
            load_policy(self.path)

    def test_documented_table_covers_exactly_the_bundled_paths(self):
        document = Path(__file__).resolve().parents[1] / "docs" / "default-policy.md"
        paths = {line.split("`", 2)[1] for line in document.read_text(encoding="utf-8").splitlines()
                 if line.startswith("| `")}
        self.assertEqual(paths, set(default_policy()["fields"]))


if __name__ == "__main__":
    unittest.main()
