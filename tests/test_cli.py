"""Public CLI return codes, binary streams and inspection behavior."""
from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from hl7scrub.cli import main
from hl7scrub.display import diff, show
from hl7scrub.model import parse

DEMO = "demo-key-do-not-use"
INPUT = "examples/adt_sequence.hl7"


@pytest.fixture(autouse=True)
def no_env_key(monkeypatch):
    monkeypatch.delenv("HL7SCRUB_KEY", raising=False)


def test_missing_key_is_error(capsys):
    assert main(["scrub", INPUT]) == 2
    out = capsys.readouterr()
    assert out.out == ""
    assert "required" in out.err


@pytest.mark.parametrize("argv", [[], ["unknown"], ["scrub"], ["policy"], ["scan"], ["diff", INPUT]])
def test_usage_errors_return_two(argv, capsys):
    assert main(argv) == 2
    assert "usage:" in capsys.readouterr().err


def test_help_and_version_return_zero(capsys):
    assert main(["--help"]) == 0
    assert "scrub" in capsys.readouterr().out
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == "hl7scrub 0.1.0"


def test_scrub_output_report_and_scan(tmp_path, capsys):
    output = tmp_path / "clean.hl7"
    report = tmp_path / "report.json"
    assert main(["scrub", INPUT, "--key", DEMO, "-o", str(output), "--report", str(report), "--reference-date", "2026-01-01"]) == 0
    assert len(parse(output.read_bytes())) == 6
    assert main(["scan", str(output)]) == 0
    assert main(["scan", INPUT]) == 1
    data = json.loads(report.read_text())
    assert data["messages"] == 6
    assert "SYNTH001" not in report.read_text()
    assert "ALICE" not in report.read_text()
    assert "SYNTH001" not in capsys.readouterr().out


def test_cli_env_key(tmp_path, monkeypatch):
    monkeypatch.setenv("HL7SCRUB_KEY", DEMO)
    assert main(["scrub", INPUT, "-o", str(tmp_path / "clean.hl7")]) == 0


def test_cli_key_file_same_as_key(tmp_path):
    keyfile = tmp_path / "secret"
    keyfile.write_bytes(DEMO.encode() + b"\n")
    a, b = tmp_path / "a.hl7", tmp_path / "b.hl7"
    assert main(["scrub", INPUT, "--key", DEMO, "-o", str(a)]) == 0
    assert main(["scrub", INPUT, "--key-file", str(keyfile), "-o", str(b)]) == 0
    assert a.read_bytes() == b.read_bytes()


def test_random_key_prints_no_secret(tmp_path, capsys):
    assert main(["scrub", INPUT, "--random-key", "-o", str(tmp_path / "clean")]) == 0
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "key" not in captured.err.casefold()


def test_empty_key_refused_even_with_env(tmp_path, monkeypatch):
    monkeypatch.setenv("HL7SCRUB_KEY", DEMO)
    assert main(["scrub", INPUT, "--key", "", "-o", str(tmp_path / "clean")]) == 2


def test_key_sources_mutually_exclusive(capsys):
    assert main(["scrub", INPUT, "--key", DEMO, "--random-key"]) == 2


def test_multiple_inputs_output_directory(tmp_path):
    assert main(["scrub", INPUT, "examples/oru_lab.hl7", "--key", DEMO, "--out-dir", str(tmp_path)]) == 0
    assert len(parse((tmp_path / "adt_sequence.hl7").read_bytes())) == 6
    assert len(parse((tmp_path / "oru_lab.hl7").read_bytes())) == 1


def test_multi_input_consolidated_output(tmp_path):
    output = tmp_path / "combined.hl7"
    assert main(["scrub", INPUT, "examples/oru_lab.hl7", "--key", DEMO, "-o", str(output)]) == 0
    assert len(parse(output.read_bytes())) == 7


def test_out_dir_duplicate_basename_refused(tmp_path):
    assert main(["scrub", INPUT, INPUT, "--key", DEMO, "--out-dir", str(tmp_path)]) == 2
    assert not (tmp_path / "adt_sequence.hl7").exists()


def test_never_overwrite_original_or_report_collision(tmp_path):
    original = tmp_path / "input.hl7"
    original.write_bytes(Path(INPUT).read_bytes())
    before = original.read_bytes()
    assert main(["scrub", str(original), "--key", DEMO, "-o", str(original)]) == 2
    assert main(["scrub", str(original), "--key", DEMO, "--report", str(original)]) == 2
    assert original.read_bytes() == before


def test_output_not_written_if_later_input_bad(tmp_path):
    output = tmp_path / "out"
    bad = tmp_path / "bad"
    bad.write_text("NOT HL7")
    assert main(["scrub", INPUT, str(bad), "--key", DEMO, "-o", str(output)]) == 2
    assert not output.exists()


def test_mllp_flag_and_default_strip(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    source = "examples/batch_mllp.hl7"
    assert main(["scrub", source, "--key", DEMO, "-o", str(a), "--mllp"]) == 0
    assert a.read_bytes().startswith(b"\x0b")
    assert a.read_bytes().endswith(b"\x1c\r")
    assert main(["scrub", source, "--key", DEMO, "-o", str(b)]) == 0
    assert b"\x0b" not in b.read_bytes()
    assert b"\x1c" not in b.read_bytes()


def test_stdin_stdout_binary(monkeypatch):
    source = Path("examples/oru_lab.hl7").read_bytes()
    class Stream:
        def __init__(self, data=b""):
            self.buffer = io.BytesIO(data)
    stdin, stdout = Stream(source), Stream()
    monkeypatch.setattr("sys.stdin", stdin)
    monkeypatch.setattr("sys.stdout", stdout)
    assert main(["scrub", "-", "--key", DEMO]) == 0
    assert parse(stdout.buffer.getvalue()).messages[0].get("MSH-9.1") == "ORU"
    assert b"ALICE" not in stdout.buffer.getvalue()


def test_show_contains_field_labels_and_tree(capsys):
    assert main(["show", INPUT]) == 0
    output = capsys.readouterr().out
    assert "Message 1" in output
    assert "PID-5" in output
    assert "Patient Name" in output
    assert "SAMPLE" in output


def test_diff_no_change_and_changed_fields(tmp_path, capsys):
    assert main(["diff", INPUT, INPUT]) == 0
    assert capsys.readouterr().out == ""
    output = tmp_path / "clean"
    assert main(["scrub", INPUT, "--key", DEMO, "-o", str(output)]) == 0
    capsys.readouterr()
    assert main(["diff", INPUT, str(output)]) == 0
    text = capsys.readouterr().out
    assert "PID[1]-5" in text
    assert "SAMPLE^ALICE" in text
    assert " -> " in text


def test_default_policy_dump(capsys):
    assert main(["policy", "--dump-default"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["version"] == 1
    assert data["fields"]["PID-5"]["action"] == "pseudonym"


@pytest.mark.parametrize("argv", [
    ["show", "/nonexistent/fixture.hl7"],
    ["scrub", INPUT, "--key", DEMO, "--date-shift-days", "-1"],
    ["scrub", "-", "-", "--key", DEMO],
    ["scan", "-", "-"],
    ["diff", "-", "-"],
])
def test_io_and_value_errors(argv, capsys):
    assert main(argv) == 2
    assert "error:" in capsys.readouterr().err


def test_strict_warning_exit(tmp_path):
    output = tmp_path / "clean"
    assert main(["scrub", INPUT, "--key", DEMO, "-o", str(output), "--strict"]) == 1
    assert output.exists()


def test_bad_custom_policy(tmp_path):
    policy = tmp_path / "bad.json"
    policy.write_text('{"version":1,"fields":{"PID-5":{"action":"oops"}}}')
    assert main(["scrub", INPUT, "--key", DEMO, "--policy", str(policy)]) == 2


def test_cli_custom_component_policy(tmp_path):
    policy = tmp_path / "custom.json"
    policy.write_text(json.dumps({"version": 1, "fields": {"PID-3[*].1": {"action": "redact", "text": "TOKEN"}}}))
    output = tmp_path / "output"
    assert main(["scrub", INPUT, "--key", DEMO, "--policy", str(policy), "-o", str(output)]) == 0
    assert parse(output.read_bytes()).messages[0].get("PID-3.1") == "TOKEN"
