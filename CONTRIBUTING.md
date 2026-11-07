# Contributing

Use Python 3.9 or newer. Runtime code uses only the Python standard library.

Create a virtual environment, then install the project and test extra:

```console
python -m venv .venv
python -m pip install -e ".[dev]"
python -m pytest
```

Activate the environment using the command appropriate for your shell before
installing. Keep runtime dependencies out of the package unless an agreed change
requires them. Put package code under `src/hl7scrub` and tests under `tests`.

All example data must be 100% fictitious. Never submit real patient messages,
identifiers, credentials, or production logs in code, issues, or pull requests.
Use invented names and identifiers, reserved example email domains, 555-01xx
telephone numbers, and invalid SSNs with area 900.

Regenerate committed example inputs from the repository root:

```console
python examples/generate_examples.py
PYTHONPATH=src python3 examples/scrub_examples.py
```

The generator has no package dependency, writes bytes deterministically, and uses
HL7 carriage-return segment separators. Do not let an editor normalize fixture
line endings. Extend the generator when changing an input fixture; do not edit
generated inputs by hand. The second command rebuilds scrubbed outputs and the aggregate report using the public demo key and a fixed age reference date.

For a pull request, describe the behavior change and relevant validation. Include
regression coverage for parser, delimiter, framing, privacy, or CLI changes.
Check consistency across messages for repeat patient identifiers. Review free
text, uncommon segments, and attachments when changing scrubbing behavior.

Report suspected security issues without posting sensitive data. A minimal,
entirely synthetic reproducer is sufficient for public reports.
