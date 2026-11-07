"""Rebuild committed synthetic outputs via the public CLI.

Run with PYTHONPATH=src python3 examples/scrub_examples.py from the repository.
The demo key is public; never reuse it for real data. A fixed age reference date
keeps the century-old synthetic birth date reproducible in future years.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    """Regenerate scrubbed fixtures and aggregate report using the documented key."""
    sources = sorted((ROOT / "examples").glob("*.hl7"))
    output = ROOT / "examples" / "scrubbed"
    output.mkdir(exist_ok=True)
    common = ["--key", "demo-key-do-not-use", "--reference-date", "2026-01-01"]
    subprocess.run([sys.executable, "-m", "hl7scrub", "scrub"] + [str(p) for p in sources]
                   + common + ["--out-dir", str(output), "--report", str(output / "report.json")], check=True)
    subprocess.run([sys.executable, "-m", "hl7scrub", "scrub", str(ROOT / "examples" / "batch_mllp.hl7")]
                   + common + ["--mllp", "-o", str(output / "batch_mllp.hl7")], check=True)


if __name__ == "__main__":
    main()
