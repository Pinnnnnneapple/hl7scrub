"""Command-line interface. stdout is reserved for requested data."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import tempfile
from datetime import date
from pathlib import Path
from typing import List, Optional

from . import __version__
from .display import diff, show
from .engine import Scrubber
from .model import ParseError, parse
from .policy import default_policy, load_policy
from .scanner import scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hl7scrub", description="Structure-aware HL7 v2 pseudonymisation. Expert review remains necessary.")
    parser.add_argument("--version", action="version", version="hl7scrub " + __version__)
    sub = parser.add_subparsers(dest="command", required=True)
    scrub = sub.add_parser("scrub", help="Pseudonymise messages with a secret key")
    scrub.add_argument("inputs", nargs="+", metavar="IN")
    output = scrub.add_mutually_exclusive_group()
    output.add_argument("-o", "--output", metavar="OUT", help="Output file; default stdout, '-' also means stdout")
    output.add_argument("--out-dir", type=Path, metavar="DIR")
    scrub.add_argument("--policy", type=Path)
    key = scrub.add_mutually_exclusive_group()
    key.add_argument("--key", help="Secret (prefer environment/key-file to avoid shell history)")
    key.add_argument("--key-file", type=Path)
    key.add_argument("--random-key", action="store_true", help="Use an ephemeral random secret; never print it")
    scrub.add_argument("--date-shift-days", type=int, default=30, metavar="N")
    scrub.add_argument("--reference-date", type=date.fromisoformat, metavar="YYYY-MM-DD", help="Fixed reference for age capping (default today)")
    scrub.add_argument("--mllp", action="store_true", help="Wrap each output transmission in MLLP (otherwise strip framing)")
    scrub.add_argument("--report", type=Path, metavar="JSON")
    scrub.add_argument("--strict", action="store_true", help="Exit 1 on parsing or policy warnings; output is still produced")
    inspect = sub.add_parser("show", help="Display a labelled tree; contains input values")
    inspect.add_argument("file")
    inspect.add_argument("--strict", action="store_true")
    compare = sub.add_parser("diff", help="Print field-level changes; contains input values")
    compare.add_argument("a")
    compare.add_argument("b")
    policy = sub.add_parser("policy", help="Print the built-in policy JSON")
    policy.add_argument("--dump-default", action="store_true", required=True)
    scanner = sub.add_parser("scan", help="Flag likely residual PHI; findings contain positions only")
    scanner.add_argument("files", nargs="+")
    scanner.add_argument("--strict", action="store_true")
    return parser


def _read(path: str) -> bytes:
    if path == "-":
        stream = getattr(sys.stdin, "buffer", sys.stdin)
        value = stream.read()
        return value.encode("utf-8", "surrogateescape") if isinstance(value, str) else value
    return Path(path).read_bytes()


def _stdout(data: bytes) -> None:
    stream = getattr(sys.stdout, "buffer", None)
    if stream is not None:
        stream.write(data)
        stream.flush()
    else:
        sys.stdout.write(data.decode("utf-8", "surrogateescape"))


def _write(path: Path, data: bytes) -> None:
    # Replace complete outputs atomically and restrict newly created files to
    # the current user. Failed writes do not leave partially scrubbed fixtures.
    descriptor, temporary = tempfile.mkstemp(prefix=".hl7scrub-", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _scrub(args: argparse.Namespace) -> int:
    if args.date_shift_days < 0:
        raise ValueError("--date-shift-days must be nonnegative")
    if args.inputs.count("-") > 1:
        raise ValueError("stdin may only be read once")
    if args.key is not None:
        key = args.key.encode("utf-8")
    elif args.key_file is not None:
        key = args.key_file.read_bytes().rstrip(b"\r\n")
    elif args.random_key:
        key = secrets.token_bytes(32)
    else:
        key = os.environ.get("HL7SCRUB_KEY", "").encode("utf-8")
    if not key:
        raise ValueError("A nonempty --key, --key-file, HL7SCRUB_KEY, or --random-key is required")
    policy = load_policy(args.policy)
    scrubber = Scrubber(key, policy, args.date_shift_days, args.reference_date)
    inputs = [Path(p).resolve() for p in args.inputs if p != "-"]
    destinations: List[Path] = []
    if args.out_dir:
        destinations = [args.out_dir / (Path(p).name if p != "-" else "stdin.hl7") for p in args.inputs]
        if len({p.resolve() for p in destinations}) != len(destinations):
            raise ValueError("Input basenames collide in --out-dir")
    elif args.output and args.output != "-":
        destinations = [Path(args.output)]
    if any(p.resolve() in inputs for p in destinations):
        raise ValueError("Output would overwrite an input; choose another path")
    if args.report and (args.report.resolve() in inputs or args.report.resolve() in [p.resolve() for p in destinations]):
        raise ValueError("Report path must differ from inputs and outputs")
    # Parse and transform every input before writing anything, including stdout.
    outputs = [scrubber.scrub(_read(p)).to_bytes(mllp=args.mllp) for p in args.inputs]
    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        for path, data in zip(destinations, outputs):
            _write(path, data)
    else:
        data = b""
        for output in outputs:
            if data and output and data[-1:] not in (b"\r", b"\n") and output[:1] != b"\x0b":
                data += b"\r"
            data += output
        if destinations:
            _write(destinations[0], data)
        else:
            _stdout(data)
    if args.report:
        _write(args.report, (json.dumps(scrubber.report.to_dict(), indent=2, sort_keys=True) + "\n").encode("utf-8"))
    for warning in scrubber.report.warnings:
        print("hl7scrub: warning: " + warning, file=sys.stderr)
    return 1 if args.strict and scrubber.report.warnings else 0


def main(argv: Optional[List[str]] = None) -> int:
    """Run the CLI and return 0 (success), 1 (findings/warnings), or 2 (error)."""
    try:
        args = _parser().parse_args(argv)
    except SystemExit as error:
        return int(error.code)
    try:
        if args.command == "scrub":
            return _scrub(args)
        if args.command == "policy":
            print(json.dumps(default_policy(), indent=2, sort_keys=True))
            return 0
        if args.command == "show":
            document = parse(_read(args.file))
            sys.stdout.write(show(document))
            return 1 if args.strict and document.warnings else 0
        if args.command == "diff":
            if args.a == "-" and args.b == "-":
                raise ValueError("stdin may only be read once")
            for item in diff(_read(args.a), _read(args.b)):
                print(item["path"] + "\t" + json.dumps(item["old"], ensure_ascii=True) + " -> " + json.dumps(item["new"], ensure_ascii=True))
            return 0
        if args.command == "scan":
            if args.files.count("-") > 1:
                raise ValueError("stdin may only be read once")
            found = False
            for index, filename in enumerate(args.files, 1):
                document = parse(_read(filename))
                findings = scan(document)
                for finding in findings:
                    print("input=" + str(index) + " message=" + str(finding["message"]) + " segment=" + str(finding["segment"]) + " " + str(finding["path"]) + " " + str(finding["category"]))
                found = found or bool(findings) or (args.strict and bool(document.warnings))
            return 1 if found else 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        # Never include a key, raw input, or parser exception payload in errors.
        if isinstance(error, OSError):
            print("hl7scrub: error: input/output operation failed (" + str(error.errno) + ")", file=sys.stderr)
        elif isinstance(error, ParseError):
            print("hl7scrub: error: invalid HL7 input: " + str(error), file=sys.stderr)
        else:
            print("hl7scrub: error: " + str(error), file=sys.stderr)
        return 2
    return 0
