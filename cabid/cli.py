"""Command-line interface for CABID."""
import argparse
import json
import sys
from . import __version__
from .detector import analyze
from .explain import render_report
from .ingest import read_jsonl
from .normalize import EventError

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cabid", description="Telemetry-aware Linux behavior analysis (research prototype)")
    parser.add_argument("--version", action="version", version=f"CABID {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("analyze", help="analyze a JSONL event stream")
    run.add_argument("input", help="path to JSON Lines event file")
    run.add_argument("--output", "-o", help="write report to this path instead of stdout")
    args = parser.parse_args(argv)
    try:
        output = render_report(analyze(read_jsonl(args.input))) + "\n"
        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle: handle.write(output)
        else:
            sys.stdout.write(output)
        return 0
    except (OSError, EventError, json.JSONDecodeError) as exc:
        print(f"cabid: error: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
