"""Command-line interface for CABID."""
import argparse
import json
import sys

from . import __version__
from .collector import collect_to_jsonl
from .detector import analyze
from .explain import render_report
from .ingest import read_jsonl
from .normalize import EventError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cabid",
        description="Telemetry-aware Linux behavior analysis (research prototype)",
    )
    parser.add_argument("--version", action="version", version=f"CABID {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("analyze", help="analyze a JSONL event stream")
    run.add_argument("input", help="path to JSON Lines event file")
    run.add_argument("--output", "-o", help="write report to this path instead of stdout")

    collect = sub.add_parser("collect-proc", help="poll visible Linux process metadata from /proc (best effort)")
    collect.add_argument("--output", "-o", required=True, help="append observations to this JSONL file")
    collect.add_argument("--interval", type=float, default=2.0, help="poll interval in seconds (default: 2)")
    collect.add_argument("--duration", type=float, default=30.0, help="collection duration in seconds (default: 30)")

    args = parser.parse_args(argv)
    try:
        if args.command == "collect-proc":
            count = collect_to_jsonl(args.output, args.interval, args.duration)
            print(f"CABID: wrote {count} observations to {args.output}")
            return 0
        output = render_report(analyze(read_jsonl(args.input))) + "\n"
        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(output)
        else:
            sys.stdout.write(output)
        return 0
    except (OSError, EventError, json.JSONDecodeError, ValueError) as exc:
        print(f"cabid: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
