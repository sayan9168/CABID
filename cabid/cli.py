"""Command-line interface for CABID."""
import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .audit import parse_audit_raw
from .benchmark import run_benchmark
from .collector import collect_to_jsonl
from .detector import analyze
from .explain import render_report
from .ingest import normalize_many, read_jsonl
from .normalize import EventError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cabid", description="Telemetry-aware Linux behavior analysis (research prototype)")
    parser.add_argument("--version", action="version", version=f"CABID {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("analyze", help="analyze a JSONL event stream")
    run.add_argument("input")
    run.add_argument("--output", "-o")
    collect = sub.add_parser("collect-proc", help="poll visible Linux process metadata from /proc")
    collect.add_argument("--output", "-o", required=True)
    collect.add_argument("--interval", type=float, default=2.0)
    collect.add_argument("--duration", type=float, default=30.0)
    audit = sub.add_parser("import-audit", help="convert selected ausearch raw records to CABID JSONL")
    audit.add_argument("input", help="file exported with ausearch --format raw")
    audit.add_argument("--output", "-o", required=True)
    audit.add_argument("--report", help="optional parser summary JSON path")
    bench = sub.add_parser("benchmark", help="run deterministic synthetic benchmark")
    bench.add_argument("--output", "-o", default="results/synthetic-benchmark.json")
    bench.add_argument("--seed", type=int, default=20261113)
    bench.add_argument("--per-class", type=int, default=50)
    args = parser.parse_args(argv)
    try:
        if args.command == "collect-proc":
            count = collect_to_jsonl(args.output, args.interval, args.duration)
            print(f"CABID: wrote {count} observations to {args.output}")
            return 0
        if args.command == "import-audit":
            with Path(args.input).open("r", encoding="utf-8", errors="replace") as handle:
                parsed = parse_audit_raw(handle.readlines())
            normalized = normalize_many(parsed["events"])
            destination = Path(args.output)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("w", encoding="utf-8") as handle:
                for event in normalized:
                    handle.write(json.dumps(event, sort_keys=True) + "\n")
            summary = {key: value for key, value in parsed.items() if key != "events"}
            summary["normalized_events_written"] = len(normalized)
            if args.report:
                report_path = Path(args.report)
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(json.dumps(summary, indent=2, sort_keys=True))
            return 0
        if args.command == "benchmark":
            report = run_benchmark(args.output, args.seed, args.per_class)
            print(json.dumps(report, indent=2, sort_keys=True))
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
