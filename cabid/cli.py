"""Command-line interface for CABID."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .audit import parse_audit_raw
from .aggregate import IngestError, ingest_sources
from .baseline import build_profile, drift_suggestions, load_profile, write_profile
from .benchmark import run_benchmark
from .collector import collect_to_jsonl
from .config import ConfigError, config_template, load_config
from .detector import analyze, analyze_windows, explain_score, render_score_explanation
from .filters import FilterError, filter_events
from .explain import FORMATS, render, render_json
from .history import DEFAULT_DB, HistoryError, compare_runs, list_runs, record_run
from .ingest import normalize_many, read_jsonl
from .normalize import EventError
from .policy import PolicyError, evaluate_policy, load_policy
from .rules import RuleError, load_rules
from .sigma import SigmaError, import_sigma
from .stix import build_bundle, write_bundle
from .signature import SealError, seal_report, sign_file, verify_file
from .timeline import build_timeline, render_timeline_markdown, render_timeline_text
from .watch import watch_file

EXIT_CODES = {"NO_ANOMALY_DETECTED": 0, "INSUFFICIENT_EVIDENCE": 0, "SUSPICIOUS": 1, "HIGH_RISK": 2}


def _fail(message: str) -> int:
    print(f"cabid: error: {message}", file=sys.stderr)
    return 2


def _fmt_from_path(path: str | None, default: str = "json") -> str:
    if not path:
        return default
    suffix = Path(path).suffix.lower().lstrip(".")
    return {"markdown": "md", "sarif.json": "sarif"}.get(suffix, suffix if suffix in FORMATS else default)


def _emit(report: dict, args, default_format: str = "json") -> int:
    fmt = getattr(args, "format", None) or _fmt_from_path(getattr(args, "output", None), default_format)
    source = getattr(args, "input", "events.jsonl")
    if isinstance(source, (list, tuple)):
        source = ", ".join(str(item) for item in source)
    payload = render(report, fmt, source)
    if getattr(args, "output", None):
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(payload, encoding="utf-8")
        if not getattr(args, "quiet", False):
            sys.stdout.write(f"CABID: report written to {destination}\n")
    else:
        sys.stdout.write(payload)
    if getattr(args, "fail_on", None):
        return _threshold_exit(report, args.fail_on)
    if getattr(args, "exit_code", False):
        return EXIT_CODES.get(report.get("status", ""), 0)
    return 0


def _threshold_exit(report: dict, fail_on: str) -> int:
    order = ["NO_ANOMALY_DETECTED", "INSUFFICIENT_EVIDENCE", "SUSPICIOUS", "HIGH_RISK"]
    if fail_on not in order:
        raise ValueError(f"fail-on must be one of: {', '.join(order)}")
    status = report.get("status") or (report.get("summary") or {}).get("worst_status", "NO_ANOMALY_DETECTED")
    return 1 if order.index(status) >= order.index(fail_on) else 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cabid",
        description="Telemetry-aware Linux behavior analysis (research prototype)",
    )
    parser.add_argument("--version", action="version", version=f"CABID {__version__}")
    # Not required: `cabid` alone should print help and exit 0, the way most CLIs
    # behave. main() handles the missing-command case explicitly.
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("analyze", help="analyze one or more JSONL event streams")
    run.add_argument("input", nargs="+", help="JSONL file(s); multiple files are merged")
    run.add_argument("--output", "-o")
    run.add_argument("--format", "-f", choices=FORMATS, help="report format (default: json)")
    run.add_argument("--config", "-c", help="analysis configuration JSON")
    run.add_argument("--baseline", "-b", help="benign baseline profile for novelty scoring")
    run.add_argument("--policy", "-p", help="detection policy JSON (sensitive paths, suppressions)")
    run.add_argument("--window", "-w", type=float, help="also analyze in fixed time windows of N seconds")
    run.add_argument("--fail-on", help="exit 1 when status is at or above this severity")
    run.add_argument("--exit-code", action="store_true", help="map status to an exit code (0/1/2)")
    run.add_argument("--quiet", "-q", action="store_true", help="suppress stdout when --output is used")
    run.add_argument("--since", help="keep events at or after this time (Unix seconds or ISO-8601)")
    run.add_argument("--until", help="keep events at or before this time (Unix seconds or ISO-8601)")
    run.add_argument("--history-db", default=DEFAULT_DB, metavar="DB",
                     help=f"history database path (default: {DEFAULT_DB})")
    run.add_argument("--save-history", action="store_true",
                     help="record this run in --history-db")
    run.add_argument("--label", default="run", help="label for the history record")
    run.add_argument("--compare-history", type=int, metavar="RUN_ID",
                     help="diff this run against a stored run id")
    run.add_argument("--rules", "-r", help="correlation rule file (default: built-in pack)")
    run.add_argument("--no-rules", action="store_true", help="skip correlation rules entirely")
    run.add_argument("--no-tree", action="store_true", help="skip process-tree reconstruction")
    run.add_argument("--seal-key-env", metavar="VAR",
                     help="HMAC key read from this environment variable when sealing")
    run.add_argument("--sign", action="store_true",
                     help="add an integrity seal to JSON output")
    run.add_argument("--explain-score", action="store_true",
                     help="print the score as arithmetic, term by term")

    tl = sub.add_parser("timeline", help="export a chronological investigation timeline")
    tl.add_argument("input", nargs="+")
    tl.add_argument("--output", "-o")
    tl.add_argument("--format", "-f", choices=("md", "json", "txt"), default="md")
    tl.add_argument("--limit", type=int, default=300)
    tl.add_argument("--config", "-c")
    tl.add_argument("--baseline", "-b")
    tl.add_argument("--policy", "-p")
    tl.add_argument("--rules", "-r")
    tl.add_argument("--since")
    tl.add_argument("--until")

    sig = sub.add_parser("import-sigma", help="translate a Sigma YAML rule into a CABID rule pack")
    sig.add_argument("input", help="Sigma .yml file")
    sig.add_argument("--output", "-o", required=True)
    sig.add_argument("--quiet", "-q", action="store_true")

    export = sub.add_parser("export-stix", help="export a JSON report as a STIX 2.1 bundle")
    export.add_argument("report", help="CABID JSON report")
    export.add_argument("--output", "-o", required=True)
    export.add_argument("--host", default="unknown-host")
    export.add_argument("--quiet", "-q", action="store_true")

    seal = sub.add_parser("seal", help="seal a JSON report or verify an existing seal")
    seal.add_argument("report")
    seal.add_argument("--key-env", metavar="VAR", help="HMAC key from this environment variable")
    seal.add_argument("--verify", action="store_true", help="verify instead of sealing")
    seal.add_argument("--output", "-o")
    seal.add_argument("--quiet", "-q", action="store_true")

    hist = sub.add_parser("history", help="list or inspect recorded runs")
    hist.add_argument("--db", default=DEFAULT_DB)
    hist.add_argument("--limit", type=int, default=20)
    hist.add_argument("--show", type=int, metavar="RUN_ID", help="print the stored summary for a run")
    hist.add_argument("--compare", nargs=2, type=int, metavar=("RUN_A", "RUN_B"),
                      help="diff two stored runs")
    hist.add_argument("--format", "-f", choices=("json", "md"), default="md")

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
    bench.add_argument("--config", "-c", help="analysis configuration JSON")
    bench.add_argument("--baseline", "-b", help="baseline profile for the novelty ablation")
    bench.add_argument("--format", "-f", choices=("json", "md"), default="json")

    profile = sub.add_parser("build-baseline", help="fit a benign baseline profile from labelled sessions")
    profile.add_argument("inputs", nargs="+", help="JSONL files containing benign sessions")
    profile.add_argument("--output", "-o", default="baseline-profile.json")
    profile.add_argument("--min-sessions", type=int, default=3)
    profile.add_argument("--quiet", "-q", action="store_true")

    drift = sub.add_parser(
        "baseline-drift",
        help="suggest baseline profile updates from newer benign sessions")
    drift.add_argument("profile", help="existing baseline profile JSON")
    drift.add_argument("inputs", nargs="+", help="JSONL files of newer benign sessions")
    drift.add_argument("--output", "-o", help="write suggestions here instead of stdout")
    drift.add_argument("--min-support", type=int, default=2,
                       help="sessions that must agree before a suggestion is made (default: 2)")
    drift.add_argument("--quiet", "-q", action="store_true")

    doctor = sub.add_parser("doctor", help="check environment, telemetry sources and configuration")
    doctor.add_argument("--input", help="optional JSONL file to validate")
    doctor.add_argument("--config", "-c")
    doctor.add_argument("--baseline", "-b")
    doctor.add_argument("--policy", "-p")
    doctor.add_argument("--format", "-f", choices=("json", "md"), default="md")

    init = sub.add_parser("init-config", help="write a documented configuration template")
    init.add_argument("--output", "-o", default="cabid-config.json")
    init.add_argument("--force", action="store_true")

    dash = sub.add_parser("dashboard", help="serve the local read-only analysis dashboard")
    dash.add_argument("--host", default="127.0.0.1", help="bind address (default: loopback only)")
    dash.add_argument("--port", type=int, default=8765)
    dash.add_argument("--config", "-c")
    dash.add_argument("--policy", "-p")

    watch = sub.add_parser("watch", help="continuously analyze a growing JSONL file")
    watch.add_argument("input")
    watch.add_argument("--window", "-w", type=float, default=300.0, help="trailing window in seconds")
    watch.add_argument("--interval", type=float, default=2.0, help="seconds between polls")
    watch.add_argument("--iterations", type=int, default=None, help="stop after N polls (default: forever)")
    watch.add_argument("--config", "-c")
    watch.add_argument("--baseline", "-b")
    watch.add_argument("--policy", "-p")
    watch.add_argument("--json", action="store_true", help="emit newline-delimited JSON per poll")
    watch.add_argument("--rules", "-r", help="correlation rule file (default: built-in pack)")
    return parser


def _load_analyze_events(args) -> tuple[list[dict], dict]:
    """Load, merge, and time-filter the analyze inputs."""
    sources_block = None
    if len(args.input) > 1:
        merged = ingest_sources(args.input)
        events = merged.pop("events")
        sources_block = merged
    else:
        events = read_jsonl(args.input[0])
    events, window = filter_events(events, getattr(args, "since", None), getattr(args, "until", None))
    return events, {"sources": sources_block, "time_filter": window}


def _cmd_analyze(args) -> int:
    config = load_config(args.config)
    profile = load_profile(args.baseline) if args.baseline else None
    policy = load_policy(args.policy)
    rules = [] if args.no_rules else load_rules(args.rules)
    events, metadata = _load_analyze_events(args)
    report = analyze(events, config, profile, policy, rules)
    if args.no_tree:
        report.pop("tree", None)
    if args.no_rules:
        report.pop("rules", None)
    evaluation = evaluate_policy(events, policy, report.get("reasons"))
    if evaluation["reasons_after_suppression"]:
        report["reasons"] = evaluation["reasons_after_suppression"]
    report["policy"] = evaluation
    if metadata["sources"]:
        report["sources"] = metadata["sources"]
    report["time_filter"] = metadata["time_filter"]
    if args.window:
        report["windowed"] = analyze_windows(events, args.window, config, profile, policy, rules)
        if args.no_rules:
            for block in (report["windowed"], report["windowed"].get("aggregate") or {}):
                if isinstance(block, dict):
                    block.pop("rules", None)
    if args.compare_history is not None:
        report["history_comparison"] = compare_runs(report, args.compare_history, args.history_db)
    if args.save_history:
        report["history_record"] = {
            "database": str(args.history_db),
            "run_id": record_run(report, args.history_db, args.label, ", ".join(args.input)),
        }
    if args.sign:
        key = _key_from_env(args.seal_key_env)
        report = seal_report(report, key)
    if args.explain_score:
        explanation = explain_score(report, config)
        if args.format in (None, "json"):
            report["score_explanation"] = explanation
        else:
            sys.stderr.write(render_score_explanation(explanation))
    return _emit(report, args)


def _key_from_env(variable: str | None) -> str | None:
    if not variable:
        return None
    import os

    value = os.environ.get(variable)
    if not value:
        raise SealError(f"environment variable {variable} is not set or is empty")
    return value


def _cmd_timeline(args) -> int:
    config = load_config(args.config)
    profile = load_profile(args.baseline) if args.baseline else None
    policy = load_policy(args.policy)
    rules = load_rules(args.rules)
    events, _metadata = _load_analyze_events(args)
    report = analyze(events, config, profile, policy, rules)
    report["policy"] = evaluate_policy(events, policy, report.get("reasons"))
    timeline = build_timeline(events, report, limit=args.limit)
    if args.format == "json":
        payload = render_json(timeline) + "\n"
    elif args.format == "txt":
        payload = render_timeline_text(timeline)
    else:
        payload = render_timeline_markdown(timeline)
    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(payload, encoding="utf-8")
        sys.stdout.write(f"CABID: timeline written to {destination}\n")
    else:
        sys.stdout.write(payload)
    return 0


def _cmd_import_sigma(args) -> int:
    document = import_sigma(args.input)
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    if not args.quiet:
        print(json.dumps(document["provenance"], indent=2, sort_keys=True))
    return 0


def _cmd_export_stix(args) -> int:
    try:
        report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{args.report}: invalid JSON: {exc}") from exc
    destination = write_bundle(report, args.output, args.host, args.report)
    if not args.quiet:
        bundle = build_bundle(report, args.host, args.report)
        kinds: dict[str, int] = {}
        for item in bundle["objects"]:
            kinds[item["type"]] = kinds.get(item["type"], 0) + 1
        print(f"CABID: wrote {destination} ({', '.join(f'{k}={v}' for k, v in sorted(kinds.items()))})")
    return 0


def _cmd_seal(args) -> int:
    key = _key_from_env(args.key_env)
    if args.verify:
        result = verify_file(args.report, key)
        sys.stdout.write(render_json(result) + "\n")
        return 0 if result["verified"] else 1
    seal = sign_file(args.report, key, args.output)
    if not args.quiet:
        sys.stdout.write(render_json(seal) + "\n")
    return 0


def _cmd_history(args) -> int:
    if args.compare:
        first, second = args.compare
        connection_report = {"runs": list_runs(args.db, limit=10)}
        from .history import _connect, _load_row  # local import keeps the module surface small

        connection = _connect(args.db)
        try:
            left = _load_row(connection, first)
            right = _load_row(connection, second)
        finally:
            connection.close()
        payload = {"comparison": _compare_stored(left, right), "context": connection_report}
        if args.format == "json":
            sys.stdout.write(render_json(payload) + "\n")
        else:
            comparison = payload["comparison"]
            sys.stdout.write(f"# CABID history comparison\n\n"
                             f"| Field | Run {first} | Run {second} | Delta |\n| --- | --- | --- | --- |\n"
                             f"| Status | {comparison['left']['status']} | {comparison['right']['status']} | "
                             f"{'changed' if comparison['status_changed'] else 'same'} |\n"
                             f"| Score | {comparison['left']['anomaly_score']:.3f} | "
                             f"{comparison['right']['anomaly_score']:.3f} | {comparison['score_delta']:+.3f} |\n"
                             f"| Events | {comparison['left']['event_count']} | "
                             f"{comparison['right']['event_count']} | "
                             f"{comparison['right']['event_count'] - comparison['left']['event_count']:+d} |\n\n"
                             f"- New reason codes: {', '.join(comparison['new_reason_codes']) or 'none'}\n"
                             f"- Cleared reason codes: {', '.join(comparison['cleared_reason_codes']) or 'none'}\n")
        return 0
    if args.show is not None:
        from .history import _connect, _load_row

        connection = _connect(args.db)
        try:
            row = _load_row(connection, args.show)
        finally:
            connection.close()
        sys.stdout.write(render_json(row) + "\n" if args.format == "json" else
                         f"# Run {row['id']} — {row['label']}\n\n"
                         f"- Created: {row['created_at']}\n- Status: {row['status']}\n"
                         f"- Score: {row['anomaly_score']:.3f}\n- Events: {row['event_count']}\n"
                         f"- Coverage: {row['coverage']:.2f}\n"
                         f"- Reason codes: {', '.join(row['summary'].get('reason_codes') or []) or 'none'}\n")
        return 0
    rows = list_runs(args.db, args.limit)
    if args.format == "json":
        sys.stdout.write(render_json({"db": args.db, "runs": rows}) + "\n")
        return 0
    if not rows:
        sys.stdout.write(f"No runs recorded in {args.db}. Use `cabid analyze --save-history`.\n")
        return 0
    sys.stdout.write(f"# CABID history ({args.db})\n\n| # | When | Label | Status | Score | Events |\n"
                     "| --- | --- | --- | --- | --- | --- |\n")
    for row in rows:
        sys.stdout.write(f"| {row['id']} | {row['created_at']} | {row['label']} | {row['status']} | "
                         f"{row['anomaly_score']:.3f} | {row['event_count']} |\n")
    return 0


def _compare_stored(left: dict, right: dict) -> dict:
    left_codes = [code for code in left["summary"].get("reason_codes", []) if code]
    right_codes = [code for code in right["summary"].get("reason_codes", []) if code]
    return {
        "left": {"id": left["id"], "label": left["label"], "status": left["status"],
                 "anomaly_score": left["anomaly_score"], "event_count": left["event_count"]},
        "right": {"id": right["id"], "label": right["label"], "status": right["status"],
                  "anomaly_score": right["anomaly_score"], "event_count": right["event_count"]},
        "status_changed": left["status"] != right["status"],
        "score_delta": round(right["anomaly_score"] - left["anomaly_score"], 6),
        "new_reason_codes": sorted(set(right_codes) - set(left_codes)),
        "cleared_reason_codes": sorted(set(left_codes) - set(right_codes)),
    }


def _cmd_watch(args) -> int:
    config = load_config(args.config)
    profile = load_profile(args.baseline) if args.baseline else None
    policy = load_policy(args.policy)
    rules = load_rules(args.rules)

    def emit(report: dict) -> None:
        payload = evaluate_policy([], policy, report.get("reasons"))
        report["reasons"] = payload["reasons_after_suppression"] or report.get("reasons", [])
        if args.json:
            sys.stdout.write(render_json(report, pretty=False) + "\n")
        else:
            watch = report["watch"]
            sys.stdout.write(
                f"[{watch['batch']:>3}] {report['status']:<21} score={report['anomaly_score']:.3f} "
                f"events={report['event_count']:<6} buffered={watch['buffered_events']} "
                f"top={report['reasons'][0]['code'] if report['reasons'] else '-'}\n"
            )
        sys.stdout.flush()

    watch_file(
        args.input, window_seconds=args.window, interval=args.interval,
        iterations=args.iterations, config=config, profile=profile, rules=rules,
        on_report=emit,
    )
    return 0


def _cmd_doctor(args) -> int:
    import platform

    checks = []
    config = load_config(args.config)
    checks.append({"check": "configuration", "ok": True,
                   "detail": args.config or "built-in defaults"})
    if args.baseline:
        profile = load_profile(args.baseline)
        checks.append({"check": "baseline profile", "ok": True,
                       "detail": f"{profile.get('session_count')} benign sessions, "
                                 f"{profile.get('event_count')} events"})
    if args.policy:
        policy = load_policy(args.policy)
        checks.append({"check": "policy", "ok": True,
                       "detail": f"{len(policy['sensitive_paths'])} path patterns, "
                                 f"{len(policy['sensitive_ports'])} sensitive ports"})
    proc_ok = Path("/proc/self/stat").exists()
    checks.append({"check": "procfs readable", "ok": proc_ok,
                   "detail": "/proc/self/stat present" if proc_ok else "procfs unavailable; collect-proc will fail"})
    audit_ok = Path("/var/log/audit/audit.log").exists()
    checks.append({"check": "auditd log present", "ok": audit_ok,
                   "detail": "visible to this user" if audit_ok else
                   "not readable (expected without root); import-audit needs an exported file"})
    if args.input:
        events = read_jsonl(args.input)
        report = analyze(events, config)
        checks.append({"check": "input events", "ok": True,
                       "detail": f"{len(events)} events, status {report['status']}, "
                                 f"coverage {report['completeness']['completeness']:.2f}"})
    payload = {
        "cabid_version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "checks": checks,
        "ready": all(item["ok"] for item in checks if item["check"] in {"configuration", "procfs readable"}),
        "notes": ["CABID does not install audit rules, kernel sensors, or background services."],
    }
    if args.format == "json":
        sys.stdout.write(render_json(payload) + "\n")
    else:
        sys.stdout.write(f"# CABID doctor\n\n- CABID {payload['cabid_version']} on Python {payload['python']}\n"
                         f"- Platform: {payload['platform']}\n- Ready: {'yes' if payload['ready'] else 'no'}\n\n"
                         "| Check | OK | Detail |\n| --- | --- | --- |\n")
        for item in checks:
            sys.stdout.write(f"| {item['check']} | {'yes' if item['ok'] else 'no'} | {item['detail']} |\n")
    return 0 if payload["ready"] else 1


def _cmd_build_baseline(args) -> int:
    sessions = []
    for path in args.inputs:
        events = read_jsonl(path)
        if not events:
            raise ValueError(f"{path}: no events found")
        sessions.append((Path(path).stem, events))
    profile = build_profile(sessions, minimum_sessions=args.min_sessions)
    destination = write_profile(profile, args.output)
    if not args.quiet:
        sys.stdout.write(
            f"CABID: baseline profile from {profile['session_count']} sessions "
            f"({profile['event_count']} events) written to {destination}\n"
        )
    return 0


def _cmd_baseline_drift(args) -> int:
    profile = load_profile(args.profile)
    sessions = []
    for path in args.inputs:
        events = read_jsonl(path)
        if not events:
            raise ValueError(f"{path}: no events found")
        sessions.append((Path(path).stem, events))
    result = drift_suggestions(profile, sessions, min_support=args.min_support)
    payload = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(payload, encoding="utf-8")
        if not args.quiet:
            sys.stdout.write(
                f"CABID: {result['suggestion_count']} baseline suggestion(s) from "
                f"{result['sessions_evaluated']} session(s) written to {destination} "
                "(profile unchanged)\n")
    elif not args.quiet:
        sys.stdout.write(payload)
    return 0


def _cmd_init_config(args) -> int:
    destination = Path(args.output)
    if destination.exists() and not args.force:
        raise ValueError(f"{destination} already exists; pass --force to overwrite")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(config_template(), indent=2, sort_keys=False) + "\n",
                           encoding="utf-8")
    sys.stdout.write(f"CABID: wrote configuration template to {destination}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        # Running `cabid` with no subcommand is a request for help, not an error.
        parser.print_help()
        return 0
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
            report = run_benchmark(args.output, args.seed, args.per_class,
                                   config=load_config(args.config),
                                   profile=(load_profile(args.baseline) if args.baseline else None))
            if args.format == "md":
                Path(args.output).with_suffix(".md").write_text(_benchmark_markdown(report), encoding="utf-8")
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
        if args.command == "analyze":
            return _cmd_analyze(args)
        if args.command == "history":
            return _cmd_history(args)
        if args.command == "timeline":
            return _cmd_timeline(args)
        if args.command == "seal":
            return _cmd_seal(args)
        if args.command == "import-sigma":
            return _cmd_import_sigma(args)
        if args.command == "export-stix":
            return _cmd_export_stix(args)
        if args.command == "watch":
            return _cmd_watch(args)
        if args.command == "dashboard":
            from .server import serve

            httpd = serve(args.host, args.port, args.config, args.policy)
            shown = "127.0.0.1" if args.host in {"0.0.0.0", "::"} else args.host
            print(f"CABID: dashboard on http://{shown}:{args.port}/  (Ctrl+C to stop)", flush=True)
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                print("\nCABID: dashboard stopped")
            finally:
                httpd.server_close()
            return 0
        if args.command == "doctor":
            return _cmd_doctor(args)
        if args.command == "build-baseline":
            return _cmd_build_baseline(args)
        if args.command == "baseline-drift":
            return _cmd_baseline_drift(args)
        if args.command == "init-config":
            return _cmd_init_config(args)
        raise ValueError(f"unknown command: {args.command}")
    except (OSError, EventError, ConfigError, PolicyError, HistoryError, IngestError,
            FilterError, RuleError, SealError, SigmaError, json.JSONDecodeError, ValueError) as exc:
        return _fail(str(exc))


def _benchmark_markdown(report: dict) -> str:
    lines = ["# CABID synthetic benchmark", "", f"> {report.get('warning', '')}", ""]
    lines += ["| Model | Precision | Recall | F1 | FPR | False-safe rate | Samples |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for name, metrics in sorted(report.get("models", {}).items()):
        lines.append(
            f"| {name} | {metrics['precision']:.3f} | {metrics['recall']:.3f} | {metrics['f1']:.3f} | "
            f"{metrics['false_positive_rate']:.3f} | {metrics['false_safe_rate']:.3f} | {metrics['sample_count']} |"
        )
    lines += ["", "## Per scenario", "",
              "| Scenario | Precision | Recall | F1 | Samples |", "| --- | --- | --- | --- | --- |"]
    for name, metrics in sorted(report.get("scenario_metrics", {}).items()):
        lines.append(f"| {name} | {metrics['precision']:.3f} | {metrics['recall']:.3f} | "
                     f"{metrics['f1']:.3f} | {metrics['sample_count']} |")
    lines += ["", "Synthetic fixture metrics are software diagnostics, not real-world IDS results."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
