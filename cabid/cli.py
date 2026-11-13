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
from .calibrate import (
    CalibrationError,
    apply_config,
    calibrate,
    compare as compare_thresholds,
    load_calibration,
    write_calibration,
)
from .config import ConfigError, config_template, load_config
from .corpus import CorpusError, catalogue as corpus_catalogue, fetch as corpus_fetch
from .detector import analyze, analyze_windows, explain_score, render_score_explanation
from .alerting import (
    CHANNELS as ALERT_CHANNELS,
    AlertError,
    load_state as load_alert_state,
    send as send_alerts,
    send_from_stream_report,
    write_state as write_alert_state,
)
from .filters import FilterError, filter_events
from .fleet import (
    FleetError,
    collect as collect_fleet,
    compare as compare_fleets,
    render_markdown as render_fleet_markdown,
)
from .explain import FORMATS, render, render_json
from .history import DEFAULT_DB, HistoryError, compare_runs, list_runs, record_run
from .ingest import normalize_many, read_jsonl
from .normalize import EventError
from .novelty import NoveltyError, drift as drift_report, validate as validate_baseline
from .policy import PolicyError, evaluate_policy, load_policy
from .realworld import run_adfa_benchmark
from .rules import RuleError, load_rules
from .executor import ExecutionError, dry_run, execute_plan
from .response import ACTIONS, ResponseError, build_plan, render_plan, write_plan
from .sigma import SigmaError, import_sigma
from .stix import build_bundle, write_bundle
from .streaming import StreamError, stream_file
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

    respond = sub.add_parser(
        "respond",
        help="build a containment plan from a report, or apply one (human gated)")
    respond.add_argument("report", help="a JSON report from `cabid analyze`")
    respond.add_argument("--output", "-o", help="write the plan (JSON) here instead of stdout")
    respond.add_argument("--format", "-f", choices=("text", "json"), default="text")
    respond.add_argument("--allow", metavar="ACTION[,ACTION...]",
                         help="restrict which actions a plan may recommend "
                              f"(available: {', '.join(sorted(ACTIONS))})")
    respond.add_argument("--max-destructive", type=int, default=3,
                         help="at most this many destructive actions per plan (default: 3)")
    respond.add_argument("--history-db", metavar="DB",
                         help="history database used to detect containment loops")
    respond.add_argument("--apply", action="store_true",
                         help="execute a plan's non-emitted actions (requires --confirm)")
    respond.add_argument("--confirm", metavar="PLAN_DIGEST",
                         help="the plan_digest printed by `cabid respond`")
    respond.add_argument("--dry-run", action="store_true",
                         help="with --apply, report what would happen without doing it")
    respond.add_argument("--quarantine-dir", metavar="DIR",
                         help="write evidence copies here (snapshot/quarantine)")
    respond.add_argument("--file", action="append", metavar="PATH",
                         help="a file to quarantine with a quarantine_file decision")
    respond.add_argument("--audit", metavar="PATH",
                         help="audit trail for --apply (default: alongside the report)")
    respond.add_argument("--quiet", "-q", action="store_true")

    corpus = sub.add_parser("corpus", help="list, fetch or verify public benchmark corpora")
    corpus.add_argument("action", nargs="?", choices=("list", "fetch", "verify"), default="list")
    corpus.add_argument("name", nargs="?", help="corpus name (see 'cabid corpus list')")
    corpus.add_argument("--cache", help="cache directory (default: $CABID_CACHE or ~/.cache/cabid)")
    corpus.add_argument("--refresh", action="store_true", help="re-download even if cached")
    corpus.add_argument("--offline", action="store_true", help="never touch the network")

    alert = sub.add_parser(
        "alert",
        help="send findings to Slack, Discord, email or a webhook (dry-run by default)")
    alert.add_argument("reports", nargs="+", help="report JSON files (session or stream)")
    alert.add_argument("--channel", "-C", choices=ALERT_CHANNELS, required=True)
    alert.add_argument("--host", help="host label recorded in the alert")
    alert.add_argument("--minimum", choices=("SUSPICIOUS", "HIGH_RISK", "INSUFFICIENT_EVIDENCE"),
                       default="SUSPICIOUS")
    alert.add_argument("--quiet-seconds", type=float, default=1800.0,
                       help="suppress a repeat of the same finding within this window")
    alert.add_argument("--state", help="JSON file holding suppression state between runs")
    alert.add_argument("--max-per-run", type=int, default=20)
    alert.add_argument("--dashboard-url", help="link included in the alert text")
    alert.add_argument("--email-from", help="sender address (email channel)")
    alert.add_argument("--email-to", help="recipient address (email channel)")
    alert.add_argument("--smtp-host", help="SMTP host (email channel)")
    alert.add_argument("--smtp-port", type=int, default=587)
    alert.add_argument("--smtp-user", help="SMTP username (email channel)")
    alert.add_argument("--no-tls", action="store_true", help="skip STARTTLS (discouraged)")
    alert.add_argument("--send", action="store_true",
                       help="actually deliver; without this the command is a dry run")
    alert.add_argument("--output", "-o", help="write the receipt as JSON")

    fleet = sub.add_parser(
        "fleet",
        help="aggregate or compare reports across many hosts")
    fleet.add_argument("pairs", nargs="*", metavar="HOST=REPORT.json",
                       help="one HOST=REPORT.json argument per host")
    fleet.add_argument("--compare", action="store_true",
                       help="compare two snapshots instead of collecting one")
    fleet.add_argument("--expected", help="file listing expected host names, one per line")
    fleet.add_argument("--baseline", metavar="HOST=REPORT",
                       help="baseline snapshot for compare (repeat by comma)")
    fleet.add_argument("--current", metavar="HOST=REPORT",
                       help="current snapshot for compare (repeat by comma)")
    fleet.add_argument("--format", "-f", choices=("json", "md"), default="json")
    fleet.add_argument("--output", "-o", help="write the fleet report")

    astream = sub.add_parser(
        "analyze-stream",
        help="score a JSONL stream window by window with bounded memory")
    astream.add_argument("input", help="JSONL event stream")
    astream.add_argument("--window-seconds", type=float, default=60.0)
    astream.add_argument("--config", "-c", help="analysis configuration JSON")
    astream.add_argument("--baseline", "-b", help="baseline profile JSON")
    astream.add_argument("--sample-limit", type=int, default=2000)
    astream.add_argument("--output", "-o", help="write the stream report as JSON")

    val = sub.add_parser(
        "validate-baseline",
        help="audit a baseline profile against held-out benign sessions")
    val.add_argument("profile", help="baseline profile JSON")
    val.add_argument("inputs", nargs="+", help="held-out benign JSONL sessions")
    val.add_argument("--min-sessions", type=int, default=20)
    val.add_argument("--novelty-cutoff", type=float, default=0.25)
    val.add_argument("--output", "-o", help="write the validation report as JSON")

    drf = sub.add_parser(
        "drift-report",
        help="compare recent benign sessions against a baseline and propose updates")
    drf.add_argument("profile", help="baseline profile JSON")
    drf.add_argument("inputs", nargs="+", help="recent benign JSONL sessions")
    drf.add_argument("--threshold", type=float, default=0.30)
    drf.add_argument("--novelty-cutoff", type=float, default=0.25)
    drf.add_argument("--output", "-o", help="write the drift report as JSON")

    calib = sub.add_parser(
        "calibrate",
        help="derive thresholds from benign sessions instead of using hand-picked constants")
    calib.add_argument("inputs", nargs="+", help="JSONL files containing benign sessions")
    calib.add_argument("--output", "-o", default="calibration.json")
    calib.add_argument("--config", "-c", help="analysis configuration JSON")
    calib.add_argument("--reference-percentile", type=float, default=0.99,
                       help="benign score percentile used as the suspicious floor")
    calib.add_argument("--high-percentile", type=float, default=0.999)
    calib.add_argument("--mad-multiplier", type=float, default=3.0)
    calib.add_argument("--min-sessions", type=int, default=20)
    calib.add_argument("--compare", metavar="CALIBRATION",
                       help="show how a saved calibration moves the current thresholds")
    calib.add_argument("--apply-to", metavar="CONFIG",
                       help="write a configuration file with the calibrated thresholds applied")

    real = sub.add_parser(
        "benchmark-real",
        help="run the real-world benchmark on a public intrusion corpus")
    real.add_argument("--corpus-cache", help="cache directory holding the fetched corpus")
    real.add_argument("--corpus-root", help="use an already-extracted corpus directory")
    real.add_argument("--window-seconds", type=float, default=20.0)
    real.add_argument("--ngram-size", type=int, default=3)
    real.add_argument("--calibration-fraction", type=float, default=0.25)
    real.add_argument("--calibration-percentile", type=float, default=0.99)
    real.add_argument("--seed", type=int, default=20261113)
    real.add_argument("--config", "-c", help="analysis configuration JSON")
    real.add_argument("--output", "-o", default="results/adfa-realworld.json")
    real.add_argument("--format", "-f", choices=("json", "md"), default="json")
    real.add_argument("--require-verified", action="store_true",
                      help="refuse to run unless the cached archive matches its pinned digest")

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


def _cmd_alert(args) -> int:
    reports = []
    for raw in args.reports:
        path = Path(raw)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"error: {path}: {exc}", file=sys.stderr)
            return 1
        if not isinstance(payload, dict):
            print(f"error: {path}: report must be a JSON object", file=sys.stderr)
            return 1
        reports.append(payload)
    try:
        state = load_alert_state(args.state) if args.state else None
    except AlertError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    common = dict(channel=args.channel, host=args.host, minimum=args.minimum,
                  quiet_seconds=args.quiet_seconds, state=state,
                  max_per_run=args.max_per_run, dashboard_url=args.dashboard_url,
                  email_from=args.email_from, email_to=args.email_to,
                  smtp_host=args.smtp_host, smtp_port=args.smtp_port,
                  smtp_user=args.smtp_user, smtp_tls=not args.no_tls)
    try:
        if args.send:
            receipts = []
            for report in reports:
                if "windows_scored" in report:
                    receipts.append(send_from_stream_report(report, **common))
                else:
                    receipts.append(send_alerts([report], **common))
                common["state"] = state
            receipt = receipts[0] if len(receipts) == 1 else {
                "format": "cabid-alert-receipt/1",
                "aggregate": True,
                "receipts": receipts,
                "sent": sum(item.get("sent", 0) for item in receipts),
                "channel": args.channel,
            }
        else:
            # Dry run is the default so a first integration cannot page anyone. It
            # previews the exact payload and still exercises suppression.
            batched = []
            for report in reports:
                if "windows_scored" in report:
                    batched.append(send_from_stream_report(
                        report, dry_run=True, **common))
                else:
                    batched.append(send_alerts([report], dry_run=True, **common))
                common["state"] = state
            receipt = batched[0] if len(batched) == 1 else {
                "format": "cabid-alert-receipt/1",
                "aggregate": True,
                "receipts": batched,
                "sent": sum(item.get("sent", 0) for item in batched),
                "channel": args.channel,
                "dry_run": True,
            }
    except AlertError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.state and state is not None and args.send:
        write_alert_state(state, args.state)
    text = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0


def _parse_host_pairs(items: list[str]) -> list[tuple[str, str]]:
    pairs = []
    for item in items:
        for chunk in item.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            host, separator, path = chunk.partition("=")
            if not separator or not host or not path:
                raise FleetError(f"expected HOST=REPORT.json, got {chunk!r}")
            pairs.append((host.strip(), path.strip()))
    return pairs


def _cmd_fleet(args) -> int:
    try:
        if not args.compare:
            pairs = _parse_host_pairs(args.pairs)
            expected = None
            if args.expected:
                expected = [line.strip() for line in
                            Path(args.expected).read_text(encoding="utf-8").splitlines()
                            if line.strip()]
            report = collect_fleet(pairs, expected_hosts=expected)
        else:
            baseline = _parse_host_pairs([args.baseline] if args.baseline else [])
            current = _parse_host_pairs([args.current] if args.current else [])
            if not baseline or not current:
                raise FleetError("compare needs --baseline and --current host=report lists")
            before = [_row_from(path, host) for host, path in baseline]
            after = [_row_from(path, host) for host, path in current]
            report = compare_fleets(before, after)
    except (FleetError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    text = (render_fleet_markdown(report) if args.format == "md"
            else json.dumps(report, indent=2, sort_keys=True) + "\n")
    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    return 0


def _row_from(path: str, host: str) -> dict:
    from .fleet import _read_report, host_summary
    return host_summary(_read_report(Path(path)), host=host, path=path)


def _cmd_validate_baseline(args) -> int:
    try:
        profile = load_profile(args.profile)
        sessions = [(Path(raw).name, read_jsonl(raw)) for raw in args.inputs]
        report = validate_baseline(profile, sessions, minimum_sessions=args.min_sessions,
                                   novelty_cutoff=args.novelty_cutoff)
    except (NoveltyError, EventError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["verdict"] != "INVALID" else 1


def _cmd_drift_report(args) -> int:
    try:
        profile = load_profile(args.profile)
        sessions = [(Path(raw).name, read_jsonl(raw)) for raw in args.inputs]
        report = drift_report(profile, sessions, threshold=args.threshold,
                              novelty_cutoff=args.novelty_cutoff)
    except (NoveltyError, EventError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _cmd_calibrate(args) -> int:
    config = load_config(args.config)
    if args.compare:
        try:
            saved = load_calibration(args.compare)
        except CalibrationError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(json.dumps({"comparison": compare_thresholds(config, saved)},
                         indent=2, sort_keys=True))
        return 0
    sessions = []
    for raw in args.inputs:
        path = Path(raw)
        try:
            sessions.append((path.name, read_jsonl(path)))
        except EventError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    try:
        result = calibrate(sessions, reference_percentile=args.reference_percentile,
                           high_percentile=args.high_percentile,
                           mad_multiplier=args.mad_multiplier,
                           config=config, minimum_sessions=args.min_sessions)
        write_calibration(result, args.output)
        if args.apply_to:
            applied = apply_config(result, json.loads(json.dumps(config)))
            applied.update({"$schema": "https://github.com/sayan9168/CABID/blob/main/"
                                        "docs/configuration.md",
                            "format": "cabid-config/1"})
            destination = Path(args.apply_to)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(applied, indent=2, sort_keys=True) + "\n",
                                   encoding="utf-8")
    except CalibrationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _cmd_corpus(args) -> int:
    if args.action == "list":
        print(json.dumps({"format": "cabid-corpus/1", "corpora": corpus_catalogue()},
                         indent=2, sort_keys=True))
        return 0
    if not args.name:
        print("error: a corpus name is required for fetch/verify", file=sys.stderr)
        return 2
    try:
        if args.action == "fetch":
            result = corpus_fetch(args.name, args.cache, refresh=args.refresh,
                                  offline=args.offline)
        else:
            from .corpus import verify as corpus_verify
            result = corpus_verify(args.name, args.cache)
    except CorpusError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _cmd_benchmark_real(args) -> int:
    from .corpus import load_manifest, verify as corpus_verify

    root = args.corpus_root
    cache = None
    if root is None:
        try:
            if args.require_verified:
                checked = corpus_verify("adfa-ld", args.corpus_cache)
                if not checked["verified"]:
                    print(f"error: corpus checksum mismatch: {checked['actual_sha256']}",
                          file=sys.stderr)
                    return 1
            manifest = load_manifest("adfa-ld", args.corpus_cache)
        except CorpusError as exc:
            print(f"error: {exc}\nhint: run 'cabid corpus fetch adfa-ld' first",
                  file=sys.stderr)
            return 1
        root = manifest.get("path")
        cache = {"archive_sha256": manifest.get("archive_sha256"),
                 "source_url": manifest.get("source_url"),
                 "source_commit": manifest.get("source_commit")}
    try:
        report = run_adfa_benchmark(
            root,
            window_seconds=args.window_seconds,
            ngram_size=args.ngram_size,
            calibration_fraction=args.calibration_fraction,
            calibration_percentile=args.calibration_percentile,
            seed=args.seed,
            config=load_config(args.config),
        )
    except (ValueError, ConfigError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if cache is not None:
        report["corpus"].update({k: v for k, v in cache.items() if v})
    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.format == "md":
        markdown = Path(args.output).with_suffix(".md")
        markdown.parent.mkdir(parents=True, exist_ok=True)
        markdown.write_text(_realworld_markdown(report), encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


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


def _cmd_respond(args) -> int:
    report_path = Path(args.report)
    report = json.loads(report_path.read_text(encoding="utf-8"))

    if args.apply:
        return _apply_plan(args, report_path, report)

    allowed = None
    if args.allow:
        allowed = tuple(part.strip() for part in args.allow.split(",") if part.strip())
        unknown = sorted(set(allowed) - set(ACTIONS))
        if unknown:
            raise ResponseError(f"unknown actions: {', '.join(unknown)}")
    history = _containment_history(args.history_db) if args.history_db else None
    plan = build_plan(report, allowed_actions=allowed, max_actions=args.max_destructive,
                      known_containments=history)
    if args.output:
        destination = write_plan(plan, args.output)
        if not args.quiet:
            if args.format == "json":
                sys.stdout.write(json.dumps(plan, indent=2, sort_keys=True) + "\n")
            else:
                sys.stdout.write(render_plan(plan))
            sys.stdout.write(f"\nCABID: plan written to {destination}\n")
    elif args.format == "json":
        sys.stdout.write(json.dumps(plan, indent=2, sort_keys=True) + "\n")
    else:
        sys.stdout.write(render_plan(plan))
    return 0


def _containment_history(path: str) -> list[dict]:
    """Prior containments recorded in the history database's response table."""
    from .history import HistoryError, list_containments

    try:
        return list_containments(path)
    except HistoryError as exc:
        raise ResponseError(str(exc)) from exc


def _apply_plan(args, report_path: Path, report: dict) -> int:
    # A plan must be reviewed as a file: applying one from memory defeats the
    # point of the digest, and there is nothing to compare against on disk.
    plan_path = report_path.with_suffix(".response.json")
    if not plan_path.is_file():
        raise ResponseError(
            f"{plan_path} does not exist; run `cabid respond {report_path} -o {plan_path}` "
            "and review it before applying")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    audit_path = Path(args.audit) if args.audit else report_path.with_suffix(".response-audit.jsonl")

    if args.dry_run:
        result = dry_run(plan)
        sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
        return 0

    if not args.confirm:
        raise ResponseError(
            "refusing to apply without --confirm <plan_digest>; "
            f"the plan is {plan.get('plan_digest')}")
    result = execute_plan(plan, args.confirm, audit_path,
                          quarantine_dir=args.quarantine_dir, file_paths=args.file)
    _record_containments(args, result, report)
    if args.format == "json" or not args.quiet:
        sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0


def _record_containments(args, result: dict, report: dict) -> None:
    """Remember what was contained so a loop can be detected next time."""
    from .history import record_containment

    path = args.history_db or DEFAULT_DB
    for step in result.get("steps") or []:
        if step.get("status") in {"sent", "quarantined", "captured"}:
            try:
                record_containment(path, step["process_id"], step["action"],
                                   report.get("config_digest"))
            except ValueError:
                # History is a convenience, not a precondition for responding.
                continue


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
        if args.command == "alert":
            return _cmd_alert(args)
        if args.command == "fleet":
            return _cmd_fleet(args)
        if args.command == "analyze-stream":
            try:
                report = stream_file(args.input, window_seconds=args.window_seconds,
                                     config=load_config(args.config),
                                     profile=load_profile(args.baseline) if args.baseline else None,
                                     sample_limit=args.sample_limit)
            except (StreamError, ValueError, ConfigError) as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            if args.output:
                destination = Path(args.output)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                       encoding="utf-8")
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0
        if args.command == "validate-baseline":
            return _cmd_validate_baseline(args)
        if args.command == "drift-report":
            return _cmd_drift_report(args)
        if args.command == "calibrate":
            return _cmd_calibrate(args)
        if args.command == "corpus":
            return _cmd_corpus(args)
        if args.command == "benchmark-real":
            return _cmd_benchmark_real(args)
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
        if args.command == "respond":
            return _cmd_respond(args)
        if args.command == "init-config":
            return _cmd_init_config(args)
        raise ValueError(f"unknown command: {args.command}")
    except (OSError, EventError, ConfigError, PolicyError, HistoryError, IngestError,
            FilterError, RuleError, SealError, SigmaError, ResponseError, ExecutionError,
            json.JSONDecodeError, ValueError) as exc:
        return _fail(str(exc))


def _realworld_markdown(report: dict) -> str:
    corpus = report.get("corpus", {})
    lines = ["# CABID real-world benchmark (ADFA-LD)", ""]
    lines.append("> Real public corpus, but a 2013 syscall-trace dataset with no timestamps,")
    lines.append("> pids or paths. These numbers measure pipeline behaviour on that data;")
    lines.append("> they are not evidence of real-world intrusion detection quality.")
    lines.append("")
    counts = corpus.get("trace_counts", {})
    lines.append(f"Corpus traces: {counts.get('training', '?')} training, "
                 f"{counts.get('validation', '?')} validation, {counts.get('attack', '?')} attack.")
    lines.append("")
    lines += ["| Model | Precision | Recall | F1 | FPR | Samples |", "| --- | --- | --- | --- | --- | --- |"]
    for name, values in sorted(report.get("models", {}).items()):
        lines.append(f"| {name} | {values['precision']:.3f} | {values['recall']:.3f} | "
                     f"{values['f1']:.3f} | {values['false_positive_rate']:.3f} | "
                     f"{values['sample_count']} |")
    recall_ci = report.get("models", {}).get("cabid_with_baseline", {}).get("recall_ci95")
    if recall_ci:
        lines += ["", f"95% Wilson interval on CABID recall: {recall_ci[0]:.3f} to {recall_ci[1]:.3f}."]
    separation = report.get("score_separation", {})
    if separation:
        lines += ["", f"Threshold-free separation (AUC): CABID anomaly score "
                      f"{separation.get('cabid_anomaly_score_auc')}, "
                      f"syscall n-gram {separation.get('syscall_ngram_auc')}."]
    coverage = report.get("coverage", {})
    if coverage:
        lines += ["", f"Traces the event mapping could not represent: "
                      f"{coverage.get('unmappable_attack_traces')} attack, "
                      f"{coverage.get('unmappable_benign_traces')} benign. "
                      "These are counted as undetected."]
    lines += ["", "## Limitations", ""]
    lines += [f"- {item}" for item in report.get("limitations", [])]
    return "\n".join(lines) + "\n"


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
