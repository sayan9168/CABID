"""Command-line interface for CABID."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .audit import parse_audit_raw
from .baseline import build_profile, load_profile, write_profile
from .benchmark import run_benchmark
from .collector import collect_to_jsonl
from .config import ConfigError, config_template, load_config
from .detector import analyze, analyze_windows
from .explain import FORMATS, render, render_json
from .ingest import normalize_many, read_jsonl
from .normalize import EventError
from .policy import PolicyError, evaluate_policy, load_policy
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
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("analyze", help="analyze a JSONL event stream")
    run.add_argument("input")
    run.add_argument("--output", "-o")
    run.add_argument("--format", "-f", choices=FORMATS, help="report format (default: json)")
    run.add_argument("--config", "-c", help="analysis configuration JSON")
    run.add_argument("--baseline", "-b", help="benign baseline profile for novelty scoring")
    run.add_argument("--policy", "-p", help="detection policy JSON (sensitive paths, suppressions)")
    run.add_argument("--window", "-w", type=float, help="also analyze in fixed time windows of N seconds")
    run.add_argument("--fail-on", help="exit 1 when status is at or above this severity")
    run.add_argument("--exit-code", action="store_true", help="map status to an exit code (0/1/2)")
    run.add_argument("--quiet", "-q", action="store_true", help="suppress stdout when --output is used")

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
    return parser


def _cmd_analyze(args) -> int:
    config = load_config(args.config)
    profile = load_profile(args.baseline) if args.baseline else None
    events = read_jsonl(args.input)
    report = analyze(events, config, profile)
    policy = load_policy(args.policy)
    evaluation = evaluate_policy(events, policy, report.get("reasons"))
    if evaluation["reasons_after_suppression"]:
        report["reasons"] = evaluation["reasons_after_suppression"]
    report["policy"] = evaluation
    if args.window:
        report["windowed"] = analyze_windows(events, args.window, config, profile)
    return _emit(report, args)


def _cmd_watch(args) -> int:
    config = load_config(args.config)
    profile = load_profile(args.baseline) if args.baseline else None
    policy = load_policy(args.policy)

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
        iterations=args.iterations, config=config, profile=profile, on_report=emit,
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
        if args.command == "init-config":
            return _cmd_init_config(args)
        raise ValueError(f"unknown command: {args.command}")
    except (OSError, EventError, ConfigError, PolicyError, json.JSONDecodeError, ValueError) as exc:
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
