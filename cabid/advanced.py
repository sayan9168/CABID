"""Additional defensive research utilities for CABID.

These utilities are offline-first. They do not block processes, modify files,
or send telemetry to third parties.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import platform
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


def _jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows = []
    with Path(path).open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{number}: invalid JSON: {exc}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"{path}:{number}: each JSONL row must be an object")
            rows.append(item)
    return rows


def _write(data: Any, output: str | None) -> None:
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if output:
        target = Path(output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(payload, encoding="utf-8")
    else:
        sys.stdout.write(payload)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fim_snapshot(root: str, output: str) -> dict[str, Any]:
    base = Path(root).resolve(strict=True)
    if not base.is_dir():
        raise ValueError("FIM root must be a directory")
    entries = []
    for path in sorted(base.rglob("*")):
        rel = path.relative_to(base).as_posix()
        if path.is_symlink():
            entries.append({"path": rel, "type": "symlink", "target": os.readlink(path)})
        elif path.is_file():
            stat = path.stat()
            entries.append({"path": rel, "type": "file", "size": stat.st_size,
                            "mode": stat.st_mode & 0o777, "sha256": _sha256(path)})
        elif path.is_dir():
            entries.append({"path": rel, "type": "directory"})
    manifest = {"schema": "cabid-fim/1", "root": str(base), "created_unix": time.time(),
                "algorithm": "sha256", "entries": entries}
    _write(manifest, output)
    return manifest


def fim_verify(root: str, manifest_path: str) -> dict[str, Any]:
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    if manifest.get("schema") != "cabid-fim/1":
        raise ValueError("unsupported FIM manifest schema")
    base = Path(root).resolve(strict=True)
    changed, missing, added = [], [], []
    expected = {item["path"]: item for item in manifest.get("entries", [])}
    actual = set()
    for rel, item in expected.items():
        candidate = (base / rel)
        try:
            candidate.resolve(strict=False).relative_to(base)
        except ValueError:
            changed.append({"path": rel, "reason": "path escapes selected root"})
            continue
        if not candidate.exists() and not candidate.is_symlink():
            missing.append(rel)
            continue
        actual.add(rel)
        if item["type"] == "file":
            if not candidate.is_file() or candidate.is_symlink():
                changed.append({"path": rel, "reason": "type changed"})
            elif _sha256(candidate) != item["sha256"]:
                changed.append({"path": rel, "reason": "sha256 changed"})
        elif item["type"] == "symlink":
            if not candidate.is_symlink() or os.readlink(candidate) != item["target"]:
                changed.append({"path": rel, "reason": "symlink changed"})
        elif item["type"] == "directory" and not candidate.is_dir():
            changed.append({"path": rel, "reason": "directory missing or changed"})
    for path in base.rglob("*"):
        rel = path.relative_to(base).as_posix()
        if rel not in expected:
            added.append(rel)
    return {"schema": "cabid-fim-result/1", "root": str(base), "clean": not (changed or missing or added),
            "changed": changed, "missing": missing, "added": sorted(added),
            "summary": {"changed": len(changed), "missing": len(missing), "added": len(added)}}


def sensor_health(input_path: str, expected_interval: float) -> dict[str, Any]:
    if expected_interval <= 0:
        raise ValueError("expected interval must be positive")
    rows = _jsonl(input_path)
    timestamps = []
    types = Counter()
    malformed = 0
    for row in rows:
        try:
            stamp = float(row["timestamp"])
            if stamp < 0:
                raise ValueError
            timestamps.append(stamp)
            types[str(row.get("event_type", "unknown"))] += 1
        except (KeyError, TypeError, ValueError):
            malformed += 1
    timestamps.sort()
    gaps = []
    for left, right in zip(timestamps, timestamps[1:]):
        delta = right - left
        if delta > expected_interval * 2:
            gaps.append({"from": left, "to": right, "seconds": round(delta, 3)})
    return {"schema": "cabid-health/1", "events": len(rows), "valid_timestamps": len(timestamps),
            "malformed": malformed, "event_types": dict(types), "timestamp_gaps": gaps,
            "health": "DEGRADED" if malformed or gaps else ("UNKNOWN" if not rows else "NO_GAPS_OBSERVED"),
            "note": "Timestamp gaps are indicators, not proof of kernel event loss; a source sequence counter is required for exact drop accounting."}


def correlate(input_path: str, window_seconds: float) -> dict[str, Any]:
    if window_seconds <= 0:
        raise ValueError("window must be positive")
    rows = sorted(_jsonl(input_path), key=lambda x: float(x.get("timestamp", 0)))
    by_pid: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_pid[str(row.get("process_id", "unknown"))].append(row)
    findings = []
    for pid, events in by_pid.items():
        events.sort(key=lambda x: float(x.get("timestamp", 0)))
        for i, first in enumerate(events):
            start = float(first.get("timestamp", 0))
            group = [e for e in events[i:] if 0 <= float(e.get("timestamp", 0)) - start <= window_seconds]
            kinds = {str(e.get("event_type", "")) for e in group}
            chain = []
            if "process_exec" in kinds and "network_connect" in kinds:
                chain.append("execution_then_network_activity")
            if "process_exec" in kinds and "file_write" in kinds:
                chain.append("execution_then_file_write")
            if {"network_connect", "file_write"} <= kinds:
                chain.append("network_and_file_activity")
            for name in chain:
                findings.append({"rule": name, "process_id": pid, "window_start": start,
                                 "window_seconds": window_seconds,
                                 "event_ids": [e.get("event_id") for e in group if e.get("event_id")],
                                 "evidence_types": sorted(kinds),
                                 "confidence": "low",
                                 "caveat": "Co-occurrence is not causation; corroborate with process ancestry and host context."})
    # De-duplicate identical rule/pid/window tuples.
    unique = {(f["rule"], f["process_id"], f["window_start"]): f for f in findings}
    result = list(unique.values())
    return {"schema": "cabid-correlation/1", "finding_count": len(result), "findings": result,
            "note": "Heuristic triage only; no finding is proof of compromise."}


def intel_match(input_path: str, indicators_path: str) -> dict[str, Any]:
    indicators = json.loads(Path(indicators_path).read_text(encoding="utf-8"))
    hashes = set(indicators.get("sha256", []))
    ips = set(indicators.get("ips", []))
    domains = set(indicators.get("domains", []))
    matches = []
    for row in _jsonl(input_path):
        candidates = []
        for field in ("sha256", "remote_ip", "destination_ip", "domain", "hostname"):
            value = str(row.get(field, "")).lower()
            if not value:
                continue
            if field == "sha256" and value in hashes:
                candidates.append({"type": "sha256", "value": value})
            elif field in ("remote_ip", "destination_ip") and value in ips:
                candidates.append({"type": "ip", "value": value})
            elif field in ("domain", "hostname") and value in domains:
                candidates.append({"type": "domain", "value": value})
        if candidates:
            matches.append({"event": row, "indicators": candidates})
    return {"schema": "cabid-intel-match/1", "matches": matches, "match_count": len(matches),
            "source": "local-user-supplied-indicators", "note": "Exact matches only; no reputation is inferred."}


def explain(report_path: str) -> dict[str, Any]:
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    reasons = report.get("reasons", [])
    return {"schema": "cabid-explanation/1", "status": report.get("status", "UNKNOWN"),
            "anomaly_score": report.get("anomaly_score"), "event_count": report.get("event_count"),
            "evidence": reasons, "limitations": report.get("limitations", []),
            "interpretation": "Evidence summary only. Validate source coverage and investigate the underlying events."}


def benchmark_dashboard(input_path: str, output: str) -> None:
    data = json.loads(Path(input_path).read_text(encoding="utf-8"))
    models = data.get("models", {})
    rows = []
    for name, metrics in sorted(models.items()):
        rows.append("<tr>" + "".join("<td>" + html.escape(str(value)) + "</td>" for value in
                    (name, metrics.get("precision", ""), metrics.get("recall", ""),
                     metrics.get("f1", ""), metrics.get("false_positive_rate", ""))) + "</tr>")
    page = """<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>CABID benchmark</title><style>body{font:16px system-ui;max-width:900px;margin:3rem auto;padding:0 1rem}
table{border-collapse:collapse;width:100%}td,th{padding:.7rem;border-bottom:1px solid #bbb;text-align:left}</style>
<h1>CABID benchmark dashboard</h1><p>Metrics are copied from the supplied JSON report; synthetic results are not real-world efficacy claims.</p>
<table><thead><tr><th>Model</th><th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th></tr></thead><tbody>""" + "".join(rows) + "</tbody></table>"
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(page, encoding="utf-8")


def reproducibility_manifest(inputs: Iterable[str], output: str) -> dict[str, Any]:
    files = []
    for name in inputs:
        path = Path(name).resolve(strict=True)
        if not path.is_file():
            raise ValueError(f"not a file: {name}")
        files.append({"path": str(path), "size": path.stat().st_size, "sha256": _sha256(path)})
    result = {"schema": "cabid-reproducibility/1", "python": sys.version,
              "platform": platform.platform(), "inputs": files,
              "limitations": ["Does not capture Git commit, dependency lock state, kernel config, or hardware counters."]}
    _write(result, output)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cabid-research", description="Offline CABID research utilities")
    sub = parser.add_subparsers(dest="action", required=True)
    snap = sub.add_parser("fim-snapshot"); snap.add_argument("root"); snap.add_argument("-o", "--output", required=True)
    verify = sub.add_parser("fim-verify"); verify.add_argument("root"); verify.add_argument("manifest")
    health = sub.add_parser("health"); health.add_argument("input"); health.add_argument("--expected-interval", type=float, default=2.0)
    corr = sub.add_parser("correlate"); corr.add_argument("input"); corr.add_argument("--window", type=float, default=60.0)
    intel = sub.add_parser("intel-match"); intel.add_argument("input"); intel.add_argument("indicators")
    exp = sub.add_parser("explain"); exp.add_argument("report")
    dash = sub.add_parser("benchmark-dashboard"); dash.add_argument("input"); dash.add_argument("-o", "--output", required=True)
    repro = sub.add_parser("reproduce"); repro.add_argument("inputs", nargs="+"); repro.add_argument("-o", "--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "fim-snapshot": _write(fim_snapshot(args.root, args.output), None)
        elif args.action == "fim-verify": _write(fim_verify(args.root, args.manifest), None)
        elif args.action == "health": _write(sensor_health(args.input, args.expected_interval), None)
        elif args.action == "correlate": _write(correlate(args.input, args.window), None)
        elif args.action == "intel-match": _write(intel_match(args.input, args.indicators), None)
        elif args.action == "explain": _write(explain(args.report), None)
        elif args.action == "benchmark-dashboard": benchmark_dashboard(args.input, args.output); print(f"wrote {args.output}")
        elif args.action == "reproduce": _write(reproducibility_manifest(args.inputs, args.output), None)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"cabid-research: error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
