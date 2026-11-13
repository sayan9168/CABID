"""Report renderers: stable JSON, human Markdown, CSV and SARIF 2.1.0.

Every renderer is dependency-free and deterministic so that reports can be
diffed between runs. Markdown and HTML output escape collected event content
(paths, names from untrusted logs) before embedding it.
"""
from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path

from . import __version__

FORMATS = ("json", "md", "csv", "sarif", "html")
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SEVERITY = {"HIGH_RISK": "error", "SUSPICIOUS": "warning", "INSUFFICIENT_EVIDENCE": "note"}
_SARIF_LEVEL = {"HIGH_RISK": "error", "SUSPICIOUS": "warning", "INSUFFICIENT_EVIDENCE": "note"}

_RULE_HELP = {
    "temporal_rate_or_burst": "Event rate or inter-arrival burstiness exceeded the configured bound.",
    "self_parent_ancestry": "A process reported itself as its own parent, which no real fork does.",
    "lifecycle_contradiction": "Events contradict the observed process lifecycle (activity after exit or duplicate start/exit).",
    "telemetry_gap": "One or more expected event classes were absent, so absence of evidence is not evidence of safety.",
    "baseline_novelty": "Session shape deviates from the labelled benign baseline.",
    "no_heuristic_triggered": "No configured heuristic crossed its explanation threshold.",
    "windowed_anomaly": "At least one time window inside the stream crossed a risk threshold.",
    "sensitive_path_write": "An event touched a path pattern declared sensitive by operator policy.",
    "sensitive_port_connect": "A connection targeted a port declared sensitive by operator policy.",
}


def render_json(report: dict, pretty: bool = True) -> str:
    return json.dumps(report, indent=2 if pretty else None, sort_keys=True)


# Backwards-compatible name used by earlier releases.
def render_report(report: dict, pretty: bool = True) -> str:
    return render_json(report, pretty)


def _windows_of(report: dict) -> dict | None:
    """Return the windowed block whether nested under `windowed` or top-level."""
    if isinstance(report.get("windowed"), dict):
        return report["windowed"]
    if "windows" in report and "summary" in report:
        return report
    return None


def _pct(value: float) -> str:
    return f"{100.0 * float(value):.1f}%"


def _severity_badge(status: str) -> str:
    return {
        "HIGH_RISK": "🔴 HIGH_RISK",
        "SUSPICIOUS": "🟠 SUSPICIOUS",
        "INSUFFICIENT_EVIDENCE": "🔵 INSUFFICIENT_EVIDENCE",
        "NO_ANOMALY_DETECTED": "🟢 NO_ANOMALY_DETECTED",
    }.get(status, status)


def _component_rows(report: dict) -> list[str]:
    weights = report.get("normalized_weights") or {}
    contribution = report.get("contribution") or {}
    rows = ["| Component | Value | Weight | Contribution |", "| --- | --- | --- | --- |"]
    for name in ("temporal", "causal", "sequence", "telemetry_gap", "novelty"):
        value = float((report.get("components") or {}).get(name, 0.0))
        rows.append(
            f"| {name} | {value:.3f} | {float(weights.get(name, 0.0)):.3f} | "
            f"{float(contribution.get(name, 0.0)):.3f} |"
        )
    return rows


def _reason_rows(report: dict) -> list[str]:
    reasons = report.get("reasons") or []
    rows = ["| Code | Detail |", "| --- | --- |"]
    for reason in reasons:
        rows.append(f"| `{reason['code']}` | {reason['detail']} |")
    return rows


def _window_rows(windows: dict) -> list[str]:
    rows = ["| # | Start | Events | Status | Score | Top reason |", "| --- | --- | --- | --- | --- | --- |"]
    for window in windows.get("windows") or []:
        rows.append(
            f"| {window['window_index']} | {window['start']:.0f} | {window['event_count']} | "
            f"{window['status']} | {window['anomaly_score']:.3f} | `{window['top_reason']}` |"
        )
    return rows


def render_markdown(report: dict) -> str:
    lines = ["# CABID analysis report", ""]
    if "windows" in report and "summary" in report:
        summary = report["summary"]
        lines += [f"**Overall status:** {_severity_badge(summary['worst_status'])}", ""]
        lines += [f"- Window size: {report['window_seconds']:.0f}s",
                  f"- Windows analyzed: {summary['window_count']}",
                  f"- Worst score: {summary['worst_anomaly_score']:.3f}",
                  "- Status counts: " + ", ".join(
                      f"{status}={count}" for status, count in summary["status_counts"].items()),
                  ""]
        lines += _window_rows(report)
        lines += ["", "---", ""]
        report = report.get("aggregate") or report
        if not report.get("status"):
            lines.append("_Window summary only; no aggregate report was attached._")
            return "\n".join(lines) + "\n"

    status = report.get("status", "UNKNOWN")
    lines += [f"**Status:** {_severity_badge(status)}",
              f"**Anomaly score:** {float(report.get('anomaly_score', 0.0)):.3f}  ",
              f"**Events analyzed:** {report.get('event_count', 0)}  ",
              f"**Baseline profile used:** {'yes' if report.get('baseline_used') else 'no'}  ",
              f"**Config digest:** `{report.get('config_digest', 'n/a')}`", ""]
    lines += ["## Component breakdown", ""] + _component_rows(report) + [""]
    lines += ["## Why this status", ""] + _reason_rows(report) + [""]

    completeness = report.get("completeness") or {}
    if completeness:
        lines += ["## Telemetry coverage", "",
                  f"- Observed classes: {', '.join(completeness.get('observed_event_types') or []) or 'none'}",
                  f"- Missing classes: {', '.join(completeness.get('missing_event_types') or []) or 'none'}",
                  f"- Coverage ratio: {_pct(completeness.get('completeness', 0.0))}",
                  f"- Required for a conclusive verdict: {_pct(completeness.get('minimum_required_completeness', 1.0))}",
                  ""]
    sequence = report.get("sequence") or {}
    if sequence.get("common_transitions"):
        lines += ["## Process lifecycle", "",
                  f"- Processes observed: {sequence.get('process_count', 0)}",
                  f"- Contradictory events: {sequence.get('contradiction_events', 0)}", ""]
        lines += ["| Transition | Count |", "| --- | --- |"]
        for item in sequence["common_transitions"]:
            lines.append(f"| {item['from']} → {item['to']} | {item['count']} |")
        lines.append("")

    policy = report.get("policy") or {}
    if policy.get("policy_applied") or policy.get("finding_count"):
        lines += ["## Policy findings", "",
                  f"- Findings: {policy.get('finding_count', 0)}",
                  f"- Allow-listed events: {policy.get('allow_listed_events', 0)}",
                  f"- Suppressed reason codes: {', '.join(policy.get('suppressed_reason_codes') or []) or 'none'}",
                  ""]
        if policy.get("findings"):
            lines += ["| Rule | Severity | Detail | Process | Reference |", "| --- | --- | --- | --- | --- |"]
            for finding in policy["findings"]:
                lines.append(
                    f"| `{finding['rule']}` | {finding['severity']} | {finding['detail']} | "
                    f"{finding.get('process_name') or 'unknown'} | `{finding.get('target_ref') or ''}` |"
                )
            lines.append("")

    nested = _windows_of(report)
    if nested is not report and nested is not None:
        summary = nested.get("summary") or {}
        lines += ["## Time windows", "",
                  f"- Window size: {nested.get('window_seconds', 0):.0f}s",
                  f"- Windows analyzed: {summary.get('window_count', 0)}",
                  f"- Worst status: {summary.get('worst_status', 'n/a')}",
                  f"- Worst score: {float(summary.get('worst_anomaly_score', 0.0)):.3f}", ""]
        lines += _window_rows(nested) + [""]

    lines += ["## Interpretation limits", "",
              "- The anomaly score is a transparent heuristic, not a probability.",
              "- Missing telemetry is reported as insufficient evidence, never as safe.",
              "- Use only on systems and logs you are authorized to analyze.", "",
              f"_CABID {__version__} · generated by `cabid analyze`._"]
    return "\n".join(lines) + "\n"


def render_csv(report: dict) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([
        "record_type", "status", "anomaly_score", "component", "component_value",
        "weight", "contribution", "reason_code", "reason_detail", "top_reason",
    ])
    if "windows" in report and "summary" in report:
        for window in report["windows"]:
            writer.writerow([
                "window", window["status"], window["anomaly_score"], "", "", "", "",
                window["top_reason"], "", window["top_reason"],
            ])
        return buffer.getvalue()

    status = report.get("status", "")
    score = report.get("anomaly_score", "")
    weights = report.get("normalized_weights") or {}
    contribution = report.get("contribution") or {}
    components = report.get("components") or {}
    top = (report.get("reasons") or [{}])[0].get("code", "")
    for name in ("temporal", "causal", "sequence", "telemetry_gap", "novelty"):
        writer.writerow([
            "component", status, score, name, components.get(name, ""),
            weights.get(name, ""), contribution.get(name, ""), "", "", top,
        ])
    for reason in report.get("reasons") or []:
        writer.writerow([
            "reason", status, score, "", "", "", "", reason.get("code", ""),
            reason.get("detail", ""), top,
        ])
    for finding in (report.get("policy") or {}).get("findings") or []:
        writer.writerow([
            "policy", status, score, finding.get("rule", ""), finding.get("severity", ""), "", "",
            finding.get("process_name", ""), finding.get("detail", ""), top,
        ])
    nested = _windows_of(report)
    if nested is not report and nested is not None:
        for window in nested.get("windows") or []:
            writer.writerow([
                "window", window["status"], window["anomaly_score"], "", "", "", "",
                window["top_reason"], f"window {window['window_index']}", top,
            ])
    return buffer.getvalue()


def _sarif_results(report: dict, source: str) -> list[dict]:
    results = []
    if "windows" in report and "summary" in report:
        for window in report["windows"]:
            if window["status"] == "NO_ANOMALY_DETECTED":
                continue
            results.append({
                "ruleId": "windowed_anomaly",
                "level": _SARIF_LEVEL.get(window["status"], "note"),
                "message": {"text": f"Window {window['window_index']} ({window['status']}, "
                                    f"score {window['anomaly_score']:.3f}) top reason: {window['top_reason']}"},
                "properties": {"status": window["status"], "anomaly_score": window["anomaly_score"]},
                "locations": [_location(source)],
            })
        return results
    nested = _windows_of(report)
    if nested is not report and nested is not None:
        for window in nested.get("windows") or []:
            if window["status"] == "NO_ANOMALY_DETECTED":
                continue
            results.append({
                "ruleId": "windowed_anomaly",
                "level": _SARIF_LEVEL.get(window["status"], "note"),
                "message": {"text": f"Window {window['window_index']} ({window['status']}, "
                                    f"score {window['anomaly_score']:.3f}) top reason: {window['top_reason']}"},
                "properties": {"status": window["status"], "anomaly_score": window["anomaly_score"]},
                "locations": [_location(source)],
            })
    status = report.get("status", "")
    for finding in (report.get("policy") or {}).get("findings") or []:
        results.append({
            "ruleId": finding["rule"],
            "level": "warning" if finding.get("severity") == "high" else "note",
            "message": {"text": finding["detail"]},
            "properties": {
                "process_name": finding.get("process_name"),
                "allow_listed_process": finding.get("allow_listed_process"),
            },
            "locations": [_location(f"{source}#{finding.get('target_ref') or 'event'}")],
        })
    for reason in report.get("reasons") or []:
        if reason["code"] == "no_heuristic_triggered":
            continue
        results.append({
            "ruleId": reason["code"],
            "level": _SEVERITY.get(status, "note"),
            "message": {"text": reason["detail"]},
            "properties": {"status": status, "anomaly_score": report.get("anomaly_score")},
            "locations": [_location(source)],
        })
    return results


def _location(source: str) -> dict:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": str(source).replace("\\", "/")},
            "region": {"startLine": 1},
        }
    }


def render_sarif(report: dict, source: str = "events.jsonl") -> str:
    rules = []
    for code, help_text in sorted(_RULE_HELP.items()):
        rules.append({
            "id": code,
            "name": code.replace("_", " ").title().replace(" ", ""),
            "shortDescription": {"text": help_text},
            "helpUri": "https://github.com/sayan9168/CABID/blob/main/docs/reports.md",
        })
    document = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CABID",
                    "version": __version__,
                    "informationUri": "https://github.com/sayan9168/CABID",
                    "rules": rules,
                }
            },
            "automationDetails": {"id": "cabid/behavioral-integrity"},
            "results": _sarif_results(report, source),
            "properties": {
                "warning": "Heuristic research output; not a calibrated security verdict.",
                "config_digest": report.get("config_digest"),
            },
        }],
    }
    return json.dumps(document, indent=2, sort_keys=True)


def render_html(report: dict, source: str = "events.jsonl") -> str:
    """Self-contained, offline-viewable report with an inline SVG score bar."""
    status = report.get("status") or (report.get("summary") or {}).get("worst_status", "UNKNOWN")
    score = float(report.get("anomaly_score") or (report.get("summary") or {}).get("worst_anomaly_score", 0.0))
    escape = html.escape
    parts = [
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        f"<title>CABID report — {escape(str(status))}</title>",
        "<style>",
        ":root{color-scheme:light dark;--bg:#f7f8fa;--card:#fff;--ink:#14181f;--muted:#5c6675;"
        "--line:#e3e7ee;--accent:#2557d6}",
        "@media (prefers-color-scheme:dark){:root{--bg:#0f1319;--card:#161b23;--ink:#e8edf5;"
        "--muted:#9aa6b8;--line:#242c38;--accent:#7aa2ff}}",
        "*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);"
        "font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}",
        ".wrap{max-width:960px;margin:0 auto;padding:32px 20px 64px}",
        "h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.05rem;margin:28px 0 10px}",
        ".sub{color:var(--muted);margin:0 0 24px;font-size:.9rem}",
        ".card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:0 0 16px}",
        ".badge{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:600;font-size:.85rem;"
        "border:1px solid var(--line)}",
        ".HIGH_RISK{background:#fde8e8;color:#9b1c1c}.SUSPICIOUS{background:#fdf0d5;color:#8a4b00}",
        ".INSUFFICIENT_EVIDENCE{background:#e4efff;color:#1e429f}.NO_ANOMALY_DETECTED{background:#e3f6e9;color:#0f6b32}",
        "@media (prefers-color-scheme:dark){.HIGH_RISK{background:#3b1414;color:#ffb4b4}"
        ".SUSPICIOUS{background:#3a2708;color:#ffcf87}.INSUFFICIENT_EVIDENCE{background:#122744;color:#a8c8ff}"
        ".NO_ANOMALY_DETECTED{background:#0f2e1c;color:#8ce0ab}}",
        "table{width:100%;border-collapse:collapse;font-size:.9rem}",
        "th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line)}",
        "th{color:var(--muted);font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}",
        "code{font:.85em ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--bg);"
        "padding:1px 5px;border-radius:5px}",
        ".metric{display:flex;gap:28px;flex-wrap:wrap}.metric div span{display:block;color:var(--muted);font-size:.78rem;"
        "text-transform:uppercase;letter-spacing:.05em}",
        ".metric div strong{font-size:1.25rem}",
        "footer{color:var(--muted);font-size:.8rem;margin-top:28px}",
        "</style></head><body><div class=\"wrap\">",
        "<h1>CABID analysis report</h1>",
        f'<p class="sub">Source: <code>{escape(str(source))}</code> · CABID {escape(__version__)} · '
        "heuristic research output, not a calibrated probability</p>",
        '<div class="card">',
        f'<div class="badge {escape(str(status))}">{escape(str(status))}</div>',
        '<div class="metric" style="margin-top:16px">',
        f"<div><span>Anomaly score</span><strong>{score:.3f}</strong></div>",
        f"<div><span>Events</span><strong>{int(report.get('event_count', 0) or 0)}</strong></div>",
        f"<div><span>Coverage</span><strong>"
        f"{100.0 * float((report.get('completeness') or {}).get('completeness', 0.0)):.0f}%</strong></div>",
        f"<div><span>Baseline</span><strong>{'yes' if report.get('baseline_used') else 'no'}</strong></div>",
        "</div>",
        f'<svg width="100%" height="12" role="img" aria-label="score bar" style="margin-top:18px">'
        f'<rect width="100%" height="12" rx="6" fill="var(--line)"></rect>'
        f'<rect width="{min(100.0, max(0.0, score * 100.0)):.1f}%" height="12" rx="6" fill="var(--accent)"></rect></svg>',
        "</div>",
    ]
    rows = _component_rows(report)
    if len(rows) > 2:
        parts += ['<div class="card"><h2 style="margin-top:0">Component breakdown</h2><table>']
        header, sep, *body = rows
        parts.append("<tr>" + "".join(f"<th>{escape(cell)}</th>" for cell in _cells(header)) + "</tr>")
        for row in body:
            parts.append("<tr>" + "".join(f"<td>{escape(cell)}</td>" for cell in _cells(row)) + "</tr>")
        parts.append("</table></div>")
    reasons = report.get("reasons") or []
    if reasons:
        parts.append('<div class="card"><h2 style="margin-top:0">Why this status</h2><table>')
        parts.append("<tr><th>Code</th><th>Detail</th></tr>")
        for reason in reasons:
            parts.append(
                f"<tr><td><code>{escape(str(reason.get('code')))}</code></td>"
                f"<td>{escape(str(reason.get('detail')))}</td></tr>"
            )
        parts.append("</table></div>")
    findings = (report.get("policy") or {}).get("findings") or []
    if findings:
        parts.append('<div class="card"><h2 style="margin-top:0">Policy findings</h2><table>')
        parts.append("<tr><th>Rule</th><th>Severity</th><th>Detail</th><th>Process</th></tr>")
        for finding in findings:
            parts.append(
                f"<tr><td><code>{escape(str(finding['rule']))}</code></td>"
                f"<td>{escape(str(finding.get('severity')))}</td>"
                f"<td>{escape(str(finding.get('detail')))}</td>"
                f"<td>{escape(str(finding.get('process_name') or 'unknown'))}</td></tr>"
            )
        parts.append("</table></div>")

    windows = (_windows_of(report) or {}).get("windows") or []
    if windows:
        parts.append('<div class="card"><h2 style="margin-top:0">Time windows</h2><table>')
        parts.append("<tr><th>#</th><th>Start</th><th>Events</th><th>Status</th><th>Score</th></tr>")
        for window in windows:
            parts.append(
                f"<tr><td>{int(window['window_index'])}</td><td>{float(window['start']):.0f}</td>"
                f"<td>{int(window['event_count'])}</td>"
                f'<td><span class="badge {escape(str(window["status"]))}">{escape(str(window["status"]))}</span></td>'
                f"<td>{float(window['anomaly_score']):.3f}</td></tr>"
            )
        parts.append("</table></div>")
    parts += [
        "<footer>Missing telemetry is reported as insufficient evidence, never as safe. "
        "Use only on systems and logs you are authorized to analyze.</footer>",
        "</div></body></html>",
    ]
    return "\n".join(parts) + "\n"


def _cells(row: str) -> list[str]:
    return [cell.strip() for cell in row.strip().strip("|").split("|")]


def render(report: dict, fmt: str = "json", source: str = "events.jsonl") -> str:
    fmt = (fmt or "json").lower()
    if fmt not in FORMATS:
        raise ValueError(f"unsupported report format: {fmt} (choose from {', '.join(FORMATS)})")
    if fmt == "json":
        return render_json(report) + "\n"
    if fmt == "md":
        return render_markdown(report)
    if fmt == "csv":
        return render_csv(report)
    if fmt == "sarif":
        return render_sarif(report, source) + "\n"
    return render_html(report, source)


def write_report(report: dict, path: str | Path, fmt: str = "json", source: str = "events.jsonl") -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render(report, fmt, source), encoding="utf-8")
    return destination
