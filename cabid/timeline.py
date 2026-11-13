"""Investigation timeline export.

Reports are JSON-shaped; investigators usually need a chronological narrative they
can paste into notes or a ticketing system. This module renders one, interleaving
events with the rule matches and policy findings attached to them.

The export deliberately keeps the counters factual and labelled: "activity after
an observed exit", not "impossible activity"; "policy-sensitive target", not
"exfiltration". An analyst should be able to lift a line into a report without
inheriting a claim the tool cannot support.
"""
from __future__ import annotations

from datetime import datetime, timezone

MAX_ROWS = 5000
_DEFAULT_LIMIT = 300


def _iso(stamp: float) -> str:
    try:
        return datetime.fromtimestamp(float(stamp), tz=timezone.utc).isoformat(timespec="milliseconds")
    except (OverflowError, OSError, ValueError):
        return f"epoch:{stamp}"


def _row_prefix(index: int) -> str:
    return f"{index:04d}"


def build_timeline(events: list[dict], report: dict | None = None,
                   limit: int = _DEFAULT_LIMIT, include_events_only: bool = False) -> dict:
    """Build a chronological timeline with annotations from a report."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer")
    limit = min(limit, MAX_ROWS)
    annotations = _annotations(report or {})
    rows = []
    for index, event in enumerate(sorted(events, key=lambda item: float(item["timestamp"]))):
        stamp = float(event["timestamp"])
        notes = annotations.get(index, [])
        rows.append({
            "seq": index,
            "timestamp": round(stamp, 6),
            "timestamp_iso": _iso(stamp),
            "event_type": event["event_type"],
            "process_id": event["process_id"],
            "parent_process_id": event["parent_process_id"],
            "process_name": str(event.get("process_name") or "unknown"),
            "target": str(event.get("target") or "")[:200],
            "source": str(event.get("source") or "unknown"),
            "annotations": notes,
        })
        if len(rows) >= limit:
            break
    annotated = sum(1 for row in rows if row["annotations"])
    return {
        "row_count": len(rows),
        "total_events": len(events),
        "truncated": len(events) > len(rows),
        "annotated_rows": annotated,
        "limit": limit,
        "events_only": bool(include_events_only),
        "rows": rows,
    }


def _annotations(report: dict) -> dict[int, list[dict]]:
    """Map event index -> annotation list using report evidence blocks."""
    annotations: dict[int, list[dict]] = {}
    rules = report.get("rules") or {}
    for finding in rules.get("findings") or []:
        for item in finding.get("evidence") or []:
            index = item.get("index")
            if isinstance(index, int):
                annotations.setdefault(index, []).append({
                    "kind": "rule",
                    "id": finding.get("rule_id"),
                    "severity": finding.get("severity"),
                    "detail": finding.get("title"),
                })
    for finding in (report.get("policy") or {}).get("findings") or []:
        index = finding.get("event_index")
        if isinstance(index, int):
            annotations.setdefault(index, []).append({
                "kind": "policy",
                "id": finding.get("rule"),
                "severity": finding.get("severity"),
                "detail": finding.get("detail"),
            })
    # Several matches can share an evidence row (e.g. overlapping sequence anchors).
    # Collapse to one annotation per (kind, id, severity) per row.
    for index, items in annotations.items():
        seen = set()
        unique = []
        for item in items:
            key = (item["kind"], item["id"], item.get("severity"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)
        annotations[index] = unique
    return annotations


def render_timeline_markdown(timeline: dict, title: str = "CABID timeline") -> str:
    lines = [f"# {title}", ""]
    lines += [
        f"- Rows: {timeline['row_count']} of {timeline['total_events']} events"
        + (" (truncated)" if timeline["truncated"] else ""),
        f"- Annotated rows: {timeline['annotated_rows']}",
        "- Annotations mark where a rule or policy check fired; they describe observable shape, "
        "not proven intent.",
        "",
        "| # | Time (UTC) | Event | PID | Process | Target | Annotations |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in timeline["rows"]:
        marks = "; ".join(
            f"{item['kind']}:{item['id']}" + (f" ({item['severity']})" if item.get("severity") else "")
            for item in row["annotations"]
        )
        target = row["target"].replace("|", "\\|")[:80]
        lines.append(
            f"| {row['seq']} | {row['timestamp_iso']} | {row['event_type']} | "
            f"{row['process_id']} | {row['process_name']} | {target or '—'} | {marks or '—'} |"
        )
    if timeline["truncated"]:
        lines += ["", f"_Showing the first {timeline['row_count']} events; raise --limit to widen._"]
    return "\n".join(lines) + "\n"


def render_timeline_text(timeline: dict, title: str = "CABID timeline") -> str:
    """Plain chronological lines, for pasting into notes or a ticket."""
    lines = [title,
             f"rows={timeline['row_count']}/{timeline['total_events']} "
             f"annotated={timeline['annotated_rows']}", ""]
    for row in timeline["rows"]:
        marks = " ".join(f"[{item['kind']}:{item['id']}]" for item in row["annotations"])
        target = f" {row['target'][:60]}" if row["target"] else ""
        lines.append(f"{row['timestamp_iso']} {row['event_type']:<16} pid={row['process_id']:<7} "
                     f"{row['process_name'][:24]:<24}{target} {marks}".rstrip())
    return "\n".join(lines) + "\n"
