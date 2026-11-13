"""Fleet-level aggregation and comparison across many hosts.

A per-host report answers "what happened on this box". The questions that actually
get asked during an incident are fleet-shaped: *which hosts are worst, which are
quiet, which have gone blind, and did last night's rollout change anything?* This
module answers those by consuming the reports CABID already produces.

Design constraints that come from the data:

* **Reports are heterogeneous.** A host may produce a session report, a windowed
  report, a stream report, or a drift report. Rather than require one shape,
  :func:`host_summary` normalizes the fields that are common and records which shape
  it read, so a mixed fleet aggregates without losing provenance.
* **Missing hosts are a finding.** A fleet view that silently lists only the hosts
  that reported is dangerous: the compromised host is often the silent one. Silent
  hosts are reported explicitly, and a fleet where they are numerous is marked
  degraded rather than green.
* **Comparison is ranking, not scoring.** Hosts are ordered by the evidence in their
  own reports. No new score is invented here, because a fleet-level number would
  have no calibration behind it.

Nothing in this module fetches anything: reports are files the operator supplies,
so a fleet view can be built from an air-gapped collection.
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

FLEET_FORMAT = "cabid-fleet-report/1"

#: Statuses counted as needing attention, in escalating order.
ATTENTION_STATUSES = ("SUSPICIOUS", "HIGH_RISK", "INSUFFICIENT_EVIDENCE")

#: Share of silent hosts above which a fleet view is reported as degraded.
SILENT_HOST_DEGRADED_RATIO = 0.10


class FleetError(ValueError):
    """Raised when a fleet cannot be assembled or compared safely."""


def _read_report(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FleetError(f"{path}: file not found") from exc
    except json.JSONDecodeError as exc:
        raise FleetError(f"{path}: invalid JSON: {exc}") from exc
    except OSError as exc:
        raise FleetError(f"{path}: cannot read: {exc}") from exc
    if not isinstance(data, dict):
        raise FleetError(f"{path}: report must be a JSON object")
    return data


def host_summary(report: dict, *, host: str | None = None,
                 path: str | None = None) -> dict:
    """Normalize one host report into a fleet row.

    Accepts a session report (``status``/``anomaly_score``), a stream report
    (``status_counts``/``flagged_window_rate``), a drift report (``drifted``), or a
    validation report (``verdict``). The detected shape is recorded so a mixed fleet
    stays auditable.
    """
    if not isinstance(report, dict):
        raise FleetError("a report object is required")
    identifier = host or report.get("host") or (Path(path).stem if path else None)
    if not identifier:
        raise FleetError("a host identifier is required (pass host= or include 'host')")
    row: dict = {
        "host": str(identifier)[:200],
        "source_path": path,
        "status": None,
        "anomaly_score": None,
        "event_count": None,
        "coverage": None,
        "flagged_window_rate": None,
        "window_count": None,
        "drifted": None,
        "baseline_verdict": None,
        "shape": "unknown",
        "needs_attention": False,
        "reasons": [],
    }

    if "status_counts" in report:
        row["shape"] = "stream"
        counts = report.get("status_counts") or {}
        row["status"] = _worst_status(counts)
        row["flagged_window_rate"] = report.get("flagged_window_rate")
        row["window_count"] = report.get("window_count")
        row["event_count"] = report.get("events_normalized")
        row["reasons"] = sorted(counts)
    elif "status" in report:
        row["shape"] = "session"
        row["status"] = str(report.get("status"))
        row["anomaly_score"] = report.get("anomaly_score")
        row["event_count"] = report.get("event_count")
        row["coverage"] = (report.get("completeness") or {}).get("completeness")
        row["reasons"] = [reason.get("code") for reason in report.get("reasons") or []
                          if isinstance(reason, dict)]
    elif "drifted" in report:
        row["shape"] = "drift"
        row["drifted"] = bool(report.get("drifted"))
        row["status"] = "DRIFT" if row["drifted"] else "NO_ANOMALY_DETECTED"
        row["reasons"] = [feature.get("feature") for feature in report.get("features") or []
                          if isinstance(feature, dict)]
        row["event_count"] = report.get("session_count")
    elif "verdict" in report:
        row["shape"] = "baseline-validation"
        row["baseline_verdict"] = str(report.get("verdict"))
        row["status"] = "INSUFFICIENT_EVIDENCE" if report.get("verdict") != "SOUND" \
            else "NO_ANOMALY_DETECTED"
        row["coverage"] = report.get("coverage")
        row["event_count"] = report.get("session_count")
    else:
        raise FleetError(
            f"{identifier}: unrecognized report shape; expected a session, stream, "
            "drift, or baseline-validation report")

    row["needs_attention"] = row["status"] in ATTENTION_STATUSES or bool(row["drifted"])
    return row


def _worst_status(counts: dict) -> str:
    for candidate in ("HIGH_RISK", "SUSPICIOUS", "INSUFFICIENT_EVIDENCE"):
        if int(counts.get(candidate, 0) or 0) > 0:
            return candidate
    return "NO_ANOMALY_DETECTED"


def collect(entries: Sequence[tuple[str, str | Path]],
            expected_hosts: list[str] | None = None) -> dict:
    """Build a fleet view from ``(host, report_path)`` pairs.

    Duplicate hosts are rejected rather than merged: two reports for one host is
    almost always a collection error, and silently picking one can hide the worse
    of the two.
    """
    if not entries:
        raise FleetError("at least one (host, report) pair is required")
    rows: list[dict] = []
    seen: set[str] = set()
    for host, raw_path in entries:
        path = Path(raw_path)
        if str(host) in seen:
            raise FleetError(
                f"host {host!r} appears more than once; supply one report per host or "
                "aggregate them before collecting")
        seen.add(str(host))
        rows.append(host_summary(_read_report(path), host=str(host), path=str(path)))
    return summarize(rows, expected_hosts=expected_hosts)


def summarize(rows: list[dict], *, expected_hosts: list[str] | None = None) -> dict:
    """Aggregate host rows into a fleet report.

    ``expected_hosts`` is what makes the view trustworthy: hosts expected but absent
    are reported as silent, because the host that stopped reporting is exactly the one
    worth looking at.
    """
    if not isinstance(rows, list) or not rows:
        raise FleetError("at least one host row is required")
    identifiers = [row["host"] for row in rows]
    if len(set(identifiers)) != len(identifiers):
        raise FleetError("host rows contain duplicates")

    expected = sorted({str(name) for name in (expected_hosts or [])})
    present = set(identifiers)
    silent = [name for name in expected if name not in present]
    unexpected = sorted(present - set(expected)) if expected else []

    status_counts: dict[str, int] = {}
    shape_counts: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or "UNKNOWN")
        status_counts[status] = status_counts.get(status, 0) + 1
        shape = str(row.get("shape") or "unknown")
        shape_counts[shape] = shape_counts.get(shape, 0) + 1

    attention = sorted(
        (row for row in rows if row.get("needs_attention")),
        key=lambda row: (
            -(float(row.get("anomaly_score") or 0.0)),
            -(float(row.get("flagged_window_rate") or 0.0)),
            row["host"]),
    )
    silent_ratio = len(silent) / len(expected) if expected else 0.0
    degraded = bool(expected) and silent_ratio > SILENT_HOST_DEGRADED_RATIO

    scores = [float(row["anomaly_score"]) for row in rows
              if isinstance(row.get("anomaly_score"), (int, float))]
    ranked = sorted(rows, key=lambda row: (
        -(float(row.get("anomaly_score") or 0.0)), row["host"]))

    findings: list[str] = []
    if silent:
        findings.append(
            f"{len(silent)} expected host(s) did not report: "
            + ", ".join(silent[:10]) + ("..." if len(silent) > 10 else ""))
    if degraded:
        findings.append(
            f"silent-host ratio {silent_ratio:.0%} exceeds {SILENT_HOST_DEGRADED_RATIO:.0%}; "
            "fleet coverage is degraded and absence should be investigated before "
            "trusting the quiet hosts")
    if unexpected:
        findings.append("hosts reported that were not expected: " + ", ".join(unexpected[:10]))
    if attention:
        findings.append(f"{len(attention)} host(s) need attention")
    if not findings:
        findings.append("all expected hosts reported and none need attention")

    return {
        "format": FLEET_FORMAT,
        "host_count": len(rows),
        "expected_host_count": len(expected),
        "silent_hosts": silent,
        "silent_host_ratio": round(silent_ratio, 6),
        "unexpected_hosts": unexpected,
        "degraded": degraded,
        "status_counts": dict(sorted(status_counts.items())),
        "shape_counts": dict(sorted(shape_counts.items())),
        "attention_hosts": [
            {
                "host": row["host"],
                "status": row["status"],
                "anomaly_score": row["anomaly_score"],
                "flagged_window_rate": row["flagged_window_rate"],
                "needs_attention": True,
                "reasons": row.get("reasons", []),
            }
            for row in attention
        ],
        "ranking": [
            {
                "rank": index + 1,
                "host": row["host"],
                "anomaly_score": row["anomaly_score"],
                "status": row["status"],
                "shape": row["shape"],
            }
            for index, row in enumerate(ranked)
        ],
        "score_spread": {
            "min": round(min(scores), 6) if scores else None,
            "max": round(max(scores), 6) if scores else None,
            "hosts_with_scores": len(scores),
        },
        "findings": findings,
        "notes": [
            "Hosts are ranked by the evidence already present in their own reports; "
            "no fleet-level score is invented.",
            "Silent hosts are reported explicitly: a fleet view listing only the hosts "
            "that answered can hide the one that went dark.",
            "Reports may be of different shapes; shape_counts shows what was read.",
        ],
    }


def compare(baseline_rows: list[dict], current_rows: list[dict]) -> dict:
    """Compare two fleet snapshots host by host.

    Returns only what moved. A host present in one snapshot and absent from the
    other is reported as appeared or disappeared rather than compared against a
    missing value.
    """
    if not baseline_rows or not current_rows:
        raise FleetError("both snapshots need at least one host row")
    before = {row["host"]: row for row in baseline_rows}
    after = {row["host"]: row for row in current_rows}
    if len(before) != len(baseline_rows) or len(after) != len(current_rows):
        raise FleetError("duplicate hosts within a snapshot")

    changed: list[dict] = []
    for host in sorted(set(before) & set(after)):
        old, new = before[host], after[host]
        old_score = float(old.get("anomaly_score") or 0.0)
        new_score = float(new.get("anomaly_score") or 0.0)
        status_changed = old.get("status") != new.get("status")
        delta = new_score - old_score
        if not status_changed and abs(delta) < 1e-9:
            continue
        changed.append({
            "host": host,
            "status_before": old.get("status"),
            "status_after": new.get("status"),
            "score_before": round(old_score, 6),
            "score_after": round(new_score, 6),
            "score_delta": round(delta, 6),
            "direction": ("worse" if delta > 0 else "better") if delta else "status-only",
        })
    changed.sort(key=lambda row: (-row["score_delta"], row["host"]))

    return {
        "format": "cabid-fleet-comparison/1",
        "baseline_host_count": len(baseline_rows),
        "current_host_count": len(current_rows),
        "appeared": sorted(set(after) - set(before)),
        "disappeared": sorted(set(before) - set(after)),
        "improved": [row for row in changed if row["score_delta"] < 0],
        "worsened": [row for row in changed if row["score_delta"] > 0],
        "status_only_changes": [row for row in changed if row["score_delta"] == 0],
        "unchanged_count": len(set(before) & set(after)) - len(changed),
        "notes": [
            "A host that disappeared may have been decommissioned or may have stopped "
            "reporting; that difference matters and is not inferred here.",
            "Scores are the hosts' own report scores; a change in score across "
            "snapshots may reflect a configuration or baseline change rather than "
            "host behaviour.",
        ],
    }


def render_markdown(fleet: dict) -> str:
    """A human-readable fleet summary for an incident channel."""
    lines = ["# CABID fleet report", ""]
    lines.append(f"Hosts: {fleet.get('host_count')} of {fleet.get('expected_host_count')} "
                 f"expected. Degraded: {'yes' if fleet.get('degraded') else 'no'}.")
    if fleet.get("silent_hosts"):
        lines += ["", f"**Silent hosts ({len(fleet['silent_hosts'])}):** "
                      + ", ".join(fleet["silent_hosts"])]
    rows = fleet.get("attention_hosts") or []
    lines += ["", "## Hosts needing attention", ""]
    if not rows:
        lines.append("None.")
    else:
        lines += ["| Host | Status | Score | Flagged windows | Reasons |",
                  "| --- | --- | --- | --- | --- |"]
        for row in rows:
            lines.append(
                f"| {row['host']} | {row['status']} | "
                f"{_fmt(row.get('anomaly_score'))} | "
                f"{_fmt(row.get('flagged_window_rate'))} | "
                f"{', '.join(str(reason) for reason in (row.get('reasons') or [])[:4])} |")
    lines += ["", "## Findings", ""]
    lines += [f"- {item}" for item in fleet.get("findings") or []]
    lines += ["", "_Findings are triage hints derived from per-host reports, not "
              "assessments of intent._"]
    return "\n".join(lines) + "\n"


def _fmt(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, (int, float)):
        return f"{float(value):.3f}"
    return str(value)
