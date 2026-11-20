"""Compare two CABID reports and say what changed, in both directions.

`cabid history --compare` diffs a run against a *stored summary*; it can only see
what the database keeps. This module diffs two report files, so it can also see
rule findings, policy findings, process names, window verdicts, and the config
digest that produced each number.

Design rules, because a diff that lies is worse than no diff:

* A moved score is only called a regression when both reports were produced with
  the same ``config_digest``. Otherwise the direction is reported as unknown and
  the reason is stated, because a threshold change moves every score at once.
* ``INSUFFICIENT_EVIDENCE`` is not a risk level. Losing evidence is reported as
  its own change (``evidence_lost``) instead of being folded into "worse".
* Findings are keyed by stable identity — rule id, policy rule plus process and
  target reference, process *name* — never by event index, which is not stable
  across two different collections.
"""
from __future__ import annotations

from . import __version__

FORMAT = "cabid-report-diff/1"
RISK_RANK = {"NO_ANOMALY_DETECTED": 0, "SUSPICIOUS": 1, "HIGH_RISK": 2}


class ReportDiffError(ValueError):
    """Raised when an input is not a report this module can compare."""


def _is_stream(report: dict) -> bool:
    return "windows_scored" in report


def _report_kind(report: dict, origin: str) -> str:
    if not isinstance(report, dict):
        raise ReportDiffError(f"{origin}: report must be a JSON object")
    declared = str(report.get("format", ""))
    if declared.startswith("cabid-fleet"):
        raise ReportDiffError(
            f"{origin}: this is a fleet report; compare per-host reports or use `cabid fleet --compare`")
    if _is_stream(report):
        return "stream"
    if "anomaly_score" in report or "status" in report:
        return "session"
    raise ReportDiffError(f"{origin}: no status or anomaly_score; is this a CABID report?")


def _worst_status(counts: dict) -> str:
    for status in ("HIGH_RISK", "SUSPICIOUS", "INSUFFICIENT_EVIDENCE"):
        if counts.get(status):
            return status
    return "NO_ANOMALY_DETECTED"


def _reason_codes(report: dict) -> list[str]:
    return [str(reason.get("code")) for reason in report.get("reasons") or []
            if reason.get("code")]


def _rule_counts(report: dict) -> dict[str, int]:
    findings = ((report.get("rules") or {}).get("findings")) or []
    counts: dict[str, int] = {}
    for finding in findings:
        rule_id = str(finding.get("rule_id") or "")
        if rule_id:
            counts[rule_id] = counts.get(rule_id, 0) + 1
    return counts


def _policy_counts(report: dict) -> dict[str, int]:
    findings = ((report.get("policy") or {}).get("findings")) or []
    counts: dict[str, int] = {}
    for finding in findings:
        key = "|".join(str(finding.get(part) or "") for part in
                       ("rule", "process_name", "target_ref"))
        counts[key] = counts.get(key, 0) + 1
    return counts


def _process_names(report: dict) -> list[str]:
    names: set[str] = set()
    for entity in ((report.get("entities") or {}).get("top_entities")) or []:
        for name in entity.get("process_names") or []:
            names.add(str(name))
    return sorted(names)


def _component_values(report: dict) -> dict[str, float]:
    return {str(name): float(value)
            for name, value in (report.get("components") or {}).items()}


def summary_of(report: dict, origin: str = "report") -> dict:
    """Normalize a session or stream report into the fields a diff can use."""
    kind = _report_kind(report, origin)
    if kind == "stream":
        counts = {str(name): int(value)
                  for name, value in (report.get("status_counts") or {}).items()}
        status = _worst_status(counts)
        score = report.get("flagged_window_rate")
        coverage = None
        missing: list[str] = []
    else:
        counts = {}
        status = str(report.get("status") or "NO_ANOMALY_DETECTED")
        score = report.get("anomaly_score")
        completeness = report.get("completeness") or {}
        coverage = completeness.get("completeness")
        missing = [str(item) for item in completeness.get("missing_event_types") or []]
    return {
        "kind": kind,
        "status": status,
        "anomaly_score": None if score is None else float(score),
        "event_count": int(report.get("event_count") or report.get("events_normalized") or 0),
        "coverage": None if coverage is None else float(coverage),
        "config_digest": str(report.get("config_digest") or ""),
        "reason_codes": _reason_codes(report),
        "components": _component_values(report),
        "rule_counts": _rule_counts(report),
        "policy_counts": _policy_counts(report),
        "process_names": _process_names(report),
        "missing_event_types": missing,
        "status_counts": counts,
    }


def _score_field(kind: str) -> str:
    return "flagged_window_rate" if kind == "stream" else "anomaly_score"


def compare_reports(before: dict, after: dict, *, epsilon: float = 0.01,
                    before_origin: str = "before", after_origin: str = "after") -> dict:
    """Diff two reports. ``epsilon`` is the score change treated as noise."""
    left = summary_of(before, before_origin)
    right = summary_of(after, after_origin)
    warnings: list[str] = []
    comparable = True
    if left["kind"] != right["kind"]:
        comparable = False
        warnings.append(f"comparing a {left['kind']} report with a {right['kind']} report; "
                        "scores measure different things and are not compared")
    if left["config_digest"] and right["config_digest"] and \
            left["config_digest"] != right["config_digest"]:
        comparable = False
        warnings.append(
            f"config_digest differs ({left['config_digest'][:12]} -> "
            f"{right['config_digest'][:12]}); the two scores came from different "
            "configurations and a change in direction cannot be attributed to behaviour")
    if not left["config_digest"] or not right["config_digest"]:
        warnings.append("one report has no config_digest, so configuration identity is unknown")
        comparable = False
    if left["kind"] == "session" and (left["anomaly_score"] is None
                                      or right["anomaly_score"] is None):
        comparable = False
        warnings.append("a report has no anomaly_score")

    evidence_lost = left["status"] != "INSUFFICIENT_EVIDENCE" and \
        right["status"] == "INSUFFICIENT_EVIDENCE"
    evidence_gained = left["status"] == "INSUFFICIENT_EVIDENCE" and \
        right["status"] != "INSUFFICIENT_EVIDENCE"
    if evidence_lost:
        warnings.append("the newer report has insufficient telemetry, so its score is not "
                        "used; this is a loss of evidence, not evidence of improvement")

    score_delta = None
    if comparable and left["anomaly_score"] is not None and right["anomaly_score"] is not None:
        score_delta = round(right["anomaly_score"] - left["anomaly_score"], 6)

    risk_before = RISK_RANK.get(left["status"])
    risk_after = RISK_RANK.get(right["status"])
    if risk_before is not None and risk_after is not None:
        if risk_after > risk_before:
            risk_direction = "worsened"
        elif risk_after < risk_before:
            risk_direction = "improved"
        else:
            risk_direction = "unchanged"
    else:
        risk_direction = "unknown"
        warnings.append("a status is not a risk level (INSUFFICIENT_EVIDENCE), so risk "
                        "direction is reported as unknown")

    if evidence_lost:
        verdict = "evidence-lost"
    elif evidence_gained:
        verdict = "evidence-gained"
    elif not comparable:
        verdict = "not-comparable"
    elif risk_direction == "worsened" or (score_delta is not None and score_delta > epsilon):
        verdict = "regression"
    elif risk_direction == "improved" or (score_delta is not None and score_delta < -epsilon):
        verdict = "improvement"
    elif _has_structural_change(left, right):
        verdict = "changed"
    else:
        verdict = "unchanged"

    component_delta = {}
    for name in sorted(set(left["components"]) | set(right["components"])):
        delta = right["components"].get(name, 0.0) - left["components"].get(name, 0.0)
        component_delta[name] = round(delta, 6)

    new_rules = sorted(set(right["rule_counts"]) - set(left["rule_counts"]))
    cleared_rules = sorted(set(left["rule_counts"]) - set(right["rule_counts"]))
    rule_delta = {rule_id: {"before": left["rule_counts"].get(rule_id, 0),
                            "after": right["rule_counts"].get(rule_id, 0)}
                  for rule_id in sorted(set(left["rule_counts"]) | set(right["rule_counts"]))
                  if left["rule_counts"].get(rule_id, 0) != right["rule_counts"].get(rule_id, 0)}
    new_policy = sorted(set(right["policy_counts"]) - set(left["policy_counts"]))
    cleared_policy = sorted(set(left["policy_counts"]) - set(right["policy_counts"]))

    return {
        "format": FORMAT,
        "cabid_version": __version__,
        "before": {key: value for key, value in left.items() if key != "status_counts"},
        "after": {key: value for key, value in right.items() if key != "status_counts"},
        "score_field": _score_field(left["kind"]),
        "comparable": comparable,
        "score_delta": score_delta,
        "epsilon": epsilon,
        "status": {"before": left["status"], "after": right["status"],
                   "changed": left["status"] != right["status"],
                   "risk_direction": risk_direction},
        "verdict": verdict,
        "evidence_lost": evidence_lost,
        "evidence_gained": evidence_gained,
        "component_delta": component_delta,
        "reason_codes": {
            "added": sorted(set(right["reason_codes"]) - set(left["reason_codes"])),
            "removed": sorted(set(left["reason_codes"]) - set(right["reason_codes"])),
        },
        "rules": {"new": new_rules, "cleared": cleared_rules, "count_delta": rule_delta},
        "policy": {"new": new_policy, "cleared": cleared_policy,
                   "finding_delta": sum(right["policy_counts"].values())
                   - sum(left["policy_counts"].values())},
        "processes": {
            "new": sorted(set(right["process_names"]) - set(left["process_names"])),
            "disappeared": sorted(set(left["process_names"]) - set(right["process_names"])),
        },
        "event_classes": {
            "newly_missing": sorted(set(right["missing_event_types"])
                                    - set(left["missing_event_types"])),
            "resolved": sorted(set(left["missing_event_types"])
                               - set(right["missing_event_types"])),
        },
        "windows": _window_block(before, after),
        "warnings": warnings,
        "caveat": ("A diff describes two reports, not two hosts. Identical metrics can hide "
                   "different events, and a changed score is only meaningful when the config "
                   "digest is identical."),
    }


def _has_structural_change(left: dict, right: dict) -> bool:
    return any([
        left["reason_codes"] != right["reason_codes"],
        left["rule_counts"] != right["rule_counts"],
        left["policy_counts"] != right["policy_counts"],
        left["process_names"] != right["process_names"],
        left["missing_event_types"] != right["missing_event_types"],
        left["event_count"] != right["event_count"],
    ])


def _window_block(before: dict, after: dict) -> dict:
    left = ((before.get("windowed") or {}).get("summary")) or {}
    right = ((after.get("windowed") or {}).get("summary")) or {}
    if not left and not right:
        return {"present": False}
    if not left or not right:
        return {"present": False,
                "note": "only one report was analyzed with --window; window verdicts "
                        "cannot be compared"}
    left_counts = {str(k): int(v) for k, v in (left.get("status_counts") or {}).items()}
    right_counts = {str(k): int(v) for k, v in (right.get("status_counts") or {}).items()}
    return {
        "present": True,
        "window_count_delta": int(right.get("window_count", 0)) - int(left.get("window_count", 0)),
        "worst_status_before": left.get("worst_status"),
        "worst_status_after": right.get("worst_status"),
        "status_counts_before": dict(sorted(left_counts.items())),
        "status_counts_after": dict(sorted(right_counts.items())),
        "flagged_window_delta": _flagged(right_counts) - _flagged(left_counts),
    }


def _flagged(counts: dict) -> int:
    return int(counts.get("SUSPICIOUS", 0)) + int(counts.get("HIGH_RISK", 0))


def is_regression(diff: dict) -> bool:
    """Whether ``--fail-on-regression`` should fail."""
    return diff["verdict"] in {"regression", "evidence-lost"}


def render_text(diff: dict) -> str:
    """Plain-text diff for a terminal."""
    before, after = diff["before"], diff["after"]
    lines = [f"CABID report diff — {diff['verdict'].upper()}", ""]
    lines.append(f"  status        {before['status']:<20} -> {after['status']}")
    if diff["score_delta"] is None:
        lines.append(f"  score         {before['anomaly_score']} -> {after['anomaly_score']}"
                     "  (not comparable)")
    else:
        lines.append(f"  score         {before['anomaly_score']:.3f} -> "
                     f"{after['anomaly_score']:.3f}  ({diff['score_delta']:+.3f})")
    lines.append(f"  events        {before['event_count']} -> {after['event_count']}"
                 f"  ({after['event_count'] - before['event_count']:+d})")
    coverage = (before["coverage"], after["coverage"])
    if None not in coverage:
        lines.append(f"  coverage      {coverage[0]:.3f} -> {coverage[1]:.3f}")
    moved = {name: delta for name, delta in diff["component_delta"].items()
             if abs(delta) > 1e-9}
    if moved:
        lines.append("")
        lines.append("  components")
        for name, delta in sorted(diff["component_delta"].items(),
                                  key=lambda item: -abs(item[1])):
            if abs(delta) > 1e-9:
                lines.append(f"    {name:<14}{delta:+.4f}")
    for title, values in (("reasons added", diff["reason_codes"]["added"]),
                          ("reasons removed", diff["reason_codes"]["removed"]),
                          ("new rule matches", diff["rules"]["new"]),
                          ("rule matches cleared", diff["rules"]["cleared"]),
                          ("new policy findings", diff["policy"]["new"]),
                          ("policy findings cleared", diff["policy"]["cleared"]),
                          ("new processes", diff["processes"]["new"]),
                          ("processes gone", diff["processes"]["disappeared"]),
                          ("event classes newly missing", diff["event_classes"]["newly_missing"]),
                          ("event classes recovered", diff["event_classes"]["resolved"])):
        if values:
            lines.append(f"  {title}: {', '.join(values)}")
    if diff["windows"].get("present"):
        windows = diff["windows"]
        lines.append(f"  windows       {windows['worst_status_before']} -> "
                     f"{windows['worst_status_after']}")
    if diff["warnings"]:
        lines.append("")
        for warning in diff["warnings"]:
            lines.append(f"  ! {warning}")
    if not diff["comparable"]:
        lines.append("")
        lines.append("  scores are not comparable; the verdict describes evidence and "
                     "findings only")
    lines.append("")
    lines.append(f"  {diff['caveat']}")
    return "\n".join(lines) + "\n"


def render_markdown(diff: dict) -> str:
    """Markdown diff, suitable for attaching to a ticket."""
    before, after = diff["before"], diff["after"]
    lines = [f"# CABID report diff — {diff['verdict']}", ""]
    lines += ["| Field | Before | After | Delta |", "| --- | --- | --- | --- |"]
    lines.append(f"| Status | {before['status']} | {after['status']} | "
                 f"{'changed' if diff['status']['changed'] else 'same'} |")
    if diff["score_delta"] is None:
        lines.append(f"| Score | {before['anomaly_score']} | {after['anomaly_score']} | "
                     "not comparable |")
    else:
        lines.append(f"| Score | {before['anomaly_score']:.3f} | {after['anomaly_score']:.3f} | "
                     f"{diff['score_delta']:+.3f} |")
    lines.append(f"| Events | {before['event_count']} | {after['event_count']} | "
                 f"{after['event_count'] - before['event_count']:+d} |")
    if before["coverage"] is not None and after["coverage"] is not None:
        lines.append(f"| Coverage | {before['coverage']:.3f} | {after['coverage']:.3f} | "
                     f"{after['coverage'] - before['coverage']:+.3f} |")
    lines.append("")
    if diff["component_delta"]:
        lines += ["## Component movement", "", "| Component | Delta |", "| --- | --- |"]
        for name, delta in sorted(diff["component_delta"].items(), key=lambda item: -abs(item[1])):
            lines.append(f"| {name} | {delta:+.4f} |")
        lines.append("")
    sections = [("Reasons added", diff["reason_codes"]["added"]),
                ("Reasons removed", diff["reason_codes"]["removed"]),
                ("New rule matches", diff["rules"]["new"]),
                ("Rule matches cleared", diff["rules"]["cleared"]),
                ("New policy findings", diff["policy"]["new"]),
                ("Policy findings cleared", diff["policy"]["cleared"]),
                ("New processes", diff["processes"]["new"]),
                ("Processes gone", diff["processes"]["disappeared"]),
                ("Event classes newly missing", diff["event_classes"]["newly_missing"]),
                ("Event classes recovered", diff["event_classes"]["resolved"])]
    for title, values in sections:
        if values:
            lines.append(f"- **{title}:** {', '.join(f'`{value}`' for value in values)}")
    if sections and any(values for _, values in sections):
        lines.append("")
    if diff["warnings"]:
        lines += ["## Warnings", ""]
        lines += [f"- {warning}" for warning in diff["warnings"]]
        lines.append("")
    lines += ["## Caveat", "", diff["caveat"]]
    return "\n".join(lines) + "\n"


__all__ = ["FORMAT", "ReportDiffError", "summary_of", "compare_reports",
           "is_regression", "render_text", "render_markdown"]
