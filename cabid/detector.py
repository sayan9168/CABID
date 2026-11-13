"""Explainable CABID scoring engine.

Scores are documented research heuristics, not calibrated probabilities. The
engine fuses temporal shape, ancestry consistency, lifecycle contradictions,
telemetry completeness and (optionally) novelty against a benign baseline.
"""
from __future__ import annotations

from .baseline import novelty_features
from .causal import causal_features
from .completeness import completeness_features
from .config import DEFAULT_CONFIG, config_digest, default_config, validate_config
from .containers import analyse_scopes
from .entities import entity_features
from .rules import evaluate_rules, load_rules
from .tree import process_tree
from .sequence import sequence_features
from .temporal import temporal_features, temporal_score

SCORE_SEMANTICS = "heuristic score; not a calibrated probability"
STATUS_ORDER = ("NO_ANOMALY_DETECTED", "SUSPICIOUS", "HIGH_RISK", "INSUFFICIENT_EVIDENCE")


def _reason(code: str, detail: str, weight: float, value: float) -> dict:
    return {"code": code, "detail": detail, "weight": round(weight, 6), "component_value": round(value, 6)}


def analyze(events: list[dict], config: dict | None = None, profile: dict | None = None,
            policy: dict | None = None, rules: list[dict] | None = None) -> dict:
    """Analyze normalized events and return a structured, explainable report.

    ``policy`` feeds the per-process entity rollup; policy findings themselves are
    produced by :func:`cabid.policy.evaluate_policy`. ``rules`` defaults to the
    built-in correlation pack; pass an explicit list (including ``[]``) to control
    what is evaluated. Rule and tree output are context only: neither changes the
    weighted score.
    """
    cfg = validate_config(config or {})
    weights = cfg["weights"]
    thresholds = cfg["thresholds"]
    completeness_cfg = cfg["completeness"]

    temporal = temporal_features(events)
    causal = causal_features(events)
    sequence = sequence_features(events, cfg["sequence"]["amplification"])
    completeness = completeness_features(
        events,
        expected_event_types=set(completeness_cfg["expected_event_types"]),
        minimum_ratio=float(completeness_cfg["minimum_ratio"]),
    )
    baseline_profile = profile if profile is not None else None
    if baseline_profile is None and cfg.get("baseline"):
        from .baseline import load_profile

        baseline_profile = load_profile(cfg["baseline"])
    novelty = novelty_features(events, baseline_profile)
    entities = entity_features(events, policy, baseline_profile)
    tree = process_tree(events, baseline_profile)
    scopes = analyse_scopes(events)
    active_rules = load_rules(None) if rules is None else rules
    rule_report = evaluate_rules(events, active_rules)

    t_score = temporal_score(temporal, thresholds)
    c_score = float(causal["causal_score"])
    s_score = float(sequence["sequence_score"])
    gap_score = 1.0 - float(completeness["completeness"])
    n_score = float(novelty["novelty_score"])

    contributions = {
        "temporal": t_score,
        "causal": c_score,
        "sequence": s_score,
        "telemetry_gap": gap_score,
        "novelty": n_score,
    }
    active = {name: max(0.0, float(weights[name])) for name in contributions}
    if not novelty["novelty_available"]:
        active["novelty"] = 0.0
    denominator = sum(active.values())
    if denominator <= 0:
        raise ValueError("configuration leaves no active scoring component")
    weighted = {name: active[name] * contributions[name] for name in contributions}
    anomaly = sum(weighted.values()) / denominator

    suspicious = float(thresholds["suspicious"])
    high = float(thresholds["high"])
    if not completeness["telemetry_sufficient"]:
        status = "INSUFFICIENT_EVIDENCE"
    elif anomaly >= high:
        status = "HIGH_RISK"
    elif anomaly >= suspicious:
        status = "SUSPICIOUS"
    else:
        status = "NO_ANOMALY_DETECTED"

    reasons: list[dict] = []
    if t_score >= 0.5:
        reasons.append(_reason(
            "temporal_rate_or_burst",
            f"event rate {temporal['rate_per_minute']:.1f}/min or burstiness "
            f"{temporal['burstiness']:.2f} exceeds configured bounds",
            active["temporal"], t_score))
    if c_score > 0:
        reasons.append(_reason(
            "self_parent_ancestry",
            f"{causal['self_parent_events']} event(s) report a process as its own parent",
            active["causal"], c_score))
    if s_score > 0:
        reasons.append(_reason(
            "lifecycle_contradiction",
            f"{sequence['contradiction_events']} lifecycle contradiction(s): "
            f"{sequence['activity_after_exit']} activity-after-exit, "
            f"{sequence['duplicate_start']} duplicate start, "
            f"{sequence['duplicate_exit']} duplicate exit",
            active["sequence"], s_score))
    if gap_score > 0:
        reasons.append(_reason(
            "telemetry_gap",
            "missing event classes: " + ", ".join(completeness["missing_event_types"]),
            active["telemetry_gap"], gap_score))
    if n_score > 0:
        detail = "session deviates from the benign baseline"
        if novelty["novel_executable_processes"]:
            detail += "; novel executables for known process names: " + ", ".join(
                novelty["novel_executable_processes"][:5])
        reasons.append(_reason("baseline_novelty", detail, active["novelty"], n_score))
    if not reasons:
        reasons.append(_reason(
            "no_heuristic_triggered",
            "no configured heuristic crossed its explanation threshold",
            0.0, 0.0))
    reasons.sort(key=lambda item: item["weight"] * item["component_value"], reverse=True)

    return {
        "status": status,
        "anomaly_score": round(anomaly, 6),
        "score_semantics": SCORE_SEMANTICS,
        "components": {name: round(value, 6) for name, value in contributions.items()},
        "contribution": {name: round(weighted[name] / denominator, 6) for name in contributions},
        "normalized_weights": {name: round(active[name] / denominator, 6) for name in contributions},
        "temporal": temporal,
        "causal": causal,
        "sequence": sequence,
        "completeness": completeness,
        "novelty": novelty,
        "entities": entities,
        "tree": tree,
        "containers": scopes,
        "rules": rule_report,
        "reasons": reasons,
        "event_count": len(events),
        "config_digest": config_digest(cfg),
        "baseline_used": novelty["novelty_available"],
        "window_seconds": cfg.get("window_seconds"),
    }


def analyze_windows(events: list[dict], window_seconds: float,
                    config: dict | None = None, profile: dict | None = None,
                    policy: dict | None = None, rules: list[dict] | None = None) -> dict:
    """Split a stream into fixed windows and analyze each independently."""
    if not isinstance(window_seconds, (int, float)) or window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    ordered = sorted(events, key=lambda item: float(item["timestamp"]))
    if not ordered:
        return {"window_seconds": float(window_seconds), "windows": [], "summary": {}}
    origin = float(ordered[0]["timestamp"])
    buckets: dict[int, list[dict]] = {}
    for event in ordered:
        index = int((float(event["timestamp"]) - origin) // float(window_seconds))
        buckets.setdefault(index, []).append(event)
    windows, reports = [], []
    for index in sorted(buckets):
        report = analyze(buckets[index], config, profile, policy, rules)
        reports.append(report)
        windows.append({
            "window_index": index,
            "start": round(origin + index * float(window_seconds), 6),
            "end": round(origin + (index + 1) * float(window_seconds), 6),
            "status": report["status"],
            "anomaly_score": report["anomaly_score"],
            "event_count": report["event_count"],
            "top_reason": report["reasons"][0]["code"],
            "flagged_entities": report["entities"]["flagged_entity_count"],
        })
    counts: dict[str, int] = {}
    for window in windows:
        counts[window["status"]] = counts.get(window["status"], 0) + 1
    overall = max(
        reports,
        key=lambda report: (report["status"] == "HIGH_RISK", report["status"] == "SUSPICIOUS",
                            report["anomaly_score"]),
    )
    return {
        "window_seconds": float(window_seconds),
        "windows": windows,
        "aggregate": analyze(ordered, config, profile, policy, rules),
        "summary": {
            "window_count": len(windows),
            "status_counts": dict(sorted(counts.items())),
            "worst_status": overall["status"],
            "worst_anomaly_score": overall["anomaly_score"],
            "max_events_per_window": max(window["event_count"] for window in windows),
        },
    }


def explain_score(report: dict, config: dict | None = None) -> dict:
    """Show the score as arithmetic, term by term.

    The engine renormalizes over *active* components, so a weight in the config is
    not the weight actually used. That surprises people reading a report, so this
    returns every multiplication, the denominator, and the status decision, in the
    order the code applies them.
    """
    cfg = validate_config(config or {})
    thresholds = cfg["thresholds"]
    components = report.get("components") or {}
    weights = report.get("normalized_weights") or {}
    steps = []
    total = 0.0
    for name in ("temporal", "causal", "sequence", "telemetry_gap", "novelty"):
        value = float(components.get(name, 0.0))
        weight = float(weights.get(name, 0.0))
        product = weight * value
        total += product
        note = ""
        if name == "novelty" and not report.get("baseline_used", True):
            note = "inactive: no baseline profile, weight redistributed to other components"
        steps.append({
            "component": name,
            "component_value": round(value, 6),
            "normalized_weight": round(weight, 6),
            "product": round(product, 6),
            "share_of_score": round(product, 6),
            "note": note,
        })
    denominator = sum(float(weights.get(name, 0.0)) for name in components)
    steps.sort(key=lambda item: item["product"], reverse=True)
    score = round(total, 6)
    reported = report.get("anomaly_score")
    completeness = report.get("completeness") or {}
    status = report.get("status")
    decision = []
    if not completeness.get("telemetry_sufficient", True):
        decision.append(
            "telemetry_sufficient is false (completeness "
            f"{completeness.get('completeness')} < {completeness.get('minimum_required_completeness')}), "
            "so the score is not used and the status is INSUFFICIENT_EVIDENCE")
    else:
        decision.append(
            f"score {score} vs suspicious >= {float(thresholds['suspicious'])}: "
            + ("met" if score >= float(thresholds["suspicious"]) else "not met"))
        if score >= float(thresholds["high"]):
            decision.append(f"score {score} >= high {float(thresholds['high'])}: HIGH_RISK")
        elif score >= float(thresholds["suspicious"]):
            decision.append(f"score < high {float(thresholds['high'])}: SUSPICIOUS")
        else:
            decision.append("score below both thresholds: NO_ANOMALY_DETECTED")
    return {
        "formula": "anomaly_score = sum(normalized_weight_i * component_value_i) over active components",
        "steps": steps,
        "weight_denominator": round(denominator, 6),
        "recomputed_score": score,
        "reported_score": reported,
        "recomputes_consistently": reported is not None and abs(float(reported) - score) <= 1e-6,
        "thresholds": {"suspicious": float(thresholds["suspicious"]), "high": float(thresholds["high"])},
        "decision": decision,
        "final_status": status,
        "semantics": SCORE_SEMANTICS,
        "caveat": "Every term is a documented heuristic in [0,1]; the sum is not a probability of attack.",
    }


def render_score_explanation(explanation: dict) -> str:
    """Plain-text arithmetic walkthrough for the CLI."""
    lines = [
        "Score arithmetic (highest term first)",
        f"  formula: {explanation['formula']}",
        "",
        f"  {'component':<16}{'value':>9}{'weight':>9}{'product':>10}  note",
    ]
    for step in explanation["steps"]:
        lines.append(
            f"  {step['component']:<16}{step['component_value']:>9.4f}"
            f"{step['normalized_weight']:>9.4f}{step['product']:>10.4f}  {step['note']}".rstrip())
    lines.append(f"  {'sum':<16}{'':>9}{explanation['weight_denominator']:>9.4f}"
                 f"{explanation['recomputed_score']:>10.4f}")
    lines.append("")
    lines.append(f"  weights sum to {explanation['weight_denominator']} before renormalization; "
                 "the score is the plain sum of the products above.")
    lines.append(f"  reported score {explanation['reported_score']} recomputes consistently: "
                 f"{explanation['recomputes_consistently']}")
    lines.append("")
    for line in explanation["decision"]:
        lines.append(f"  decision: {line}")
    lines.append(f"  final status: {explanation['final_status']}")
    lines.append("")
    lines.append(f"  {explanation['caveat']}")
    return "\n".join(lines) + "\n"


def risk_level(score: float, config: dict | None = None) -> str:
    """Map a raw anomaly score to the configured risk band (no telemetry gate)."""
    thresholds = (config or {}).get("thresholds", DEFAULT_CONFIG["thresholds"])
    suspicious = float(thresholds.get("suspicious", 0.55))
    high = float(thresholds.get("high", 0.80))
    if score >= high:
        return "HIGH_RISK"
    if score >= suspicious:
        return "SUSPICIOUS"
    return "NO_ANOMALY_DETECTED"


__all__ = ["analyze", "analyze_windows", "explain_score", "render_score_explanation",
           "risk_level", "default_config", "STATUS_ORDER"]
