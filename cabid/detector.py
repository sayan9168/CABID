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
from .sequence import sequence_features
from .temporal import temporal_features, temporal_score

SCORE_SEMANTICS = "heuristic score; not a calibrated probability"
STATUS_ORDER = ("NO_ANOMALY_DETECTED", "SUSPICIOUS", "HIGH_RISK", "INSUFFICIENT_EVIDENCE")


def _reason(code: str, detail: str, weight: float, value: float) -> dict:
    return {"code": code, "detail": detail, "weight": round(weight, 6), "component_value": round(value, 6)}


def analyze(events: list[dict], config: dict | None = None, profile: dict | None = None) -> dict:
    """Analyze normalized events and return a structured, explainable report."""
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
        "reasons": reasons,
        "event_count": len(events),
        "config_digest": config_digest(cfg),
        "baseline_used": novelty["novelty_available"],
        "window_seconds": cfg.get("window_seconds"),
    }


def analyze_windows(events: list[dict], window_seconds: float,
                    config: dict | None = None, profile: dict | None = None) -> dict:
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
        report = analyze(buckets[index], config, profile)
        reports.append(report)
        windows.append({
            "window_index": index,
            "start": round(origin + index * float(window_seconds), 6),
            "end": round(origin + (index + 1) * float(window_seconds), 6),
            "status": report["status"],
            "anomaly_score": report["anomaly_score"],
            "event_count": report["event_count"],
            "top_reason": report["reasons"][0]["code"],
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
        "aggregate": analyze(ordered, config, profile),
        "summary": {
            "window_count": len(windows),
            "status_counts": dict(sorted(counts.items())),
            "worst_status": overall["status"],
            "worst_anomaly_score": overall["anomaly_score"],
            "max_events_per_window": max(window["event_count"] for window in windows),
        },
    }


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


__all__ = ["analyze", "analyze_windows", "risk_level", "default_config", "STATUS_ORDER"]
