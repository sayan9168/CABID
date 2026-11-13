"""Explainable CABID scoring engine. Scores are research heuristics, not probabilities."""
from .causal import causal_features
from .completeness import completeness_features
from .temporal import temporal_features, temporal_score

DEFAULT_CONFIG = {
    "weights": {"temporal": 0.45, "causal": 0.35, "telemetry_gap": 0.20},
    "thresholds": {"suspicious": 0.55, "high": 0.80, "rate_per_minute": 120.0, "burstiness": 3.0},
}


def analyze(events: list[dict], config: dict | None = None) -> dict:
    cfg = config or DEFAULT_CONFIG
    temporal = temporal_features(events)
    causal = causal_features(events)
    completeness = completeness_features(events)
    t_score, c_score = temporal_score(temporal, cfg.get("thresholds")), causal["causal_score"]
    gap_score = 1.0 - completeness["completeness"]
    weights = cfg.get("weights", DEFAULT_CONFIG["weights"])
    effective = {key: max(0.0, float(weights.get(key, 0.0)))
                 for key in ("temporal", "causal", "telemetry_gap")}
    denominator = sum(effective.values()) or 1.0
    anomaly = (effective["temporal"] * t_score + effective["causal"] * c_score
               + effective["telemetry_gap"] * gap_score) / denominator
    thresholds = cfg.get("thresholds", DEFAULT_CONFIG["thresholds"])
    suspicious, high = float(thresholds.get("suspicious", 0.55)), float(thresholds.get("high", 0.80))
    if not 0.0 <= suspicious <= high <= 1.0:
        raise ValueError("risk thresholds must satisfy 0 <= suspicious <= high <= 1")
    if not completeness["telemetry_sufficient"]:
        status = "INSUFFICIENT_EVIDENCE"
    elif anomaly >= high:
        status = "HIGH_RISK"
    elif anomaly >= suspicious:
        status = "SUSPICIOUS"
    else:
        status = "NO_ANOMALY_DETECTED"
    reasons = []
    if t_score >= 0.5:
        reasons.append("unusual event rate or burstiness")
    if c_score > 0:
        reasons.append("process ancestry contains self-parent references")
    if gap_score > 0:
        reasons.append("expected telemetry classes are missing")
    if not reasons:
        reasons.append("no configured heuristic crossed its explanation threshold")
    return {"status": status, "anomaly_score": round(anomaly, 6),
            "score_semantics": "heuristic score; not a calibrated probability",
            "components": {"temporal": t_score, "causal": c_score, "telemetry_gap": round(gap_score, 6)},
            "temporal": temporal, "causal": causal, "completeness": completeness,
            "reasons": reasons, "event_count": len(events)}
