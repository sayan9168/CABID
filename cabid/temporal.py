"""Temporal features; deterministic and dependency-free."""
from collections import Counter
from statistics import pstdev

from .normalize import CORE_EVENT_TYPES


def temporal_features(events: list[dict]) -> dict:
    if not events:
        return {"event_count": 0, "rate_per_minute": 0.0, "burstiness": 0.0, "type_diversity": 0.0}
    times = sorted(float(e["timestamp"]) for e in events)
    duration = max(times) - min(times)
    gaps = [b - a for a, b in zip(times, times[1:])]
    mean_gap = sum(gaps) / len(gaps) if gaps else 0.0
    burstiness = pstdev(gaps) / mean_gap if len(gaps) > 1 and mean_gap > 0 else 0.0
    counts = Counter(e["event_type"] for e in events)
    # Diversity is measured against the core classes so optional auditd classes
    # cannot push the ratio above 1.0 or change the meaning between sensor types.
    diversity = len(set(counts) & CORE_EVENT_TYPES) / float(len(CORE_EVENT_TYPES))
    return {"event_count": len(events), "rate_per_minute": len(events) * 60.0 / max(duration, 1.0),
            "burstiness": burstiness, "type_diversity": diversity,
            "event_type_counts": dict(sorted(counts.items()))}


def temporal_score(features: dict, thresholds: dict | None = None) -> float:
    thresholds = thresholds or {}
    rate_limit = float(thresholds.get("rate_per_minute", 120.0))
    burst_limit = float(thresholds.get("burstiness", 3.0))
    if rate_limit <= 0 or burst_limit <= 0:
        raise ValueError("temporal thresholds must be positive")
    rate_component = min(1.0, max(0.0, features.get("rate_per_minute", 0.0)) / rate_limit)
    burst_component = min(1.0, max(0.0, features.get("burstiness", 0.0)) / burst_limit)
    return round(0.6 * rate_component + 0.4 * burst_component, 6)
