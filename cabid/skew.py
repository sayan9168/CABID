"""Clock-skew estimation across merged sources.

`aggregate` warns when two sources overlap in time, but overlapping *coverage* is
not the same as agreeing *clocks*. If one host's clock is 40 seconds fast, the
merged stream interleaves events in the wrong order and lifecycle/sequence results
change silently.

This module estimates relative offset between sources without assuming which one
is correct, using the only signal a log-only tool has: repeated events that should
be simultaneous-ish (same process name and type occurring close together in
different sources), plus per-source cadence.

The estimator is deliberately conservative and says so: it reports an offset only
when there is enough repeated co-occurrence to support one, and it never applies a
correction automatically.
"""
from __future__ import annotations

from statistics import median

MIN_PAIRS = 5
MAX_PLAUSIBLE_SKEW = 600.0


def _source_of(event: dict) -> str:
    return str(event.get("source_file") or event.get("source") or "unknown")


def _signature(event: dict) -> tuple[str, str, str]:
    return (str(event.get("process_name") or "unknown"), event["event_type"],
            str(event.get("target") or ""))


def estimate_skew(events: list[dict]) -> dict:
    """Estimate per-source offsets relative to the largest source."""
    by_source: dict[str, list[dict]] = {}
    for event in events:
        by_source.setdefault(_source_of(event), []).append(event)
    if len(by_source) < 2:
        return {
            "sources_compared": len(by_source),
            "skew_detected": False,
            "offsets": {},
            "notes": ["Fewer than two sources; relative clock offset cannot be estimated."],
        }

    reference = max(by_source, key=lambda name: len(by_source[name]))
    ref_events = by_source[reference]
    index: dict[tuple[str, str, str], list[float]] = {}
    for event in ref_events:
        index.setdefault(_signature(event), []).append(float(event["timestamp"]))

    offsets: dict[str, dict] = {}
    for name, source_events in sorted(by_source.items()):
        if name == reference:
            continue
        deltas = []
        for event in source_events:
            candidates = index.get(_signature(event))
            if not candidates:
                continue
            stamp = float(event["timestamp"])
            nearest = min(candidates, key=lambda candidate: abs(candidate - stamp))
            if abs(nearest - stamp) <= MAX_PLAUSIBLE_SKEW:
                deltas.append(stamp - nearest)
        entry = {
            "source": name,
            "reference": reference,
            "matched_pairs": len(deltas),
            "events": len(source_events),
        }
        if len(deltas) >= MIN_PAIRS:
            offset = float(median(deltas))
            spread = float(median([abs(delta - offset) for delta in deltas]))
            entry.update({
                "estimated_offset_seconds": round(offset, 3),
                "spread_seconds": round(spread, 3),
                "confident": spread <= 5.0,
            })
        else:
            entry.update({
                "estimated_offset_seconds": None,
                "spread_seconds": None,
                "confident": False,
                "reason": f"only {len(deltas)} matched pairs (need {MIN_PAIRS})",
            })
        offsets[name] = entry

    confident = {name: item["estimated_offset_seconds"]
                 for name, item in offsets.items()
                 if item.get("confident") and abs(item["estimated_offset_seconds"]) >= 1.0}
    return {
        "sources_compared": len(by_source),
        "reference_source": reference,
        "skew_detected": bool(confident),
        "offsets": offsets,
        "confident_offsets": confident,
        "applied": False,
        "notes": [
            "Offsets are estimated from repeated identical events across sources.",
            "No correction is applied automatically; a wrong correction is worse than skew.",
            "Sign convention: positive means the source clock is ahead of the reference.",
            "Estimates need at least five matched pairs and tight spread to be called confident.",
        ],
    }
