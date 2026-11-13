"""Process-lifecycle sequencing checks.

Only *internally contradictory* histories are scored. A process whose creation
predates the observation window is normal context, not an anomaly, so missing
predecessors are reported separately and never contribute to the score.
"""
from __future__ import annotations

from collections import Counter

SUSPICIOUS_TRANSITIONS = (
    ("activity after process exit", "file_write or network_connect after process_exit without a new process_start"),
    ("duplicate process start", "process_start for a live process that never exited"),
    ("duplicate process exit", "process_exit without an observed start or an earlier exit"),
)


def sequence_features(events: list[dict], amplification: float = 4.0) -> dict:
    """Score lifecycle contradictions and summarise observed transitions."""
    if not isinstance(amplification, (int, float)) or amplification <= 0:
        raise ValueError("amplification must be positive")
    ordered = sorted(events, key=lambda item: float(item["timestamp"]))
    state: dict[int, dict] = {}
    transitions: Counter[tuple[str, str]] = Counter()
    activity_after_exit = duplicate_start = duplicate_exit = 0
    observed_types: dict[int, set[str]] = {}

    for event in ordered:
        pid = event["process_id"]
        kind = event["event_type"]
        current = state.get(pid)
        if current is None:
            current = {"alive": False, "started": False, "exited": False, "last": None}
            state[pid] = current
        previous = current["last"]
        if previous is not None and previous != kind:
            transitions[(previous, kind)] += 1
        if kind == "process_start":
            if current["alive"] and current["started"]:
                duplicate_start += 1
            current.update(alive=True, started=True, exited=False)
        elif kind == "process_exec":
            current.update(alive=True)
            if not current["started"]:
                current["started"] = True
        elif kind == "process_exit":
            if current["exited"]:
                duplicate_exit += 1
            current.update(alive=False, exited=True)
        elif kind in {"file_write", "network_connect"}:
            if current["exited"] and not current["alive"]:
                activity_after_exit += 1
        current["last"] = kind
        observed_types.setdefault(pid, set()).add(kind)

    contradictions = activity_after_exit + duplicate_start + duplicate_exit
    denominator = max(len(ordered), 1)
    ratio = contradictions / denominator
    score = min(1.0, ratio * float(amplification))
    top = [
        {"from": source, "to": target, "count": count}
        for (source, target), count in transitions.most_common(8)
    ]
    return {
        "sequence_score": round(score, 6),
        "contradiction_events": contradictions,
        "contradiction_ratio": round(ratio, 6),
        "amplification": float(amplification),
        "activity_after_exit": activity_after_exit,
        "duplicate_start": duplicate_start,
        "duplicate_exit": duplicate_exit,
        "process_count": len(state),
        "processes_with_multiple_types": sum(1 for kinds in observed_types.values() if len(kinds) > 1),
        "common_transitions": top,
        "checked_transitions": sorted(SUSPICIOUS_TRANSITIONS),
    }
