"""Per-process (entity) risk rollup.

A window verdict tells an analyst *that* something looked wrong. This module
answers *which process* to open first: it aggregates lifecycle contradictions,
ancestry oddities, sensitive-target touches, and novelty per process and ranks
them. Ranking is a triage hint, never an attribution: a high-ranked process is
one whose behaviour is least consistent with the observed baseline, which is also
what a noisy but harmless service can look like.
"""
from __future__ import annotations

from .policy import _matches, _port_of

MAX_ENTITIES = 25


def _contradictions(events: list[dict]) -> dict[int, int]:
    """Count lifecycle contradictions per process, mirroring sequence.py logic."""
    state: dict[int, dict] = {}
    counts: dict[int, int] = {}
    for event in sorted(events, key=lambda item: float(item["timestamp"])):
        pid = event["process_id"]
        kind = event["event_type"]
        current = state.setdefault(pid, {"alive": False, "started": False, "exited": False})
        if kind == "process_start":
            if current["alive"] and current["started"]:
                counts[pid] = counts.get(pid, 0) + 1
            current.update(alive=True, started=True, exited=False)
        elif kind == "process_exec":
            current.update(alive=True, started=True)
        elif kind == "process_exit":
            if current["exited"]:
                counts[pid] = counts.get(pid, 0) + 1
            current.update(alive=False, exited=True)
        elif kind in {"file_write", "network_connect"}:
            if current["exited"] and not current["alive"]:
                counts[pid] = counts.get(pid, 0) + 1
    return counts


def entity_features(events: list[dict], policy: dict | None = None,
                    profile: dict | None = None) -> dict:
    """Aggregate and rank per-process risk signals."""
    contradictions = _contradictions(events)
    sensitive_paths = list((policy or {}).get("sensitive_paths") or [])
    sensitive_ports = set((policy or {}).get("sensitive_ports") or [])
    known_executables = (profile or {}).get("executables") or {}

    entities: dict[int, dict] = {}
    for event in events:
        pid = event["process_id"]
        entity = entities.setdefault(pid, {
            "process_id": pid,
            "process_names": set(),
            "executables": set(),
            "event_count": 0,
            "event_types": set(),
            "first_seen": float(event["timestamp"]),
            "last_seen": float(event["timestamp"]),
            "self_parent_events": 0,
            "sensitive_hits": 0,
            "sensitive_refs": [],
            "novel_executable": False,
        })
        stamp = float(event["timestamp"])
        entity["event_count"] += 1
        entity["event_types"].add(event["event_type"])
        entity["first_seen"] = min(entity["first_seen"], stamp)
        entity["last_seen"] = max(entity["last_seen"], stamp)
        name = str(event.get("process_name") or "").strip()
        executable = str(event.get("executable") or "").strip()
        if name and name != "unknown":
            entity["process_names"].add(name[:120])
        if executable:
            entity["executables"].add(executable[:200])
        if event["parent_process_id"] == pid:
            entity["self_parent_events"] += 1
        target = str(event.get("target") or "")
        hit = None
        if event["event_type"] == "file_write" and target:
            hit = _matches(target, sensitive_paths)
        elif event["event_type"] == "network_connect" and target:
            port = _port_of(target)
            if port is not None and port in sensitive_ports:
                hit = f"port {port}"
        if hit:
            entity["sensitive_hits"] += 1
            if len(entity["sensitive_refs"]) < 5:
                entity["sensitive_refs"].append(str(hit)[:80])
        if profile is not None and name and executable:
            seen = known_executables.get(name)
            if seen is not None and executable not in seen:
                entity["novel_executable"] = True

    ranked = []
    for entity in entities.values():
        multiplicity = max(1, entity["event_count"])
        contradiction_rate = contradictions.get(entity["process_id"], 0) / multiplicity
        self_parent_rate = entity["self_parent_events"] / multiplicity
        sensitive_rate = min(1.0, entity["sensitive_hits"] / 3.0)
        risk = (0.35 * min(1.0, contradiction_rate * 4.0)
                + 0.30 * self_parent_rate
                + 0.20 * sensitive_rate
                + 0.15 * (1.0 if entity["novel_executable"] else 0.0))
        ranked.append({
            "process_id": entity["process_id"],
            "process_names": sorted(entity["process_names"]) or ["unknown"],
            "executables": sorted(entity["executables"])[:5],
            "event_count": entity["event_count"],
            "event_types": sorted(entity["event_types"]),
            "first_seen": round(entity["first_seen"], 3),
            "last_seen": round(entity["last_seen"], 3),
            "contradiction_events": contradictions.get(entity["process_id"], 0),
            "self_parent_events": entity["self_parent_events"],
            "sensitive_hits": entity["sensitive_hits"],
            "sensitive_refs": entity["sensitive_refs"],
            "novel_executable": entity["novel_executable"],
            "entity_risk": round(risk, 6),
        })
    ranked.sort(key=lambda item: (-item["entity_risk"], -item["event_count"], item["process_id"]))
    flagged = [item for item in ranked if item["entity_risk"] > 0]
    return {
        "entity_count": len(ranked),
        "flagged_entity_count": len(flagged),
        "top_entities": ranked[:MAX_ENTITIES],
        "entities_truncated": len(ranked) > MAX_ENTITIES,
        "ranking_semantics": "triage hint based on observed inconsistencies; not an attribution",
    }
