"""Benign-baseline profiles for novelty scoring.

A profile is a compact, auditable summary of *labelled benign* sessions:
a robust event-rate band, the observed event-type mix, and per-process
executable sets. Novelty is reported as context and only enters the weighted
score when a profile is supplied explicitly.

Profiles never store raw command lines, file paths, or addresses, so a profile
can be shared for review without leaking collected content.
"""
from __future__ import annotations

import json
import math
from pathlib import Path
from statistics import median

from .normalize import ALLOWED

PROFILE_FORMAT = "cabid-baseline/1"
_MIN_SCALE = 0.05


def _rates(events: list[dict]) -> list[float]:
    """Per-minute rate of one session; mirrors temporal_features arithmetic."""
    if len(events) < 2:
        return []
    times = sorted(float(event["timestamp"]) for event in events)
    duration = max(times) - min(times)
    return [len(times) * 60.0 / max(duration, 1.0)]


def _type_mix(events: list[dict]) -> dict[str, float]:
    if not events:
        return {}
    counts = {kind: 0 for kind in sorted(ALLOWED)}
    for event in events:
        counts[event["event_type"]] = counts.get(event["event_type"], 0) + 1
    total = len(events)
    return {kind: round(count / total, 6) for kind, count in counts.items()}


def build_profile(sessions: list[tuple[str, list[dict]]], minimum_sessions: int = 3) -> dict:
    """Fit a baseline profile from ``(session_id, events)`` benign sessions."""
    usable = [(name, events) for name, events in sessions if events]
    if len(usable) < max(1, minimum_sessions):
        raise ValueError(
            f"a baseline needs at least {max(1, minimum_sessions)} non-empty benign sessions"
        )
    rates = []
    for _, events in usable:
        rates.extend(_rates(events))
    if not rates:
        raise ValueError("baseline sessions need at least two events to measure a rate")
    median_rate = float(median(rates))
    deviations = [abs(rate - median_rate) for rate in rates]
    scale = float(median(deviations)) * 1.4826 or _MIN_SCALE

    per_process: dict[str, set[str]] = {}
    edges: set[tuple[str, str]] = set()
    for _, events in usable:
        names = {}
        for event in events:
            name = str(event.get("process_name") or "unknown")
            executable = str(event.get("executable") or "").strip()
            per_process.setdefault(name, set())
            if executable:
                per_process[name].add(executable)
            if name != "unknown":
                names[event["process_id"]] = name
        for event in events:
            parent = names.get(event.get("parent_process_id") or -1)
            child = names.get(event["process_id"])
            if parent and child and parent != "unknown" and child != "unknown":
                edges.add((parent, child))

    mix_totals = _type_mix([event for _, events in usable for event in events])
    return {
        "format": PROFILE_FORMAT,
        "session_count": len(usable),
        "event_count": sum(len(events) for _, events in usable),
        "sessions": sorted(name for name, _ in usable),
        "rate_per_minute": {"median": round(median_rate, 6), "scale": round(scale, 6)},
        "type_mix": mix_totals,
        "process_names": sorted(per_process),
        "parent_child": [list(edge) for edge in sorted(edges)],
        "executables": {name: sorted(values) for name, values in sorted(per_process.items())},
        "notes": [
            "Derived only from sessions labelled benign by the operator.",
            "No raw paths, addresses, or command lines are stored.",
            "Novelty events require an executable set difference for a known process name.",
            "Parent/child edges are stored as names so tree drift can be compared without pids.",
        ],
    }


def write_profile(profile: dict, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def load_profile(path: str | Path) -> dict:
    source = Path(path)
    try:
        profile = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{source}: invalid baseline profile JSON: {exc}") from exc
    if not isinstance(profile, dict) or profile.get("format") != PROFILE_FORMAT:
        raise ValueError(f"{source}: not a {PROFILE_FORMAT} profile")
    rate = profile.get("rate_per_minute") or {}
    try:
        median_rate = float(rate["median"])
        scale = float(rate["scale"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"{source}: profile is missing a usable rate band") from exc
    if median_rate < 0 or scale <= 0 or not math.isfinite(median_rate + scale):
        raise ValueError(f"{source}: profile rate band is invalid")
    if not isinstance(profile.get("executables", {}), dict):
        raise ValueError(f"{source}: profile executables must be an object")
    return profile


def novelty_features(events: list[dict], profile: dict | None = None) -> dict:
    """Compare a session against a benign baseline profile."""
    if profile is None:
        return {
            "novelty_available": False,
            "novelty_score": 0.0,
            "note": "no baseline profile supplied; novelty is not scored",
        }
    rate = profile.get("rate_per_minute") or {}
    median_rate = float(rate.get("median", 0.0))
    scale = float(rate.get("scale", _MIN_SCALE)) or _MIN_SCALE
    observed_rate = (_rates(events) or [0.0])[0]
    z_rate = min(1.0, abs(observed_rate - median_rate) / (6.0 * scale)) if scale > 0 else 0.0

    executables = profile.get("executables") or {}
    known_names = set(executables)
    observations: dict[str, set[str]] = {}
    for event in events:
        name = str(event.get("process_name") or "unknown")
        executable = str(event.get("executable") or "").strip()
        observations.setdefault(name, set())
        if executable:
            observations[name].add(executable)
    novel = sorted(
        name
        for name, found in observations.items()
        if name in known_names and found - set(executables.get(name) or [])
    )
    unknown_names = sorted(name for name in observations if name not in known_names)
    total = max(len(observations), 1)
    novelty_ratio = len(novel) / total
    mix_novelty = _mix_novelty(events, profile.get("type_mix") or {})
    score = min(1.0, 0.5 * z_rate + 0.3 * novelty_ratio + 0.2 * mix_novelty)
    return {
        "novelty_available": True,
        "novelty_score": round(score, 6),
        "observed_rate_per_minute": round(observed_rate, 6),
        "baseline_rate_per_minute": round(median_rate, 6),
        "rate_z_score": round(z_rate, 6),
        "novel_executable_processes": novel,
        "unseen_process_names": unknown_names,
        "process_type_mix_divergence": round(mix_novelty, 6),
        "baseline_session_count": profile.get("session_count"),
    }


def _mix_novelty(events: list[dict], baseline: dict[str, float]) -> float:
    """Total-variation distance between observed and baselined type mix."""
    observed = _type_mix(events)
    if not baseline or not observed:
        return 0.0
    total = 0.0
    for kind in sorted(set(baseline) | set(observed)):
        total += abs(float(baseline.get(kind, 0.0)) - float(observed.get(kind, 0.0)))
    return min(1.0, total / 2.0)


def drift_suggestions(profile: dict, sessions: list[tuple[str, list[dict]]],
                      min_support: int = 2, max_suggestions: int = 25) -> dict:
    """Suggest profile updates from newer benign sessions.

    Baseline rot is silent: a package upgrade adds an executable, the profile goes
    stale, and benign activity starts scoring as novel. This produces a *diff*
    for the operator to review — it never rewrites the profile. A suggestion is
    only made when at least ``min_support`` sessions agree, so one odd but benign
    session cannot widen the baseline on its own.
    """
    if not isinstance(profile, dict):
        raise ValueError("a baseline profile object is required")
    known = {str(name): set(values or []) for name, values in (profile.get("executables") or {}).items()}
    seen_names: dict[str, set[str]] = {}
    seen_edges: dict[tuple[str, str], int] = {}
    edge_support: dict[tuple[str, str], set[str]] = {}
    support: dict[str, set[str]] = {}
    for session_name, events in sessions:
        names = {}
        local: dict[str, set[str]] = {}
        for event in events:
            name = str(event.get("process_name") or "unknown")
            if name == "unknown":
                continue
            local.setdefault(name, set())
            executable = str(event.get("executable") or "").strip()
            if executable:
                local[name].add(executable)
            names[event["process_id"]] = name
        for name, executables in local.items():
            seen_names.setdefault(name, set()).update(executables)
            support.setdefault(name, set()).add(str(session_name))
        for event in events:
            parent = names.get(event.get("parent_process_id") or -1)
            child = names.get(event["process_id"])
            if parent and child and parent != child:
                edge = (parent, child)
                seen_edges[edge] = seen_edges.get(edge, 0) + 1
                edge_support.setdefault(edge, set()).add(str(session_name))

    known_edges = {tuple(edge) for edge in (profile.get("parent_child") or [])}
    new_processes, new_executables = [], []
    for name, executables in sorted(seen_names.items()):
        if len(support.get(name, ())) < min_support:
            continue
        if name not in known:
            new_processes.append({"process_name": name, "executables": sorted(executables)[:10],
                                  "sessions": len(support.get(name, ()))})
            continue
        added = sorted(executables - known[name])
        if added:
            new_executables.append({"process_name": name, "new_executables": added[:10],
                                    "sessions": len(support.get(name, ()))})
    new_edges = [
        {"parent": parent, "child": child, "occurrences": count,
         "sessions": len(edge_support.get((parent, child), ()))}
        for (parent, child), count in sorted(seen_edges.items())
        if (parent, child) not in known_edges
        and len(edge_support.get((parent, child), ())) >= min_support
    ]
    suggestions = new_processes + new_executables + new_edges
    return {
        "profile_format": profile.get("format"),
        "sessions_evaluated": len(sessions),
        "min_support": min_support,
        "suggestion_count": len(suggestions),
        "new_processes": new_processes[:max_suggestions],
        "new_executables": new_executables[:max_suggestions],
        "new_parent_child_edges": new_edges[:max_suggestions],
        "applied": False,
        "notes": [
            "Suggestions only; the profile is never modified automatically.",
            "A suggestion needs support from at least the minimum number of sessions.",
            "Review a suggestion before widening the baseline: drift and compromise look identical in a diff.",
        ],
    }
