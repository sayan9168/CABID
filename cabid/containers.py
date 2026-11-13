"""Best-effort container / PID-namespace reconstruction from event metadata.

The problem: an auditd record from inside a container reports the *child*
namespace pid. Two containers can both have a pid 42, and a container pid 1 has no
visible relationship to the host tree. Merging such streams naively produces
bogus parent links, false cycles, and inflated entity counts.

CABID cannot read ``/proc/<pid>/cgroup`` from a log file, so this module works from
metadata that events may carry:

``container_id`` / ``container``  short or long container id
``namespace_pid`` / ``pid_ns``    the pid as seen inside the namespace

When no container metadata is present, everything is treated as one host scope and
behaviour is unchanged. When it is present, pids are namespaced into stable
``scope:pid`` keys, and the report states which scopes were seen and whether any
pid collided across scopes. Nothing here is guessed from names.
"""
from __future__ import annotations

import re

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
MAX_SCOPES = 50


class ScopeError(ValueError):
    """Raised when container metadata is present but unusable."""


def _scope_of(event: dict) -> tuple[str, int]:
    """Return (scope, pid-in-scope) for one event.

    Falls back to the host scope, which keeps every existing dataset valid.
    """
    container = event.get("container_id") or event.get("container") or ""
    scope = str(container).strip()[:128]
    if scope and not _ID_RE.match(scope):
        raise ScopeError(f"invalid container_id: {scope[:40]!r}")
    pid = event.get("pid_ns") if "pid_ns" in event else event.get("namespace_pid")
    if pid is not None:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid < 0:
            raise ScopeError(f"namespace pid must be a non-negative integer, got {pid!r}")
        return (scope or "container"), pid
    return (scope or "host"), int(event["process_id"])


def analyse_scopes(events: list[dict]) -> dict:
    """Summarise container scopes and detect pid collisions across them."""
    scopes: dict[str, dict] = {}
    pid_owners: dict[int, set[str]] = {}
    namespaced = 0
    for event in events:
        scope, scoped_pid = _scope_of(event)
        pid_owners.setdefault(scoped_pid, set()).add(scope)
        if scope != "host":
            namespaced += 1
        entry = scopes.setdefault(scope, {
            "scope": scope,
            "events": 0,
            "process_ids": set(),
            "process_names": set(),
            "first_timestamp": float(event["timestamp"]),
            "last_timestamp": float(event["timestamp"]),
        })
        entry["events"] += 1
        entry["process_ids"].add(scoped_pid)
        name = str(event.get("process_name") or "").strip()
        if name and name != "unknown":
            entry["process_names"].add(name[:80])
        stamp = float(event["timestamp"])
        entry["first_timestamp"] = min(entry["first_timestamp"], stamp)
        entry["last_timestamp"] = max(entry["last_timestamp"], stamp)

    collisions = {pid: sorted(scopes_seen) for pid, scopes_seen in pid_owners.items()
                  if len(scopes_seen) > 1}
    summaries = [
        {"scope": item["scope"], "events": item["events"],
         "process_count": len(item["process_ids"]),
         "process_names": sorted(item["process_names"])[:10],
         "first_timestamp": round(item["first_timestamp"], 3),
         "last_timestamp": round(item["last_timestamp"], 3)}
        for item in sorted(scopes.values(), key=lambda entry: -entry["events"])[:MAX_SCOPES]
    ]
    return {
        "container_aware": namespaced > 0,
        "scope_count": len(scopes),
        "namespaced_event_count": namespaced,
        "host_event_count": len(events) - namespaced,
        "scopes": summaries,
        "pid_collisions": [{"pid": pid, "scopes": owners}
                           for pid, owners in sorted(collisions.items())[:20]],
        "collision_count": len(collisions),
        "notes": [
            "Scopes come from event metadata only; CABID does not read cgroups or namespaces.",
            "Container pids are not related to host pids, so cross-scope parent links are meaningless.",
            "A pid collision across scopes is expected, not suspicious.",
        ] if namespaced else [
            "No container metadata present; every event is treated as one host scope.",
        ],
    }


def namespaced_events(events: list[dict]) -> list[dict]:
    """Rewrite ``process_id`` to a stable ``scope:pid`` integer-free key.

    Only used for grouping; the original ids are preserved in ``_host_*`` fields so
    reports can still show what the sensor reported.
    """
    rewritten = []
    for event in events:
        scope, scoped_pid = _scope_of(event)
        if scope == "host":
            rewritten.append(event)
            continue
        rewritten.append({
            **event,
            "_host_process_id": event["process_id"],
            "_scope": scope,
            "_scoped_pid": scoped_pid,
        })
    return rewritten


def group_key(event: dict) -> tuple[str, int]:
    """(scope, pid) used when a caller needs collision-free grouping."""
    scope, scoped_pid = _scope_of(event)
    return scope, scoped_pid
