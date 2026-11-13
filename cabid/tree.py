"""Process ancestry tree reconstruction and structural findings.

The detector deliberately does not score ancestry beyond self-parent references.
This module reconstructs the parent/child structure that *was* observed and
reports structural facts an analyst can act on: depth, cycles, orphan roots, and
edges that a benign baseline never contained.

Everything here is context. A deep chain or an interpreter spawned by a service
is a reason to look, not a finding of compromise: build systems, package hooks,
and CGI handlers all produce those shapes legitimately.
"""
from __future__ import annotations

from collections import Counter, defaultdict

INTERPRETER_NAMES = {
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish",
    "python", "python2", "python3", "perl", "ruby", "node", "php",
    "nc", "ncat", "netcat", "socat", "curl", "wget", "telnet",
}
NETWORK_FACING_NAMES = {
    "nginx", "apache2", "httpd", "lighttpd", "caddy", "sshd", "postfix",
    "dovecot", "mysqld", "postgres", "redis-server", "mongod", "docker",
    "containerd", "dockerd", "node", "java", "tomcat", "gunicorn", "uwsgi",
}
MAX_FINDINGS = 40
DEEP_CHAIN_THRESHOLD = 6


def _labels(events: list[dict]) -> dict[int, str]:
    """Most frequently reported name per pid, falling back to unknown."""
    counts: dict[int, Counter] = defaultdict(Counter)
    for event in events:
        name = str(event.get("process_name") or "").strip()
        if name and name != "unknown":
            counts[event["process_id"]][name] += 1
    return {pid: counter.most_common(1)[0][0] for pid, counter in counts.items()}


def _edges(events: list[dict]) -> dict[int, int]:
    """Resolve one parent per pid (most frequently reported, then smallest)."""
    candidates: dict[int, Counter] = defaultdict(Counter)
    for event in events:
        pid, ppid = event["process_id"], event["parent_process_id"]
        if ppid != pid:
            candidates[pid][ppid] += 1
    resolved = {}
    for pid, counter in candidates.items():
        resolved[pid] = min(counter.items(), key=lambda item: (-item[1], item[0]))[0]
    return resolved


def process_tree(events: list[dict], profile: dict | None = None) -> dict:
    """Build the observed process tree and report structural findings."""
    labels = _labels(events)
    parents = _edges(events)
    pids = {event["process_id"] for event in events}
    children: dict[int, set[int]] = defaultdict(set)
    roots = []
    for pid in sorted(pids):
        ppid = parents.get(pid)
        if ppid is None or ppid not in pids:
            roots.append(pid)
        else:
            children[ppid].add(pid)

    depths = _depths(roots, children)
    cycles = _cycles(pids, parents)
    known_edges = _baseline_edges(profile)

    findings: list[dict] = []
    edge_counts: Counter[tuple[str, str]] = Counter()
    for pid, ppid in parents.items():
        parent_name = labels.get(ppid, "unknown")
        child_name = labels.get(pid, "unknown")
        edge_counts[(parent_name, child_name)] += 1
        if parent_name == "unknown" or child_name == "unknown":
            continue
        if parent_name in NETWORK_FACING_NAMES and child_name in INTERPRETER_NAMES:
            findings.append({
                "kind": "interpreter_spawn", "severity": "high",
                "detail": f"network-facing process {parent_name!r} spawned interpreter {child_name!r}",
                "parent_pid": ppid, "child_pid": pid,
                "parent_name": parent_name, "child_name": child_name,
            })
        if known_edges is not None and (parent_name, child_name) not in known_edges:
            findings.append({
                "kind": "novel_parent_child", "severity": "medium",
                "detail": f"edge {parent_name!r} -> {child_name!r} was absent from the benign baseline",
                "parent_pid": ppid, "child_pid": pid,
                "parent_name": parent_name, "child_name": child_name,
            })

    for pid in cycles:
        findings.append({
            "kind": "ancestry_cycle", "severity": "high",
            "detail": "parent references form a cycle, which cannot occur in a real process tree",
            "parent_pid": parents.get(pid), "child_pid": pid,
            "parent_name": labels.get(parents.get(pid, -1), "unknown"),
            "child_name": labels.get(pid, "unknown"),
        })

    deep = sorted((pid for pid, depth in depths.items() if depth >= DEEP_CHAIN_THRESHOLD),
                  key=lambda pid: -depths[pid])[:10]
    for pid in deep:
        findings.append({
            "kind": "deep_chain", "severity": "low",
            "detail": f"process sits at depth {depths[pid]} in the observed tree",
            "parent_pid": parents.get(pid), "child_pid": pid,
            "parent_name": labels.get(parents.get(pid, -1), "unknown"),
            "child_name": labels.get(pid, "unknown"),
        })

    findings.sort(key=lambda item: ({"high": 0, "medium": 1, "low": 2}.get(item["severity"], 3),
                                    item["kind"]))
    truncated = findings[MAX_FINDINGS:]
    values = sorted(depths.values())
    return {
        "node_count": len(pids),
        "edge_count": len(parents),
        "root_count": len(roots),
        "max_depth": max(values) if values else 0,
        "median_depth": values[len(values) // 2] if values else 0,
        "cycle_count": len(cycles),
        "orphan_root_count": sum(1 for pid in roots if parents.get(pid, 0) > 1),
        "finding_count": len(findings),
        "findings": findings[:MAX_FINDINGS],
        "findings_truncated": bool(truncated),
        "common_edges": [
            {"parent": parent, "child": child, "count": count}
            for (parent, child), count in edge_counts.most_common(15)
        ],
        "baseline_compared": known_edges is not None,
        "semantics": "structural context from reported parent ids; not proof of execution order or intent",
    }


def _depths(roots: list[int], children: dict[int, set[int]]) -> dict[int, int]:
    depths: dict[int, int] = {pid: 0 for pid in roots}
    queue = list(roots)
    while queue:
        current = queue.pop(0)
        for child in sorted(children.get(current, ())):
            candidate = depths.get(current, 0) + 1
            if child not in depths or candidate < depths[child]:
                depths[child] = candidate
                queue.append(child)
    return depths


def _cycles(pids: set[int], parents: dict[int, int]) -> list[int]:
    """Return pids that participate in a multi-node ancestry cycle."""
    in_cycle = []
    for start in sorted(pids):
        seen: list[int] = []
        current = start
        while current in parents and len(seen) <= len(pids):
            current = parents[current]
            if current == start:
                if len(seen) >= 1:
                    in_cycle.append(start)
                break
            if current in seen:
                break
            seen.append(current)
    return in_cycle


def _baseline_edges(profile: dict | None) -> set[tuple[str, str]] | None:
    if not profile:
        return None
    stored = profile.get("parent_child")
    if not isinstance(stored, list):
        return None
    edges = set()
    for item in stored:
        if isinstance(item, list) and len(item) == 2:
            edges.add((str(item[0]), str(item[1])))
    return edges
