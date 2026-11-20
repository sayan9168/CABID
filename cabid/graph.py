"""Export the observed process graph for tools that already understand graphs.

The dashboard draws this graph in a browser; this module writes it out so it can
be opened in Graphviz, pasted into a Mermaid-capable wiki, or loaded by a graph
library. It contains the same facts the tree analysis reports — observed pids,
observed parent edges, baseline drift — and no extra inference.

What it is not: a kernel-level process tree. Edges come from reported
``parent_process_id`` values, so a missed ``process_start`` makes a child look like
a root, and pid reuse inside a long window can merge two unrelated processes into
one node. Nodes are pids, not identities.
"""
from __future__ import annotations

import xml.sax.saxutils as sax

from . import __version__
from .tree import baseline_edges, observed_labels, observed_parents

GRAPH_FORMAT = "cabid-process-graph/1"
FORMATS = ("json", "dot", "mermaid", "graphml")
_UNKNOWN = "unknown"
_WRITE_TYPES = ("file_write", "file_create", "file_rename", "file_delete")


class GraphError(ValueError):
    """Raised when the graph cannot be built or the format is unsupported."""


def process_graph(events: list[dict], profile: dict | None = None,
                  max_nodes: int = 500) -> dict:
    """Build a node/edge view of the observed process tree.

    ``max_nodes`` bounds the exported nodes, keeping the highest-activity pids.
    Truncation is reported in ``truncated``/``omitted_nodes`` — never silent.
    """
    if not isinstance(events, list):
        raise GraphError("events must be a list of normalized event dicts")
    if any(not isinstance(event, dict) for event in events):
        raise GraphError("events must be a list of normalized event dicts; "
                         "one or more entries are not objects")
    if not isinstance(max_nodes, int) or isinstance(max_nodes, bool) or max_nodes < 1:
        raise GraphError("max_nodes must be a positive integer")
    labels = observed_labels(events)
    parents = observed_parents(events)
    known = baseline_edges(profile)
    baseline_names = None
    if profile:
        stored = profile.get("process_names")
        if isinstance(stored, list):
            # Names are stored as [name, count] pairs; accept bare names too.
            baseline_names = {str(item[0] if isinstance(item, (list, tuple)) else item)
                              for item in stored}

    totals: dict[int, dict] = {}
    edge_counts: dict[tuple[int, int], int] = {}
    kinds: dict[int, set[str]] = {}
    for event in events:
        pid = int(event["process_id"])
        stamp = float(event["timestamp"])
        record = totals.setdefault(pid, {"events": 0, "writes": 0,
                                         "first_event": event, "last_event": event,
                                         "first_seen": stamp, "last_seen": stamp})
        record["events"] += 1
        kind = str(event.get("event_type") or _UNKNOWN)
        kinds.setdefault(pid, set()).add(kind)
        if kind in _WRITE_TYPES:
            record["writes"] += 1
        if stamp < record["first_seen"]:
            record["first_seen"], record["first_event"] = stamp, event
        if stamp >= record["last_seen"]:
            record["last_seen"], record["last_event"] = stamp, event
        parent = parents.get(pid)
        if parent is not None and int(event.get("parent_process_id", -1)) == parent:
            edge_counts[(parent, pid)] = edge_counts.get((parent, pid), 0) + 1

    pids = sorted(totals)
    roots = [pid for pid in pids if parents.get(pid) not in totals]
    depths = _depths(roots, parents, totals)
    cyclic = _cycle_nodes(events, parents, totals)
    kept = set(pids)
    omitted = 0
    if len(pids) > max_nodes:
        kept = set(sorted(pids, key=lambda pid: (-totals[pid]["events"], pid))[:max_nodes])
        omitted = len(pids) - len(kept)

    nodes = []
    for pid in sorted(kept):
        record = totals[pid]
        name = labels.get(pid, _UNKNOWN)
        first, last = record["first_event"], record["last_event"]
        nodes.append({
            "id": pid,
            "label": name,
            "name": name,
            "events": record["events"],
            "writes": record["writes"],
            "event_count": record["events"],
            "event_types": sorted(kinds.get(pid, ())),
            "executable": str(last.get("executable") or ""),
            "first_target": str(first.get("target") or ""),
            "last_target": str(last.get("target") or ""),
            "first_seen": round(record["first_seen"], 6),
            "last_seen": round(record["last_seen"], 6),
            "parent": parents.get(pid) if parents.get(pid) in kept else None,
            "root": parents.get(pid) not in totals,
            "depth": depths.get(pid),
            "in_cycle": pid in cyclic,
            "in_baseline": None if baseline_names is None else name in baseline_names,
        })

    edges = []
    for (parent, child), count in sorted(edge_counts.items()):
        if parent not in kept or child not in kept:
            continue
        parent_name = labels.get(parent, _UNKNOWN)
        child_name = labels.get(child, _UNKNOWN)
        edges.append({
            "parent": parent,
            "child": child,
            "parent_label": parent_name,
            "child_label": child_name,
            "observations": count,
            "baseline_known": (None if known is None
                               else (parent_name, child_name) in known),
        })

    return {
        "format": GRAPH_FORMAT,
        "cabid_version": __version__,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "root_count": len(roots),
        "max_depth": max((node["depth"] or 0) for node in nodes) if nodes else 0,
        "cycle_node_count": sum(1 for node in nodes if node["in_cycle"]),
        "baseline_compared": known is not None,
        "novel_edge_count": sum(1 for edge in edges if edge["baseline_known"] is False),
        "baseline": _baseline_block(profile, known, edges),
        "truncated": omitted > 0,
        "omitted_nodes": omitted,
        "warnings": _warnings(nodes, omitted, profile, edges),
        "max_nodes": max_nodes,
        "nodes": nodes,
        "edges": edges,
        "semantics": ("observed parent/child edges from reported parent ids; not kernel "
                      "ancestry and not proof of execution order"),
    }


def _baseline_block(profile: dict | None, known: set | None, edges: list[dict]) -> dict:
    if known is None:
        return {"present": False, "compared": False, "session_count": 0,
                "note": "no baseline profile supplied; every edge is reported without a "
                        "novelty judgement, which is not the same as 'benign'"}
    sessions = profile.get("session_count") if isinstance(profile, dict) else None
    novel = sum(1 for edge in edges if edge["baseline_known"] is False)
    return {"present": True, "compared": True,
            "session_count": sessions if isinstance(sessions, int) else 0,
            "note": (f"{novel} edge(s) never appeared in the baseline; absence from a "
                     "baseline is not evidence of malice, and a small baseline marks "
                     "ordinary behaviour as novel")}


def _warnings(nodes: list[dict], omitted: int, profile: dict | None,
              edges: list[dict]) -> list[str]:
    notes = []
    if not nodes:
        notes.append("no process nodes: these events carry no usable process ids")
    if omitted:
        notes.append(f"{omitted} node(s) omitted by max_nodes; edges touching them are "
                     "dropped, so the exported graph is smaller than the observation")
    if profile is None:
        notes.append("no baseline profile: edges are exported without novelty marking")
    if nodes and all(node["root"] for node in nodes):
        notes.append("every node is a root: no parent ids were observed, so the graph has "
                     "no structure to read")
    if any(node["in_cycle"] for node in nodes):
        notes.append("a parent/child cycle was observed; cycles mean the reported parent "
                     "ids contradict the event order, not that a process contains itself")
    return notes


def _cycle_nodes(events: list[dict], parents: dict[int, int],
                 totals: dict[int, dict]) -> set[int]:
    """Nodes that lie on a reported parent cycle (iterative Tarjan SCC).

    A pid is "in a cycle" only when it belongs to a strongly connected component
    with more than one member, or reports itself as its own parent. Unreached
    nodes are *not* cycles — they are orphans whose parent was never observed.
    """
    graph = {pid: (parents[pid] if parents.get(pid) in totals and parents[pid] != pid
                   else None)
             for pid in totals}
    index: dict[int, int] = {}
    low: dict[int, int] = {}
    on_stack: set[int] = set()
    stack: list[int] = []
    members: set[int] = set()
    counter = 0
    for start in sorted(graph):
        if start in index:
            continue
        work: list[tuple[int, int]] = [(start, 0)]
        while work:
            node, child_state = work.pop()
            if child_state == 0:
                index[node] = low[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)
            child = graph[node]
            recurse = False
            if child is not None:
                if child not in index:
                    work.append((node, 1))
                    work.append((child, 0))
                    recurse = True
                elif child in on_stack:
                    low[node] = min(low[node], index[child])
            if recurse:
                continue
            if child_state == 1 and child is not None and child in on_stack:
                low[node] = min(low[node], low[child])
            if low[node] == index[node]:
                component = []
                while True:
                    popped = stack.pop()
                    on_stack.discard(popped)
                    component.append(popped)
                    if popped == node:
                        break
                if len(component) > 1:
                    members.update(component)
    # observed_parents() drops self-parents (ppid == pid), so scan the events for
    # them: a pid that claims itself as its own parent is a cycle of one.
    for event in events:
        pid = int(event["process_id"])
        if pid in totals and int(event.get("parent_process_id", -1)) == pid:
            members.add(pid)
    return members


def _depths(roots: list[int], parents: dict[int, int],
            totals: dict[int, dict]) -> dict[int, int]:
    children: dict[int, list[int]] = {}
    for pid in sorted(totals):
        parent = parents.get(pid)
        if parent is not None and parent in totals and parent != pid:
            children.setdefault(parent, []).append(pid)
    depths = {pid: 0 for pid in roots}
    queue = list(roots)
    while queue:
        current = queue.pop(0)
        for pid in children.get(current, ()):
            if pid not in depths:
                depths[pid] = depths[current] + 1
                queue.append(pid)
    return depths


def _escape_dot(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _escape_mermaid(text: str) -> str:
    return text.replace('"', "&quot;").replace("\n", " ")


def _node_summary(node: dict) -> str:
    parts = [f'{node["events"]} event(s)']
    if node["writes"]:
        parts.append(f'{node["writes"]} write(s)')
    return ", ".join(parts)


def render_dot(graph: dict) -> str:
    """Graphviz DOT. Baseline-unseen edges are dashed and labelled."""
    lines = ["// CABID process graph (observed pids, observed parent edges)"]
    if graph["truncated"]:
        lines.append(f"// truncated: {graph['omitted_nodes']} node(s) omitted by --max-nodes")
    lines.append("digraph cabid_process_graph {")
    lines.append("  rankdir=TB;")
    lines.append('  node [shape=box, fontname="Helvetica", fontsize=10];')
    for node in graph["nodes"]:
        label = (f'{node["label"]}\npid={node["id"]}\n{_node_summary(node)}'
                 + (f'\nexec={node["executable"]}' if node["executable"] else ""))
        attributes = [f'label="{_escape_dot(label)}"']
        if node["root"]:
            attributes.append("style=bold")
        if node["in_cycle"]:
            attributes.append('color="#b22222"')
        elif node["in_baseline"] is False:
            attributes.append('color="#b22222"')
        lines.append(f'  n{node["id"]} [{", ".join(attributes)}];')
    for edge in graph["edges"]:
        attributes = [f'label="{edge["observations"]}"']
        if edge["baseline_known"] is False:
            attributes += ["style=dashed", 'color="#b22222"']
        lines.append(f'  n{edge["parent"]} -> n{edge["child"]} '
                     f'[{", ".join(attributes)}];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_mermaid(graph: dict) -> str:
    """Mermaid flowchart, for a wiki or a Markdown code block."""
    lines = ["%% CABID process graph (observed pids, observed parent edges)"]
    if graph["truncated"]:
        lines.append(f"%% truncated: {graph['omitted_nodes']} node(s) omitted by --max-nodes")
    lines.append("flowchart TD")
    for node in graph["nodes"]:
        lines.append(f'  n{node["id"]}["{_escape_mermaid(node["label"])} '
                     f'({node["id"]}, {node["events"]} ev)"]')
        if node["in_cycle"] or node["in_baseline"] is False:
            lines.append(f"  style n{node['id']} fill:#ffe0e0,stroke:#b22222")
    for edge in graph["edges"]:
        arrow = "-.->" if edge["baseline_known"] is False else "-->"
        lines.append(f'  n{edge["parent"]} {arrow}|{edge["observations"]}| n{edge["child"]}')
    return "\n".join(lines) + "\n"


def render_graphml(graph: dict) -> str:
    """GraphML 1.0, readable by NetworkX, Gephi, yEd, and friends."""
    lines = ['<?xml version="1.0" encoding="UTF-8"?>',
             f"<!-- CABID process graph: {graph['node_count']} nodes, "
             f"{graph['edge_count']} edges"
             + (f"; {graph['omitted_nodes']} node(s) omitted" if graph["truncated"] else "")
             + " -->",
             '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
             '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
             '  <key id="events" for="node" attr.name="events" attr.type="int"/>',
             '  <key id="writes" for="node" attr.name="writes" attr.type="int"/>',
             '  <key id="depth" for="node" attr.name="depth" attr.type="int"/>',
             '  <key id="root" for="node" attr.name="root" attr.type="boolean"/>',
             '  <key id="in_cycle" for="node" attr.name="in_cycle" attr.type="boolean"/>',
             '  <key id="event_types" for="node" attr.name="event_types" attr.type="string"/>',
             '  <key id="observations" for="edge" attr.name="observations" '
             'attr.type="int"/>',
             '  <key id="baseline_known" for="edge" attr.name="baseline_known" '
             'attr.type="string"/>',
             '  <graph id="cabid" edgedefault="directed">']
    for node in graph["nodes"]:
        lines.append(f'    <node id="n{node["id"]}">')
        lines.append(f'      <data key="label">{sax.escape(str(node["label"]))}</data>')
        lines.append(f'      <data key="events">{node["events"]}</data>')
        lines.append(f'      <data key="writes">{node["writes"]}</data>')
        lines.append(f'      <data key="depth">'
                     f'{node["depth"] if node["depth"] is not None else -1}</data>')
        lines.append(f'      <data key="root">{"true" if node["root"] else "false"}</data>')
        lines.append(f'      <data key="in_cycle">'
                     f'{"true" if node["in_cycle"] else "false"}</data>')
        lines.append(f'      <data key="event_types">'
                     f'{sax.escape(",".join(node["event_types"]))}</data>')
        lines.append('    </node>')
    for index, edge in enumerate(graph["edges"]):
        lines.append(f'    <edge id="e{index}" source="n{edge["parent"]}" '
                     f'target="n{edge["child"]}">')
        lines.append(f'      <data key="observations">{edge["observations"]}</data>')
        known = {None: "unknown", True: "true", False: "false"}[edge["baseline_known"]]
        lines.append(f'      <data key="baseline_known">{known}</data>')
        lines.append('    </edge>')
    lines.append("  </graph>")
    lines.append("</graphml>")
    return "\n".join(lines) + "\n"


def render(graph: dict, fmt: str) -> str:
    """Render a graph in one of ``FORMATS``."""
    if fmt == "json":
        import json

        return json.dumps(graph, indent=2, sort_keys=True) + "\n"
    if fmt == "dot":
        return render_dot(graph)
    if fmt == "mermaid":
        return render_mermaid(graph)
    if fmt == "graphml":
        return render_graphml(graph)
    raise GraphError(f"unsupported graph format: {fmt}; choose from {', '.join(FORMATS)}")


__all__ = ["GRAPH_FORMAT", "FORMATS", "GraphError", "process_graph",
           "render", "render_dot", "render_mermaid", "render_graphml"]
