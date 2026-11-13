"""Process ancestry consistency checks (not a full causal provenance graph)."""
from collections import defaultdict

def causal_features(events: list[dict]) -> dict:
    parents: dict[int, set[int]] = defaultdict(set)
    seen_pids: set[int] = set()
    orphan_events = self_parent = 0
    for event in events:
        pid, ppid = event["process_id"], event["parent_process_id"]
        seen_pids.add(pid)
        if ppid == pid:
            self_parent += 1
        elif ppid > 0:
            parents[pid].add(ppid)
    for event in events:
        if event["parent_process_id"] > 0 and event["parent_process_id"] not in seen_pids:
            orphan_events += 1
    count = max(len(events), 1)
    score = min(1.0, orphan_events / count + self_parent / count)
    return {"unique_processes": len(seen_pids), "orphan_parent_events": orphan_events,
            "self_parent_events": self_parent, "parent_links": sum(len(v) for v in parents.values()),
            "causal_score": round(score, 6)}
