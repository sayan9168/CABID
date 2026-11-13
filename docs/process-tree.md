# Process tree analysis

Detector scoring deliberately ignores ancestry beyond self-parent references,
because an unseen parent is usually just a process that started before the window.
This module reconstructs the parent/child structure that *was* observed and reports
structural facts an analyst can act on.

Everything here is **context**. A deep chain or a shell spawned by a service is a
reason to look — build systems, package hooks, and CGI handlers produce those
shapes legitimately.

## Reconstruction

- **Labels:** most frequently reported `process_name` per pid.
- **Edges:** one parent per pid — the most frequently reported `parent_process_id`,
  ties broken by the smaller pid. Self-references (`ppid == pid`) are excluded here
  because the causal component already scores them.
- **Roots:** pids whose parent was not observed in the window, or has no parent.
- **Depth:** BFS from roots; a pid reachable by several paths keeps the shallowest.

## Structural findings

| Kind | Severity | Condition |
| --- | --- | --- |
| `interpreter_spawn` | high | a network-facing name (`nginx`, `sshd`, `dockerd`, `node`, …) spawned an interpreter or transfer tool (`bash`, `python`, `curl`, `nc`, …) |
| `novel_parent_child` | medium | the name-level edge was absent from the supplied baseline profile |
| `ancestry_cycle` | high | parent references form a cycle, which no real process tree can |
| `deep_chain` | low | a process sits at depth ≥ 6 |

`novel_parent_child` requires a baseline built with `build-baseline`; profiles now
store `parent_child` edges as **name pairs**, so drift compares without caring about
pids. Without a profile the field is `baseline_compared: false` and the check is
skipped rather than assumed clean.

## Output

```json
{
  "node_count": 10, "edge_count": 10, "root_count": 1,
  "max_depth": 4, "median_depth": 1, "cycle_count": 2,
  "orphan_root_count": 0,
  "finding_count": 3,
  "findings": [{"kind": "interpreter_spawn", "severity": "high",
                "detail": "network-facing process 'nginx' spawned interpreter 'sh'",
                "parent_pid": 401, "child_pid": 402}],
  "common_edges": [{"parent": "nginx", "child": "sh", "count": 1}],
  "baseline_compared": true,
  "semantics": "structural context from reported parent ids; not proof of execution order or intent"
}
```

`orphan_root_count` counts roots with `parent_process_id > 1`: those are likely
window-boundary artefacts, and they are counted, not treated as suspicious.

## Limits

- Edges come from reported pids. If the sensor misses a `process_start`, the child
  appears as a root and the chain looks shorter than it was.
- Pid reuse inside a long window can merge two unrelated processes. The window
  filter (`--since`/`--until`) is the mitigation.
- Depth is *observed* depth, not kernel depth.
- Name-based matching is tolerant of pid changes but not of renamed binaries; a
  renamed `bash` is just an unknown name.

## Interface

```bash
cabid analyze events.jsonl --format md   # "Process tree" section
cabid analyze events.jsonl --no-tree     # skip reconstruction
```

Dashboard: **Tree** tab — node/edge/depth/cycle counters, structural findings, and
the most common observed edges.
