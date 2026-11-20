# Exporting the process graph

    cabid graph events.jsonl                        # Graphviz DOT
    cabid graph events.jsonl -f mermaid             # paste into a wiki / PR
    cabid graph events.jsonl -f graphml -o g.graphml
    cabid graph events.jsonl -f json -o g.json
    cabid graph events.jsonl -b baseline.json       # mark unseen edges

The dashboard draws the process graph in a browser. `cabid graph` writes the same
structure out as a file, so the analysis can leave the browser: `dot -Tsvg`,
Gephi, NetworkX, a Mermaid block in a review comment.

## What is in the graph

Nodes are pids observed in the window, labelled with the most frequently reported
name for that pid. Each node carries `events`, `writes`, `event_types`,
`first_seen`, `last_seen`, `executable`, `depth`, `root`, `in_cycle`, and whether
it appeared in the baseline. Edges are reported parent → child pairs with an
`observations` count and `baseline_known`.

`in_cycle` means the node lies on a *reported* parent cycle — that is, two pids
claim ancestry of each other. CABID does not resolve the lie; it marks the
contradiction, because a cycle is a statement about the evidence, not about the
kernel. A node whose parent was never observed is **not** a cycle: it is an
orphan, reported as a root with a warning when every node looks like one.

## Formats

| Format | Intended use |
| --- | --- |
| `dot` | `dot -Tsvg graph.dot > graph.svg`; baseline-unseen edges dashed |
| `mermaid` | Markdown-renderable; follows the same dashed/red marking |
| `graphml` | GraphML 1.0 for NetworkX, Gephi, yEd (XML escaped, attribute keys declared) |
| `json` | The analysis dict: counts, warnings, per-node and per-edge attributes |

`--max-nodes` (default 500) bounds the export. Nodes are kept by activity, and
truncation is always reported: `truncated`, `omitted_nodes`, a comment in the DOT
and GraphML headers, a `%%` line in Mermaid, and a warning. Edges touching an
omitted node are dropped rather than pointing at a node that is not there.

## Baseline marking

With `--baseline profile.json`, edges never seen in the baseline are dashed and
named in `novel_edge_count`. Without one, `baseline` is `{"present": false}` and
the edges carry no novelty judgement — which is not the same as "benign". A small
baseline marks ordinary behaviour as novel; read `baseline.session_count`.

## Limitations

- These are **observed** pids and **reported** parent ids, not kernel ancestry. A
  missed `process_start` makes a child look like a root; pid reuse inside a long
  window merges two unrelated processes into one node.
- Nodes are pids, not identities. Two processes with the same name are two nodes;
  one process that exec'd twice is one node with two names in `event_types`.
- Depth is observed depth along the most common parent edge. It is not kernel
  depth and it is undefined (`-1` in GraphML) for nodes on a cycle.
- File and network activity appear only as aggregate counts (`writes`,
  `last_target`). The graph is a process skeleton — a `target` detail panel like
  the dashboard's is not part of the export.
- GraphML is written but never validated against a third-party parser in the test
  suite beyond `xml.etree` round-tripping the structure.
- A truncated graph is a smaller claim, not a summary: the process you wanted may
  be exactly the one that was omitted.
