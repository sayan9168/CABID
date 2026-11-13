# Per-process entity rollup

A window verdict says *something* looked wrong. The entity rollup says *which
process to open first*.

Each report contains an `entities` block that aggregates, per `process_id`:

| Field | Meaning |
| --- | --- |
| `process_names`, `executables` | observed names/executables (empty-name events are ignored) |
| `event_count`, `first_seen`, `last_seen` | activity volume and span |
| `contradiction_events` | lifecycle contradictions attributed to that process |
| `self_parent_events` | events where the process reported itself as its parent |
| `sensitive_hits` | policy-sensitive path/port touches (capped refs, max 5) |
| `novel_executable` | a baselined process name running an unseen executable |
| `entity_risk` | weighted rollup of the signals above |

Ranking formula:

```
risk = 0.35 * min(1, contradiction_rate * 4)
     + 0.30 * self_parent_rate
     + 0.20 * min(1, sensitive_hits / 3)
     + 0.15 * novel_executable
```

Rates are per event for that process, so a chatty process is not ranked higher
merely for being chatty. The top 25 processes are reported; the count of omitted
ones is flagged in `entities_truncated`.

## Reading it honestly

`ranking_semantics` in the report states the rule plainly: this is a **triage
hint, not an attribution**. A top-ranked process is one whose behaviour is least
consistent with the observed baseline — which is exactly what a misconfigured but
harmless service, a build agent, or a noisy backup job can look like. The rollup
narrows where to look; it does not name a culprit.

## Interface

```bash
cabid analyze events.jsonl --format md      # "Process rollup" table
cabid analyze events.jsonl --format csv     # rows with record_type=entity
cabid analyze events.jsonl --format html    # rollup card
```

In the dashboard, open the **Processes** tab: it lists each process with an inline
risk bar, contradiction count, and sensitive-hit count.

`entities` is also written into the history database (pid, names, risk, hits) so
trend comparisons can show newly appearing processes without storing event
content.
