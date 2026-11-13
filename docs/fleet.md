# Multi-host fleet view

A per-host report answers *what happened on this box*. The questions asked during an
incident are fleet-shaped: which hosts are worst, which are quiet, which have gone
blind, and did last night's rollout change anything?

```bash
cabid fleet web-01=reports/web-01.json web-02=reports/web-02.json \
            db-01=reports/db-01.json --expected hosts.txt --format md
```

```
# CABID fleet report

Hosts: 3 of 5 expected. Degraded: yes.

**Silent hosts (2):** h4, h5

## Hosts needing attention

| Host | Status | Score | Flagged windows | Reasons |
| --- | --- | --- | --- | --- |
| h1 | HIGH_RISK | 0.910 | - | temporal_rate_or_burst |
| h3 | SUSPICIOUS | - | 0.167 | NO_ANOMALY_DETECTED, SUSPICIOUS |

## Findings

- 2 expected host(s) did not report: h4, h5
- silent-host ratio 40% exceeds 10%; fleet coverage is degraded and absence should
  be investigated before trusting the quiet hosts
- 2 host(s) need attention
```

## The design decision that matters: silence is a finding

The obvious implementation lists the hosts that reported. That is dangerous. During
an incident, the host that stopped reporting is frequently the one worth looking at,
and a fleet view that renders it as simply absent is actively misleading — the output
looks complete because it only contains what arrived.

CABID requires `--expected hosts.txt` for this reason. Any expected host missing from
the collection is listed under **Silent hosts**, and if the silent ratio exceeds 10%
the fleet is marked **degraded** and says so before any per-host verdict:

> silent-host ratio 40% exceeds 10%; fleet coverage is degraded and absence should be
> investigated before trusting the quiet hosts

Without `--expected`, the view still works but reports `expected_host_count: 0` and
never claims completeness it cannot verify.

## Mixed report shapes are normal

A real fleet does not produce uniform output. Enforcement hosts run
`analyze-stream`, investigation hosts have one-shot session reports, and some hosts
carry drift or baseline-validation output. Rather than require conversion,
`host_summary` detects the shape and records it:

| Shape | Detected by | Status column |
| --- | --- | --- |
| `session` | `status` | the report's own status |
| `stream` | `status_counts` | worst status present in the windows |
| `drift` | `drifted` | `DRIFT` / `NO_ANOMALY_DETECTED` |
| `baseline-validation` | `verdict` | `INSUFFICIENT_EVIDENCE` unless `SOUND` |

`shape_counts` in the output records what was read, so a fleet comparison across
different sensor types stays auditable.

## Ranking is not scoring

Hosts are ordered by the evidence already in their own reports — anomaly score
first, then flagged-window rate, then name as a deterministic tiebreak. **No
fleet-level score is invented**, because a new composite number would have no
calibration behind it and would hide which host-level report produced it.

## Comparing snapshots

```bash
cabid fleet --compare \
  --baseline web-01=mon/web-01.json,web-02=mon/web-02.json \
  --current  web-01=tue/web-01.json,web-02=tue/web-02.json
```

```json
{
  "appeared": ["h4"],
  "disappeared": ["h3"],
  "improved": [],
  "worsened": [
    {"host": "h1", "status_before": "NO_ANOMALY_DETECTED", "status_after": "HIGH_RISK",
     "score_before": 0.1, "score_after": 0.9, "score_delta": 0.8, "direction": "worse"}
  ],
  "unchanged_count": 1
}
```

Only what moved is reported. A host in one snapshot and not the other is listed as
appeared or disappeared rather than compared against a missing value — "the host
vanished" and "the host scored 0" are different findings, and the report refuses to
merge them.

## Validation rules

| Condition | Behaviour |
| --- | --- |
| Duplicate host in a collection | `FleetError` — two reports for one host is a collection bug, and silently picking one can hide the worse of them |
| Unrecognised report shape | `FleetError` naming the host, rather than a row of nulls |
| No host identifier | `FleetError` |
| Empty fleet | `FleetError` |

## Limitations

- **Collection is the operator's job.** This command reads files. It does not ship a
  transport, an agent, or a scheduler; getting reports off hosts is left to whatever
  the environment already has.
- **A report is a point in time.** Comparing snapshots compares whatever windows those
  reports covered. Overlapping or differently-sized windows make score deltas hard to
  interpret, and the report cannot detect that.
- **No cross-host correlation.** The view does not join events across hosts, so
  lateral movement visible only by correlating two hosts' activity is out of scope.
- **Ranking is per-report evidence.** A host with a richer sensor produces more
  findings; that reflects telemetry, not compromise.
- **Findings are triage hints.** The rendered report ends with that caveat because a
  fleet table is easy to read as a verdict list.

## Files

| Path | Purpose |
| --- | --- |
| `cabid/fleet.py` | Shape normalization, aggregation, silent-host accounting, comparison. |
| `cabid fleet` | CLI with `--expected`, `--compare`, JSON and Markdown output. |
| `tests/test_fleet.py` | 27 tests. |
