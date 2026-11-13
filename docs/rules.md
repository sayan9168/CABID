# Correlation rules

The five weighted components answer *"how unusual is this window?"*. Rules answer
*"does this specific multi-event pattern occur?"* — which is where most triage
actually starts.

Rules are **data, not code**, so an analyst can add a check without touching the
engine. Rule matches do not change the anomaly score, and a match is not a
verdict: it means the shape occurred, not that the host is compromised.

## File format (`cabid-rules/1`)

```json
{
  "format": "cabid-rules/1",
  "name": "site rules",
  "description": "what this pack is for",
  "rules": [
    {
      "id": "sshd-then-shadow",
      "title": "sshd touched the shadow file",
      "description": "context for the analyst",
      "severity": "critical",
      "mitre": "hint: T1003 OS credential dumping",
      "steps": [
        {"event_type": "process_exec", "process_name": "sshd"},
        {"event_type": "file_write", "target": "/etc/shadow", "within": 10}
      ]
    }
  ]
}
```

```bash
cabid analyze events.jsonl --rules my-rules.json --format md -o report.md
cabid analyze events.jsonl --no-rules          # skip rule evaluation entirely
```

## Rule kinds

### `sequence` (default when `steps` is present)

An ordered chain. Each step may filter on `event_type`, `process_name`,
`executable`, `target` (globs allowed), and may set:

| Step key | Meaning |
| --- | --- |
| `within` | max seconds between the *previous* matched step and this one |
| `same_process` | require the same `process_id` as the first step |
| `min_events` | reserved; not yet used for matching |

A sequence needs at least two steps. Step 1 cannot set `within` or `min_events`.

### `count`

At least `min_count` matching events inside a rolling `window`:

```json
{
  "id": "rapid-restart-loop",
  "title": "Repeated starts of one process",
  "severity": "medium",
  "kind": "count",
  "filter": {"event_type": "process_start"},
  "window": 10,
  "min_count": 12
}
```

**One finding per burst.** A burst is a maximal run of matching events where
consecutive matches are at most `window` seconds apart. This is deliberately not
"N events within `window` of the first match" — that formulation emits a new
finding at every sample of a steady stream. Separate bursts produce separate
findings, which is what an analyst expects.

## Validation

Unknown keys are rejected at file, rule, and step level. IDs must match
`[a-z0-9][a-z0-9_-]{1,63}`, severity must be `low`/`medium`/`high`/`critical`,
event types must be supported, `window`/`within` must be positive, and duplicate
IDs are rejected. Invalid files exit `2` rather than silently skipping.

Rules with `"enabled": false` are dropped after validation (so a broken disabled
rule still fails loudly).

## Built-in pack

Five rules ship by default and are always evaluated unless `--no-rules` is given:

| Rule | Severity | Shape |
| --- | --- | --- |
| `shell-from-service` | high | network-facing daemon → shell within 30s |
| `download-then-exec` | high | egress tool → execution from `/tmp`, `/var/tmp`, `/dev/shm` |
| `sensitive-write-then-egress` | critical | write to shadow/sudoers/ssh/root → outbound connect within 300s |
| `rapid-restart-loop` | medium | ≥12 `process_start` bursts (crash loop / re-exec stomp) |
| `exit-then-activity` | high | `process_exit` → same-pid file/network activity |

Each carries a `mitre` string prefixed `hint:` on purpose — the mapping is
suggestive, not an assertion of technique use.

## Output

```json
{
  "rule_count": 5,
  "matched_rule_count": 2,
  "finding_count": 5,
  "severity_counts": {"critical": 4, "medium": 1},
  "findings": [
    {"rule_id": "sensitive-write-then-egress", "severity": "critical",
     "matched_steps": 2, "start_timestamp": 1760100000.104,
     "process_ids": [900, 902], "evidence": [{"index": 2, "event_type": "file_write"}]}
  ],
  "semantics": "pattern matches describe observed shape; they are not verdicts or attributions"
}
```

Findings are sorted worst-severity first, then earliest. Evidence carries the
event `index`, which the timeline exporter uses to annotate the exact rows.
`max_matches` (default 20, capped at 200) bounds output per rule.

## Writing rules responsibly

- Prefer two-step shapes over single-event matches; single-event rules duplicate
  what policy already does.
- Keep `within` windows tight. A 300-second "download then exec" window matches
  ordinary package installs constantly.
- Treat a noisy rule as a measurement problem, not a threshold to raise in
  silence: note the change and re-run the history comparison.
