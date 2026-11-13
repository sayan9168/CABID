# Investigation timeline

Reports are JSON-shaped. Investigators usually need a chronological narrative they
can paste into notes or a ticket, with the interesting rows marked.

```bash
cabid timeline events.jsonl                        # markdown table
cabid timeline events.jsonl -f txt                 # plain lines for notes
cabid timeline events.jsonl -f json -o tl.json     # structured
cabid timeline a.jsonl b.jsonl --since 2026-11-13T00:00:00Z --limit 500
```

## What it does

1. Re-runs the analysis (same config, policy, rules, baseline as the CLI).
2. Sorts events chronologically.
3. Annotates each row where a **rule** or **policy** check fired, using the
   `event.index` values in those findings' evidence blocks.

Annotations describe observable shape — "rule:sensitive-write-then-egress
(critical)" — not proven intent. The header says so, so a line lifted into a report
does not carry an implied claim.

## Output shape

```json
{
  "row_count": 8,
  "total_events": 72,
  "truncated": true,
  "annotated_rows": 4,
  "limit": 8,
  "rows": [
    {
      "seq": 2,
      "timestamp": 1760100000.104,
      "timestamp_iso": "2025-10-10T12:40:00.104+00:00",
      "event_type": "file_write",
      "process_id": 902,
      "parent_process_id": 902,
      "process_name": "worker-2",
      "target": "/etc/shadow",
      "source": "synthetic",
      "annotations": [
        {"kind": "rule", "id": "sensitive-write-then-egress", "severity": "critical"},
        {"kind": "policy", "id": "sensitive_path_write", "severity": "medium"}
      ]
    }
  ]
}
```

## Markdown sample

```markdown
| # | Time (UTC) | Event | PID | Process | Target | Annotations |
| --- | --- | --- | --- | --- | --- | --- |
| 2 | 2025-10-10T12:40:00.104+00:00 | file_write | 902 | worker-2 | /etc/shadow | rule:sensitive-write-then-egress (critical); policy:sensitive_path_write (medium) |
```

## Notes

- `--limit` defaults to 300 and is capped at 5000. Truncation is stated in both the
  output and the header, so a short timeline is never mistaken for a short incident.
- Timestamps render in UTC with millisecond precision. Sub-second ordering is real
  in the data, so a second-resolution view can hide sequence.
- Targets are truncated to 200 characters and `|` is escaped in markdown so one
  hostile path cannot break the table.
- The timeline does not add information the report lacks — it re-shapes it for
  reading. If a row is unannotated, nothing in the rule or policy layer flagged it.
