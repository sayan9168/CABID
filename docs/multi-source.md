# Multi-source analysis and time filtering

## Combine several artifacts

An investigation usually spans more than one file: a procfs snapshot, an auditd
export, a container log. Pass multiple files to `analyze`:

    cabid analyze procfs.jsonl audit-export.jsonl --format md -o merged.md

Events are merged and sorted by timestamp, and every event is tagged with a
`source_file` field. The report gains a `sources` block:

```json
{
  "source_count": 2,
  "events_total": 78,
  "duplicate_events": 0,
  "overlapping_sources": [],
  "sources": [
    {"source": "procfs.jsonl", "events": 6, "first_timestamp": 1760000000.0, "last_timestamp": 1760000025.0}
  ]
}
```

Notes that matter:

- **No clock correction.** Sources are assumed to share a usable clock. Cross-host
  skew can reorder events and change lifecycle/sequence results.
- **Duplicates are counted, not removed.** `duplicate_events` uses
  (timestamp, type, pids, target) as the fingerprint. Two genuine identical events
  in the same second look like a duplicate; inspect before trusting the count.
- **Overlaps are flagged.** If two sources cover the same time range the report
  lists the overlapping pairs, because the same activity may be represented twice
  and inflate temporal features.

## Filter by time

    cabid analyze events.jsonl --since 2026-11-13T00:00:00Z --until 2026-11-13T06:00:00Z
    cabid analyze events.jsonl --since 1794570000 --until 1794590000

`--since`/`--until` accept Unix seconds or ISO-8601. A timestamp without a zone is
interpreted as **UTC** so reports are identical across analyst timezones. Bounds
are inclusive, and `until` earlier than `since` is an error (exit `2`) rather than
an empty result.

The report always carries a `time_filter` block:

```json
{"active": true, "events_in": 78, "events_out": 72, "events_removed": 6,
 "since_iso": "2026-11-13T00:00:00+00:00", "until_iso": "2026-11-13T06:00:00+00:00"}
```

A filtered report can therefore never be mistaken for the full stream — and a
filter that removes everything yields `INSUFFICIENT_EVIDENCE`, not a pass.

## Dashboard

The dashboard exposes the same features: **Merge all** analyzes every bundled
fixture together, and the Since/Until fields apply the time filter. The verdict
strip shows the source count and, when filtering is active, replaces the config
digest chip with `filtered: kept/total events`.
