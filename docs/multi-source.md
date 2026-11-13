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

- **Skew is estimated, never applied.** See the next section.
- **Duplicates are counted, not removed.** `duplicate_events` uses
  (timestamp, type, pids, target) as the fingerprint. Two genuine identical events
  in the same second look like a duplicate; inspect before trusting the count.
- **Overlaps are flagged.** If two sources cover the same time range the report
  lists the overlapping pairs, because the same activity may be represented twice
  and inflate temporal features.

## Clock skew between sources

Overlapping coverage is not the same as agreeing clocks. A host whose clock is 40
seconds fast interleaves its events out of order after the merge, and lifecycle
and sequence results change without anything in the report looking wrong.

CABID estimates a relative offset per source from repeated identical events
(same process name, event type, and target) that occur close together in different
sources:

```json
{
  "clock_skew": {
    "sources_compared": 2,
    "reference_source": "hostA.jsonl",
    "skew_detected": true,
    "confident_offsets": {"hostB.jsonl": 40.0},
    "applied": false,
    "offsets": {
      "hostB.jsonl": {
        "matched_pairs": 12,
        "estimated_offset_seconds": 40.0,
        "spread_seconds": 0.0,
        "confident": true
      }
    }
  }
}
```

The offset also appears in the report's human-readable `notes`, so it is visible
in Markdown output rather than buried in JSON.

**Nothing is corrected automatically.** A wrong correction reorders evidence
silently, which is worse than a known-skewed timeline. When the block reports
`skew_detected`, the honest next step is to check NTP on the affected host, not to
let a tool rewrite timestamps.

Sign convention: positive means that source's clock is ahead of the reference.
The reference is the source with the most events.

An estimate needs at least five matched pairs, and it needs the pairs to agree
within five seconds to be called `confident`. With fewer pairs it reports `null`
and the reason, rather than a guess.

### Limits of the estimator

It needs events that genuinely repeat across sources. Two hosts doing unrelated
work produce few usable pairs, and the block will say so. It also cannot separate
real skew from two hosts doing the same thing at nearly the same time on purpose —
read `spread_seconds` before believing a number.

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
