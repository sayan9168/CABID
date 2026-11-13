"""Aggregate several event sources into one analysis.

Real investigations span more than one artifact: a procfs snapshot, an auditd
export, a container log. ``ingest_sources`` combines them with provenance so a
report can state exactly which files contributed, how many events each supplied,
and whether any pair of sources overlaps in time (a common cause of double-counted
activity).
"""
from __future__ import annotations

from pathlib import Path

from .ingest import read_jsonl
from .normalize import EventError
from .skew import estimate_skew


class IngestError(ValueError):
    """Raised when a source set cannot be combined safely."""


def _source_label(path: Path) -> str:
    return path.name or str(path)


def ingest_sources(paths: list[str | Path]) -> dict:
    """Read and merge several JSONL files, tagging each event with its source."""
    if not paths:
        raise IngestError("at least one input file is required")
    sources: list[dict] = []
    merged: list[dict] = []
    for raw_path in paths:
        path = Path(raw_path)
        try:
            events = read_jsonl(path)
        except EventError as exc:
            raise IngestError(str(exc)) from exc
        label = _source_label(path)
        for event in events:
            merged.append({**event, "source_file": label[:200]})
        span = _span(events)
        sources.append({
            "source": label,
            "events": len(events),
            "first_timestamp": span[0],
            "last_timestamp": span[1],
            "event_types": sorted({event["event_type"] for event in events}),
        })
    merged.sort(key=lambda item: item["timestamp"])
    overlaps = _overlaps(sources)
    total = sum(item["events"] for item in sources)
    unique = {(event["timestamp"], event["event_type"], event["process_id"],
               event["parent_process_id"], event.get("target", "")) for event in merged}
    skew = estimate_skew(merged)
    return {
        "events": merged,
        "clock_skew": skew,
        "sources": sources,
        "source_count": len(sources),
        "events_total": total,
        "events_after_merge": len(merged),
        "duplicate_events": total - len(unique),
        "overlapping_sources": overlaps,
        "first_timestamp": merged[0]["timestamp"] if merged else None,
        "last_timestamp": merged[-1]["timestamp"] if merged else None,
        "notes": [
            "Events are merged by timestamp; clock skew is estimated but never corrected automatically.",
            "Duplicate detection uses timestamp, type, pids, and target only.",
            "Overlapping time ranges may double-count the same real activity.",
        ] + ([f"Estimated clock offset for {name}: {offset:+.1f}s "
              "(not applied; verify before trusting event order)."
              for name, offset in sorted(skew.get("confident_offsets", {}).items())]
             if skew.get("skew_detected") else []),
    }


def _span(events: list[dict]) -> tuple[float | None, float | None]:
    if not events:
        return None, None
    stamps = [float(event["timestamp"]) for event in events]
    return round(min(stamps), 3), round(max(stamps), 3)


def _overlaps(sources: list[dict]) -> list[dict]:
    found = []
    for index, left in enumerate(sources):
        for right in sources[index + 1:]:
            if left["first_timestamp"] is None or right["first_timestamp"] is None:
                continue
            start = max(left["first_timestamp"], right["first_timestamp"])
            end = min(left["last_timestamp"], right["last_timestamp"])
            if end >= start:
                found.append({"sources": [left["source"], right["source"]],
                              "overlap_seconds": round(end - start, 3)})
    return found
