"""Time-range filtering for analysis windows.

Collectors write everything they see; analysts usually care about one incident
window. Filtering happens *after* normalization so that timestamps are already
validated floats, and the applied range is echoed into every report so a trimmed
result can never be mistaken for a full one.
"""
from __future__ import annotations

from datetime import datetime, timezone


class FilterError(ValueError):
    """Raised when a time range cannot be parsed or is contradictory."""


def parse_timestamp(value: str | float | int | None, field: str = "timestamp") -> float | None:
    """Accept Unix seconds, an ISO-8601 date/datetime, or ``None``.

    Naive ISO timestamps are interpreted as UTC so that a report is byte-identical
    regardless of the analyst's local timezone.
    """
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise FilterError(f"{field} must be a timestamp, not a boolean")
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    candidate = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise FilterError(
            f"{field} must be Unix seconds or ISO-8601 (e.g. 2026-11-13T12:00:00Z)"
        ) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def resolve_range(since: str | float | None, until: str | float | None) -> dict:
    """Validate a range and return it in report-ready form."""
    start = parse_timestamp(since, "since")
    end = parse_timestamp(until, "until")
    if start is not None and end is not None and end < start:
        raise FilterError("until must not be earlier than since")
    return {
        "since": start,
        "until": end,
        "since_iso": _iso(start),
        "until_iso": _iso(end),
        "active": start is not None or end is not None,
    }


def _iso(value: float | None) -> str | None:
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def filter_events(events: list[dict], since: str | float | None = None,
                  until: str | float | None = None) -> tuple[list[dict], dict]:
    """Return events inside ``[since, until]`` plus a description of the trim."""
    window = resolve_range(since, until)
    if not window["active"]:
        window["events_in"] = len(events)
        window["events_out"] = len(events)
        window["events_removed"] = 0
        return events, window
    kept = []
    for event in events:
        stamp = float(event["timestamp"])
        if window["since"] is not None and stamp < window["since"]:
            continue
        if window["until"] is not None and stamp > window["until"]:
            continue
        kept.append(event)
    window["events_in"] = len(events)
    window["events_out"] = len(kept)
    window["events_removed"] = len(events) - len(kept)
    return kept, window
