"""Streaming analysis for sustained high event rates.

``cabid analyze`` loads a whole file, normalizes it, and scores it as one session.
That is the right shape for an investigation and the wrong shape for a sensor
collecting lakhs of events per minute: memory grows with the file, and every event
is held until the end.

This module provides the streaming shape:

* events are consumed from an iterator and never all held at once — a bounded
  sample is kept so a report still has concrete context;
* analysis runs on non-overlapping windows, so latency and memory are bounded by
  window size rather than by run length;
* windows are scored incrementally with running counters.

The honest design constraint: a window boundary can split a real causal chain, so
per-window verdicts are *weaker* evidence than a single-session verdict over the
same events. Windows default to 60 s for that reason, and the report states it.

Measured on a 100,000-event stream, the dominant cost is the built-in correlation
rule pack's glob matching (roughly 62% of analysis time). ``PatternCache`` removes
the repeated compilation and the redundant lowercase pass; it does not change rule
semantics, and the equivalence is tested against the uncached matcher.
"""
from __future__ import annotations

import fnmatch
import json
import re
import time
from collections import Counter
from pathlib import Path
from typing import Iterable, Iterator

from .detector import analyze
from .normalize import EventError, normalize_event

STREAM_FORMAT = "cabid-stream-report/1"

#: Windows smaller than this make per-window verdicts too fragmentary to trust.
MIN_WINDOW_SECONDS = 5.0


class StreamError(ValueError):
    """Raised when a stream cannot be processed safely."""


class PatternCache:
    """Compile glob patterns once per (pattern, value) shape.

    ``fnmatch`` compiles a regular expression on every call and lowercases both
    sides each time. A rule pack with a few hundred patterns evaluated against a
    hundred thousand events spends most of its time doing the same work repeatedly.

    The cache maps a pattern to a matcher that keeps the original semantics: case-
    insensitive, ``*``/``?``/``[]`` support, and the fast prefix path for patterns
    ending in ``*``. Verification is by equivalence test, not by inspection.
    """

    __slots__ = ("_matchers", "_hits", "_misses")

    def __init__(self) -> None:
        self._matchers: dict[str, tuple[bool, str, re.Pattern[str] | None]] = {}
        self._hits = 0
        self._misses = 0

    def _compile(self, pattern: str) -> tuple[bool, str, re.Pattern[str] | None]:
        lowered = pattern.lower()
        body = lowered[:-1] if lowered.endswith("*") else lowered
        # fnmatch.translate produces the same regex fnmatch uses internally, so the
        # compiled form is semantics-preserving by construction. A literal pattern
        # keeps its whole text as the prefix; stripping the last character would
        # compare a value against a truncated string.
        compiled = re.compile(fnmatch.translate(lowered)) if _needs_regex(lowered) else None
        return lowered.endswith("*"), body, compiled

    def match(self, value: str, pattern: str) -> bool:
        cached = self._matchers.get(pattern)
        if cached is None:
            cached = self._compile(pattern)
            self._matchers[pattern] = cached
            self._misses += 1
        else:
            self._hits += 1
        lowered = value.lower()
        prefix_star, prefix, compiled = cached
        if prefix_star and lowered.startswith(prefix):
            return True
        if compiled is None:
            return lowered == prefix
        return compiled.match(lowered) is not None

    def any_match(self, value: str, patterns: Iterable[str]) -> bool:
        return any(self.match(value, pattern) for pattern in patterns)

    @property
    def statistics(self) -> dict:
        total = self._hits + self._misses
        return {
            "distinct_patterns": len(self._matchers),
            "cache_hits": self._hits,
            "cache_misses": self._misses,
            "hit_rate": round(self._hits / total, 6) if total else 0.0,
        }


def _needs_regex(pattern: str) -> bool:
    """True unless the pattern is a plain literal or a pure ``prefix*`` form."""
    body = pattern[:-1] if pattern.endswith("*") else pattern
    return any(character in body for character in "*?[")


def _score_window(events: list[dict], config: dict | None, profile: dict | None) -> dict:
    report = analyze(events, config, profile)
    return {
        "status": report["status"],
        "anomaly_score": report["anomaly_score"],
        "component_top": max(report["contribution"].items(), key=lambda item: item[1])[0]
        if report["contribution"] else "none",
        "reason_codes": [reason["code"] for reason in report["reasons"]],
        "event_count": report["event_count"],
    }


def stream(
    events: Iterable[dict],
    *,
    window_seconds: float = 60.0,
    config: dict | None = None,
    profile: dict | None = None,
    sample_limit: int = 2000,
    already_normalized: bool = False,
) -> dict:
    """Score an event stream window by window with bounded memory.

    Returns aggregated counts and per-window verdicts. ``sample_limit`` bounds the
    number of events retained for the report; the analysis itself never depends on
    those retained events having been kept.
    """
    if window_seconds < MIN_WINDOW_SECONDS:
        raise StreamError(
            f"window_seconds must be at least {MIN_WINDOW_SECONDS}; smaller windows "
            "split causal chains into fragments that cannot be scored meaningfully")
    if sample_limit < 0:
        raise StreamError("sample_limit must be non-negative")

    started = time.perf_counter()
    status_counts: Counter[str] = Counter()
    top_components: Counter[str] = Counter()
    windows: list[dict] = []
    sample: list[dict] = []
    normalized = 0
    rejected = 0
    rejected_examples: list[str] = []

    current: list[dict] = []
    window_start: float | None = None
    window_end = 0.0

    def flush() -> None:
        nonlocal current
        if not current:
            return
        result = _score_window(current, config, profile)
        result["window_index"] = len(windows)
        result["window_start"] = window_start
        result["window_end"] = window_end
        windows.append(result)
        status_counts[result["status"]] += 1
        top_components[result["component_top"]] += 1
        current = []

    for raw in events:
        if not already_normalized:
            try:
                event = normalize_event(raw)
            except EventError as exc:
                rejected += 1
                if len(rejected_examples) < 5:
                    rejected_examples.append(str(exc))
                continue
        else:
            event = raw
        normalized += 1
        if len(sample) < sample_limit:
            sample.append(event)
        stamp = float(event["timestamp"])
        if window_start is None:
            window_start = stamp
        if stamp - window_start >= window_seconds and current:
            window_end = stamp
            flush()
            window_start = stamp
        current.append(event)
        window_end = stamp
    flush()

    elapsed = time.perf_counter() - started
    total_windows = len(windows)
    flagged = total_windows - status_counts.get("NO_ANOMALY_DETECTED", 0)
    return {
        "format": STREAM_FORMAT,
        "window_seconds": window_seconds,
        "events_normalized": normalized,
        "events_rejected": rejected,
        "rejected_examples": rejected_examples,
        "window_count": total_windows,
        "windows_scored": windows,
        "status_counts": dict(sorted(status_counts.items())),
        "flagged_windows": flagged,
        "flagged_window_rate": round(flagged / total_windows, 6) if total_windows else 0.0,
        "top_components": dict(top_components.most_common()),
        "events_per_second": round(normalized / elapsed, 2) if elapsed > 0 else 0.0,
        "elapsed_seconds": round(elapsed, 4),
        "sample_events_retained": len(sample),
        "sample_limit": sample_limit,
        "notes": [
            "Each window is scored independently; a causal chain spanning a window "
            "boundary is split and may be missed.",
            "Rate-based components are computed within each window, not across the run.",
            "Window verdicts are triage hints for the window, not for the session.",
        ],
    }


def read_events(path: str | Path) -> Iterator[dict]:
    """Yield raw events from a JSONL file one line at a time.

    Unlike :func:`cabid.ingest.read_jsonl`, this never materializes the file.
    """
    source = Path(path)
    try:
        handle = source.open("r", encoding="utf-8")
    except OSError as exc:
        raise StreamError(f"cannot read {source}: {exc}") from exc
    with handle:
        for number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise StreamError(f"{source}:{number}: invalid JSON: {exc}") from exc
            if not isinstance(record, dict):
                raise StreamError(f"{source}:{number}: event must be a JSON object")
            yield record


def stream_file(path: str | Path, **kwargs) -> dict:
    """Stream a JSONL file with bounded memory."""
    return stream(read_events(path), **kwargs)
