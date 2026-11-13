"""Streaming analysis of a growing JSONL file.

Watch mode re-analyzes a bounded, time-based window of the most recent events
whenever the file grows. It is a research convenience for short collection runs,
not a low-latency sensor: it polls the file and re-reads changed data.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from .detector import analyze
from .normalize import EventError, normalize_event


class WatchState:
    """Incrementally ingest a JSONL file and score the trailing window."""

    def __init__(self, window_seconds: float = 300.0, config: dict | None = None,
                 profile: dict | None = None, max_events: int = 20000,
                 rules: list[dict] | None = None) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if max_events <= 0:
            raise ValueError("max_events must be positive")
        self.window_seconds = float(window_seconds)
        self.config = config or {}
        self.profile = profile
        self.rules = rules
        self.max_events = int(max_events)
        self.events: list[dict] = []
        self.offset = 0
        self.partial = ""
        self.invalid_lines = 0
        self.batches = 0

    def read_new(self, path: str | Path) -> list[dict]:
        """Read bytes appended since the last call; tolerate a partial last line."""
        source = Path(path)
        if not source.exists():
            return []
        with source.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(self.offset)
            chunk = handle.read()
            self.offset = handle.tell()
        if not chunk:
            return []
        payload = self.partial + chunk
        lines = payload.split("\n")
        self.partial = lines.pop()
        added = []
        for line in lines:
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                added.append(normalize_event(json.loads(line)))
            except (json.JSONDecodeError, EventError):
                self.invalid_lines += 1
        self.events.extend(added)
        self.events.sort(key=lambda item: item["timestamp"])
        return added

    def window(self) -> list[dict]:
        if not self.events:
            return []
        cutoff = float(self.events[-1]["timestamp"]) - self.window_seconds
        recent = [event for event in self.events if float(event["timestamp"]) >= cutoff]
        return recent[-self.max_events:]

    def score(self) -> dict:
        self.batches += 1
        events = self.window()
        report = analyze(events, self.config, self.profile, rules=self.rules)
        report["watch"] = {
            "batch": self.batches,
            "buffered_events": len(self.events),
            "window_events": len(events),
            "invalid_lines": self.invalid_lines,
            "window_seconds": self.window_seconds,
        }
        return report


def watch_file(path: str | Path, window_seconds: float = 300.0, interval: float = 2.0,
               iterations: int | None = None, config: dict | None = None,
               profile: dict | None = None, on_report=None, sleep=time.sleep,
               rules: list[dict] | None = None) -> list[dict]:
    """Poll ``path`` and emit a report each time new data arrives.

    ``iterations`` bounds the number of polls (None = until interrupted) and
    forces a report per poll so the caller always sees progress. A caller may
    inject ``sleep`` for deterministic tests.
    """
    if interval < 0:
        raise ValueError("interval must not be negative")
    state = WatchState(window_seconds, config, profile, rules=rules)
    reports: list[dict] = []
    polls = 0
    while iterations is None or polls < iterations:
        polls += 1
        added = state.read_new(path)
        if added or polls == 1 or iterations is not None:
            report = state.score()
            reports.append(report)
            if on_report is not None:
                on_report(report)
        if iterations is not None and polls >= iterations:
            break
        sleep(interval)
    return reports
