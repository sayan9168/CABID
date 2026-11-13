"""JSON Lines ingestion with line-aware validation errors."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Iterable
from .normalize import EventError, normalize_event

def read_jsonl(path: str | Path) -> list[dict]:
    events = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                events.append(normalize_event(json.loads(line)))
            except (json.JSONDecodeError, EventError) as exc:
                raise EventError(f"{path}:{line_no}: {exc}") from exc
    return sorted(events, key=lambda item: item["timestamp"])

def normalize_many(rows: Iterable[dict]) -> list[dict]:
    return sorted((normalize_event(row) for row in rows), key=lambda item: item["timestamp"])
