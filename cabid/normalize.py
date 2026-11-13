"""Strict event normalization for CABID JSONL input."""
from __future__ import annotations
import math
from datetime import datetime, timezone
from typing import Any

REQUIRED = ("timestamp", "event_type", "process_id")
ALLOWED = {"process_start", "process_exec", "file_write", "network_connect", "process_exit", "heartbeat"}


class EventError(ValueError):
    """Raised when an input event is malformed or unsafe to interpret."""


def _strict_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise EventError(f"{field} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise EventError(f"{field} must be an integer") from exc
    if isinstance(value, float) and not value.is_integer():
        raise EventError(f"{field} must be an integer")
    if isinstance(value, str) and str(parsed) != value.strip():
        raise EventError(f"{field} must be an integer")
    return parsed


def normalize_event(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise EventError("event must be a JSON object")
    missing = [key for key in REQUIRED if key not in raw]
    if missing:
        raise EventError(f"missing required fields: {', '.join(missing)}")
    try:
        if isinstance(raw["timestamp"], bool):
            raise ValueError("boolean is not a timestamp")
        timestamp = float(raw["timestamp"])
        if not math.isfinite(timestamp) or timestamp < 0:
            raise ValueError("timestamp must be finite and non-negative")
        timestamp_iso = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError) as exc:
        raise EventError("timestamp must be a finite Unix timestamp in seconds") from exc
    event_type = str(raw["event_type"]).strip().lower()
    if event_type not in ALLOWED:
        raise EventError(f"unsupported event_type: {event_type}")
    pid = _strict_int(raw["process_id"], "process_id")
    ppid = _strict_int(raw.get("parent_process_id", 0), "parent_process_id")
    if pid <= 0 or ppid < 0:
        raise EventError("process_id must be positive and parent_process_id non-negative")
    event = {"timestamp": timestamp, "timestamp_iso": timestamp_iso, "event_type": event_type,
             "process_id": pid, "parent_process_id": ppid,
             "process_name": str(raw.get("process_name", "unknown"))[:256],
             "executable": str(raw.get("executable", ""))[:1024],
             "target": str(raw.get("target", ""))[:1024],
             "source": str(raw.get("source", "unknown"))[:128]}
    if "event_id" in raw:
        event["event_id"] = str(raw["event_id"])[:128]
    return event
