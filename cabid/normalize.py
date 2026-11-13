"""Strict event normalization for CABID JSONL input."""
from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

REQUIRED = ("timestamp", "event_type", "process_id")
ALLOWED = {"process_start", "process_exec", "file_write", "network_connect", "process_exit", "heartbeat"}

class EventError(ValueError):
    """Raised when an input event is malformed or unsafe to interpret."""

def normalize_event(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise EventError("event must be a JSON object")
    missing = [key for key in REQUIRED if key not in raw]
    if missing:
        raise EventError(f"missing required fields: {', '.join(missing)}")
    try:
        timestamp = float(raw["timestamp"])
    except (TypeError, ValueError) as exc:
        raise EventError("timestamp must be a Unix timestamp in seconds") from exc
    if timestamp < 0:
        raise EventError("timestamp cannot be negative")
    event_type = str(raw["event_type"]).strip().lower()
    if event_type not in ALLOWED:
        raise EventError(f"unsupported event_type: {event_type}")
    try:
        pid = int(raw["process_id"])
        ppid = int(raw.get("parent_process_id", 0))
    except (TypeError, ValueError) as exc:
        raise EventError("process_id and parent_process_id must be integers") from exc
    if pid <= 0 or ppid < 0:
        raise EventError("process_id must be positive and parent_process_id non-negative")
    event = {
        "timestamp": timestamp,
        "timestamp_iso": datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat(),
        "event_type": event_type, "process_id": pid, "parent_process_id": ppid,
        "process_name": str(raw.get("process_name", "unknown"))[:256],
        "executable": str(raw.get("executable", ""))[:1024],
        "target": str(raw.get("target", ""))[:1024],
        "source": str(raw.get("source", "unknown"))[:128],
    }
    if "event_id" in raw:
        event["event_id"] = str(raw["event_id"])[:128]
    return event
