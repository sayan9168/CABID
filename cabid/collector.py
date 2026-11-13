"""Polling Linux procfs collector. No root privileges or third-party packages required."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .procfs import iter_processes


class ProcfsCollector:
    """Emit process start/exec observations by comparing successive procfs snapshots."""

    def __init__(self, proc_root: str | Path = "/proc") -> None:
        self.proc_root = proc_root
        self.previous: dict[int, tuple[int, str, str]] = {}

    def poll(self, timestamp: float | None = None) -> list[dict]:
        now = time.time() if timestamp is None else float(timestamp)
        current: dict[int, tuple[int, str, str]] = {}
        events: list[dict] = []
        for process in iter_processes(self.proc_root):
            pid = process["pid"]
            identity = (process["start_ticks"], process["executable"], process["cmdline"])
            current[pid] = identity
            old = self.previous.get(pid)
            base = {
                "timestamp": now,
                "process_id": pid,
                "parent_process_id": process["ppid"],
                "process_name": process["name"],
                "executable": process["executable"],
                "target": process["cmdline"],
                "source": "procfs-poll",
            }
            if old is None or old[0] != identity[0]:
                events.append({**base, "event_type": "process_start"})
                # This is an observed executable snapshot, not proof of the exact exec time.
                events.append({**base, "event_type": "process_exec"})
            elif old[1:] != identity[1:]:
                events.append({**base, "event_type": "process_exec"})
        self.previous = current
        events.append({
            "timestamp": now,
            "event_type": "heartbeat",
            "process_id": os.getpid(),
            "parent_process_id": os.getppid(),
            "process_name": "cabid-collector",
            "source": "procfs-poll",
        })
        return events


def collect_to_jsonl(
    output: str | Path,
    interval: float = 2.0,
    duration: float = 30.0,
    proc_root: str | Path = "/proc",
) -> int:
    """Append polling observations to JSONL for duration seconds; return event count."""
    if interval <= 0 or duration <= 0:
        raise ValueError("interval and duration must be positive")
    collector = ProcfsCollector(proc_root)
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + duration
    count = 0
    with destination.open("a", encoding="utf-8") as handle:
        while True:
            batch = collector.poll()
            for event in batch:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
            handle.flush()
            count += len(batch)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(interval, remaining))
    return count
