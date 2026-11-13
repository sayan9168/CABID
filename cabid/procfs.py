"""Best-effort, unprivileged Linux /proc process snapshot reader.

This is polling telemetry, not an audit-grade event stream. Short-lived processes
may be missed and access restrictions can hide process metadata.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator


def parse_proc_stat(text: str) -> tuple[int, int]:
    """Return (parent_pid, start_time_ticks) from a Linux /proc/PID/stat line."""
    close = text.rfind(")")
    if close < 0:
        raise ValueError("malformed /proc stat: missing command terminator")
    fields = text[close + 1 :].strip().split()
    # fields starts with field 3 (state); ppid is field 4, starttime field 22.
    if len(fields) <= 19:
        raise ValueError("malformed /proc stat: not enough fields")
    try:
        parent_pid = int(fields[1])
        start_ticks = int(fields[19])
    except ValueError as exc:
        raise ValueError("malformed /proc stat: invalid numeric field") from exc
    if parent_pid < 0 or start_ticks < 0:
        raise ValueError("malformed /proc stat: negative process metadata")
    return parent_pid, start_ticks


def iter_processes(proc_root: str | Path = "/proc") -> Iterator[dict]:
    """Yield readable process metadata; races and permission errors are skipped."""
    root = Path(proc_root)
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        raise OSError(f"cannot read procfs at {root}: {exc}") from exc
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            pid = int(entry.name)
            stat_text = (entry / "stat").read_text(encoding="utf-8")
            ppid, start_ticks = parse_proc_stat(stat_text)
            try:
                executable = os.readlink(entry / "exe")
            except (OSError, PermissionError):
                executable = ""
            try:
                raw_cmdline = (entry / "cmdline").read_bytes()
                cmdline = raw_cmdline.replace(b"\0", b" ").decode("utf-8", "replace").strip()
            except (OSError, PermissionError):
                cmdline = ""
            comm = stat_text[stat_text.find("(") + 1 : stat_text.rfind(")")]
            yield {
                "pid": pid,
                "ppid": ppid,
                "start_ticks": start_ticks,
                "name": comm[:256] or "unknown",
                "executable": executable[:1024],
                "cmdline": cmdline[:1024],
            }
        except (OSError, ValueError, IndexError):
            # A process may exit between readdir and reading its procfs files.
            continue
