"""Best-effort parser for Linux auditd raw records (ausearch --format raw)."""
from __future__ import annotations
import re
from collections import defaultdict

_EVENT_RE = re.compile(r"msg=audit\((\d+(?:\.\d+)?):(\d+)\)")
_KV_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|[^\s]+)')
_WRITE_MASK = 0x1 | 0x2 | 0x40 | 0x200 | 0x400
_SYSCALLS = {
    "c000003e": {2:"open",41:"socket",42:"connect",56:"clone",57:"fork",58:"vfork",59:"execve",60:"exit",82:"rename",83:"mkdir",85:"creat",87:"unlink",231:"exit_group",257:"openat",263:"unlinkat",316:"renameat",322:"execveat"},
    "c00000b7": {56:"openat",198:"socket",203:"connect",220:"clone",221:"execve",93:"exit",94:"exit_group",276:"renameat",278:"mkdirat",35:"unlinkat",281:"execveat",437:"openat2"},
}


def _fields(line: str) -> dict[str, str]:
    result = {}
    for match in _KV_RE.finditer(line):
        value = match.group(2)
        if value.startswith('"') and value.endswith('"'):
            value = bytes(value[1:-1], "utf-8").decode("unicode_escape", errors="replace")
        result[match.group(1)] = value
    return result


def _number(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 10)
    except ValueError:
        return None


def _audit_arg(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value, 0) if value.lower().startswith("0x") else int(value, 16)
    except ValueError:
        return None


def _syscall_name(fields: dict[str, str]) -> str:
    raw = fields.get("syscall", "")
    if not raw:
        return ""
    if not raw.isdigit():
        return raw.lower()
    return _SYSCALLS.get(fields.get("arch", "").lower(), {}).get(int(raw), "")


def parse_audit_raw(lines: list[str]) -> dict:
    """Translate selected audit syscall records; unknown data is never guessed."""
    grouped = defaultdict(list)
    unparsed = 0
    for line in lines:
        match = _EVENT_RE.search(line)
        if not match:
            if line.strip():
                unparsed += 1
            continue
        timestamp, serial = match.groups()
        record_match = re.search(r"^type=([A-Z0-9_]+)", line)
        if not record_match:
            unparsed += 1
            continue
        grouped[f"{timestamp}:{serial}"].append((record_match.group(1), _fields(line)))

    events, ignored = [], 0
    for event_id, records in sorted(grouped.items(), key=lambda item: float(item[0].split(":", 1)[0])):
        syscall = next((f for kind, f in records if kind == "SYSCALL"), None)
        if syscall is None or syscall.get("success", "yes") not in {"yes", "1"}:
            ignored += 1
            continue
        name = _syscall_name(syscall)
        pid, ppid = _number(syscall.get("pid")), _number(syscall.get("ppid")) or 0
        if not pid or pid < 1:
            ignored += 1
            continue
        paths = [f.get("name", "") for kind, f in records if kind == "PATH" and f.get("name")]
        base = {"timestamp": float(event_id.split(":", 1)[0]), "process_id": pid,
                "parent_process_id": max(0, ppid), "process_name": syscall.get("comm", "unknown"),
                "executable": syscall.get("exe", ""), "source": "linux-auditd", "event_id": event_id}
        kind, target = None, ""
        if name in {"execve", "execveat"}:
            kind = "process_exec"
        elif name in {"fork", "vfork", "clone", "clone3"}:
            child_pid = _number(syscall.get("exit"))
            if child_pid and child_pid > 0:
                base["process_id"], base["parent_process_id"] = child_pid, pid
                kind = "process_start"
        elif name == "connect":
            kind = "network_connect"
        elif name in {"open", "openat"}:
            flags = _audit_arg(syscall.get("a1" if name == "open" else "a2"))
            if flags is not None and flags & _WRITE_MASK:
                kind, target = "file_write", (paths[0] if paths else "")
        elif name == "creat":
            kind, target = "file_write", (paths[0] if paths else "")
        elif name in {"exit", "exit_group"}:
            kind = "process_exit"
        if kind is None:
            ignored += 1
        else:
            events.append({**base, "event_type": kind, "target": target})
    return {"events": events, "records_seen": len(lines), "audit_events_seen": len(grouped),
            "events_emitted": len(events), "records_unparsed": unparsed, "audit_events_ignored": ignored,
            "limitations": ["Only selected x86_64 and aarch64 syscall families are translated.",
                "File-write extraction depends on syscall arguments and PATH records.",
                "Missing records do not prove that activity did not occur.",
                "Audit rules are configured separately; this parser never changes system policy."]}
