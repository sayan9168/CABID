"""ADFA-LD syscall traces mapped onto CABID events.

ADFA-LD (Creech & Hu, 2013) records Linux system-call *numbers* per trace. Each
file is a space-separated sequence such as ``3 4 5 6 11 ...`` with no timestamps,
no pids, no paths, and no process names. Mapping that onto CABID events therefore
requires synthetic context, and this module is deliberately conservative about how
much it invents:

* **Timing is synthetic.** Every trace is spread across a fixed collection window
  (20 s by default, matching the dataset's documented capture period). Event
  ordering is preserved; wall-clock time is not recoverable from the corpus.
* **Attribution is synthetic.** A trace is modelled as one process, because the
  corpus does not record which pid issued which call. No process is given a parent
  that could trigger ancestry heuristics, and no exit event is emitted for a process
  that continues to emit calls. This is intentional: synthesising lifecycle detail
  would manufacture contradictions that the corpus never contained, inflating
  detection scores with artifacts.
* **Unmodelled calls are dropped.** A syscall with no security-relevant CABID event
  class (``read``, ``futex``, ``mmap``...) is not invented into a category.

Consequences, stated plainly: this adapter exercises CABID's event-class and novelty
components only. The ancestry and lifecycle detectors, which are central to CABID on
real host telemetry, cannot be exercised by syscall-only data at all.
"""
from __future__ import annotations

import re
from pathlib import Path

#: i386 syscall numbers, taken from the kernel's arch/x86/entry/syscalls/
#: syscall_32.tbl. ADFA-LD was captured on 32-bit userspace, so x86-64 numbering
#: (where read is 0 and open is 2) does not apply. Only numbers that appear in
#: the corpus are listed; the table is generated from the kernel source.
SYSCALL_NAMES: dict[int, str] = {
    3: "read", 4: "write", 5: "open", 6: "close", 7: "waitpid", 10: "unlink",
    11: "execve", 12: "chdir", 13: "time", 19: "lseek", 20: "getpid",
    27: "alarm", 33: "access", 37: "kill", 38: "rename", 39: "mkdir",
    40: "rmdir", 41: "dup", 42: "pipe", 43: "times", 45: "brk", 54: "ioctl",
    57: "setpgid", 60: "umask", 63: "dup2", 64: "getppid", 65: "getpgrp",
    66: "setsid", 78: "gettimeofday", 85: "readlink", 91: "munmap",
    102: "socketcall", 104: "setitimer", 114: "wait4", 117: "ipc",
    118: "fsync", 119: "sigreturn", 120: "clone", 122: "uname", 125: "mprotect",
    132: "getpgid", 140: "_llseek", 141: "getdents", 142: "_newselect",
    146: "writev", 156: "sched_setscheduler", 158: "sched_yield",
    160: "sched_get_priority_min", 162: "nanosleep", 163: "mremap", 168: "poll",
    172: "prctl", 173: "rt_sigreturn", 174: "rt_sigaction",
    175: "rt_sigprocmask", 183: "getcwd", 191: "ugetrlimit", 192: "mmap2",
    194: "ftruncate64", 195: "stat64", 196: "lstat64", 197: "fstat64",
    199: "getuid32", 200: "getgid32", 201: "geteuid32", 202: "getegid32",
    205: "getgroups32", 206: "setgroups32", 219: "madvise", 220: "getdents64",
    221: "fcntl64", 224: "gettid", 240: "futex", 242: "sched_getaffinity",
    243: "set_thread_area", 256: "epoll_wait", 258: "set_tid_address",
    265: "clock_gettime", 266: "clock_getres", 268: "statfs64",
    292: "inotify_add_watch", 295: "openat", 300: "fstatat64", 301: "unlinkat",
    307: "faccessat", 309: "ppoll", 311: "set_robust_list", 324: "fallocate",
    331: "pipe2", 340: "prlimit64",
}

#: Syscall number -> CABID event class. Only mappings with a defensible
#: security meaning are listed; everything else is dropped rather than guessed.
SYSCALL_EVENT_TYPES: dict[int, str] = {
    # Process lifecycle
    11: "process_exec",
    120: "process_start",
    # File activity that changes state on disk
    4: "file_write", 5: "file_write", 10: "file_write", 38: "file_write",
    39: "file_write", 40: "file_write", 194: "file_write", 295: "file_write",
    301: "file_write", 324: "file_write", 118: "file_write", 146: "file_write",
    # Network egress / ingress. On i386, socket(), connect(), bind(), listen()
    # and the send/recv family are multiplexed through `socketcall`, so a single
    # number covers outbound connection attempts.
    102: "network_connect",
    # Credential and group manipulation
    206: "privilege_change",
    # Kernel-visible control operations
    172: "kernel_state_change",
}

#: Event classes this corpus can express at all. Declared explicitly so the
#: benchmark never asks a syscall corpus for classes it cannot produce.
ADFA_EVENT_CLASSES = (
    "file_write",
    "kernel_state_change",
    "network_connect",
    "privilege_change",
    "process_exec",
    "process_start",
)

_TRACE_NAME = re.compile(r"^(?:UAD|UTD|UVD)-.*?(\d+)\.txt$", re.IGNORECASE)


class TraceError(ValueError):
    """Raised when a trace file cannot be interpreted."""


def read_trace(path: str | Path) -> list[int]:
    """Read a trace file into a list of syscall numbers, preserving order."""
    source = Path(path)
    try:
        text = source.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise TraceError(f"cannot read trace {source}: {exc}") from exc
    numbers: list[int] = []
    for token in text.split():
        try:
            numbers.append(int(token))
        except ValueError as exc:
            raise TraceError(f"{source}: non-numeric syscall token {token!r}") from exc
    if not numbers:
        raise TraceError(f"{source}: trace is empty")
    return numbers


def trace_id(path: str | Path) -> str:
    """A stable identifier for a trace file, independent of its directory."""
    return Path(path).stem


def _session_pid(identifier: str) -> int:
    """Deterministic synthetic pid for a trace.

    Derived from the trace name so repeated runs produce byte-identical output,
    and bounded to keep it clear of realistic kernel pid ranges.
    """
    digest = 0
    for char in identifier:
        digest = (digest * 131 + ord(char)) % 60000
    return 1000 + digest


def trace_to_events(path: str | Path, *, window_seconds: float = 20.0,
                    source: str = "adfa-ld") -> list[dict]:
    """Convert one trace into CABID-shaped raw events.

    Returns ``[]`` when every syscall in the trace is unmodelled, so the caller
    can report that trace as unusable instead of scoring an empty session.
    """
    numbers = read_trace(path)
    if window_seconds <= 0:
        raise TraceError("window_seconds must be positive")
    identifier = trace_id(path)
    pid = _session_pid(identifier)
    spacing = window_seconds / float(len(numbers))
    # A fixed synthetic epoch keeps output deterministic and makes the corpus's
    # 2013 provenance explicit rather than implying these are recent captures.
    start = 1370000000.0
    events: list[dict] = [{
        "timestamp": start,
        "event_type": "process_start",
        "process_id": pid,
        "parent_process_id": 1,
        "process_name": "adfa-trace",
        "executable": "",
        "target": "trace-root",
        "source": source,
        "event_id": f"{identifier}:0",
    }]
    for index, number in enumerate(numbers):
        event_type = SYSCALL_EVENT_TYPES.get(number)
        if event_type is None:
            continue
        events.append({
            "timestamp": start + (index + 1) * spacing,
            "event_type": event_type,
            "process_id": pid,
            "parent_process_id": 1,
            "process_name": "adfa-trace",
            "executable": "",
            "target": SYSCALL_NAMES.get(number, f"syscall-{number}"),
            "source": source,
            "event_id": f"{identifier}:{index + 1}",
        })
    # The synthetic root start alone is not evidence of anything; drop it when no
    # modelled call followed, so an unmodelled trace reports zero real events.
    if len(events) == 1:
        return []
    return events


def corpus_sessions(root: str | Path) -> dict[str, list[tuple[str, str, int]]]:
    """Index a fetched corpus into labelled sessions.

    Returns ``{"training": [...], "validation": [...], "attack": [...]}`` where
    each entry is ``(session_id, path, label)``. Training and validation traces
    are benign (label 0); Attack_Data_Master traces carry their technique name.
    """
    base = Path(root)
    if not base.is_dir():
        raise TraceError(f"corpus directory not found: {base}")
    groups: dict[str, list[tuple[str, str, int]]] = {
        "training": [], "validation": [], "attack": [],
    }
    for directory, group in (("Training_Data_Master", "training"),
                             ("Validation_Data_Master", "validation")):
        folder = base / directory
        if not folder.is_dir():
            raise TraceError(f"{base}: missing {directory}")
        for path in sorted(folder.glob("*.txt")):
            groups[group].append((f"{group}/{path.stem}", str(path), 0))
    attack_root = base / "Attack_Data_Master"
    if not attack_root.is_dir():
        raise TraceError(f"{base}: missing Attack_Data_Master")
    for path in sorted(attack_root.rglob("*.txt")):
        technique = path.parent.name
        groups["attack"].append((f"attack/{technique}/{path.stem}", str(path), 1))
    return groups


def technique_of(session_id: str) -> str:
    """Extract the attack technique from an ``attack/<technique>/<trace>`` id."""
    parts = session_id.split("/")
    if len(parts) >= 3 and parts[0] == "attack":
        return re.sub(r"_\d+$", "", parts[1])
    return "benign"


def ngrams(numbers: list[int], size: int = 3) -> set[tuple[int, ...]]:
    """The set of contiguous n-grams in a syscall sequence."""
    if size < 1:
        raise ValueError("ngram size must be at least 1")
    if len(numbers) < size:
        return set()
    return {tuple(numbers[index:index + size]) for index in range(len(numbers) - size + 1)}


class NgramNovelty:
    """Syscall n-gram novelty, the standard ADFA-LD reference approach.

    Fits the set of n-grams seen in benign training traces, then scores a trace by
    the fraction of its n-grams that were never seen. This is included as a
    corpus-appropriate comparison baseline, not as part of CABID's engine: CABID
    deliberately abstracts events into classes, which discards exactly the sequence
    detail this model relies on.
    """

    def __init__(self, size: int = 3) -> None:
        if size < 1:
            raise ValueError("ngram size must be at least 1")
        self.size = size
        self._seen: set[tuple[int, ...]] = set()

    def fit(self, traces: list[list[int]]) -> "NgramNovelty":
        for numbers in traces:
            self._seen |= ngrams(numbers, self.size)
        return self

    @property
    def learned_ngrams(self) -> int:
        return len(self._seen)

    def score(self, numbers: list[int]) -> float:
        """Fraction of novel n-grams; 0.0 when a trace yields no complete n-gram."""
        found = ngrams(numbers, self.size)
        if not found:
            return 0.0
        return len(found - self._seen) / float(len(found))
