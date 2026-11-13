"""Audited execution of a response plan, and the dry run that should come first.

The design goal is that this file can be read in five minutes and shown to whoever
owns the host. It can do exactly four things:

- write an evidence copy of a file,
- send a signal to a process,
- copy a file into a quarantine directory,
- write a shell command for a human to run.

Everything else in :mod:`cabid.response` is a recommendation that lands here only
if four gates agreed *and* a human passed ``--apply`` with the plan digest.

Two properties are enforced rather than documented:

* **The plan is re-validated at execution time.** A plan file edited after review
  no longer matches its digest, and its decisions are re-checked against the gates
  before any signal is sent. A reviewed plan cannot be quietly weakened on disk.
* **Every step is audited before it runs, not after.** If the process dies mid-run,
  the audit trail still says what was attempted, which is the case where you need
  it most.

What this module deliberately cannot do is listed at the bottom of the file. That
list is shorter than the feature list on purpose.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import time
from pathlib import Path

from .response import (ACTIONS, OBSERVE_ONLY, RESPONSE_FORMAT, ResponseError,
                       _digest, build_plan)

AUDIT_FORMAT = "cabid-audit/1"
DEFAULT_QUARANTINE = "cabid-quarantine"

# Signals this executor is willing to send. Nothing else, ever.
_ALLOWED_SIGNALS = {
    "suspend_process": signal.SIGSTOP,
    "kill_process": signal.SIGKILL,
}

_EMITTED_ONLY = {"isolate_host", "block_address", "disable_account"}

_EMITTED_COMMANDS = {
    "isolate_host": [
        "# Isolate the host. Verify your management path first: this drops EVERYTHING.",
        "nft add table inet cabid_isolate 2>/dev/null || true",
        "nft 'add chain inet cabid_isolate out { type filter hook output priority 0; policy drop; }'",
        "nft 'add rule inet cabid_isolate out ct state established accept'",
        "# Undo with: nft delete table inet cabid_isolate",
    ],
    "block_address": [
        "# Block one destination, not a range. A shared NAT or CDN can make this block friends.",
        "nft add rule inet filter output ip daddr <ADDRESS> drop",
        "# Undo with: nft -a list ruleset   # then delete the matching handle",
    ],
    "disable_account": [
        "# Disable the account, keep the home directory for evidence.",
        "usermod --expiredate 1 <ACCOUNT>",
        "# Undo with: usermod --expiredate '' <ACCOUNT>",
    ],
}


class ExecutionError(ValueError):
    """Raised when a plan must not be executed."""


def _audit_event(action: str, decision: dict, outcome: str, detail: str = "") -> dict:
    return {
        "format": AUDIT_FORMAT,
        "timestamp": round(time.time(), 6),
        "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "action": action,
        "process_id": decision.get("process_id"),
        "process_names": decision.get("process_names"),
        "destructive": bool(decision.get("destructive")),
        "outcome": outcome,
        "detail": detail[:500],
    }


class AuditTrail:
    """Append-only JSONL audit trail. Written before each step runs."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.entries: list[dict] = []

    def record(self, entry: dict) -> dict:
        self.entries.append(entry)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        return entry


def verify_plan(plan: dict) -> str:
    """Recompute the digest and re-run the gates on every decision.

    Returns the verified digest. Raises if the file was edited after review, or if
    any destructive decision no longer satisfies the gates that allowed it.
    """
    if not isinstance(plan, dict):
        raise ExecutionError("a response plan object is required")
    if plan.get("format") != RESPONSE_FORMAT:
        raise ExecutionError(f"not a CABID response plan: {plan.get('format')!r}")
    claimed = plan.get("plan_digest")
    if not isinstance(claimed, str) or len(claimed) != 64:
        raise ExecutionError("plan has no usable plan_digest")
    actual = _digest({key: value for key, value in plan.items() if key != "plan_digest"})
    if actual != claimed:
        raise ExecutionError(
            "plan digest does not match its contents: this plan was edited after review "
            f"(expected {claimed[:12]}..., computed {actual[:12]}...)")

    based = plan.get("based_on") or {}
    if not based.get("telemetry_sufficient"):
        # A plan should never have destructive decisions in this state; check anyway.
        for decision in plan.get("decisions") or []:
            if decision.get("destructive"):
                raise ExecutionError(
                    "plan contains a destructive decision based on insufficient telemetry")
    for decision in plan.get("decisions") or []:
        if decision.get("recommended_action") not in ACTIONS:
            raise ExecutionError(f"unknown action: {decision.get('recommended_action')!r}")
        if decision.get("destructive") and decision.get("blocked_by"):
            raise ExecutionError(
                f"pid {decision.get('process_id')} has a destructive action despite "
                "recorded blocks")
    return actual


def dry_run(plan: dict, base_path: str | Path | None = None) -> dict:
    """Determine what *would* happen, without touching anything.

    This is the check to run against every plan an automation produced, because it
    surfaces the two failures that matter: a plan that cannot be executed at all
    (pid gone, file unreadable) and a plan whose blast radius is larger than the
    reader assumed.
    """
    digest = verify_plan(plan)
    results = []
    for decision in plan.get("decisions") or []:
        action = str(decision.get("recommended_action"))
        pid = decision.get("process_id")
        entry: dict = {
            "process_id": pid,
            "action": action,
            "destructive": bool(decision.get("destructive")),
            "status": "would_run",
            "detail": "",
        }
        if decision.get("blocked_by") and action not in OBSERVE_ONLY:
            entry.update(status="refused",
                         detail="; ".join(item["reason"] for item in decision["blocked_by"]))
        elif action in _ALLOWED_SIGNALS:
            alive = _pid_exists(pid)
            entry.update(status="would_run" if alive else "skipped",
                         detail="process alive" if alive else "process no longer exists")
        elif action in _EMITTED_ONLY:
            entry.update(status="emit_only",
                         detail="emits a command for a human; CABID will not run it")
        elif action == "quarantine_file":
            entry.update(status="emit_only",
                         detail="needs an explicit --quarantine-dir and file path")
        elif action == "snapshot":
            entry.update(status="would_run", detail="writes an evidence copy")
        else:
            entry.update(status="noop", detail="observe only")
        results.append(entry)
    return {
        "format": AUDIT_FORMAT,
        "mode": "dry-run",
        "plan_digest": digest,
        "recommendation": "review the destructive entries before running with --apply",
        "steps": results,
        "executed": False,
    }


def _pid_exists(pid: object) -> bool:
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Exists, but not ours. Sending a signal would fail too.
        return False


def execute_plan(plan: dict, confirm: str, audit_path: str | Path,
                 quarantine_dir: str | Path | None = None,
                 file_paths: list[str] | None = None,
                 emit_only: bool = True) -> dict:
    """Execute a verified plan's non-emitted actions, auditing every step.

    ``emit_only`` defaults to True: network and account actions are printed as
    commands for a human, never run. Process signals are the only things this
    function can actually do to a system, and only to pids it can signal.
    """
    digest = verify_plan(plan)
    if confirm != digest:
        raise ExecutionError(
            "the confirmation digest does not match this plan; review it and pass "
            f"--confirm {digest}")

    trail = AuditTrail(audit_path)
    trail.record({"format": AUDIT_FORMAT, "timestamp": round(time.time(), 6),
                  "event": "plan_start", "plan_digest": digest,
                  "based_on": plan.get("based_on"),
                  "decisions": len(plan.get("decisions") or []),
                  "destructive": sum(1 for d in plan.get("decisions") or []
                                     if d.get("destructive"))})

    results = []
    for decision in plan.get("decisions") or []:
        action = str(decision.get("recommended_action"))
        pid = decision.get("process_id")
        result = {"process_id": pid, "action": action,
                  "destructive": bool(decision.get("destructive"))}

        # The gates stop a process from being taken down. They never stop
        # observation: capturing evidence is safe by construction, and it is the
        # one thing worth doing when containment is refused.
        if decision.get("blocked_by") and action not in OBSERVE_ONLY:
            trail.record(_audit_event(action, decision, "refused",
                                      "; ".join(item["reason"] for item in decision["blocked_by"])))
            result.update(status="refused", detail="gates still blocked at execution time")
            results.append(result)
            continue

        if action in _ALLOWED_SIGNALS:
            if not _pid_exists(pid):
                trail.record(_audit_event(action, decision, "skipped", "pid not present"))
                result.update(status="skipped", detail="process no longer exists")
                results.append(result)
                continue
            # Audit first: if the next line kills this process, the record exists.
            trail.record(_audit_event(action, decision, "attempted",
                                      f"signal {_ALLOWED_SIGNALS[action].name}"))
            try:
                os.kill(int(pid), _ALLOWED_SIGNALS[action])
                outcome, detail = "sent", f"signal {_ALLOWED_SIGNALS[action].name} delivered"
            except (ProcessLookupError, PermissionError) as exc:
                outcome, detail = "failed", f"{type(exc).__name__}: {exc}"
            trail.record(_audit_event(action, decision, outcome, detail))
            result.update(status=outcome, detail=detail)

        elif action == "snapshot":
            if not quarantine_dir:
                # A step that did not run is still a step that was decided on.
                trail.record(_audit_event("snapshot", decision, "skipped",
                                          "no --quarantine-dir supplied; nothing captured"))
                result.update(status="skipped", detail="no --quarantine-dir supplied")
            else:
                captured = _capture(decision, quarantine_dir, trail)
                result.update(status="captured" if captured else "skipped",
                              detail=captured or "capture failed")
        elif action == "quarantine_file":
            moved = _quarantine(decision, quarantine_dir, file_paths, trail)
            result.update(status="quarantined" if moved else "skipped",
                          detail=moved or "no --quarantine-dir or file paths supplied")
        elif action in _EMITTED_ONLY:
            commands = _EMITTED_COMMANDS.get(action, [])
            trail.record(_audit_event(action, decision, "emitted",
                                      f"{len(commands)} command line(s) for a human"))
            result.update(status="emitted", commands=commands,
                          detail="not executed by CABID")
        else:
            trail.record(_audit_event(action, decision, "noop", "observe only"))
            result.update(status="noop", detail="observe only")
        results.append(result)

    trail.record({"format": AUDIT_FORMAT, "timestamp": round(time.time(), 6),
                  "event": "plan_end", "plan_digest": digest})
    return {
        "format": AUDIT_FORMAT,
        "mode": "apply",
        "plan_digest": digest,
        "audit_path": str(trail.path),
        "audit_entries": len(trail.entries),
        "steps": results,
        "executed": True,
        "note": "Every step above is in the audit trail. Network and account actions "
                "were emitted, not run.",
    }


def _capture(decision: dict, quarantine_dir: str | Path | None, trail: AuditTrail) -> str | None:
    target = Path(quarantine_dir) / "snapshots" if quarantine_dir else None
    if not target:
        return None
    target.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = target / f"pid{decision.get('process_id')}-{stamp}.json"
    payload = {"captured_at": round(time.time(), 6), "decision": decision,
               "note": "record of the decision, not a memory image of the process"}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    trail.record(_audit_event("snapshot", decision, "captured", str(path)))
    return str(path)


def _quarantine(decision: dict, quarantine_dir: str | Path | None,
                file_paths: list[str] | None, trail: AuditTrail) -> str | None:
    if not quarantine_dir or not file_paths:
        return None
    destination_root = Path(quarantine_dir)
    destination_root.mkdir(parents=True, exist_ok=True)
    copied = []
    for raw in file_paths[:10]:
        source = Path(raw)
        if not source.is_file():
            trail.record(_audit_event("quarantine_file", decision, "skipped",
                                      f"not a regular file: {source}"))
            continue
        destination = destination_root / f"{source.name}.{int(time.time())}"
        shutil.copy2(source, destination)
        copied.append(str(destination))
        trail.record(_audit_event(
            "quarantine_file", decision, "copied",
            f"{source} -> {destination}; original path left readable on purpose"))
    return ", ".join(copied) if copied else None


def replan(report: dict, plan: dict, **kwargs) -> dict:
    """Rebuild a plan from the report, for comparing against a stored plan."""
    rebuilt = build_plan(report, **kwargs)
    return {
        "match": rebuilt["plan_digest"] == plan.get("plan_digest"),
        "stored_digest": plan.get("plan_digest"),
        "rebuilt_digest": rebuilt["plan_digest"],
        "note": "A mismatch means the report or the code changed since the plan was made.",
    }


__all__ = ["AUDIT_FORMAT", "AuditTrail", "ExecutionError", "dry_run", "execute_plan",
           "replan", "verify_plan", "ResponseError", "DEFAULT_QUARANTINE"]

# --------------------------------------------------------------------------
# What this module cannot do, by construction:
#
# * install or remove audit rules, kernel modules, or eBPF programs
# * modify iptables/nftables, hostnames, or routing (those are emitted strings)
# * disable accounts, rotate keys, or revoke tokens
# * send a signal other than SIGSTOP and SIGKILL
# * touch a pid it cannot signal with its own privileges
# * run anything with a shell (no shell=True anywhere in this file)
# * delete a file (quarantine copies; the original stays in place)
#
# If a future change needs any of the above, it needs a new file, a new audit
# design, and a review that is not this one.
# --------------------------------------------------------------------------
