"""Declarative detection policy: file rules, sensitive paths, and suppressions.

The detector's heuristics answer "does this stream look unusual?". A policy
answers the complementary operational question "does it touch anything the
operator declared sensitive, and which known-good activity is allow-listed?".
Policy findings are additive context; they never rewrite the heuristic score.
"""
from __future__ import annotations

import fnmatch
import json
from pathlib import Path

POLICY_FORMAT = "cabid-policy/2"
SUPPORTED_FORMATS = {"cabid-policy/1", POLICY_FORMAT}

DEFAULT_POLICY: dict = {
    "format": POLICY_FORMAT,
    "sensitive_paths": [
        "/etc/shadow", "/etc/sudoers", "/etc/ssh/", "/root/", "/boot/",
        "/lib/systemd/system/", "/etc/systemd/system/",
        "/etc/cron*", "/etc/rc.local", "/etc/ld.so.preload", "/etc/passwd",
        "/var/spool/cron/",
    ],
    "sensitive_ports": [22, 23, 445, 3389, 2375, 6379],
    "allow_process_names": ["systemd", "sshd", "cron", "dbus-daemon", "systemd-journald"],
    "allow_executables": ["/usr/lib/systemd/", "/usr/sbin/sshd", "/usr/sbin/cron"],
    "suppress_rule_codes": [],
    "suppress_for_processes": {},
    "notes": "Defaults are illustrative; review before use in any environment.",
}


class PolicyError(ValueError):
    """Raised when a policy file cannot be interpreted."""


def _string_list(value: object, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise PolicyError(f"{field} must be a list of strings")
    return [item for item in value if item]


def load_policy(path: str | Path | None) -> dict:
    """Load and validate a policy file; return defaults when path is None."""
    if path is None:
        return json.loads(json.dumps(DEFAULT_POLICY))
    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PolicyError(f"{source}: invalid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError(f"{source}: policy must be a JSON object")
    declared = raw.pop("format", POLICY_FORMAT)
    if declared not in SUPPORTED_FORMATS:
        raise PolicyError(f"{source}: unsupported policy format: {declared}")
    unknown = sorted(set(raw) - set(DEFAULT_POLICY))
    if unknown:
        raise PolicyError(f"{source}: unknown policy keys: {', '.join(unknown)}")
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    policy.update(raw)
    policy["format"] = POLICY_FORMAT
    for field in ("sensitive_paths", "allow_process_names", "allow_executables", "suppress_rule_codes"):
        policy[field] = _string_list(policy.get(field), field)
    ports = policy.get("sensitive_ports") or []
    if not isinstance(ports, list):
        raise PolicyError("sensitive_ports must be a list of integers")
    clean_ports = []
    for port in ports:
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise PolicyError("sensitive_ports must contain integers between 1 and 65535")
        clean_ports.append(port)
    policy["sensitive_ports"] = sorted(set(clean_ports))
    scoped = policy.get("suppress_for_processes") or {}
    if not isinstance(scoped, dict):
        raise PolicyError("suppress_for_processes must be an object of name -> [codes]")
    clean_scoped = {}
    for name, codes in scoped.items():
        if not isinstance(name, str) or not name.strip():
            raise PolicyError("suppress_for_processes keys must be non-empty process names")
        clean_scoped[name.strip()] = _string_list(codes, f"suppress_for_processes.{name}")
    policy["suppress_for_processes"] = clean_scoped
    return policy


def _port_of(target: str) -> int | None:
    text = str(target or "").strip()
    if not text:
        return None
    host = text.rsplit("@", 1)[-1]
    for separator in (":",):
        if separator in host:
            candidate = host.rsplit(separator, 1)[-1]
            if candidate.isdigit():
                port = int(candidate)
                return port if 1 <= port <= 65535 else None
    return None


def _matches(value: str, patterns: list[str]) -> str | None:
    for pattern in patterns:
        if fnmatch.fnmatch(value, pattern) or value.startswith(pattern.rstrip("*")):
            return pattern
    return None


def evaluate_policy(events: list[dict], policy: dict | None = None,
                    reasons: list[dict] | None = None) -> dict:
    """Return policy findings, suppressions, and per-event flags."""
    active = policy if policy is not None else json.loads(json.dumps(DEFAULT_POLICY))
    paths = list(active.get("sensitive_paths") or [])
    ports = set(active.get("sensitive_ports") or [])
    allow_names = list(active.get("allow_process_names") or [])
    allow_execs = list(active.get("allow_executables") or [])
    suppressed_codes = set(active.get("suppress_rule_codes") or [])
    scoped = dict(active.get("suppress_for_processes") or {})

    findings: list[dict] = []
    suppressed_findings = 0
    allowed_events = 0
    flagged_events: list[dict] = []
    for index, event in enumerate(events):
        name = str(event.get("process_name") or "")
        executable = str(event.get("executable") or "")
        allowed_by_name = bool(_matches(name, allow_names))
        allowed_by_exec = bool(executable and _matches(executable, allow_execs))
        if allowed_by_name or allowed_by_exec:
            allowed_events += 1
        target = str(event.get("target") or "")
        hit_path = _matches(target, paths) if target and event["event_type"] == "file_write" else None
        port = _port_of(target) if event["event_type"] == "network_connect" else None
        scoped_codes = set(scoped.get(name) or [])
        if hit_path:
            finding = {
                "rule": "sensitive_path_write", "event_index": index,
                "severity": "high" if allowed_by_name or allowed_by_exec else "medium",
                "detail": f"write-capable event on sensitive path pattern {hit_path}",
                "process_name": name, "target_ref": _safe_ref(target),
                "allow_listed_process": bool(allowed_by_name or allowed_by_exec),
            }
            if finding["rule"] in scoped_codes:
                suppressed_findings += 1
            else:
                findings.append(finding)
        if port is not None and port in ports:
            finding = {
                "rule": "sensitive_port_connect", "event_index": index, "severity": "high",
                "detail": f"connection to policy-sensitive port {port}",
                "process_name": name, "target_ref": _safe_ref(target),
                "allow_listed_process": bool(allowed_by_name or allowed_by_exec),
            }
            if finding["rule"] in scoped_codes:
                suppressed_findings += 1
            else:
                findings.append(finding)
        if hit_path or (port is not None and port in ports):
            flagged_events.append({
                "event_type": event["event_type"], "process_id": event["process_id"],
                "process_name": name, "target_ref": _safe_ref(target),
            })

    kept_reasons = []
    suppressed = []
    for reason in reasons or []:
        if reason.get("code") in suppressed_codes:
            suppressed.append(reason.get("code"))
        else:
            kept_reasons.append(reason)

    rule_counts: dict[str, int] = {}
    for finding in findings:
        rule_counts[finding["rule"]] = rule_counts.get(finding["rule"], 0) + 1
    return {
        "policy_applied": policy is not None,
        "finding_count": len(findings),
        "findings": findings[:50],
        "findings_truncated": len(findings) > 50,
        "flagged_events": flagged_events[:50],
        "rule_counts": dict(sorted(rule_counts.items())),
        "sensitive_path_patterns": len(paths),
        "sensitive_ports": sorted(ports),
        "allow_listed_events": allowed_events,
        "suppressed_findings": suppressed_findings,
        "suppressed_for_processes": sorted(scoped),
        "suppressed_reason_codes": sorted(set(suppressed)),
        "reasons_after_suppression": kept_reasons,
        "notes": [
            "Policy findings are operator-defined context, not model output.",
            "A write-capable event proves intent to write, not that data changed.",
            "Default patterns are illustrative and must be reviewed per host.",
            "Process-scoped suppressions hide findings for that process only; the count is still reported.",
        ],
    }


def _safe_ref(target: str) -> str:
    """Keep the basename and length bounded; avoid echoing full command lines."""
    text = str(target or "")
    if not text:
        return ""
    base = text.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return base[:120] or text[:120]
