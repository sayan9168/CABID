"""Declarative correlation rules.

The five weighted components answer "how unusual is this window". Rules answer
"does this specific multi-event pattern occur", which is what most real triage
starts from. A rule is data, not code, so an analyst can add a check without
touching the engine.

Two rule kinds are supported:

``sequence``  an ordered chain of event filters with per-step time bounds.
``count``     at least N matching events inside a rolling window.

Rule matches are reported as findings with an operator-facing severity. They do
not change the anomaly score, and they are not verdicts: a match means the shape
occurred, not that the host is compromised.
"""
from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

from . import __version__
from .normalize import ALLOWED

RULES_FORMAT = "cabid-rules/1"
SEVERITIES = ("low", "medium", "high", "critical")
MAX_MATCHES_PER_RULE = 20
MAX_EVIDENCE_EVENTS = 8
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,63}$")

_STEP_KEYS = {
    "event_type", "process_name", "executable", "target", "same_process",
    "parent_executable", "within", "min_events",
}
_RULE_KEYS = {"id", "title", "description", "severity", "kind", "steps", "filter",
              "window", "min_count", "max_matches", "mitre", "enabled"}
_RULE_FILE_KEYS = {"$schema", "format", "name", "description", "rules", "provenance"}


class RuleError(ValueError):
    """Raised when a rule file is malformed or internally inconsistent."""


def _string_list(value: object, field: str) -> list[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise RuleError(f"{field} must be a string or a list of strings")
    items = [item.strip() for item in value if item.strip()]
    if not items:
        raise RuleError(f"{field} must not be empty")
    return items


def _validate_filter(raw: dict, where: str, allowed: set[str]) -> dict:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise RuleError(f"{where}: unknown keys: {', '.join(unknown)}")
    if "event_type" in raw:
        types = _string_list(raw["event_type"], f"{where}.event_type")
        bad = sorted(set(types) - ALLOWED)
        if bad:
            raise RuleError(f"{where}.event_type: unsupported: {', '.join(bad)}")
        raw["event_type"] = types
    for field in ("process_name", "executable", "target", "parent_executable"):
        if field in raw:
            raw[field] = _string_list(raw[field], f"{where}.{field}")
    if "within" in raw:
        try:
            within = float(raw["within"])
        except (TypeError, ValueError) as exc:
            raise RuleError(f"{where}.within must be a number") from exc
        if within <= 0:
            raise RuleError(f"{where}.within must be positive")
        raw["within"] = within
    if "min_events" in raw:
        if isinstance(raw["min_events"], bool) or not isinstance(raw["min_events"], int):
            raise RuleError(f"{where}.min_events must be an integer")
        if raw["min_events"] < 1:
            raise RuleError(f"{where}.min_events must be at least 1")
    if "same_process" in raw and not isinstance(raw["same_process"], bool):
        raise RuleError(f"{where}.same_process must be a boolean")
    return raw


def _validate_rule(raw: dict, index: int) -> dict:
    if not isinstance(raw, dict):
        raise RuleError(f"rule {index} must be an object")
    unknown = sorted(set(raw) - _RULE_KEYS)
    if unknown:
        raise RuleError(f"rule {index}: unknown keys: {', '.join(unknown)}")
    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not _ID_RE.match(rule_id):
        raise RuleError(f"rule {index}: id must match [a-z0-9][a-z0-9_-]{{1,63}}")
    rule: dict = {"id": rule_id}
    rule["title"] = str(raw.get("title") or rule_id.replace("-", " ").replace("_", " ")).strip()
    if not rule["title"]:
        raise RuleError(f"rule {rule_id}: title must not be empty")
    rule["description"] = str(raw.get("description") or "").strip()
    severity = str(raw.get("severity") or "medium").lower()
    if severity not in SEVERITIES:
        raise RuleError(f"rule {rule_id}: severity must be one of {', '.join(SEVERITIES)}")
    rule["severity"] = severity
    rule["mitre"] = str(raw.get("mitre") or "").strip()
    rule["enabled"] = bool(raw.get("enabled", True))
    max_matches = raw.get("max_matches", MAX_MATCHES_PER_RULE)
    if isinstance(max_matches, bool) or not isinstance(max_matches, int) or max_matches < 1:
        raise RuleError(f"rule {rule_id}: max_matches must be a positive integer")
    rule["max_matches"] = min(int(max_matches), 200)

    kind = str(raw.get("kind") or ("sequence" if "steps" in raw else "count")).lower()
    if kind not in {"sequence", "count"}:
        raise RuleError(f"rule {rule_id}: kind must be 'sequence' or 'count'")
    rule["kind"] = kind

    if kind == "sequence":
        steps = raw.get("steps")
        if not isinstance(steps, list) or len(steps) < 2:
            raise RuleError(f"rule {rule_id}: a sequence needs at least 2 steps")
        if "filter" in raw or "window" in raw or "min_count" in raw:
            raise RuleError(f"rule {rule_id}: sequence rules cannot use filter/window/min_count")
        rule["steps"] = [
            _validate_filter(dict(step), f"rule {rule_id} step {position}", _STEP_KEYS)
            for position, step in enumerate(steps)
        ]
        if "within" in rule["steps"][0]:
            raise RuleError(f"rule {rule_id}: the first step cannot set 'within'")
        if "min_events" in rule["steps"][0]:
            raise RuleError(f"rule {rule_id}: the first step cannot set 'min_events'")
    else:
        if "steps" in raw:
            raise RuleError(f"rule {rule_id}: count rules use 'filter', not 'steps'")
        if not isinstance(raw.get("filter"), dict):
            raise RuleError(f"rule {rule_id}: count rules need a 'filter' object")
        rule["filter"] = _validate_filter(dict(raw["filter"]), f"rule {rule_id} filter", _STEP_KEYS)
        try:
            window = float(raw.get("window", 60))
        except (TypeError, ValueError) as exc:
            raise RuleError(f"rule {rule_id}: window must be a number") from exc
        if window <= 0:
            raise RuleError(f"rule {rule_id}: window must be positive")
        rule["window"] = window
        min_count = raw.get("min_count", 5)
        if isinstance(min_count, bool) or not isinstance(min_count, int) or min_count < 1:
            raise RuleError(f"rule {rule_id}: min_count must be a positive integer")
        rule["min_count"] = min_count
    return rule


def load_rules(path: str | Path | None) -> list[dict]:
    """Load a rule file; ``None`` returns the built-in pack."""
    if path is None:
        return load_rules_from_dict({"rules": BUILTIN_RULES})
    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuleError(f"{source}: invalid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise RuleError(f"{source}: rule file must be a JSON object")
    unknown = sorted(set(raw) - _RULE_FILE_KEYS)
    if unknown:
        raise RuleError(f"{source}: unknown keys: {', '.join(unknown)}")
    declared = raw.get("format", RULES_FORMAT)
    if declared != RULES_FORMAT:
        raise RuleError(f"{source}: unsupported rule format: {declared}")
    return load_rules_from_dict(raw, origin=str(source))


def load_rules_from_dict(raw: dict, origin: str = "builtin") -> list[dict]:
    """Validate a rule document.

    A ``provenance`` block is carried through for imported rule packs (Sigma
    translation, vendor packs) and validated only for being an object; it has no
    effect on evaluation.
    """
    if "provenance" in raw and not isinstance(raw["provenance"], dict):
        raise RuleError(f"{origin}: provenance must be an object")
    rules = raw.get("rules")
    if not isinstance(rules, list) or not rules:
        raise RuleError(f"{origin}: 'rules' must be a non-empty list")
    validated = [_validate_rule(rule, index) for index, rule in enumerate(rules)]
    seen = set()
    for rule in validated:
        if rule["id"] in seen:
            raise RuleError(f"{origin}: duplicate rule id: {rule['id']}")
        seen.add(rule["id"])
    return [rule for rule in validated if rule["enabled"]]


#: Process-wide cache of translated glob patterns. Rule packs are re-evaluated on
#: every window, so the same few hundred patterns are translated thousands of times
#: per stream. ``fnmatch`` translates on every call; caching the translation is
#: semantics-preserving because ``fnmatch.translate`` is the same function it uses.
_GLOB_CACHE: dict[str, tuple[bool, str, re.Pattern[str] | None]] = {}


def _translate(pattern: str) -> tuple[bool, str, re.Pattern[str] | None]:
    """Split a pattern into (ends-with-star, literal prefix, regex-or-None).

    A literal pattern keeps its original text as the prefix so an exact match still
    compares against the whole value; the original implementation lowercased the
    value once and then reconstructed the literal, which compared a value against
    the wrong string.
    """
    lowered = pattern.lower()
    body = lowered[:-1] if lowered.endswith("*") else lowered
    needs_regex = any(character in body for character in "*?[")
    compiled = re.compile(fnmatch.translate(lowered)) if needs_regex else None
    return lowered.endswith("*"), body, compiled


def _glob_any(value: str, patterns: list[str]) -> bool:
    lowered = value.lower()
    for pattern in patterns:
        translated = _GLOB_CACHE.get(pattern)
        if translated is None:
            translated = _translate(pattern)
            if len(_GLOB_CACHE) < 4096:
                _GLOB_CACHE[pattern] = translated
        prefix_star, prefix, compiled = translated
        if prefix_star and lowered.startswith(prefix):
            return True
        if compiled is None:
            if lowered == prefix:
                return True
        elif compiled.match(lowered) is not None:
            return True
    return False


def _parent_labels(event: dict, by_pid: dict[int, dict]) -> list[str]:
    """Name and executable of the parent process, as far as this stream can tell.

    Looks up the parent's own event; a parent missing from the window matches
    nothing, so a rule can never fire on an unobserved parent. Both the name and
    the executable are offered because a translated Sigma rule may glob either.
    """
    parent_id = event.get("parent_process_id")
    parent = by_pid.get(parent_id) if isinstance(parent_id, int) else None
    if not parent:
        return []
    labels = [str(parent.get("process_name") or ""), str(parent.get("executable") or "")]
    return [label for label in labels if label]


def _matches(event: dict, step: dict, by_pid: dict[int, dict] | None = None) -> bool:
    if "event_type" in step and event["event_type"] not in step["event_type"]:
        return False
    if "process_name" in step and not _glob_any(str(event.get("process_name") or ""),
                                                step["process_name"]):
        return False
    if "executable" in step and not _glob_any(str(event.get("executable") or ""),
                                              step["executable"]):
        return False
    if "target" in step and not _glob_any(str(event.get("target") or ""), step["target"]):
        return False
    if "parent_executable" in step:
        labels = _parent_labels(event, by_pid or {})
        if not any(_glob_any(label, step["parent_executable"]) for label in labels):
            return False
    return True


def _evidence(events: list[dict], indices: list[int]) -> list[dict]:
    evidence = []
    for index in indices[:MAX_EVIDENCE_EVENTS]:
        event = events[index]
        evidence.append({
            "index": index,
            "timestamp": round(float(event["timestamp"]), 6),
            "event_type": event["event_type"],
            "process_id": event["process_id"],
            "process_name": str(event.get("process_name") or "unknown"),
            "target": str(event.get("target") or "")[:200],
        })
    return evidence


def _match_sequence(events: list[dict], rule: dict,
                    by_pid: dict[int, dict] | None = None) -> list[dict]:
    steps = rule["steps"]
    matches: list[dict] = []
    for start in range(len(events)):
        if not _matches(events[start], steps[0], by_pid):
            continue
        anchor_pid = events[start]["process_id"]
        indices = [start]
        last_timestamp = float(events[start]["timestamp"])
        failed = False
        for step in steps[1:]:
            found = None
            cursor = indices[-1] + 1
            while cursor < len(events):
                candidate = events[cursor]
                gap = float(candidate["timestamp"]) - last_timestamp
                if "within" in step and gap > step["within"]:
                    break
                if step.get("same_process") and candidate["process_id"] != anchor_pid:
                    cursor += 1
                    continue
                if _matches(candidate, step, by_pid):
                    found = cursor
                    break
                cursor += 1
            if found is None:
                failed = True
                break
            indices.append(found)
            last_timestamp = float(events[found]["timestamp"])
        if failed:
            continue
        if matches and matches[-1]["matched_steps"] == len(indices) and \
                abs(matches[-1]["start_timestamp"] - float(events[start]["timestamp"])) < 1e-6:
            continue
        matches.append({
            "rule_id": rule["id"],
            "kind": "sequence",
            "severity": rule["severity"],
            "title": rule["title"],
            "description": rule["description"],
            "mitre": rule["mitre"],
            "matched_steps": len(indices),
            "start_timestamp": round(float(events[start]["timestamp"]), 6),
            "duration_seconds": round(last_timestamp - float(events[start]["timestamp"]), 6),
            "process_ids": sorted({events[index]["process_id"] for index in indices}),
            "evidence": _evidence(events, indices),
        })
        if len(matches) >= rule.get("max_matches", MAX_MATCHES_PER_RULE):
            break
    return matches


def _match_count(events: list[dict], rule: dict,
                 by_pid: dict[int, dict] | None = None) -> list[dict]:
    """Report one finding per burst, not per event inside a burst.

    A burst is a maximal run of matching events in which consecutive matches are
    no more than ``window`` seconds apart. Using consecutive gaps (rather than
    "N events within window of the first") keeps a steady stream from producing a
    finding at every sample while still splitting genuinely separate bursts.
    """
    filter_step = rule["filter"]
    window = rule["window"]
    needed = rule["min_count"]
    matching = [index for index, event in enumerate(events)
                if _matches(event, filter_step, by_pid)]
    bursts: list[list[int]] = []
    for index in matching:
        if bursts and float(events[index]["timestamp"]) - float(
                events[bursts[-1][-1]]["timestamp"]) <= window:
            bursts[-1].append(index)
        else:
            bursts.append([index])
    matches: list[dict] = []
    for bucket in bursts:
        if len(bucket) < needed:
            continue
        start_time = float(events[bucket[0]]["timestamp"])
        matches.append({
            "rule_id": rule["id"],
            "kind": "count",
            "severity": rule["severity"],
            "title": rule["title"],
            "description": rule["description"],
            "mitre": rule["mitre"],
            "matched_steps": len(bucket),
            "start_timestamp": round(start_time, 6),
            "duration_seconds": round(float(events[bucket[-1]]["timestamp"]) - start_time, 6),
            "process_ids": sorted({events[i]["process_id"] for i in bucket}),
            "evidence": _evidence(events, bucket),
        })
        if len(matches) >= rule.get("max_matches", MAX_MATCHES_PER_RULE):
            break
    return matches


def evaluate_rules(events: list[dict], rules: list[dict]) -> dict:
    """Evaluate every enabled rule against timestamp-sorted events."""
    ordered = sorted(events, key=lambda item: (float(item["timestamp"]), item["process_id"]))
    # Parent lookups for steps that constrain the parent process.
    by_pid: dict[int, dict] = {}
    for event in ordered:
        by_pid.setdefault(event["process_id"], event)
    findings = []
    per_rule = []
    for rule in rules:
        if rule["kind"] == "sequence":
            matches = _match_sequence(ordered, rule, by_pid)
        else:
            matches = _match_count(ordered, rule, by_pid)
        per_rule.append({"rule_id": rule["id"], "kind": rule["kind"], "matches": len(matches),
                         "enabled": True, "severity": rule["severity"]})
        findings.extend(matches)
    # SEVERITIES is ascending, so rank must be reversed for worst-first ordering.
    order = {severity: rank for rank, severity in enumerate(reversed(SEVERITIES))}
    findings.sort(key=lambda item: (order.get(item["severity"], 9), item["start_timestamp"]))
    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity_counts[finding["severity"]] = severity_counts.get(finding["severity"], 0) + 1
    return {
        "engine": f"cabid-rules {RULES_FORMAT}",
        "cabid_version": __version__,
        "rule_count": len(rules),
        "matched_rule_count": sum(1 for item in per_rule if item["matches"]),
        "finding_count": len(findings),
        "severity_counts": dict(sorted(severity_counts.items())),
        "findings": findings,
        "rules": per_rule,
        "semantics": "pattern matches describe observed shape; they are not verdicts or attributions",
    }


BUILTIN_RULES: list[dict] = [
    {
        "id": "shell-from-service",
        "title": "Service process spawned a shell",
        "description": "A network-facing daemon started an interactive shell shortly after. "
                       "Commonly abuse, but also produced by CGI handlers and admin tooling.",
        "severity": "high",
        "mitre": "hint: T1059 command and scripting interpreter",
        "steps": [
            {"event_type": ["process_start", "process_exec"],
             "process_name": ["nginx", "apache2", "httpd", "sshd", "postfix", "mysqld",
                              "postgres", "redis-server", "dockerd", "node", "java", "tomcat"]},
            {"event_type": ["process_exec", "process_start"],
             "process_name": ["bash", "sh", "dash", "zsh", "python", "python3", "perl", "ruby"],
             "within": 30},
        ],
    },
    {
        "id": "download-then-exec",
        "title": "Execution after a network fetch",
        "description": "An egress-capable tool ran before a new process was executed.",
        "severity": "high",
        "mitre": "hint: T1105 ingress tool transfer",
        "steps": [
            {"event_type": ["network_connect", "process_exec"],
             "executable": ["*/curl", "*/wget", "*/nc", "*/socat", "*python*"]},
            {"event_type": ["process_exec", "process_start"],
             "executable": ["/tmp/*", "/var/tmp/*", "/dev/shm/*", "*/.*"],
             "within": 120},
        ],
    },
    {
        "id": "sensitive-write-then-egress",
        "title": "Sensitive write followed by egress",
        "description": "A write to a policy-sensitive path was followed by an outbound connection.",
        "severity": "critical",
        "mitre": "hint: T1567 exfiltration over web service",
        "steps": [
            {"event_type": "file_write", "target": ["/etc/shadow", "/etc/sudoers", "/etc/ssh/*",
                                                    "/root/*", "*/secrets*", "*id_rsa*"]},
            {"event_type": "network_connect", "within": 300},
        ],
    },
    {
        "id": "rapid-restart-loop",
        "title": "Repeated starts of one process",
        "description": "A process started many times inside a short window, which looks like a "
                       "crash loop or automated re-execution.",
        "severity": "medium",
        "kind": "count",
        "filter": {"event_type": "process_start"},
        "window": 10,
        "min_count": 12,
    },
    {
        "id": "privilege-escalation-to-exec",
        "title": "Privilege change followed by execution",
        "description": "A successful setuid-family call was followed by executing a binary from a "
                       "writable path. Legitimate sudo use usually execs from /usr or /bin.",
        "severity": "critical",
        "mitre": "hint: T1548 abuse elevation control mechanism",
        "steps": [
            {"event_type": "privilege_change"},
            {"event_type": "process_exec",
             "executable": ["/tmp/*", "/var/tmp/*", "/dev/shm/*", "/home/*"],
             "within": 60},
        ],
    },
    {
        "id": "ptrace-then-credential-read",
        "title": "ptrace followed by credential file access",
        "description": "A traced-attach call preceded a write-capable open of a credential file. "
                       "Debuggers and some profilers produce the first step legitimately.",
        "severity": "critical",
        "mitre": "hint: T1003 OS credential dumping",
        "steps": [
            {"event_type": "kernel_state_change", "target": ["ptrace*"]},
            {"event_type": ["file_write", "permission_change"],
             "target": ["/etc/shadow", "/etc/gshadow", "*id_rsa*", "*/secrets*"],
             "within": 120},
        ],
    },
    {
        "id": "permission-relaxed-on-credential",
        "title": "Permissions changed on a credential file",
        "description": "A chmod/chown call targeted a credential path. Commonly misconfiguration, "
                       "occasionally preparation for exfiltration.",
        "severity": "high",
        "steps": [
            # The chmod that causes a permission_change is logged *before* it, so
            # the exec has to come first or this rule can never match.
            {"event_type": "process_exec",
             "executable": ["/bin/chmod", "/usr/bin/chmod", "/bin/chown", "/usr/bin/chown",
                            "/usr/bin/setfacl", "/bin/chattr", "/usr/bin/chattr"]},
            {"event_type": "permission_change",
             "target": ["/etc/shadow", "/etc/gshadow", "/etc/sudoers", "*/id_rsa*"],
             "within": 30},
        ],
    },
    {
        "id": "kernel-state-then-persistence",
        "title": "Kernel state change followed by persistence write",
        "description": "mount/umount2/ptrace was followed by a write to a startup or cron path.",
        "severity": "critical",
        "mitre": "hint: T1543 create or modify system process",
        "steps": [
            {"event_type": "kernel_state_change",
             "target": ["mount*", "ptrace*", "pivot_root*", "umount2*"]},
            {"event_type": "file_write",
             "target": ["/etc/cron*", "/etc/rc.local", "/etc/systemd/system/*",
                        "/etc/ld.so.preload", "/var/spool/cron/*"],
             "within": 300},
        ],
    },
    {
        "id": "bulk-accept-then-exec",
        "title": "Burst of inbound connections before execution",
        "description": "Many accepts followed by a new process may indicate exploitation of a "
                       "network service; it also matches ordinary request bursts.",
        "severity": "medium",
        "kind": "count",
        "filter": {"event_type": "network_accept"},
        "window": 30,
        "min_count": 20,
    },
    {
        "id": "exit-then-activity",
        "title": "Activity after exit",
        "description": "File or network activity attributed to a process after its observed exit.",
        "severity": "high",
        "steps": [
            {"event_type": "process_exit"},
            {"event_type": ["file_write", "network_connect"], "same_process": True, "within": 60},
        ],
    },
]
