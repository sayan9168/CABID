"""What CABID can actually see, derived from the artifacts rather than asserted.

A coverage table that is typed by hand rots the moment a rule changes. This module
builds it from the loaded rule pack, the completeness configuration, and the
policy defaults, so the report cannot claim a class is covered when no rule and no
component references it.

Three things are deliberately separated:

1. **Visibility** — which event classes exist, which the completeness gate
   requires, and which a sensor actually observed.
2. **Reachability** — which rules can even fire given the observed classes. A rule
   that needs ``privilege_change`` cannot fire on a sensor that never emits it,
   and that is a blind spot, not a silent zero.
3. **Mapping** — which ATT&CK techniques the pack hints at. A hint is a label on a
   pattern, not evidence that the technique would be detected in the wild.

The report therefore answers "what could this deployment notice?" and explicitly
refuses to answer "how much of ATT&CK do you detect?".
"""
from __future__ import annotations

import re

from . import __version__
from .config import default_config, validate_config
from .normalize import ALLOWED, CORE_EVENT_TYPES, OPTIONAL_EVENT_TYPES
from .policy import load_policy
from .rules import load_rules

FORMAT = "cabid-coverage/1"
# Heartbeat is a liveness marker, not a behaviour: no rule should fire on it, so its
# absence from the rule pack is not counted as a gap.
BEHAVIOURAL_CLASSES = ALLOWED - {"heartbeat"}
_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# What each weighted component needs from the telemetry, and how it fails. These
# are descriptions of the implementation, not measurements.
COMPONENTS = (
    {"component": "temporal", "depends_on": ["timestamp"],
     "event_classes": [],
     "blind_spot": "a slow, steady intrusion looks like routine traffic; rate is a "
                   "shape, not an intent"},
    {"component": "causal", "depends_on": ["process_id", "parent_process_id"],
     "event_classes": [],
     "blind_spot": "only self-parent references are scored; a missing parent is "
                   "treated as a window boundary"},
    {"component": "sequence", "depends_on": ["process_id", "event_type"],
     "event_classes": ["process_start", "process_exit"],
     "blind_spot": "contradictions inside one window; a process that starts before "
                   "the window is not flagged"},
    {"component": "telemetry_gap", "depends_on": ["event_type"],
     "event_classes": sorted(CORE_EVENT_TYPES),
     "blind_spot": "class presence is not class quality: a sensor can emit "
                   "heartbeats while dropping file events"},
    {"component": "novelty", "depends_on": ["process_name", "executable"],
     "event_classes": [],
     "blind_spot": "only as good as the benign labels in the baseline; a "
                   "contaminated baseline hides the attack"},
)


class CoverageError(ValueError):
    """Raised when coverage cannot be computed from the supplied artifacts."""


def _required_classes(rule: dict) -> list[str]:
    filters = [step for step in rule.get("steps") or []]
    if rule.get("filter"):
        filters = filters + [rule["filter"]]
    required = set()
    for step in filters:
        for event_type in step.get("event_type") or []:
            required.add(str(event_type))
    return sorted(required)


def _techniques(rule: dict) -> list[str]:
    return sorted(set(_TECHNIQUE_RE.findall(str(rule.get("mitre") or ""))))


def analyse_coverage(rules: list[dict] | None = None,
                     policy: dict | None = None,
                     config: dict | None = None,
                     observed_classes: set[str] | None = None,
                     profile: dict | None = None) -> dict:
    """Build the coverage matrix from the real rule pack, policy, and config."""
    active_rules = load_rules(None) if rules is None else rules
    if not isinstance(active_rules, list):
        raise CoverageError("rules must be a list of loaded rule dicts")
    active_policy = load_policy(None) if policy is None else policy
    cfg = validate_config(config or {})
    completeness = cfg.get("completeness") or default_config()["completeness"]
    required_by_gate = sorted(set(completeness.get("expected_event_types") or []))

    observed = None
    if observed_classes is not None:
        unknown = sorted({str(item) for item in observed_classes} - ALLOWED)
        if unknown:
            raise CoverageError(
                "observed event classes not in the schema: " + ", ".join(unknown))
        observed = {str(item) for item in observed_classes}

    rule_rows = []
    per_class: dict[str, list[str]] = {event_type: [] for event_type in sorted(ALLOWED)}
    techniques: dict[str, list[str]] = {}
    rules_without_technique: list[str] = []
    for rule in active_rules:
        requires = _required_classes(rule)
        for event_type in requires:
            per_class[event_type].append(rule["id"])
        found = _techniques(rule)
        for technique in found:
            techniques.setdefault(technique, []).append(rule["id"])
        if not found:
            rules_without_technique.append(rule["id"])
        reachable = None
        if observed is not None:
            reachable = all(event_type in observed for event_type in requires)
        rule_rows.append({
            "rule_id": rule["id"],
            "severity": rule.get("severity", "medium"),
            "kind": rule.get("kind", "sequence"),
            "requires_event_types": requires,
            "mitre_hints": found,
            "reachable": reachable,
        })

    classes_without_rules = sorted(event_type for event_type, ids in per_class.items()
                                   if not ids and event_type in BEHAVIOURAL_CLASSES)
    optional_not_gated = sorted(set(OPTIONAL_EVENT_TYPES) - set(required_by_gate))
    unreachable = sorted(row["rule_id"] for row in rule_rows if row["reachable"] is False)

    policy_block: dict[str, object] = {
        "sensitive_path_patterns": len(active_policy.get("sensitive_paths") or []),
        "sensitive_ports": list(active_policy.get("sensitive_ports") or []),
        "allow_listed_process_names": len(active_policy.get("allow_process_names") or []),
        "suppressed_reason_codes": list(active_policy.get("suppress_rule_codes") or []),
        "scoped_suppressions": len(active_policy.get("suppress_for_processes") or {}),
        "note": "policy findings are operator-defined; a suppressed code is hidden "
                "from the report, not from the score",
    }

    baseline_block: dict[str, object] = {"present": profile is not None}
    if profile is not None:
        baseline_block.update({
            "session_count": profile.get("session_count"),
            "process_names": len(profile.get("process_names") or []),
            "executables": len(profile.get("executables") or []),
            "note": "novelty is only as broad as the baseline's process and executable sets",
        })
    else:
        baseline_block["note"] = ("no baseline supplied: the novelty component is inactive "
                                  "and its weight is redistributed at scoring time")

    gaps: dict[str, object] = {
        "classes_without_rules": classes_without_rules,
        "optional_classes_not_gated": optional_not_gated,
        "rules_unreachable_from_observed": unreachable,
        "rules_without_mitre_hint": sorted(rules_without_technique),
    }
    if observed is not None:
        gaps["observed_classes_missing_but_required"] = sorted(
            set(required_by_gate) - observed)
    gaps["has_gaps"] = bool(classes_without_rules or unreachable)

    return {
        "format": FORMAT,
        "cabid_version": __version__,
        "event_classes": {
            "core": sorted(CORE_EVENT_TYPES),
            "optional": sorted(OPTIONAL_EVENT_TYPES),
            "required_by_completeness_gate": required_by_gate,
            "observed": sorted(observed) if observed is not None else None,
        },
        "rules": rule_rows,
        "rule_count": len(rule_rows),
        "classes_to_rules": {event_type: ids for event_type, ids in per_class.items()},
        "techniques": {technique: sorted(ids)
                       for technique, ids in sorted(techniques.items())},
        "technique_count": len(techniques),
        "components": [dict(item) for item in COMPONENTS],
        "policy": policy_block,
        "baseline": baseline_block,
        "gaps": gaps,
        "semantics": ("coverage means a rule or component references an event class; it is "
                      "not validation that the rule fires correctly, and ATT&CK hints are "
                      "labels on patterns, not measured detection of techniques"),
        "caveats": [
            "A rule that can fire is not a rule that has been tested against real attacks.",
            "Classes with no rule are not uncovered by definition: policy findings and the "
            "weighted components also consume them.",
            "Reachability is computed against the classes you supplied, not against what the "
            "sensor promised to deliver.",
            "No mapping to ATT&CK is a claim about detection breadth; hints are suggestions "
            "written by the rule author.",
        ],
    }


def has_gaps(report: dict) -> bool:
    """True when a class or a rule is unreachable — used by ``--fail-on-gap``."""
    return bool((report.get("gaps") or {}).get("has_gaps"))


def render_markdown(report: dict) -> str:
    """Markdown coverage matrix for a review document."""
    lines = ["# CABID coverage", ""]
    lines.append(f"> {report['semantics']}")
    lines.append("")
    classes = report["event_classes"]
    lines += ["## Event classes", "", "| Class | Kind | Required by gate | Rules |",
              "| --- | --- | --- | --- |"]
    for event_type in sorted(classes["core"] + classes["optional"]):
        kind = "core" if event_type in classes["core"] else "optional"
        gated = "yes" if event_type in classes["required_by_completeness_gate"] else "no"
        ids = report["classes_to_rules"].get(event_type) or []
        lines.append(f"| {event_type} | {kind} | {gated} | "
                     f"{', '.join(ids) if ids else '—'} |")
    if classes["observed"] is not None:
        lines += ["", f"Observed in the supplied events: "
                      f"{', '.join(classes['observed']) or 'none'}."]
    lines += ["", "## Rules", "", "| Rule | Severity | Kind | Requires | ATT&CK hint | Reachable |",
              "| --- | --- | --- | --- | --- | --- |"]
    for row in report["rules"]:
        reachable = "unknown" if row["reachable"] is None else (
            "yes" if row["reachable"] else "no")
        lines.append(f"| {row['rule_id']} | {row['severity']} | {row['kind']} | "
                     f"{', '.join(row['requires_event_types']) or '—'} | "
                     f"{', '.join(row['mitre_hints']) or '—'} | {reachable} |")
    lines += ["", "## Techniques the pack hints at", ""]
    if report["techniques"]:
        lines += ["| Technique | Rules |", "| --- | --- |"]
        for technique, ids in report["techniques"].items():
            lines.append(f"| {technique} | {', '.join(ids)} |")
    else:
        lines.append("None: no loaded rule carries a technique hint.")
    lines += ["", "## Components", "",
              "| Component | Depends on | Known blind spot |", "| --- | --- | --- |"]
    for component in report["components"]:
        lines.append(f"| {component['component']} | {', '.join(component['depends_on'])} | "
                     f"{component['blind_spot']} |")
    lines += ["", "## Gaps", ""]
    gaps = report["gaps"]
    lines.append(f"- Classes no rule references: "
                 f"{', '.join(gaps['classes_without_rules']) or 'none'}")
    lines.append(f"- Optional classes not gated by completeness: "
                 f"{', '.join(gaps['optional_classes_not_gated']) or 'none'}")
    lines.append(f"- Rules without an ATT&CK hint: "
                 f"{', '.join(gaps['rules_without_mitre_hint']) or 'none'}")
    if "rules_unreachable_from_observed" in gaps:
        lines.append("- Rules unreachable from the observed classes: "
                     f"{', '.join(gaps['rules_unreachable_from_observed']) or 'none'}")
    if "observed_classes_missing_but_required" in gaps:
        lines.append("- Required classes the events never contained: "
                     f"{', '.join(gaps['observed_classes_missing_but_required']) or 'none'}")
    baseline = report["baseline"]
    lines += ["", "## Baseline", "", baseline["note"]]
    if baseline.get("present"):
        lines.append(f"Baseline: {baseline.get('session_count')} sessions, "
                     f"{baseline.get('process_names')} process names, "
                     f"{baseline.get('executables')} executables.")
    lines += ["", "## Caveats", ""]
    lines += [f"- {caveat}" for caveat in report["caveats"]]
    return "\n".join(lines) + "\n"


def observed_classes_from_events(events: list[dict]) -> set[str]:
    """Event classes present in a normalized event list."""
    return {str(event.get("event_type")) for event in events if event.get("event_type")}


__all__ = ["FORMAT", "BEHAVIOURAL_CLASSES", "CoverageError", "analyse_coverage", "has_gaps",
           "observed_classes_from_events", "render_markdown"]
