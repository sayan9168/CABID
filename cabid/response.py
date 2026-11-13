"""Response planning: turn findings into a containment plan, with the brakes on.

CABID does not block anything by itself, and this module exists to explain why
that is a design decision rather than a missing feature.

An automated blocker driven by a heuristic score will, on any busy host, eventually
kill the wrong process — the score is a triage hint, not a probability. Worse, the
failure is adversarial: an attacker who learns which shapes trigger containment
does not need to defeat the detector, only to *emit* those shapes at a target of
their choosing. Spawn a pattern next to a rival service and the defender kills it
for you. That is a known, cheap attack on automated response, and a heuristic
detector is the worst possible thing to arm with it.

So the pipeline here is:

    report -> evidence per target -> kill-chain phases -> gates -> plan
                                                              |
                                              `cabid respond --apply`
                                              (explicit, audited, verified)

Three properties matter and are enforced in code, not just documented:

1. **Destructive actions require corroboration, not a high score.** A single rule
   match is never enough. The evidence must span more than one kill-chain phase.
2. **Destructive actions require sufficient telemetry.** Acting on a stream that is
   missing event classes means acting on a partial picture. The plan refuses and
   says which classes were missing.
3. **Every plan carries its own blast radius and its alternative.** If the plan
   cannot state what it would break, it is not ready to run.

The executor is deliberately small, lives in :mod:`cabid.executor`, and can only do
things that are reversible or locally verifiable. Network changes are emitted as
commands for a human or a sandboxed runner, never executed here.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from . import __version__

RESPONSE_FORMAT = "cabid-response/1"

# --------------------------------------------------------------------------
# Action catalogue. `destructive` means "the state cannot be put back exactly".
# `blast_radius` is what the operator loses if this was a false positive.
# --------------------------------------------------------------------------
ACTIONS: dict[str, dict] = {
    "monitor": {
        "destructive": False,
        "reversible": True,
        "blast_radius": "none; analysis continues unchanged",
        "executor": "none",
    },
    "snapshot": {
        "destructive": False,
        "reversible": True,
        "blast_radius": "disk space for captured evidence; the system is not touched",
        "executor": "cabid-exec://capture",
    },
    "suspend_process": {
        "destructive": False,
        "reversible": True,
        "blast_radius": "the process stops making progress until resumed with SIGCONT",
        "executor": "cabid-exec://signal/SIGSTOP",
    },
    "kill_process": {
        "destructive": True,
        "reversible": False,
        "blast_radius": "in-memory state is lost; a restarted service may re-earn trust",
        "executor": "cabid-exec://signal/SIGKILL",
    },
    "quarantine_file": {
        # A copy, not a move: the original stays readable, so nothing is lost and
        # the operator can undo this by deleting the copy.
        "destructive": False,
        "reversible": True,
        "blast_radius": "a copy is written to the quarantine directory; the original is untouched",
        "executor": "cabid-exec://quarantine",
    },
    "isolate_host": {
        "destructive": True,
        "reversible": False,
        "blast_radius": "all connectivity drops, including management access and health checks",
        "executor": "emit-command-only",
    },
    "block_address": {
        "destructive": True,
        "reversible": False,
        "blast_radius": "shared NAT, proxies, and CDNs can make this block unrelated traffic",
        "executor": "emit-command-only",
    },
    "disable_account": {
        "destructive": True,
        "reversible": False,
        "blast_radius": "every session and automation using that account stops working",
        "executor": "emit-command-only",
    },
}

# Actions that never fabricate evidence of an attack: they observe.
OBSERVE_ONLY = ("monitor", "snapshot")

# Escalation ladder. Selection always picks the *lowest* rung that addresses the
# observed phases; the gates only decide how high the ladder may be climbed.
# Suspension sits below killing on purpose: SIGSTOP stops the activity and leaves
# the memory image intact, which is exactly what an investigation needs.
SEVERITY = {
    "monitor": 0,
    "snapshot": 1,
    "suspend_process": 2,
    "quarantine_file": 3,
    "kill_process": 4,
    "block_address": 5,
    "isolate_host": 6,
    "disable_account": 6,
}

# --------------------------------------------------------------------------
# Kill-chain phases. Coarse on purpose: a fine-grained taxonomy invites
# over-confident mapping, and this is a mapping of *observed shapes*, not intent.
# --------------------------------------------------------------------------
PHASES = (
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "exfiltration",
    "impact",
)

PHASE_LABELS = {
    "initial_access": "initial access",
    "execution": "execution",
    "persistence": "persistence",
    "privilege_escalation": "privilege escalation",
    "defense_evasion": "defense evasion",
    "credential_access": "credential access",
    "discovery": "discovery",
    "lateral_movement": "lateral movement",
    "exfiltration": "exfiltration",
    "impact": "impact",
}

# Rule id -> phase. These are read off the built-in pack's shapes.
_RULE_PHASES = {
    "shell-from-service": "initial_access",
    "download-then-exec": "execution",
    "privilege-escalation-to-exec": "privilege_escalation",
    "ptrace-then-credential-read": "credential_access",
    "permission-relaxed-on-credential": "defense_evasion",
    "kernel-state-then-persistence": "persistence",
    "bulk-accept-then-exec": "discovery",
    "sensitive-write-then-egress": "exfiltration",
    "exit-then-activity": "defense_evasion",
    "rapid-restart-loop": "impact",
}

# Tree finding kinds that carry a phase.
_TREE_PHASES = {
    "interpreter_spawn": "execution",
    "ancestry_cycle": "defense_evasion",
    "deep_chain": "execution",
    "baseline_edge_drift": "execution",
    "orphan_root": "discovery",
}

# Event-level phase evidence, used when no rule fired but the raw shapes are there.
_EVENT_PHASES = {
    "privilege_change": "privilege_escalation",
    "kernel_state_change": "defense_evasion",
    "permission_change": "defense_evasion",
    "network_accept": "discovery",
}

_CREDENTIAL_PATHS = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "id_rsa", "id_ed25519")
_PERSISTENCE_PATHS = ("/etc/cron", "/var/spool/cron", "/etc/systemd", "/etc/rc.local",
                      "/etc/ld.so.preload", "/etc/profile.d")
_STAGING_PATHS = ("/tmp/", "/var/tmp/", "/dev/shm/")

# Never contain these automatically, whatever the evidence says. A defender that
# can be made to kill sshd has handed over the host.
_PROTECTED_NAMES = {"systemd", "init", "sshd", "sshd-session", "auditd", "cron", "crond",
                    "dbus-daemon", "udevd", "systemd-journald", "dockerd", "containerd"}

MIN_CONFIRMATIONS_FOR_DESTRUCTIVE = 2      # distinct phases
MAX_KILLS_PER_PLAN = 3                     # a plan that kills more is a human decision
KILL_LOOP_WINDOW_SECONDS = 600.0
KILL_LOOP_THRESHOLD = 3


class ResponseError(ValueError):
    """Raised when a response plan cannot be built or trusted."""


def _norm(path: str) -> str:
    return str(path or "").strip().lower()


def _matches_any(value: str, needles: tuple[str, ...]) -> bool:
    haystack = _norm(value)
    return any(needle.lower() in haystack for needle in needles)


def _phase_evidence(report: dict) -> dict[int, dict[str, list[str]]]:
    """Collect phase evidence per pid from rules, tree, events, and policy.

    Every entry keeps the source that produced it, because a plan is read by a
    human who needs to know whether a phase came from a rule match, a structural
    finding, or a raw event class.
    """
    evidence: dict[int, dict[str, list[str]]] = {}

    def add(pid: object, phase: str, note: str) -> None:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            return
        bucket = evidence.setdefault(pid, {}).setdefault(phase, [])
        if note not in bucket:
            bucket.append(note)

    for finding in (report.get("rules") or {}).get("findings") or []:
        rule_id = str(finding.get("rule_id") or "")
        phase = _RULE_PHASES.get(rule_id)
        if not phase:
            continue
        note = f"rule {rule_id} ({finding.get('severity')})"
        for pid in finding.get("process_ids") or []:
            add(pid, phase, note)

    for finding in (report.get("tree") or {}).get("findings") or []:
        phase = _TREE_PHASES.get(str(finding.get("kind") or ""))
        if not phase:
            continue
        note = f"tree {finding.get('kind')}"
        add(finding.get("child_pid"), phase, note)
        add(finding.get("parent_pid"), phase, note)

    for entity in (report.get("entities") or {}).get("top_entities") or []:
        pid = entity.get("process_id")
        for reference in entity.get("sensitive_refs") or []:
            text = str(reference)
            if _matches_any(text, _CREDENTIAL_PATHS):
                add(pid, "credential_access", f"sensitive reference {text[:80]}")
            if _matches_any(text, _PERSISTENCE_PATHS):
                add(pid, "persistence", f"persistence path {text[:80]}")
        for kind in entity.get("event_types") or []:
            phase = _EVENT_PHASES.get(str(kind))
            if phase:
                add(pid, phase, f"observed {kind}")
        for executable in entity.get("executables") or []:
            if _matches_any(str(executable), _STAGING_PATHS):
                add(pid, "execution", f"executed from a writable path: {str(executable)[:80]}")

    for finding in (report.get("policy") or {}).get("findings") or []:
        pid = finding.get("process_id")
        target = str(finding.get("target") or "")
        if _matches_any(target, _CREDENTIAL_PATHS):
            add(pid, "credential_access", f"policy hit on {target[:80]}")
        elif _matches_any(target, _PERSISTENCE_PATHS):
            add(pid, "persistence", f"policy hit on {target[:80]}")

    return evidence


def _chain_strength(phases: list[str]) -> str:
    """How much the observed phases hang together as an incident.

    Three phases is the useful threshold. Two can be coincidence on a busy host —
    a deploy does execution and persistence. Three spanning escalation, credential
    access, or exfiltration is much harder to reach by accident.
    """
    if not phases:
        return "none"
    if len(phases) == 1:
        return "single_signal"
    if len(phases) == 2:
        return "corroborated"
    return "strong"


def _protected(entity: dict, tree_roots: set[str]) -> dict | None:
    """Refuse to contain infrastructure. Returns a reason when protected."""
    names = {_norm(name) for name in entity.get("process_names") or []}
    if names & _PROTECTED_NAMES:
        return {"reason": "protected_process",
                "detail": f"{sorted(names & _PROTECTED_NAMES)} is infrastructure; "
                          "containing it is an outage, not a response"}
    if entity.get("process_id") == 1:
        return {"reason": "pid_1", "detail": "pid 1 cannot be killed without stopping the host"}
    if names & tree_roots:
        return {"reason": "tree_root",
                "detail": "this process is the root of the observed tree; "
                          "containing it hides the activity beneath it"}
    return None


def _select(phases: list[str], strength: str, allowed: tuple[str, ...], ceiling: int) -> str:
    """Pick the lowest-severity allowed action that addresses the phases.

    ``ceiling`` is the highest severity the gates permit. Everything above it is
    filtered out before a choice is made, so a destructive action can only appear
    in a plan that already cleared every gate.

    Suspension is preferred over killing whenever both are permitted. Killing is
    only reached when suspension is not allowed, or when the observed phases say
    something is being actively destroyed and stopping it cannot wait for the
    memory image to be useful.
    """
    ladder = [action for action in allowed
              if action in SEVERITY and SEVERITY[action] <= ceiling]
    if not ladder:
        return "monitor"
    ladder.sort(key=lambda action: SEVERITY[action])

    if strength == "single_signal":
        # One phase is routinely ordinary work. Cap the ladder at observation.
        return next((a for a in ladder if a in OBSERVE_ONLY), "monitor")
    if strength == "none":
        return "monitor"
    if "impact" in phases and "kill_process" in ladder and "suspend_process" not in ladder:
        return "kill_process"
    for action in ("suspend_process", "quarantine_file", "kill_process"):
        if action in ladder:
            return action
    # Nothing above observation is permitted, so climb as high as observation goes:
    # snapshot before monitor, because capturing evidence is the useful half of
    # "we cannot safely act yet".
    for action in ("snapshot", "monitor"):
        if action in ladder:
            return action
    return "monitor"


def _digest(payload: dict) -> str:
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def build_plan(report: dict, allowed_actions: tuple[str, ...] | None = None,
               max_actions: int = MAX_KILLS_PER_PLAN,
               known_containments: list[dict] | None = None) -> dict:
    """Build a containment plan from one analysis report.

    ``allowed_actions`` narrows what the plan may recommend; it can only ever make
    the plan more conservative. ``known_containments`` is prior history (pid,
    action, timestamp) used to detect a containment loop — the signature of an
    attacker using the defender as a weapon.
    """
    if not isinstance(report, dict):
        raise ResponseError("a report object is required")
    allowed = tuple(allowed_actions) if allowed_actions else tuple(ACTIONS)
    unknown = sorted(set(allowed) - set(ACTIONS))
    if unknown:
        raise ResponseError(f"unknown actions: {', '.join(unknown)}")

    completeness = report.get("completeness") or {}
    sufficient = bool(completeness.get("telemetry_sufficient"))
    missing = list(completeness.get("missing_event_types") or [])
    status = str(report.get("status") or "")
    score = float(report.get("anomaly_score") or 0.0)

    evidence = _phase_evidence(report)
    entities_by_pid = {
        entity.get("process_id"): entity
        for entity in (report.get("entities") or {}).get("top_entities") or []
    }
    # A root is a process that is a parent but never a child in the observed
    # edges. Collecting every parent would block half the tree.
    edges = (report.get("tree") or {}).get("common_edges") or []
    parents = {str(edge.get("parent") or "") for edge in edges} - {""}
    children = {str(edge.get("child") or "") for edge in edges} - {""}
    tree_roots = parents - children

    # Prior containments, for loop detection.
    history: dict[int, list[float]] = {}
    for record in known_containments or []:
        pid = record.get("process_id")
        stamp = record.get("timestamp")
        if isinstance(pid, int) and isinstance(stamp, (int, float)):
            history.setdefault(pid, []).append(float(stamp))

    chains, decisions, refusals = [], [], []
    # The budget counts anything that takes a process down, not only the
    # irreversible things. Suspending a service is an outage for as long as it lasts.
    intrusive_used = 0

    for pid in sorted(evidence, key=lambda item: (
            -len(evidence[item]), -sum(len(v) for v in evidence[item].values()))):
        phases = sorted(evidence[pid])
        strength = _chain_strength(phases)
        entity = entities_by_pid.get(pid) or {"process_id": pid, "process_names": [],
                                              "event_count": 0, "entity_risk": 0.0,
                                              "sensitive_refs": []}
        chain = {
            "process_id": pid,
            "process_names": list(entity.get("process_names") or []),
            "entity_risk": entity.get("entity_risk"),
            "phases": [{"phase": phase, "label": PHASE_LABELS[phase],
                        "evidence": evidence[pid][phase]}
                       for phase in phases],
            "phase_count": len(phases),
            "chain_strength": strength,
            "interpretation": _interpret(strength, phases),
        }
        chains.append(chain)

        # ---- gates, in order; the first failure stops the destructive path ----
        blocked_by: list[dict] = []
        protection = _protected(entity, tree_roots)
        if protection:
            blocked_by.append(protection)

        recent = [stamp for stamp in history.get(pid, [])
                  if float(report.get("event_count") or 0) >= 0 and stamp]
        if len(recent) >= KILL_LOOP_THRESHOLD:
            blocked_by.append({
                "reason": "containment_loop",
                "detail": f"this pid has already been contained {len(recent)} times; "
                          "containing it again is how an attacker converts the defender "
                          "into an outage — escalate to a human instead",
            })

        if len(phases) < MIN_CONFIRMATIONS_FOR_DESTRUCTIVE:
            blocked_by.append({
                "reason": "single_phase",
                "detail": f"{len(phases)} kill-chain phase observed; "
                          f"{MIN_CONFIRMATIONS_FOR_DESTRUCTIVE} independent phases are "
                          "required before a destructive action",
            })
        if not sufficient:
            blocked_by.append({
                "reason": "telemetry_insufficient",
                "detail": "missing event classes: " + (", ".join(missing) or "unknown")
                          + "; a destructive action on a partial picture is not a response",
            })
        if intrusive_used >= max_actions:
            blocked_by.append({
                "reason": "plan_budget_exhausted",
                "detail": f"this plan already contains {intrusive_used} action(s) that "
                          "take a process down; containing more than that is a human "
                          "decision. Suspension counts: ten suspended services is an "
                          "outage with extra steps.",
            })

        # Ceiling: the highest severity the gates allow for this pid.
        if blocked_by:
            ceiling = max(SEVERITY[action] for action in OBSERVE_ONLY)
        else:
            ceiling = max(SEVERITY[action] for action in allowed)
        recommended = _select(phases, strength, allowed, ceiling)
        if recommended not in OBSERVE_ONLY:
            intrusive_used += 1

        alternatives = [
            {"action": action,
             "why": ACTIONS[action]["blast_radius"],
             "destructive": ACTIONS[action]["destructive"]}
            for action in ("snapshot", "suspend_process", "kill_process")
            if action in allowed and action != recommended
            and SEVERITY[action] > SEVERITY[recommended]
        ]

        decisions.append({
            "process_id": pid,
            "process_names": list(entity.get("process_names") or []),
            "phases": phases,
            "chain_strength": strength,
            "recommended_action": recommended,
            "destructive": ACTIONS[recommended]["destructive"],
            "reversible": ACTIONS[recommended]["reversible"],
            "blast_radius": ACTIONS[recommended]["blast_radius"],
            "executor": ACTIONS[recommended]["executor"],
            "blocked_by": blocked_by,
            "alternatives": alternatives,
            "requires_human": bool(blocked_by),
        })
        if blocked_by:
            refusals.append({"process_id": pid,
                             "process_names": list(entity.get("process_names") or []),
                             "reasons": [item["reason"] for item in blocked_by]})

    # ---- safety review, always attached ----
    destructive = [item for item in decisions if item["destructive"]]
    # Suspension is not destructive — it is reversible — but it is not harmless
    # either. While suspended the process is down. Counting it as "observe only"
    # would hide an outage behind a tidy number.
    intrusive = [item for item in decisions
                 if not item["destructive"] and item["recommended_action"] not in OBSERVE_ONLY]
    observing = [item for item in decisions
                 if item["recommended_action"] in OBSERVE_ONLY]
    safety = {
        "would_break": [
            {"process_id": item["process_id"], "processes": item["process_names"],
             "action": item["recommended_action"], "reversible": item["reversible"],
             "impact": item["blast_radius"]}
            for item in destructive + intrusive
        ],
        "irreversible_count": len(destructive),
        "reversible_outage_count": len(intrusive),
        "observe_only_count": len(observing),
        "refused_count": len(refusals),
        "protected_processes": sorted(_PROTECTED_NAMES),
        "constraints": [
            "A plan is a claim about evidence, not about intent.",
            "Anything executed is logged to the audit trail before and after.",
            "Suspension is preferred over killing: it stops the activity and keeps the memory image.",
            "A suspended process is down. That is an outage for as long as it lasts,"
            " which is why it is counted separately from observing.",
            "Network changes are emitted as commands, never executed by CABID.",
            "A heuristic that can be triggered by an attacker is a weapon pointed the wrong way;"
            " every gate here exists to make that harder.",
        ],
    }

    plan: dict = {
        "format": RESPONSE_FORMAT,
        "cabid_version": __version__,
        "based_on": {
            "status": status,
            "anomaly_score": score,
            "score_semantics": report.get("score_semantics"),
            "telemetry_sufficient": sufficient,
            "missing_event_types": missing,
            "config_digest": report.get("config_digest"),
            "event_count": report.get("event_count"),
        },
        "kill_chains": chains,
        "decisions": decisions,
        "refusals": refusals,
        "safety_review": safety,
        "gates": [
            {"gate": "protected_process",
             "rule": f"never contain {', '.join(sorted(_PROTECTED_NAMES))} or pid 1"},
            {"gate": "kill_chain_corroboration",
             "rule": f"need >= {MIN_CONFIRMATIONS_FOR_DESTRUCTIVE} distinct phases"},
            {"gate": "telemetry_sufficiency",
             "rule": "no destructive action on an incomplete event stream"},
            {"gate": "plan_budget",
             "rule": f"at most {max_actions} destructive actions per plan"},
            {"gate": "containment_loop",
             "rule": f">= {KILL_LOOP_THRESHOLD} prior containments of the same pid "
                     "escalates instead of acting"},
        ],
        "execute": {
            "command": "cabid respond <report.json> --apply --confirm <plan_digest>",
            "note": "Nothing in this plan has been executed. The digest binds the plan "
                    "to the exact decisions reviewed.",
        },
        "semantics": [
            "This plan is a triage suggestion, not a verdict and not an attribution.",
            "Kill-chain phases describe observed shapes, not attacker intent.",
            "Acting on a plan is an operator decision that CABID cannot make for you.",
        ],
    }
    plan["plan_digest"] = _digest({k: v for k, v in plan.items() if k != "plan_digest"})
    return plan


def _interpret(strength: str, phases: list[str]) -> str:
    if not phases:
        return "no kill-chain evidence"
    labels = ", ".join(PHASE_LABELS[phase] for phase in phases)
    if strength == "single_signal":
        return (f"one phase observed ({labels}). On a busy host this is routinely "
                "ordinary deploy or admin work.")
    if strength == "corroborated":
        return (f"two phases observed ({labels}). Worth review; still reachable by a "
                "routine deployment that writes a unit file.")
    return (f"{len(phases)} phases observed ({labels}). Multi-phase agreement is much "
            "harder to reach by accident than any single rule match.")


def render_plan(plan: dict) -> str:
    """Plain-text plan for a terminal."""
    based = plan["based_on"]
    lines = [
        f"CABID response plan ({plan['format']})",
        f"  based on: status={based['status']} score={based['anomaly_score']:.3f} "
        f"telemetry_sufficient={based['telemetry_sufficient']}",
        f"  digest:   {plan['plan_digest']}",
    ]
    if based["missing_event_types"]:
        lines.append("  missing:  " + ", ".join(based["missing_event_types"]))
    lines.append("")
    if not plan["decisions"]:
        lines.append("  No kill-chain evidence in this report. Nothing to contain.")
        return "\n".join(lines) + "\n"

    lines.append("Kill chains, strongest first:")
    for chain in plan["kill_chains"][:8]:
        names = ", ".join(chain["process_names"]) or "unknown"
        lines.append(f"  pid {chain['process_id']:<6} {names}  [{chain['chain_strength']}]")
        for entry in chain["phases"]:
            lines.append(f"      {entry['label']:<20} {', '.join(entry['evidence'][:2])}")
    lines.append("")
    lines.append("Decisions:")
    for decision in plan["decisions"][:8]:
        names = ", ".join(decision["process_names"]) or "unknown"
        if decision["destructive"]:
            marker = "DESTRUCTIVE"
        elif decision["recommended_action"] in OBSERVE_ONLY:
            marker = "observe"
        else:
            marker = "reversible outage"
        lines.append(f"  pid {decision['process_id']:<6} {names:<22} "
                     f"-> {decision['recommended_action']:<16} [{marker}]")
        if decision["blocked_by"]:
            for item in decision["blocked_by"]:
                lines.append(f"      blocked: {item['reason']} - {item['detail']}")
        elif decision["destructive"]:
            lines.append(f"      would break: {decision['blast_radius']}")
    lines.append("")
    safety = plan["safety_review"]
    lines.append(f"Safety: {safety['irreversible_count']} irreversible, "
                 f"{safety['reversible_outage_count']} reversible outage, "
                 f"{safety['observe_only_count']} observe-only, "
                 f"{safety['refused_count']} refused.")
    lines.append("")
    lines.append("Nothing has been executed. To act on this exact plan:")
    lines.append(f"  {plan['execute']['command'].replace('<plan_digest>', plan['plan_digest'])}")
    return "\n".join(lines) + "\n"


def write_plan(plan: dict, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination
