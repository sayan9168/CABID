import json

import pytest

from cabid.response import (ACTIONS, MIN_CONFIRMATIONS_FOR_DESTRUCTIVE, OBSERVE_ONLY,
                            PHASE_LABELS, RESPONSE_FORMAT, ResponseError, SEVERITY,
                            build_plan, render_plan, write_plan)


def complete(*, sufficient=True, missing=None):
    return {
        "telemetry_sufficient": sufficient,
        "completeness": {1.0: 1.0, "completeness": 1.0 if sufficient else 0.5,
                         "telemetry_sufficient": sufficient,
                         "missing_event_types": missing or []},
    }


def report(*, rules=(), tree=(), entities=(), policy=(), sufficient=True,
           missing=None, status="SUSPICIOUS", score=0.7):
    return {
        "status": status,
        "anomaly_score": score,
        "score_semantics": "heuristic score; not a calibrated probability",
        "config_digest": "abc123",
        "event_count": 42,
        "completeness": {"completeness": 1.0 if sufficient else 0.5,
                         "telemetry_sufficient": sufficient,
                         "missing_event_types": missing or []},
        "rules": {"findings": list(rules)},
        "tree": {"findings": list(tree), "common_edges": []},
        "entities": {"top_entities": list(entities)},
        "policy": {"findings": list(policy)},
    }


def rule_finding(rule_id, *pids, severity="high"):
    return {"rule_id": rule_id, "severity": severity, "process_ids": list(pids),
            "title": rule_id, "description": "", "start_timestamp": 1.0}


def entity(pid, names=("evil",), event_types=(), executables=(), refs=()):
    return {"process_id": pid, "process_names": list(names),
            "event_types": list(event_types), "executables": list(executables),
            "sensitive_refs": list(refs), "entity_risk": 0.5, "event_count": 5}


# ---------------------------------------------------------------- plan basics

def test_plan_has_a_stable_digest_and_format():
    plan = build_plan(report())
    assert plan["format"] == RESPONSE_FORMAT
    assert len(plan["plan_digest"]) == 64
    assert plan["execute"]["note"].startswith("Nothing in this plan has been executed")
    # Rebuilding from the same report must produce the same digest.
    assert build_plan(report())["plan_digest"] == plan["plan_digest"]


def test_a_calm_report_produces_no_decisions():
    plan = build_plan(report(status="NO_ANOMALY_DETECTED", score=0.05))
    assert plan["decisions"] == []
    assert "Nothing to contain" in render_plan(plan)


def test_single_phase_cannot_be_destructive():
    """One rule match is never enough — this is the whole safety argument."""
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401)]))
    decision = next(d for d in plan["decisions"] if d["process_id"] == 401)
    assert decision["destructive"] is False
    assert decision["recommended_action"] in OBSERVE_ONLY
    assert "single_phase" in {item["reason"] for item in decision["blocked_by"]}


def test_two_phases_allow_suspension_but_prefer_it_to_killing():
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401),
                                    rule_finding("download-then-exec", 401)]))
    decision = next(d for d in plan["decisions"] if d["process_id"] == 401)
    assert decision["recommended_action"] == "suspend_process"
    assert decision["destructive"] is False
    # Suspension stops a process, so it must not be filed under "observe only".
    assert decision["recommended_action"] not in OBSERVE_ONLY
    assert plan["safety_review"]["reversible_outage_count"] >= 1


def test_three_phases_still_prefer_suspension():
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401),
                                    rule_finding("download-then-exec", 401),
                                    rule_finding("ptrace-then-credential-read", 401)]))
    decision = next(d for d in plan["decisions"] if d["process_id"] == 401)
    assert decision["recommended_action"] == "suspend_process"


def test_kill_is_only_reached_when_suspension_is_not_allowed():
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401),
                                    rule_finding("ptrace-then-credential-read", 401)]),
                      allowed_actions=("monitor", "snapshot", "kill_process"))
    decision = next(d for d in plan["decisions"] if d["process_id"] == 401)
    assert decision["recommended_action"] == "kill_process"


def test_impact_phase_raises_the_urgency():
    plan = build_plan(report(rules=[rule_finding("rapid-restart-loop", 501, severity="medium"),
                                    rule_finding("sensitive-write-then-egress", 501,
                                                 severity="critical")]))
    decision = next(d for d in plan["decisions"] if d["process_id"] == 501)
    assert decision["recommended_action"] in {"suspend_process", "kill_process"}


# ---------------------------------------------------------------- hard gates

def test_insufficient_telemetry_blocks_every_destructive_action():
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401),
                                    rule_finding("download-then-exec", 401)],
                             sufficient=False, missing=["process_exit"]))
    decision = next(d for d in plan["decisions"] if d["process_id"] == 401)
    assert decision["destructive"] is False
    assert "telemetry_insufficient" in {item["reason"] for item in decision["blocked_by"]}
    assert "process_exit" in plan["based_on"]["missing_event_types"]


def test_infrastructure_is_never_contained():
    """A defender that can be made to kill sshd has handed over the host."""
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 22),
                                    rule_finding("download-then-exec", 22)],
                             entities=[entity(22, names=("sshd",))]))
    decision = next(d for d in plan["decisions"] if d["process_id"] == 22)
    assert decision["destructive"] is False
    assert "protected_process" in {item["reason"] for item in decision["blocked_by"]}


def test_pid_1_is_never_contained():
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 1),
                                    rule_finding("download-then-exec", 1)],
                             entities=[entity(1, names=("weird-name",))]))
    decision = next(d for d in plan["decisions"] if d["process_id"] == 1)
    assert decision["destructive"] is False
    assert "pid_1" in {item["reason"] for item in decision["blocked_by"]}


def test_tree_root_is_not_contained():
    plan = build_plan({
        **report(rules=[rule_finding("shell-from-service", 10),
                        rule_finding("download-then-exec", 10)],
                 entities=[entity(10, names=("init-like",))]),
        "tree": {"findings": [], "common_edges": [{"parent": "init-like", "child": "sh",
                                                   "count": 1}]},
    })
    decision = next(d for d in plan["decisions"] if d["process_id"] == 10)
    assert "tree_root" in {item["reason"] for item in decision["blocked_by"]}


def test_plan_budget_caps_the_number_of_destructive_actions():
    rules = []
    for pid in range(100, 110):
        rules.append(rule_finding("shell-from-service", pid))
        rules.append(rule_finding("download-then-exec", pid))
    plan = build_plan(report(rules=rules), max_actions=2)
    intrusive = [d for d in plan["decisions"]
                 if d["recommended_action"] not in OBSERVE_ONLY]
    assert len(intrusive) <= 2
    assert any("plan_budget_exhausted" in {b["reason"] for b in d["blocked_by"]}
               for d in plan["decisions"])


def test_a_containment_loop_escalates_instead_of_acting():
    """An attacker who can make the defender act repeatedly is the threat model."""
    history = [{"process_id": 401, "timestamp": 1000.0},
               {"process_id": 401, "timestamp": 1100.0},
               {"process_id": 401, "timestamp": 1200.0}]
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401),
                                    rule_finding("download-then-exec", 401)]),
                      known_containments=history)
    decision = next(d for d in plan["decisions"] if d["process_id"] == 401)
    assert decision["destructive"] is False
    assert "containment_loop" in {item["reason"] for item in decision["blocked_by"]}


def test_unknown_action_names_are_rejected():
    with pytest.raises(ResponseError, match="unknown actions"):
        build_plan(report(), allowed_actions=("monitor", "rm_rf"))


def test_allow_list_can_only_make_a_plan_more_conservative():
    rules = [rule_finding("shell-from-service", 401),
             rule_finding("download-then-exec", 401)]
    plan = build_plan(report(rules=rules), allowed_actions=("monitor",))
    assert all(d["recommended_action"] == "monitor" for d in plan["decisions"])


# ---------------------------------------------------------------- evidence

def test_every_phase_keeps_the_source_that_produced_it():
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401),
                                    rule_finding("download-then-exec", 401)]))
    chain = next(c for c in plan["kill_chains"] if c["process_id"] == 401)
    evidence = "; ".join(item for phase in chain["phases"] for item in phase["evidence"])
    assert "rule shell-from-service" in evidence
    assert "rule download-then-exec" in evidence


def test_chain_strength_grades_with_phase_count():
    one = build_plan(report(rules=[rule_finding("shell-from-service", 401)]))
    two = build_plan(report(rules=[rule_finding("shell-from-service", 401),
                                   rule_finding("download-then-exec", 401)]))
    assert next(c for c in one["kill_chains"] if c["process_id"] == 401)["chain_strength"] == "single_signal"
    assert next(c for c in two["kill_chains"] if c["process_id"] == 401)["chain_strength"] == "corroborated"


def test_chain_interpretation_states_the_uncertainty():
    one = build_plan(report(rules=[rule_finding("shell-from-service", 401)]))
    chain = next(c for c in one["kill_chains"] if c["process_id"] == 401)
    assert "ordinary deploy" in chain["interpretation"]


def test_credential_paths_come_from_entities_and_policy():
    plan = build_plan(report(
        rules=[rule_finding("shell-from-service", 700)],
        entities=[entity(700, refs=["/etc/shadow"])],
        policy=[{"process_id": 700, "target": "/etc/shadow", "kind": "sensitive_path"}],
    ))
    chain = next(c for c in plan["kill_chains"] if c["process_id"] == 700)
    assert "credential_access" in [phase["phase"] for phase in chain["phases"]]


def test_persistence_paths_are_recognised_from_sensitive_refs():
    plan = build_plan(report(entities=[entity(701, refs=["/etc/cron.d/x"])]))
    chain = next(c for c in plan["kill_chains"] if c["process_id"] == 701)
    assert "persistence" in [phase["phase"] for phase in chain["phases"]]


def test_execution_from_a_staging_path_counts_as_a_phase():
    plan = build_plan(report(entities=[entity(702, executables=["/tmp/.cache/x"])]))
    chain = next(c for c in plan["kill_chains"] if c["process_id"] == 702)
    assert "execution" in [phase["phase"] for phase in chain["phases"]]


def test_tree_findings_contribute_phases():
    plan = build_plan(report(tree=[{"kind": "interpreter_spawn", "child_pid": 703,
                                    "parent_pid": 704, "severity": "medium",
                                    "detail": "python spawned bash"}]))
    pids = {chain["process_id"] for chain in plan["kill_chains"]}
    assert {703, 704} <= pids


def test_duplicate_evidence_notes_are_not_repeated():
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401),
                                    rule_finding("shell-from-service", 401)]))
    chain = next(c for c in plan["kill_chains"] if c["process_id"] == 401)
    notes = [note for phase in chain["phases"] for note in phase["evidence"]]
    assert len(notes) == len(set(notes))


# ---------------------------------------------------------------- shape

def test_safety_review_states_what_would_break():
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401),
                                    rule_finding("download-then-exec", 401)]))
    safety = plan["safety_review"]
    assert safety["would_break"]
    assert all(item["impact"] for item in safety["would_break"])
    assert safety["refused_count"] == 0
    assert any("weapon" in constraint for constraint in safety["constraints"])


def test_gates_are_listed_in_the_plan():
    plan = build_plan(report())
    names = {gate["gate"] for gate in plan["gates"]}
    assert {"protected_process", "kill_chain_corroboration", "telemetry_sufficiency",
            "plan_budget", "containment_loop"} <= names
    assert str(MIN_CONFIRMATIONS_FOR_DESTRUCTIVE) in \
        next(g["rule"] for g in plan["gates"] if g["gate"] == "kill_chain_corroboration")


def test_semantics_disclaim_verdict_and_attribution():
    plan = build_plan(report())
    joined = " ".join(plan["semantics"]).lower()
    assert "not a verdict" in joined
    assert "attribution" in joined


def test_severity_ladder_is_ordered_sensibly():
    assert SEVERITY["monitor"] < SEVERITY["snapshot"] < SEVERITY["suspend_process"]
    assert SEVERITY["suspend_process"] < SEVERITY["kill_process"]
    assert SEVERITY["monitor"] == 0


def test_every_phase_has_a_human_label():
    for phase in PHASE_LABELS:
        assert PHASE_LABELS[phase]


def test_every_action_states_its_blast_radius():
    for name, spec in ACTIONS.items():
        assert spec["blast_radius"], name
        assert isinstance(spec["destructive"], bool)
        assert isinstance(spec["reversible"], bool)


def test_render_plan_is_readable():
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401),
                                    rule_finding("download-then-exec", 401)]))
    text = render_plan(plan)
    assert "CABID response plan" in text
    assert "Kill chains, strongest first" in text
    assert "Nothing has been executed" in text
    assert plan["plan_digest"] in text


def test_write_plan_creates_directories(tmp_path):
    destination = write_plan(build_plan(report()), tmp_path / "a" / "b" / "plan.json")
    assert json.loads(destination.read_text())["format"] == RESPONSE_FORMAT


def test_non_object_report_is_rejected():
    with pytest.raises(ResponseError):
        build_plan(["not", "a", "report"])  # type: ignore[arg-type]


# ------------------------------------------------------- defensive edge cases

def test_invalid_pids_are_ignored_not_scored():
    plan = build_plan(report(rules=[
        {"rule_id": "shell-from-service", "severity": "high", "process_ids": [0, -5, True, "x"]},
    ]))
    assert plan["decisions"] == []


def test_a_rule_with_no_known_phase_contributes_nothing():
    plan = build_plan(report(rules=[rule_finding("some-custom-rule", 401)]))
    assert plan["decisions"] == []


def test_tree_findings_without_a_phase_are_skipped():
    plan = build_plan(report(tree=[{"kind": "unknown_kind", "child_pid": 401,
                                    "parent_pid": 402, "severity": "low", "detail": ""}]))
    assert plan["decisions"] == []


def test_policy_findings_on_persistence_paths_count_as_a_phase():
    plan = build_plan(report(policy=[{"process_id": 705, "target": "/etc/systemd/x.service",
                                      "kind": "sensitive_path"}]))
    chain = next(c for c in plan["kill_chains"] if c["process_id"] == 705)
    assert "persistence" in [phase["phase"] for phase in chain["phases"]]


def test_event_classes_alone_can_supply_a_phase():
    plan = build_plan(report(entities=[entity(706, event_types=["privilege_change"])]))
    chain = next(c for c in plan["kill_chains"] if c["process_id"] == 706)
    assert "privilege_access" in "".join(p["phase"] for p in chain["phases"]) or \
        "privilege_escalation" in [p["phase"] for p in chain["phases"]]


def test_strong_chain_interprets_as_multi_phase():
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401),
                                    rule_finding("download-then-exec", 401),
                                    rule_finding("ptrace-then-credential-read", 401)]))
    chain = next(c for c in plan["kill_chains"] if c["process_id"] == 401)
    assert chain["chain_strength"] == "strong"
    assert "Multi-phase agreement" in chain["interpretation"]


def test_no_evidence_interprets_as_nothing():
    plan = build_plan(report())
    assert plan["kill_chains"] == []


def test_render_names_every_destructive_action(tmp_path):
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401),
                                    rule_finding("download-then-exec", 401)]),
                      allowed_actions=("monitor", "kill_process"))
    text = render_plan(plan)
    assert "DESTRUCTIVE" in text
    assert "would break" in text


def test_render_shows_missing_event_classes():
    plan = build_plan(report(sufficient=False, missing=["process_exit", "heartbeat"],
                             rules=[rule_finding("shell-from-service", 401)]))
    assert "missing:" in render_plan(plan)


def test_render_lists_blocked_reasons():
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401)]))
    assert "blocked: single_phase" in render_plan(plan)


def test_an_empty_allow_list_falls_back_to_monitor():
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401),
                                    rule_finding("download-then-exec", 401)]),
                      allowed_actions=("snapshot",))
    assert all(d["recommended_action"] in OBSERVE_ONLY for d in plan["decisions"])


def test_a_report_with_no_entities_still_plans():
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401),
                                    rule_finding("download-then-exec", 401)]))
    assert plan["decisions"][0]["process_names"] == []


def test_negative_anomaly_score_is_accepted_as_given():
    plan = build_plan(report(score=-1.0))
    assert plan["based_on"]["anomaly_score"] == -1.0


def test_alternatives_only_escalate():
    plan = build_plan(report(rules=[rule_finding("shell-from-service", 401),
                                    rule_finding("download-then-exec", 401)]))
    decision = next(d for d in plan["decisions"] if d["process_id"] == 401)
    for alternative in decision["alternatives"]:
        assert SEVERITY[alternative["action"]] > SEVERITY[decision["recommended_action"]]


def test_quarantine_is_not_destructive_because_it_copies():
    """A copy leaves the original readable, so it is reversible and non-destructive."""
    assert ACTIONS["quarantine_file"]["destructive"] is False
    assert ACTIONS["quarantine_file"]["reversible"] is True
    assert "original is untouched" in ACTIONS["quarantine_file"]["blast_radius"]


def test_only_kill_and_the_network_actions_are_irreversible():
    irreversible = sorted(name for name, spec in ACTIONS.items() if spec["destructive"])
    assert irreversible == ["block_address", "disable_account", "isolate_host", "kill_process"]
