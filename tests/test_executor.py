import json
import os
import subprocess
import sys
import time

import pytest

from cabid.executor import AUDIT_FORMAT, ExecutionError, dry_run, execute_plan, verify_plan
from cabid.response import build_plan


def report(*rule_ids, sufficient=True, missing=None):
    return {
        "status": "SUSPICIOUS",
        "anomaly_score": 0.7,
        "score_semantics": "heuristic score; not a calibrated probability",
        "completeness": {"completeness": 1.0 if sufficient else 0.5,
                         "telemetry_sufficient": sufficient,
                         "missing_event_types": missing or []},
        "rules": {"findings": [
            {"rule_id": rule_id, "severity": "high", "process_ids": [401],
             "title": rule_id, "description": "", "start_timestamp": 1.0}
            for rule_id in rule_ids]},
        "tree": {"findings": [], "common_edges": []},
        "entities": {"top_entities": []},
        "policy": {"findings": []},
    }


def spaced_plan():
    """A plan whose pids are far from any real process."""
    return build_plan(report("shell-from-service", "download-then-exec"))


def test_verifying_a_plan_returns_its_digest():
    plan = spaced_plan()
    assert verify_plan(plan) == plan["plan_digest"]


def test_an_edited_plan_is_refused():
    """The digest binds the plan a human reviewed to the plan that runs."""
    plan = spaced_plan()
    plan["decisions"][0]["recommended_action"] = "kill_process"
    plan["decisions"][0]["destructive"] = True
    with pytest.raises(ExecutionError, match="edited after review"):
        verify_plan(plan)


def test_a_plan_without_a_digest_is_refused():
    plan = spaced_plan()
    plan.pop("plan_digest")
    with pytest.raises(ExecutionError, match="no usable plan_digest"):
        verify_plan(plan)


def test_a_foreign_document_is_refused():
    with pytest.raises(ExecutionError, match="not a CABID response plan"):
        verify_plan({"format": "something-else"})


def test_a_destructive_decision_with_recorded_blocks_is_refused():
    plan = spaced_plan()
    plan["decisions"][0].update(recommended_action="kill_process", destructive=True,
                                blocked_by=[{"reason": "single_phase", "detail": ""}])
    # Re-digest so the tamper check passes and the gate check is what fires.
    from cabid.response import _digest
    plan["plan_digest"] = _digest({k: v for k, v in plan.items() if k != "plan_digest"})
    with pytest.raises(ExecutionError, match="destructive action despite"):
        verify_plan(plan)


def test_destructive_action_on_insufficient_telemetry_is_refused():
    plan = spaced_plan()
    plan["based_on"]["telemetry_sufficient"] = False
    plan["decisions"][0].update(recommended_action="kill_process", destructive=True)
    from cabid.response import _digest
    plan["plan_digest"] = _digest({k: v for k, v in plan.items() if k != "plan_digest"})
    with pytest.raises(ExecutionError, match="insufficient telemetry"):
        verify_plan(plan)


def test_unknown_action_is_refused():
    plan = spaced_plan()
    plan["decisions"][0]["recommended_action"] = "shell_exec"
    from cabid.response import _digest
    plan["plan_digest"] = _digest({k: v for k, v in plan.items() if k != "plan_digest"})
    with pytest.raises(ExecutionError, match="unknown action"):
        verify_plan(plan)


# ------------------------------------------------------------------ dry run

def test_dry_run_reports_without_touching_anything(tmp_path):
    plan = spaced_plan()
    result = dry_run(plan)
    assert result["mode"] == "dry-run"
    assert result["executed"] is False
    assert result["plan_digest"] == plan["plan_digest"]
    assert all(step["status"] for step in result["steps"])
    # Nothing was audited because nothing ran.
    assert not list(tmp_path.glob("*.jsonl"))


def test_dry_run_marks_absent_processes_as_skipped():
    plan = spaced_plan()
    result = dry_run(plan)
    suspended = [s for s in result["steps"] if s["action"] == "suspend_process"]
    assert suspended and all(step["status"] == "skipped" for step in suspended)


def test_dry_run_marks_emitted_actions_as_emit_only():
    plan = build_plan(report("shell-from-service", "download-then-exec"),
                      allowed_actions=("monitor", "block_address"))
    plan["decisions"][0]["recommended_action"] = "block_address"
    from cabid.response import _digest
    plan["plan_digest"] = _digest({k: v for k, v in plan.items() if k != "plan_digest"})
    result = dry_run(plan)
    assert any(step["status"] == "emit_only" for step in result["steps"])


def test_dry_run_shows_refusals_for_actions_that_would_take_a_process_down():
    plan = build_plan(report("shell-from-service", "download-then-exec"))
    # Force a refusal by raising the floor: the gates must show up in a dry run.
    plan["decisions"][0]["recommended_action"] = "kill_process"
    plan["decisions"][0]["blocked_by"] = [{"reason": "single_phase", "detail": "x"}]
    from cabid.response import _digest
    plan["plan_digest"] = _digest({k: v for k, v in plan.items() if k != "plan_digest"})
    result = dry_run(plan)
    assert any(step["status"] == "refused" for step in result["steps"])


def test_gates_never_stop_observation():
    """Capturing evidence is safe by construction; a refused pid is still captured."""
    plan = build_plan(report("shell-from-service", "download-then-exec",
                             sufficient=False, missing=["process_exit"]))
    step = dry_run(plan)["steps"][0]
    assert step["action"] == "snapshot"
    assert step["status"] == "would_run"


def test_a_single_phase_only_warrants_monitoring():
    step = dry_run(build_plan(report("shell-from-service")))["steps"][0]
    assert step["action"] == "monitor"
    assert step["status"] == "noop"


# ------------------------------------------------------------------ execution

def test_apply_requires_the_exact_digest(tmp_path):
    plan = spaced_plan()
    with pytest.raises(ExecutionError, match="does not match this plan"):
        execute_plan(plan, "0" * 64, tmp_path / "audit.jsonl")


def test_apply_refuses_a_missing_digest(tmp_path):
    with pytest.raises(ExecutionError):
        execute_plan(spaced_plan(), "", tmp_path / "audit.jsonl")


def test_apply_on_a_tampered_plan_is_refused_before_any_audit(tmp_path):
    plan = spaced_plan()
    plan["decisions"][0]["destructive"] = True
    audit = tmp_path / "audit.jsonl"
    with pytest.raises(ExecutionError, match="edited after review"):
        execute_plan(plan, plan["plan_digest"], audit)
    assert not audit.exists()


def test_audit_trail_is_written_even_when_every_step_is_skipped(tmp_path):
    plan = spaced_plan()
    audit = tmp_path / "audit.jsonl"
    result = execute_plan(plan, plan["plan_digest"], audit)
    entries = [json.loads(line) for line in audit.read_text().splitlines()]
    assert entries[0]["event"] == "plan_start"
    assert entries[-1]["event"] == "plan_end"
    assert result["audit_entries"] == len(entries)
    assert all(entry["format"] == AUDIT_FORMAT for entry in entries)


def test_every_decided_step_leaves_an_audit_record(tmp_path):
    """Even a step that could not run must be visible afterwards."""
    plan = build_plan(report("shell-from-service", "download-then-exec",
                             sufficient=False, missing=["process_exit"]))
    audit = tmp_path / "audit.jsonl"
    execute_plan(plan, plan["plan_digest"], audit)
    entries = [json.loads(line) for line in audit.read_text().splitlines()]
    outcomes = [entry.get("outcome") for entry in entries if entry.get("outcome")]
    # The step was observation-only (snapshot) with nowhere to write, so it is
    # recorded as skipped rather than silently dropped.
    assert outcomes == ["skipped"]
    assert any(entry.get("event") == "plan_start" for entry in entries)


def test_audit_records_are_appended_not_replaced(tmp_path):
    plan = spaced_plan()
    audit = tmp_path / "audit.jsonl"
    execute_plan(plan, plan["plan_digest"], audit)
    first = audit.read_text().count("\n")
    execute_plan(plan, plan["plan_digest"], audit)
    assert audit.read_text().count("\n") > first


def test_emitted_actions_are_never_executed(tmp_path):
    plan = build_plan(report("shell-from-service", "download-then-exec"),
                      allowed_actions=("monitor", "isolate_host"))
    plan["decisions"][0]["recommended_action"] = "isolate_host"
    plan["decisions"][0]["destructive"] = True
    from cabid.response import _digest
    plan["plan_digest"] = _digest({k: v for k, v in plan.items() if k != "plan_digest"})
    result = execute_plan(plan, plan["plan_digest"], tmp_path / "audit.jsonl")
    step = next(s for s in result["steps"] if s["action"] == "isolate_host")
    assert step["status"] == "emitted"
    assert step["commands"]
    assert "not executed" in step["detail"]
    assert any("nft" in line for line in step["commands"])


# --------------------------------------------------- a real signal, end to end

@pytest.fixture()
def victim():
    """A real child process this test owns, so the signal path is genuinely exercised."""
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    time.sleep(0.3)
    yield proc
    try:
        os.kill(proc.pid, 18)  # SIGCONT, in case the test suspended it
    except (ProcessLookupError, PermissionError):
        pass
    proc.kill()
    proc.wait()


def _state(pid):
    with open(f"/proc/{pid}/stat", encoding="utf-8") as handle:
        return handle.read().rsplit(") ", 1)[1].split()[0]


def test_a_real_process_is_suspended_and_the_step_is_audited(tmp_path, victim):
    plan = build_plan(report("shell-from-service", "download-then-exec"))
    # Point the plan at the live pid and re-digest, the way a real report would.
    for decision in plan["decisions"]:
        decision["process_id"] = victim.pid
    plan["decisions"] = plan["decisions"][:1]
    from cabid.response import _digest
    plan["plan_digest"] = _digest({k: v for k, v in plan.items() if k != "plan_digest"})

    audit = tmp_path / "audit.jsonl"
    result = execute_plan(plan, plan["plan_digest"], audit)
    step = result["steps"][0]
    assert step["action"] == "suspend_process"
    assert step["status"] == "sent"
    time.sleep(0.2)
    assert _state(victim.pid) == "T"      # stopped

    entries = [json.loads(line) for line in audit.read_text().splitlines()]
    outcomes = [entry.get("outcome") for entry in entries]
    # The attempted record must exist before the sent record.
    assert "attempted" in outcomes and "sent" in outcomes
    assert outcomes.index("attempted") < outcomes.index("sent")


def test_a_kill_is_delivered_when_suspension_is_not_permitted(tmp_path, victim):
    plan = build_plan(report("shell-from-service", "download-then-exec"),
                      allowed_actions=("monitor", "kill_process"))
    for decision in plan["decisions"]:
        decision["process_id"] = victim.pid
    plan["decisions"] = plan["decisions"][:1]
    from cabid.response import _digest
    plan["plan_digest"] = _digest({k: v for k, v in plan.items() if k != "plan_digest"})
    result = execute_plan(plan, plan["plan_digest"], tmp_path / "audit.jsonl")
    assert result["steps"][0]["action"] == "kill_process"
    assert result["steps"][0]["status"] == "sent"
    victim.wait(timeout=5)
    assert victim.returncode is not None


def test_execution_skips_a_pid_that_vanished(tmp_path):
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    pid = proc.pid
    plan = build_plan(report("shell-from-service", "download-then-exec"))
    for decision in plan["decisions"]:
        decision["process_id"] = pid
    plan["decisions"] = plan["decisions"][:1]
    from cabid.response import _digest
    plan["plan_digest"] = _digest({k: v for k, v in plan.items() if k != "plan_digest"})
    proc.kill()
    proc.wait()
    time.sleep(0.2)
    result = execute_plan(plan, plan["plan_digest"], tmp_path / "audit.jsonl")
    assert result["steps"][0]["status"] in {"skipped", "sent"}


def test_quarantine_copies_and_leaves_the_original(tmp_path):
    source = tmp_path / "evidence.bin"
    source.write_bytes(b"not-really-malware")
    plan = build_plan(report("shell-from-service", "download-then-exec"),
                      allowed_actions=("monitor", "quarantine_file"))
    plan["decisions"][0]["recommended_action"] = "quarantine_file"
    from cabid.response import _digest
    plan["plan_digest"] = _digest({k: v for k, v in plan.items() if k != "plan_digest"})
    result = execute_plan(plan, plan["plan_digest"], tmp_path / "audit.jsonl",
                          quarantine_dir=tmp_path / "q", file_paths=[str(source)])
    step = result["steps"][0]
    assert step["status"] == "quarantined"
    # The original must remain: quarantine is for preservation, not destruction.
    assert source.exists()
    assert list((tmp_path / "q").glob("evidence.bin.*"))


def test_snapshot_writes_a_decision_record(tmp_path):
    # A pid that cannot be contained is still worth capturing: the evidence copy is
    # what an analyst needs, and taking it changes nothing on the host.
    plan = build_plan(report("shell-from-service", "download-then-exec",
                             sufficient=False, missing=["process_exit"]))
    execute_plan(plan, plan["plan_digest"], tmp_path / "audit.jsonl",
                 quarantine_dir=tmp_path / "q")
    snapshots = list((tmp_path / "q" / "snapshots").glob("*.json"))
    assert snapshots
    payload = json.loads(snapshots[0].read_text())
    assert "not a memory image" in payload["note"]


def test_audit_entry_records_the_uid(tmp_path):
    plan = spaced_plan()
    audit = tmp_path / "audit.jsonl"
    execute_plan(plan, plan["plan_digest"], audit)
    entries = [json.loads(line) for line in audit.read_text().splitlines()]
    assert any(entry.get("uid") == os.getuid() for entry in entries)


# ------------------------------------------------------------- edge coverage

def test_verify_rejects_a_non_object_plan():
    with pytest.raises(ExecutionError, match="plan object is required"):
        verify_plan("not a plan")  # type: ignore[arg-type]


def test_dry_run_marks_quarantine_as_emit_only(tmp_path):
    plan = spaced_plan()
    plan["decisions"][0]["recommended_action"] = "quarantine_file"
    from cabid.response import _digest
    plan["plan_digest"] = _digest({k: v for k, v in plan.items() if k != "plan_digest"})
    step = dry_run(plan)["steps"][0]
    assert step["status"] == "emit_only"
    assert "quarantine-dir" in step["detail"]


def test_pid_exists_is_false_for_junk():
    from cabid.executor import _pid_exists

    assert _pid_exists(0) is False
    assert _pid_exists(-1) is False
    assert _pid_exists(True) is False
    assert _pid_exists("42") is False


def test_execution_records_a_failed_signal(tmp_path, victim, monkeypatch):
    plan = build_plan(report("shell-from-service", "download-then-exec"))
    for decision in plan["decisions"]:
        decision["process_id"] = victim.pid
    plan["decisions"] = plan["decisions"][:1]
    from cabid.response import _digest
    plan["plan_digest"] = _digest({k: v for k, v in plan.items() if k != "plan_digest"})

    real_kill = os.kill

    def refuse(pid, sig):
        if sig == 0:            # let the existence probe through
            return real_kill(pid, sig)
        raise PermissionError("not permitted")

    monkeypatch.setattr(os, "kill", refuse)
    result = execute_plan(plan, plan["plan_digest"], tmp_path / "audit.jsonl")
    assert result["steps"][0]["status"] == "failed"
    assert "PermissionError" in result["steps"][0]["detail"]


def test_quarantine_skips_a_missing_file(tmp_path):
    plan = build_plan(report("shell-from-service", "download-then-exec"),
                      allowed_actions=("monitor", "quarantine_file"))
    plan["decisions"][0]["recommended_action"] = "quarantine_file"
    from cabid.response import _digest
    plan["plan_digest"] = _digest({k: v for k, v in plan.items() if k != "plan_digest"})
    audit = tmp_path / "audit.jsonl"
    result = execute_plan(plan, plan["plan_digest"], audit,
                          quarantine_dir=tmp_path / "q",
                          file_paths=[str(tmp_path / "absent.bin")])
    assert result["steps"][0]["status"] == "skipped"
    entries = [json.loads(line) for line in audit.read_text().splitlines()]
    assert any("not a regular file" in (entry.get("detail") or "") for entry in entries)


def test_execute_without_quarantine_dir_audits_the_skip(tmp_path):
    plan = build_plan(report("shell-from-service", "download-then-exec",
                             sufficient=False, missing=["process_exit"]))
    audit = tmp_path / "audit.jsonl"
    result = execute_plan(plan, plan["plan_digest"], audit)
    assert result["steps"][0]["status"] == "skipped"
    entries = [json.loads(line) for line in audit.read_text().splitlines()]
    assert any(entry.get("outcome") == "skipped" for entry in entries)


def test_monitor_steps_are_audited_as_noop(tmp_path):
    plan = build_plan(report("shell-from-service"))  # single phase -> monitor
    audit = tmp_path / "audit.jsonl"
    result = execute_plan(plan, plan["plan_digest"], audit)
    assert result["steps"][0]["status"] == "noop"
    entries = [json.loads(line) for line in audit.read_text().splitlines()]
    assert any(entry.get("outcome") == "noop" for entry in entries)


def test_replan_detects_a_changed_report():
    from cabid.executor import replan

    plan = build_plan(report("shell-from-service", "download-then-exec"))
    same = replan(report("shell-from-service", "download-then-exec"), plan)
    assert same["match"] is True
    changed = replan(report("shell-from-service"), plan)
    assert changed["match"] is False
    assert changed["stored_digest"] != changed["rebuilt_digest"]
