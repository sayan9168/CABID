import json

import pytest

from cabid.ingest import normalize_many, read_jsonl
from cabid.rules import (BUILTIN_RULES, RULES_FORMAT, RuleError, evaluate_rules, load_rules,
                         load_rules_from_dict)


def events(*spec):
    """spec items: (timestamp, event_type, pid, ppid, name[, target])"""
    rows = []
    for item in spec:
        ts, kind, pid, ppid, name = item[:5]
        rows.append({"timestamp": ts, "event_type": kind, "process_id": pid,
                     "parent_process_id": ppid, "process_name": name,
                     "target": item[5] if len(item) > 5 else ""})
    return normalize_many(rows)


def test_builtin_pack_loads_and_is_valid():
    rules = load_rules(None)
    assert len(rules) == len(BUILTIN_RULES)
    assert all(rule["enabled"] for rule in rules)
    assert {rule["kind"] for rule in rules} == {"sequence", "count"}


def test_shell_from_service_sequence_matches():
    stream = events(
        (1, "process_start", 10, 1, "nginx"),
        (2, "process_exec", 11, 10, "sh"),
    )
    result = evaluate_rules(stream, load_rules(None))
    ids = [finding["rule_id"] for finding in result["findings"]]
    assert "shell-from-service" in ids
    finding = next(f for f in result["findings"] if f["rule_id"] == "shell-from-service")
    assert finding["matched_steps"] == 2
    assert result["semantics"].startswith("pattern matches")


def test_sequence_respects_within_bound():
    stream = events(
        (1, "process_start", 10, 1, "nginx"),
        (500, "process_exec", 11, 10, "sh"),  # ~499s later, bound is 30s
    )
    rules = [rule for rule in load_rules(None) if rule["id"] == "shell-from-service"]
    assert evaluate_rules(stream, rules)["findings"] == []


def test_same_process_step_is_enforced():
    stream = events(
        (1, "process_exit", 10, 1, "worker"),
        (2, "file_write", 11, 1, "other"),
        (3, "file_write", 10, 1, "worker"),
    )
    rules = [rule for rule in load_rules(None) if rule["id"] == "exit-then-activity"]
    findings = evaluate_rules(stream, rules)["findings"]
    assert len(findings) == 1
    assert findings[0]["process_ids"] == [10]


def test_count_rule_reports_one_finding_per_burst():
    stream = events(*[(index, "process_start", 100 + index, 1, "svc") for index in range(20)])
    rules = [rule for rule in load_rules(None) if rule["id"] == "rapid-restart-loop"]
    findings = evaluate_rules(stream, rules)["findings"]
    assert len(findings) == 1
    assert findings[0]["matched_steps"] == 20


def test_separate_bursts_are_separate_findings():
    first = [(index, "process_start", 100 + index, 1, "svc") for index in range(12)]
    second = [(1000 + index, "process_start", 200 + index, 1, "svc") for index in range(12)]
    stream = events(*(first + second))
    rules = [rule for rule in load_rules(None) if rule["id"] == "rapid-restart-loop"]
    assert len(evaluate_rules(stream, rules)["findings"]) == 2


def test_no_matches_reports_clean_result():
    stream = events((1, "heartbeat", 1, 0, "init"))
    result = evaluate_rules(stream, load_rules(None))
    assert result["finding_count"] == 0
    assert result["matched_rule_count"] == 0
    assert result["severity_counts"] == {}


def test_findings_are_sorted_by_severity():
    stream = read_jsonl("datasets/synthetic/tree-example.jsonl")
    findings = evaluate_rules(stream, load_rules(None))["findings"]
    order = ["critical", "high", "medium", "low"]
    ranks = [order.index(finding["severity"]) for finding in findings]
    assert ranks == sorted(ranks)


def test_custom_rule_file(tmp_path):
    payload = {"format": RULES_FORMAT, "name": "custom", "rules": [{
        "id": "sshd-then-shadow",
        "title": "sshd touched shadow",
        "severity": "critical",
        "steps": [
            {"event_type": "process_exec", "process_name": "sshd"},
            {"event_type": "file_write", "target": "/etc/shadow", "within": 10},
        ],
    }]}
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    rules = load_rules(path)
    stream = events((1, "process_exec", 5, 1, "sshd"),
                    (2, "file_write", 6, 5, "sshd", "/etc/shadow"))
    findings = evaluate_rules(stream, rules)["findings"]
    assert [finding["rule_id"] for finding in findings] == ["sshd-then-shadow"]


@pytest.mark.parametrize("bad", [
    {"rules": []},
    {"rules": [{"id": "X"}]},
    {"rules": [{"id": "ok", "severity": "urgent"}]},
    {"rules": [{"id": "ok", "steps": [{"event_type": "process_start"}]}]},
    {"rules": [{"id": "ok", "steps": [{"event_type": "nope"}, {"event_type": "process_exec"}]}]},
    {"rules": [{"id": "ok", "steps": [{"event_type": "process_start"}, {"event_type": "process_exec"}],
                "min_count": 5}]},
    {"rules": [{"id": "ok", "kind": "count", "filter": {"event_type": "process_start"}, "window": 0}]},
    {"rules": [{"id": "ok", "kind": "count", "filter": {}, "min_count": 0}]},
    {"rules": [{"id": "a", "steps": [{"event_type": "process_start"}, {"event_type": "process_exec"}]},
               {"id": "a", "steps": [{"event_type": "process_start"}, {"event_type": "process_exec"}]}]},
    {"rules": [{"id": "ok", "steps": [{"event_type": "process_start"}, {"event_type": "process_exec"}],
                "unknown_key": 1}]},
    {"rules": [{"id": "ok", "steps": [{"event_type": "process_start", "within": 5},
                                      {"event_type": "process_exec"}]}]},
])
def test_invalid_rules_are_rejected(bad):
    with pytest.raises(RuleError):
        load_rules_from_dict(bad)


def test_bad_rule_file_reports_json_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{nope", encoding="utf-8")
    with pytest.raises(RuleError, match="invalid JSON"):
        load_rules(path)


def test_unsupported_format_rejected(tmp_path):
    path = tmp_path / "x.json"
    path.write_text(json.dumps({"format": "cabid-rules/9", "rules": [{
        "id": "ok", "steps": [{"event_type": "process_start"}, {"event_type": "process_exec"}]}]}),
        encoding="utf-8")
    with pytest.raises(RuleError, match="unsupported rule format"):
        load_rules(path)


def test_disabled_rule_is_dropped(tmp_path):
    path = tmp_path / "x.json"
    path.write_text(json.dumps({"rules": [
        {"id": "off-rule", "enabled": False,
         "steps": [{"event_type": "process_start"}, {"event_type": "process_exec"}]},
        {"id": "on-rule", "steps": [{"event_type": "process_start"}, {"event_type": "process_exec"}]},
    ]}), encoding="utf-8")
    assert [rule["id"] for rule in load_rules(path)] == ["on-rule"]


def test_max_matches_caps_output():
    # six separate bursts of 3 starts each (gaps far exceed the window)
    spec = []
    for burst in range(6):
        base = burst * 1000
        spec.extend((base + offset, "process_start", 100 + burst * 3 + offset, 1, "svc")
                    for offset in range(3))
    rules = load_rules_from_dict({"rules": [{
        "id": "loop", "kind": "count", "filter": {"event_type": "process_start"},
        "window": 1, "min_count": 3, "max_matches": 4}]})
    assert len(evaluate_rules(events(*spec), rules)["findings"]) == 4


def exec_events(*spec):
    """spec items: (timestamp, event_type, pid, ppid, name, executable, target)."""
    rows = []
    for item in spec:
        ts, kind, pid, ppid, name = item[:5]
        rows.append({"timestamp": ts, "event_type": kind, "process_id": pid,
                     "parent_process_id": ppid, "process_name": name,
                     "executable": item[5] if len(item) > 5 else "",
                     "target": item[6] if len(item) > 6 else ""})
    return normalize_many(rows)


def test_pack_includes_the_privilege_and_kernel_rules():
    ids = {rule["id"] for rule in load_rules(None)}
    assert {"privilege-escalation-to-exec", "ptrace-then-credential-read",
            "permission-relaxed-on-credential", "kernel-state-then-persistence",
            "bulk-accept-then-exec"} <= ids


def test_privilege_escalation_to_exec_fires():
    # The rule requires execution from a staging path, not any execution.
    stream = exec_events((1, "privilege_change", 10, 1, "sudo", "", "setuid"),
                         (2, "process_exec", 10, 1, "payload", "/tmp/.x/payload", ""))
    report = evaluate_rules(stream, load_rules(None))
    assert "privilege-escalation-to-exec" in {f["rule_id"] for f in report["findings"]}


def test_ptrace_then_credential_read_fires():
    stream = events((1, "kernel_state_change", 10, 1, "gdb", "ptrace"),
                    (2, "file_write", 10, 1, "gdb", "/etc/shadow"))
    report = evaluate_rules(stream, load_rules(None))
    assert "ptrace-then-credential-read" in {f["rule_id"] for f in report["findings"]}


def test_permission_relaxed_on_credential_fires():
    stream = exec_events((1, "process_exec", 10, 1, "chmod", "/bin/chmod", ""),
                         (2, "permission_change", 10, 1, "chmod", "", "/etc/shadow"))
    report = evaluate_rules(stream, load_rules(None))
    assert "permission-relaxed-on-credential" in {f["rule_id"] for f in report["findings"]}


def test_permission_rule_ignores_a_chmod_on_a_harmless_path():
    stream = exec_events((1, "process_exec", 10, 1, "chmod", "/bin/chmod", ""),
                         (2, "permission_change", 10, 1, "chmod", "", "/tmp/notes.txt"))
    report = evaluate_rules(stream, load_rules(None))
    assert "permission-relaxed-on-credential" not in {f["rule_id"] for f in report["findings"]}


def test_permission_rule_respects_its_window():
    stream = exec_events((1, "process_exec", 10, 1, "chmod", "/bin/chmod", ""),
                         (500, "permission_change", 10, 1, "chmod", "", "/etc/shadow"))
    report = evaluate_rules(stream, load_rules(None))
    assert "permission-relaxed-on-credential" not in {f["rule_id"] for f in report["findings"]}


def test_kernel_state_then_persistence_fires():
    stream = events((1, "kernel_state_change", 10, 1, "mount", "mount"),
                    (2, "file_write", 10, 1, "mount", "/etc/cron.d/backdoor"))
    report = evaluate_rules(stream, load_rules(None))
    assert "kernel-state-then-persistence" in {f["rule_id"] for f in report["findings"]}


def test_bulk_accept_then_exec_fires_on_a_burst():
    spec = [(float(index), "network_accept", 10, 1, "nginx") for index in range(25)]
    spec.append((30.0, "process_exec", 10, 1, "shell", "/bin/sh"))
    report = evaluate_rules(events(*spec), load_rules(None))
    assert "bulk-accept-then-exec" in {f["rule_id"] for f in report["findings"]}


def test_new_rules_stay_silent_on_a_calm_stream():
    spec = [(float(index), "heartbeat", 10, 1, "cron") for index in range(10)]
    report = evaluate_rules(events(*spec), load_rules(None))
    assert report["finding_count"] == 0


def test_rules_never_change_the_headline_score():
    from cabid.detector import analyze

    stream = exec_events((1, "privilege_change", 10, 1, "sudo", "", "setuid"),
                         (2, "process_exec", 10, 1, "payload", "/tmp/payload", ""))
    with_rules = analyze(stream, rules=load_rules(None))
    without = analyze(stream, rules=[])
    assert with_rules["anomaly_score"] == without["anomaly_score"]
    assert with_rules["components"] == without["components"]
