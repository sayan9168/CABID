import json

import pytest

from cabid.ingest import normalize_many
from cabid.policy import DEFAULT_POLICY, PolicyError, evaluate_policy, load_policy


def test_load_policy_defaults_when_path_is_none():
    policy = load_policy(None)
    assert policy["format"] == "cabid-policy/2"
    assert "/etc/shadow" in policy["sensitive_paths"]
    assert policy is not DEFAULT_POLICY


def test_sensitive_path_write_is_flagged():
    events = normalize_many([{"timestamp": 1, "event_type": "file_write", "process_id": 5,
                              "process_name": "curl", "target": "/etc/shadow"}])
    result = evaluate_policy(events)
    assert result["finding_count"] == 1
    assert result["findings"][0]["rule"] == "sensitive_path_write"
    assert result["findings"][0]["target_ref"] == "shadow"


def test_allow_listed_process_is_marked_but_still_reported():
    events = normalize_many([{"timestamp": 1, "event_type": "file_write", "process_id": 5,
                              "process_name": "systemd", "target": "/etc/systemd/system/evil.service"}])
    finding = evaluate_policy(events)["findings"][0]
    assert finding["allow_listed_process"] is True
    assert finding["severity"] == "high"


def test_sensitive_port_connect_is_flagged():
    events = normalize_many([{"timestamp": 1, "event_type": "network_connect", "process_id": 5,
                              "process_name": "nc", "target": "10.0.0.4:6379"}])
    finding = evaluate_policy(events)["findings"][0]
    assert finding["rule"] == "sensitive_port_connect"
    assert "6379" in finding["detail"]


def test_non_sensitive_targets_are_quiet():
    events = normalize_many([
        {"timestamp": 1, "event_type": "network_connect", "process_id": 5, "target": "example.invalid:443"},
        {"timestamp": 2, "event_type": "file_write", "process_id": 5, "target": "/tmp/notes.txt"},
    ])
    assert evaluate_policy(events)["finding_count"] == 0


def test_suppressed_reason_codes_are_removed():
    reasons = [{"code": "temporal_rate_or_burst", "detail": "x"}, {"code": "telemetry_gap", "detail": "y"}]
    policy = load_policy(None)
    policy["suppress_rule_codes"] = ["telemetry_gap"]
    result = evaluate_policy([], policy, reasons)
    assert [reason["code"] for reason in result["reasons_after_suppression"]] == ["temporal_rate_or_burst"]
    assert result["suppressed_reason_codes"] == ["telemetry_gap"]


def test_findings_are_truncated_with_a_flag():
    events = normalize_many([{"timestamp": index, "event_type": "network_connect", "process_id": 5,
                              "target": "10.0.0.4:22"} for index in range(60)])
    result = evaluate_policy(events)
    assert result["finding_count"] == 60
    assert len(result["findings"]) == 50
    assert result["findings_truncated"] is True


def test_invalid_policy_files_are_rejected(tmp_path):
    cases = ['{"unknown": 1}', '{"sensitive_ports": [0]}', '{"sensitive_ports": ["22"]}',
             '{"sensitive_paths": "/etc/shadow"}', "[1,2,3]", "{bad json"]
    for index, payload in enumerate(cases):
        path = tmp_path / f"p{index}.json"
        path.write_text(payload, encoding="utf-8")
        with pytest.raises(PolicyError):
            load_policy(path)


def test_custom_policy_is_applied():
    policy = load_policy(None)
    policy["sensitive_paths"] = ["/srv/app/secrets*"]
    events = normalize_many([{"timestamp": 1, "event_type": "file_write", "process_id": 1,
                              "target": "/srv/app/secrets.env"}])
    assert evaluate_policy(events, policy)["finding_count"] == 1


def test_policy_format_1_files_still_load(tmp_path):
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps({"format": "cabid-policy/1", "sensitive_ports": [2222]}), encoding="utf-8")
    policy = load_policy(path)
    assert policy["sensitive_ports"] == [2222]
    assert policy["format"] == "cabid-policy/2"


def test_unsupported_policy_format_is_rejected(tmp_path):
    path = tmp_path / "future.json"
    path.write_text(json.dumps({"format": "cabid-policy/99"}), encoding="utf-8")
    with pytest.raises(PolicyError, match="unsupported policy format"):
        load_policy(path)


def test_process_scoped_suppression_is_validated(tmp_path):
    path = tmp_path / "scoped.json"
    path.write_text(json.dumps({"suppress_for_processes": {"backup-agent": ["temporal_rate_or_burst"]}}),
                    encoding="utf-8")
    assert load_policy(path)["suppress_for_processes"]["backup-agent"] == ["temporal_rate_or_burst"]
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"suppress_for_processes": ["a"]}), encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(bad)


def test_process_scoped_suppression_only_affects_that_process():
    policy = load_policy(None)
    policy["suppress_for_processes"] = {"noisy-agent": ["sensitive_path_write"]}
    events = normalize_many([
        {"timestamp": 1, "event_type": "file_write", "process_id": 4,
         "process_name": "noisy-agent", "target": "/etc/shadow"},
        {"timestamp": 2, "event_type": "file_write", "process_id": 5,
         "process_name": "curl", "target": "/etc/shadow"},
    ])
    result = evaluate_policy(events, policy)
    assert [finding["process_name"] for finding in result["findings"]] == ["curl"]
    assert result["suppressed_findings"] == 1
