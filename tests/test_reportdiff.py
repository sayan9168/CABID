import copy

import pytest

from cabid.detector import analyze
from cabid.ingest import read_jsonl
from cabid.policy import evaluate_policy, load_policy
from cabid.reportdiff import (ReportDiffError, compare_reports, is_regression,
                              render_markdown, render_text, summary_of)


def _with_policy(path):
    events = read_jsonl(path)
    report = analyze(events)
    report["policy"] = evaluate_policy(events, load_policy(None), report.get("reasons"))
    return report


def calm():
    return _with_policy("datasets/synthetic/example.jsonl")


def noisy():
    report = _with_policy("datasets/synthetic/suspicious-example.jsonl")
    # Keep the config identical so score comparisons stay meaningful.
    report["config_digest"] = calm()["config_digest"]
    return report


def test_identical_reports_are_unchanged():
    diff = compare_reports(calm(), calm())
    assert diff["verdict"] == "unchanged"
    assert diff["comparable"] is True
    assert diff["score_delta"] == 0.0
    assert diff["status"]["changed"] is False
    assert is_regression(diff) is False


def test_higher_score_is_a_regression():
    diff = compare_reports(calm(), noisy())
    assert diff["verdict"] == "regression"
    assert diff["score_delta"] > 0
    assert diff["status"]["risk_direction"] == "worsened"
    assert "self_parent_ancestry" in diff["reason_codes"]["added"]
    assert "no_heuristic_triggered" in diff["reason_codes"]["removed"]
    assert is_regression(diff) is True


def test_reverse_direction_is_an_improvement():
    diff = compare_reports(noisy(), calm())
    assert diff["verdict"] == "improvement"
    assert diff["score_delta"] < 0
    assert diff["status"]["risk_direction"] == "improved"


def test_different_config_digests_are_not_comparable():
    after = copy.deepcopy(calm())
    after["config_digest"] = "0" * 64
    diff = compare_reports(calm(), after, after_origin="after.json")
    assert diff["comparable"] is False
    assert diff["verdict"] == "not-comparable"
    assert diff["score_delta"] is None
    assert any("config_digest differs" in warning for warning in diff["warnings"])


def test_missing_digest_is_flagged():
    before = copy.deepcopy(calm())
    before.pop("config_digest")
    diff = compare_reports(before, calm())
    assert diff["comparable"] is False
    assert any("no config_digest" in warning for warning in diff["warnings"])


def test_evidence_lost_is_its_own_verdict():
    after = copy.deepcopy(calm())
    after["status"] = "INSUFFICIENT_EVIDENCE"
    after["completeness"]["telemetry_sufficient"] = False
    diff = compare_reports(calm(), after)
    assert diff["verdict"] == "evidence-lost"
    assert diff["evidence_lost"] is True
    assert is_regression(diff) is True
    assert any("loss of evidence" in warning for warning in diff["warnings"])


def test_evidence_gained_is_reported_separately():
    before = copy.deepcopy(calm())
    before["status"] = "INSUFFICIENT_EVIDENCE"
    diff = compare_reports(before, calm())
    assert diff["verdict"] == "evidence-gained"
    assert diff["evidence_gained"] is True
    assert diff["status"]["risk_direction"] == "unknown"


def test_epsilon_controls_the_score_gate():
    before = calm()
    after = copy.deepcopy(before)
    after["anomaly_score"] = float(before["anomaly_score"]) + 0.005
    assert compare_reports(before, after, epsilon=0.01)["verdict"] == "unchanged"
    assert compare_reports(before, after, epsilon=0.001)["verdict"] == "regression"


def test_component_deltas_are_directional():
    diff = compare_reports(calm(), noisy())
    assert diff["component_delta"]["causal"] > 0
    assert diff["component_delta"]["telemetry_gap"] == 0.0


def test_rule_policy_and_process_deltas():
    diff = compare_reports(calm(), noisy())
    assert "sensitive-write-then-egress" in diff["rules"]["new"]
    assert any(key.startswith("sensitive_path_write") for key in diff["policy"]["new"])
    assert "worker-0" in diff["processes"]["new"]
    assert "systemd" in diff["processes"]["disappeared"]
    assert diff["event_classes"]["newly_missing"] == []


def test_missing_event_classes_are_tracked():
    before = calm()
    after = copy.deepcopy(before)
    after["completeness"]["missing_event_types"] = ["process_exit"]
    diff = compare_reports(before, after)
    assert diff["event_classes"]["newly_missing"] == ["process_exit"]
    assert diff["verdict"] == "changed"


def test_window_block_when_both_reports_are_windowed():
    before = analyze(read_jsonl("datasets/synthetic/example.jsonl"))
    from cabid.detector import analyze_windows

    events = read_jsonl("datasets/synthetic/example.jsonl")
    before["windowed"] = analyze_windows(events, 10)
    after = copy.deepcopy(before)
    after["windowed"]["summary"]["worst_status"] = "HIGH_RISK"
    diff = compare_reports(before, after)
    windows = diff["windows"]
    assert windows["present"] is True
    assert windows["worst_status_after"] == "HIGH_RISK"
    assert windows["flagged_window_delta"] >= 0


def test_window_block_with_one_side_only_is_explained():
    before = calm()
    after = copy.deepcopy(before)
    after["windowed"] = {"summary": {"window_count": 1, "status_counts": {},
                                     "worst_status": "NO_ANOMALY_DETECTED"}}
    diff = compare_reports(before, after)
    assert diff["windows"]["present"] is False
    assert "only one report" in diff["windows"]["note"]


def test_stream_reports_compare_on_flagged_window_rate():
    before = {"format": "cabid-stream/1", "window_count": 2,
              "events_normalized": 40, "windows_scored": [{}, {}],
              "status_counts": {"NO_ANOMALY_DETECTED": 1, "SUSPICIOUS": 1},
              "flagged_window_rate": 0.5, "config_digest": "a" * 64}
    after = copy.deepcopy(before)
    after["status_counts"] = {"SUSPICIOUS": 2}
    after["flagged_window_rate"] = 1.0
    diff = compare_reports(before, after)
    assert diff["score_field"] == "flagged_window_rate"
    assert diff["score_delta"] == 0.5
    assert diff["verdict"] == "regression"
    assert diff["after"]["event_count"] == 40


def test_mixed_report_kinds_are_not_compared():
    stream = {"windows_scored": [], "status_counts": {}, "flagged_window_rate": 0.0,
              "config_digest": "a" * 64, "events_normalized": 0}
    diff = compare_reports(calm(), stream)
    assert diff["comparable"] is False
    assert any("different things" in warning for warning in diff["warnings"])
    assert diff["verdict"] == "not-comparable"


def test_fleet_reports_are_rejected_with_guidance():
    with pytest.raises(ReportDiffError, match="fleet report"):
        summary_of({"format": "cabid-fleet/1", "hosts": []})


def test_non_reports_are_rejected():
    with pytest.raises(ReportDiffError, match="JSON object"):
        summary_of(["not", "a", "report"])
    with pytest.raises(ReportDiffError, match="no status"):
        summary_of({"hello": "world"})


def test_renderers_include_the_essentials():
    diff = compare_reports(calm(), noisy())
    text = render_text(diff)
    assert "REGRESSION" in text
    assert "reasons added" in text
    assert diff["caveat"] in text
    markdown = render_markdown(diff)
    assert "# CABID report diff — regression" in markdown
    assert "| Score |" in markdown
    assert "## Caveat" in markdown


def test_uncomparable_text_says_so():
    after = copy.deepcopy(calm())
    after["config_digest"] = "b" * 64
    text = render_text(compare_reports(calm(), after))
    assert "not comparable" in text
    assert "scores are not comparable" in text


def test_rules_block_accepts_a_findings_shaped_report():
    before = {"status": "NO_ANOMALY_DETECTED", "anomaly_score": 0.1, "config_digest": "c" * 64,
              "rules": {"findings": [{"rule_id": "a"}, {"rule_id": "a"}, {"rule_id": "b"}]}}
    after = copy.deepcopy(before)
    after["rules"]["findings"] = [{"rule_id": "b"}]
    diff = compare_reports(before, after)
    assert diff["rules"]["cleared"] == ["a"]
    assert diff["rules"]["count_delta"] == {"a": {"before": 2, "after": 0}}


def test_process_block_tolerates_missing_entity_rollup():
    diff = compare_reports({"status": "NO_ANOMALY_DETECTED", "anomaly_score": 0.0,
                            "config_digest": "d" * 64},
                           {"status": "NO_ANOMALY_DETECTED", "anomaly_score": 0.0,
                            "config_digest": "d" * 64})
    assert diff["processes"] == {"new": [], "disappeared": []}


def test_text_render_names_evidence_loss():
    before = calm()
    after = copy.deepcopy(before)
    after["status"] = "INSUFFICIENT_EVIDENCE"
    text = render_text(compare_reports(before, after))
    assert "EVIDENCE-LOST" in text


def test_markdown_render_handles_every_verdict():
    before = calm()
    after = copy.deepcopy(before)
    after["status"] = "INSUFFICIENT_EVIDENCE"
    markdown = render_markdown(compare_reports(before, after))
    assert "# CABID report diff — evidence-lost" in markdown
