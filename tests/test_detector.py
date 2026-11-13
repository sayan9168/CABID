from cabid.detector import analyze
from cabid.ingest import normalize_many


def complete_events():
    types = ["process_start", "process_exec", "file_write", "network_connect", "process_exit", "heartbeat"]
    return normalize_many([{"timestamp": 1000 + i * 5, "event_type": kind, "process_id": 10 + i, "parent_process_id": 1} for i, kind in enumerate(types)])


def test_complete_regular_stream_has_no_anomaly():
    report = analyze(complete_events())
    assert report["status"] == "NO_ANOMALY_DETECTED"
    assert report["completeness"]["completeness"] == 1.0


def test_missing_telemetry_is_not_called_safe():
    events = normalize_many([{"timestamp": 1000, "event_type": "process_start", "process_id": 7}])
    report = analyze(events)
    assert report["status"] == "INSUFFICIENT_EVIDENCE"
    assert report["completeness"]["missing_event_types"]


def test_unseen_parent_is_context_not_automatic_anomaly():
    report = analyze(complete_events())
    assert report["causal"]["orphan_parent_events"] == 6
    assert report["causal"]["causal_score"] == 0.0
    assert not any("ancestry" in reason for reason in report["reasons"])


def test_self_parent_is_scored():
    events = complete_events()
    events[0]["parent_process_id"] = events[0]["process_id"]
    report = analyze(events)
    assert report["causal"]["self_parent_events"] == 1
    assert report["causal"]["causal_score"] > 0


def test_sequence_contradiction_raises_score_and_is_explained():
    events = complete_events()
    baseline = analyze(events)
    events.append({"timestamp": events[-1]["timestamp"] + 1, "timestamp_iso": "x",
                   "event_type": "file_write", "process_id": 14,
                   "parent_process_id": 1, "process_name": "unknown", "executable": "",
                   "target": "/tmp/after-exit", "source": "test"})
    report = analyze(events)
    assert report["sequence"]["activity_after_exit"] >= 1
    assert report["anomaly_score"] > baseline["anomaly_score"]
    assert any(reason["code"] == "lifecycle_contradiction" for reason in report["reasons"])


def test_contributions_reconstruct_the_anomaly_score():
    report = analyze(complete_events())
    contribution = report["contribution"]
    # contribution is the share of the weighted sum, so it must be a valid distribution
    assert all(0.0 <= value <= 1.0 for value in contribution.values())
    assert abs(sum(contribution.values()) - report["anomaly_score"]) < 1e-6


def test_reasons_are_sorted_by_weighted_impact():
    events = complete_events()
    events[0]["parent_process_id"] = events[0]["process_id"]
    report = analyze(events)
    impacts = [reason["weight"] * reason["component_value"] for reason in report["reasons"]]
    assert impacts == sorted(impacts, reverse=True)


def test_config_changes_are_reflected_and_digest_changes():
    default = analyze(complete_events())
    tuned = analyze(complete_events(), {"weights": {"temporal": 1.0, "causal": 0.0, "sequence": 0.0,
                                                    "telemetry_gap": 0.0}})
    assert default["config_digest"] != tuned["config_digest"]
    assert tuned["components"]["causal"] == 0.0 or tuned["normalized_weights"]["causal"] == 0.0


def test_novelty_joins_the_score_only_with_a_baseline():
    from cabid.baseline import build_profile

    sessions = [(f"s{i}", complete_events()) for i in range(3)]
    profile = build_profile(sessions)
    without = analyze(complete_events())
    with_profile = analyze(complete_events(), profile=profile)
    assert without["baseline_used"] is False
    assert with_profile["baseline_used"] is True
    assert with_profile["normalized_weights"]["novelty"] > 0
    assert without["normalized_weights"]["novelty"] == 0.0


def test_empty_stream_does_not_crash():
    report = analyze([])
    assert report["status"] == "INSUFFICIENT_EVIDENCE"
    assert report["event_count"] == 0


def test_windowed_analysis_shape():
    from cabid.detector import analyze_windows

    events = complete_events()
    result = analyze_windows(events, 10)
    assert result["summary"]["window_count"] >= 1
    assert sum(result["summary"]["status_counts"].values()) == result["summary"]["window_count"]
    assert "aggregate" in result
    assert result["aggregate"]["event_count"] == len(events)


def test_window_length_must_be_positive():
    import pytest

    from cabid.detector import analyze_windows

    with pytest.raises(ValueError):
        analyze_windows(complete_events(), 0)


def test_threshold_bands_map_to_statuses():
    """A stream with enough classes to be sufficient must land in a band."""
    from cabid.detector import analyze, risk_level

    report = analyze(complete_events())
    assert report["status"] in {"NO_ANOMALY_DETECTED", "SUSPICIOUS", "HIGH_RISK"}
    assert risk_level(0.0) == "NO_ANOMALY_DETECTED"
    assert risk_level(1.0) == "HIGH_RISK"
    assert risk_level(0.7) == "SUSPICIOUS"


def test_a_baseline_from_the_config_is_loaded(tmp_path):
    import json

    from cabid.baseline import build_profile, write_profile
    from cabid.detector import analyze

    sessions = [("a", complete_events()), ("b", complete_events()),
                ("c", complete_events())]
    path = tmp_path / "profile.json"
    write_profile(build_profile(sessions), path)
    config = {"baseline": str(path)}
    report = analyze(complete_events(), config)
    assert report["baseline_used"] is True
    assert json.loads(path.read_text())["format"]


def test_empty_stream_is_insufficient_not_safe():
    from cabid.detector import analyze

    report = analyze([])
    assert report["status"] == "INSUFFICIENT_EVIDENCE"
    assert report["event_count"] == 0
    assert report["containers"]["container_aware"] is False
