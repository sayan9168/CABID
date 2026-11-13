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
