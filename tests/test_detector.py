from cabid.detector import analyze
from cabid.ingest import normalize_many

def complete_events():
    types = ["process_start", "process_exec", "file_write", "network_connect", "process_exit", "heartbeat"]
    return normalize_many([{"timestamp": 1000 + i * 5, "event_type": kind, "process_id": 10 + i, "parent_process_id": 0} for i, kind in enumerate(types)])

def test_complete_regular_stream_has_no_anomaly():
    report = analyze(complete_events())
    assert report["status"] == "NO_ANOMALY_DETECTED"
    assert report["completeness"]["completeness"] == 1.0

def test_missing_telemetry_is_not_called_safe():
    events = normalize_many([{"timestamp": 1000, "event_type": "process_start", "process_id": 7}])
    report = analyze(events)
    assert report["status"] == "INSUFFICIENT_EVIDENCE"
    assert report["completeness"]["missing_event_types"]

def test_orphan_parent_is_explained():
    kinds = ["process_start", "process_exec", "file_write", "network_connect", "process_exit", "heartbeat"]
    events = normalize_many([{"timestamp": 1000 + i, "event_type": kind, "process_id": 7 + i, "parent_process_id": 999 if i == 1 else 0} for i, kind in enumerate(kinds)])
    report = analyze(events)
    assert report["causal"]["orphan_parent_events"] == 1
    assert any("ancestry" in reason for reason in report["reasons"])
