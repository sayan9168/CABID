import pytest
from cabid.normalize import EventError, normalize_event

def test_normalize_event_fields():
    event = normalize_event({"timestamp": 1700000000, "event_type": "process_exec", "process_id": 42, "parent_process_id": 1})
    assert event["process_id"] == 42
    assert event["event_type"] == "process_exec"
    assert event["timestamp_iso"].startswith("2023-11-14T")

@pytest.mark.parametrize("payload", [None, {}, {"timestamp": -1, "event_type": "process_exec", "process_id": 1}, {"timestamp": 1, "event_type": "unknown", "process_id": 1}, {"timestamp": 1, "event_type": "process_exec", "process_id": 0}])
def test_invalid_events_rejected(payload):
    with pytest.raises(EventError):
        normalize_event(payload)
