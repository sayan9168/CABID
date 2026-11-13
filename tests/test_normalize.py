import pytest
from cabid.normalize import EventError, normalize_event


def test_rejects_nan_and_infinite_timestamps():
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(EventError):
            normalize_event({"timestamp": value, "event_type": "heartbeat", "process_id": 1})


def test_rejects_boolean_and_fractional_process_ids():
    for value in (True, 1.5, "1.5"):
        with pytest.raises(EventError):
            normalize_event({"timestamp": 1, "event_type": "heartbeat", "process_id": value})


def test_rejects_out_of_range_datetime():
    with pytest.raises(EventError):
        normalize_event({"timestamp": 1e100, "event_type": "heartbeat", "process_id": 1})
