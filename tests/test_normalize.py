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


def test_boolean_timestamp_and_pid_are_rejected():
    import pytest

    from cabid.normalize import EventError, normalize_event

    base = {"timestamp": 1, "event_type": "heartbeat", "process_id": 1,
            "parent_process_id": 0, "process_name": "a"}
    with pytest.raises(EventError, match="finite Unix timestamp"):
        normalize_event({**base, "timestamp": True})
    with pytest.raises(EventError, match="process_id must be an integer"):
        normalize_event({**base, "process_id": True})


def test_non_integer_pid_and_fractional_pid_are_rejected():
    import pytest

    from cabid.normalize import EventError, normalize_event

    base = {"timestamp": 1, "event_type": "heartbeat", "process_name": "a",
            "parent_process_id": 0}
    with pytest.raises(EventError):
        normalize_event({**base, "process_id": "one"})
    with pytest.raises(EventError):
        normalize_event({**base, "process_id": 1.5})
    # A numeric string that round-trips is fine.
    assert normalize_event({**base, "process_id": "7"})["process_id"] == 7


def test_negative_or_negative_namespace_pid_is_rejected():
    import pytest

    from cabid.normalize import EventError, normalize_event

    base = {"timestamp": 1, "event_type": "heartbeat", "process_id": 1,
            "parent_process_id": 0, "process_name": "a"}
    with pytest.raises(EventError, match="non-negative"):
        normalize_event({**base, "pid_ns": -1})
    with pytest.raises(EventError, match="process_id must be positive"):
        normalize_event({**base, "process_id": 0})


def test_container_fields_are_optional_and_trimmed():
    from cabid.normalize import normalize_event

    base = {"timestamp": 1, "event_type": "heartbeat", "process_id": 1,
            "parent_process_id": 0, "process_name": "a"}
    assert "container_id" not in normalize_event(base)
    lean = normalize_event({**base, "container_id": "  abc123  ", "namespace_pid": 4})
    assert lean["container_id"] == "abc123"
    assert lean["namespace_pid"] == 4


def test_empty_container_id_is_dropped():
    from cabid.normalize import normalize_event

    base = {"timestamp": 1, "event_type": "heartbeat", "process_id": 1,
            "parent_process_id": 0, "process_name": "a"}
    assert "container_id" not in normalize_event({**base, "container_id": "   "})


def test_missing_required_fields_are_all_named():
    import pytest

    from cabid.normalize import EventError, normalize_event

    with pytest.raises(EventError, match="missing required fields"):
        normalize_event({"timestamp": 1})
