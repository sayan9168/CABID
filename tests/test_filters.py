import pytest

from cabid.filters import FilterError, filter_events, parse_timestamp, resolve_range
from cabid.ingest import normalize_many


def make(*stamps):
    return normalize_many([{"timestamp": stamp, "event_type": "heartbeat", "process_id": 1}
                           for stamp in stamps])


def test_parse_unix_and_iso():
    assert parse_timestamp("1750000000") == 1750000000.0
    assert parse_timestamp(1750000000) == 1750000000.0
    assert parse_timestamp("2026-11-13T12:00:00Z") == 1794571200.0
    assert parse_timestamp("2026-11-13T12:00:00+00:00") == 1794571200.0
    assert parse_timestamp(None) is None


def test_naive_iso_is_treated_as_utc():
    assert parse_timestamp("2026-11-13T12:00:00") == parse_timestamp("2026-11-13T12:00:00Z")


@pytest.mark.parametrize("bad", ["yesterday", "13/11/2026", True])
def test_invalid_timestamps_rejected(bad):
    with pytest.raises(FilterError):
        parse_timestamp(bad)


def test_reversed_range_rejected():
    with pytest.raises(FilterError, match="earlier"):
        resolve_range(200, 100)


def test_filter_keeps_inclusive_bounds():
    events = make(10, 20, 30, 40)
    kept, window = filter_events(events, 20, 30)
    assert [event["timestamp"] for event in kept] == [20.0, 30.0]
    assert window["events_removed"] == 2
    assert window["active"] is True
    assert window["since_iso"].startswith("1970-01-01T00:00:20")


def test_open_ended_ranges():
    events = make(10, 20, 30)
    assert len(filter_events(events, since=15)[0]) == 2
    assert len(filter_events(events, until=15)[0]) == 1
    assert len(filter_events(events)[0]) == 3


def test_inactive_range_reports_passthrough():
    events = make(10, 20)
    kept, window = filter_events(events)
    assert kept is events
    assert window["active"] is False
    assert window["events_in"] == window["events_out"] == 2
    assert window["events_removed"] == 0
