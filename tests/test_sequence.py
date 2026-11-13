import pytest

from cabid.ingest import normalize_many
from cabid.sequence import sequence_features


def events(*spec):
    return normalize_many([
        {"timestamp": timestamp, "event_type": kind, "process_id": pid, "parent_process_id": 1}
        for timestamp, kind, pid in spec
    ])


def test_clean_lifecycle_has_no_contradiction():
    result = sequence_features(events(
        (1, "process_start", 10), (2, "process_exec", 10), (3, "file_write", 10), (4, "process_exit", 10)))
    assert result["contradiction_events"] == 0
    assert result["sequence_score"] == 0.0
    assert {"from": "process_start", "to": "process_exec", "count": 1} in result["common_transitions"]


def test_activity_after_exit_is_scored():
    result = sequence_features(events(
        (1, "process_start", 10), (2, "process_exit", 10), (3, "file_write", 10)))
    assert result["activity_after_exit"] == 1
    assert result["contradiction_events"] == 1
    assert 0 < result["sequence_score"] <= 1


def test_duplicate_start_and_duplicate_exit_are_scored():
    result = sequence_features(events(
        (1, "process_start", 10), (2, "process_start", 10), (3, "process_exit", 10), (4, "process_exit", 10)))
    assert result["duplicate_start"] == 1
    assert result["duplicate_exit"] == 1
    assert result["contradiction_events"] == 2


def test_restart_after_exit_is_not_a_contradiction():
    result = sequence_features(events(
        (1, "process_start", 10), (2, "process_exit", 10),
        (3, "process_start", 10), (4, "network_connect", 10)))
    assert result["contradiction_events"] == 0


def test_exit_without_start_is_window_artefact_not_contradiction():
    result = sequence_features(events((1, "process_exit", 99)))
    assert result["contradiction_events"] == 0


def test_score_is_capped_and_amplification_validated():
    many = sequence_features(events(*[(i, "process_exit", 10) for i in range(1, 20)]), amplification=50.0)
    assert many["sequence_score"] == 1.0
    with pytest.raises(ValueError):
        sequence_features([], amplification=0)
