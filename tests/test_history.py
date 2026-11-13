import sqlite3

import pytest

from cabid.detector import analyze
from cabid.history import (HistoryError, compare_runs, list_runs, record_run)
from cabid.ingest import read_jsonl


def reports():
    calm = analyze(read_jsonl("datasets/synthetic/example.jsonl"))
    noisy = analyze(read_jsonl("datasets/synthetic/suspicious-example.jsonl"))
    return calm, noisy


def test_record_and_list_runs(tmp_path):
    db = tmp_path / "h.sqlite3"
    calm, noisy = reports()
    first = record_run(calm, db, "calm", "example.jsonl")
    second = record_run(noisy, db, "noisy")
    assert (first, second) == (1, 2)
    rows = list_runs(db, limit=5)
    assert [row["label"] for row in rows] == ["noisy", "calm"]
    assert rows[0]["status"] == "SUSPICIOUS"
    assert rows[1]["status"] == "NO_ANOMALY_DETECTED"


def test_compare_reports_direction_and_codes(tmp_path):
    db = tmp_path / "h.sqlite3"
    calm, noisy = reports()
    record_run(calm, db, "calm")
    comparison = compare_runs(noisy, 1, db)
    assert comparison["score_delta"] > 0
    assert comparison["status_changed"] is True
    assert "self_parent_ancestry" in comparison["new_reason_codes"]
    assert comparison["config_changed"] is False


def test_history_stores_no_raw_event_content(tmp_path):
    db = tmp_path / "h.sqlite3"
    _, noisy = reports()
    record_run(noisy, db, "noisy", "datasets/synthetic/suspicious-example.jsonl")
    connection = sqlite3.connect(db)
    dump = "\n".join(line for line in connection.iterdump())
    connection.close()
    assert "/etc/shadow" not in dump
    assert "/tmp/.build/worker" not in dump
    assert "10.0.0.9" not in dump


def test_missing_run_raises(tmp_path):
    with pytest.raises(HistoryError, match="not found"):
        compare_runs(reports()[0], 99, tmp_path / "h.sqlite3")


def test_list_limit_validated(tmp_path):
    with pytest.raises(HistoryError):
        list_runs(tmp_path / "h.sqlite3", limit=0)


def test_non_database_file_is_reported(tmp_path):
    broken = tmp_path / "broken.sqlite3"
    broken.write_text("this is definitely not a database" * 50, encoding="utf-8")
    with pytest.raises(HistoryError):
        list_runs(broken)


def test_containments_are_recorded_and_listed(tmp_path):
    from cabid.history import list_containments, record_containment

    db = tmp_path / "h.sqlite3"
    record_containment(db, 401, "suspend_process", "digest")
    record_containment(db, 401, "kill_process")
    rows = list_containments(db)
    assert [row["action"] for row in rows] == ["kill_process", "suspend_process"]
    assert rows[0]["process_id"] == 401


def test_containment_records_store_nothing_about_the_process(tmp_path):
    from cabid.history import record_containment

    db = tmp_path / "h.sqlite3"
    record_containment(db, 401, "suspend_process", "digest")
    blob = db.read_bytes()
    for needle in (b"/tmp/.cache", b"evil", b"10.0.0.9", b"/etc/shadow"):
        assert needle not in blob


def test_containment_input_is_validated(tmp_path):
    import pytest

    from cabid.history import record_containment

    db = tmp_path / "h.sqlite3"
    with pytest.raises(ValueError):
        record_containment(db, 0, "kill_process")
    with pytest.raises(ValueError):
        record_containment(db, 5, "   ")
