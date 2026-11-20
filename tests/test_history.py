import sqlite3

import pytest

from cabid.detector import analyze
from cabid.history import (HistoryError, compare_runs, history_stats, list_runs,
                           prune_history, record_run)
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


def test_stats_describe_an_empty_database(tmp_path):
    stats = history_stats(tmp_path / "h.sqlite3")
    assert stats["format"] == "cabid-history-stats/1"
    assert stats["run_count"] == 0
    assert stats["first_run_at"] is None
    assert stats["max_anomaly_score"] is None
    assert stats["rule_matches_by_code"] == {}
    assert "no event content" in stats["note"]


def test_stats_aggregate_runs(tmp_path):
    db = tmp_path / "h.sqlite3"
    calm, noisy = reports()
    record_run(calm, db, "calm")
    record_run(noisy, db, "noisy", "datasets/synthetic/suspicious-example.jsonl")
    stats = history_stats(db)
    assert stats["run_count"] == 2
    assert stats["status_counts"]["SUSPICIOUS"] == 1
    assert stats["max_anomaly_score"] == pytest.approx(noisy["anomaly_score"], abs=1e-6)
    assert stats["first_run_at"] is not None and stats["last_run_at"] is not None
    assert "sensitive-write-then-egress" in stats["rule_matches_by_code"]
    assert stats["db_bytes"] > 0


def test_stats_do_not_leak_paths_or_addresses(tmp_path):
    db = tmp_path / "h.sqlite3"
    record_run(reports()[1], db, "noisy", "/tmp/secret/input.jsonl")
    payload = repr(history_stats(db))
    for needle in ("/etc/shadow", "10.0.0.9", "/tmp/.build/worker"):
        assert needle not in payload


def test_prune_requires_a_rule(tmp_path):
    with pytest.raises(HistoryError, match="refusing to guess"):
        prune_history(tmp_path / "h.sqlite3")


def test_prune_rejects_negative_keep(tmp_path):
    db = tmp_path / "h.sqlite3"
    record_run(reports()[0], db, "calm")
    with pytest.raises(HistoryError, match="keep_last"):
        prune_history(db, keep_last=-1)


def test_prune_is_a_dry_run_by_default(tmp_path):
    db = tmp_path / "h.sqlite3"
    calm, noisy = reports()
    record_run(calm, db, "calm")
    record_run(noisy, db, "noisy")
    preview = prune_history(db, keep_last=1)
    assert preview["dry_run"] is True
    assert preview["selected"] == 1
    assert preview["deleted"] == 0
    assert [row["label"] for row in preview["runs"]] == ["calm"]
    assert "nothing was deleted" in preview["note"]
    assert len(list_runs(db)) == 2


def test_prune_applies_and_keeps_the_newest(tmp_path):
    db = tmp_path / "h.sqlite3"
    calm, noisy = reports()
    for label in ("first", "second", "third"):
        record_run(calm if label != "third" else noisy, db, label)
    result = prune_history(db, keep_last=2, dry_run=False)
    assert result["deleted"] == 1
    assert result["run_count_before"] == 3
    remaining = [row["label"] for row in list_runs(db)]
    assert remaining == ["third", "second"]
    assert "cannot be recovered" in result["note"]


def test_prune_older_than_days_respects_keep_last(tmp_path):
    db = tmp_path / "h.sqlite3"
    record_run(reports()[0], db, "recent")
    preview = prune_history(db, keep_last=1, older_than_days=0.000001)
    assert preview["selected"] == 0
    assert "nothing matched the retention rule" in preview["note"]


def test_prune_selects_only_by_age_when_keep_is_absent(tmp_path):
    db = tmp_path / "h.sqlite3"
    record_run(reports()[0], db, "calm")
    # Backdate the row so an age rule can see it.
    connection = sqlite3.connect(db)
    connection.execute("UPDATE runs SET created_at = '2000-01-01T00:00:00+00:00'")
    connection.commit()
    connection.close()
    preview = prune_history(db, older_than_days=1)
    assert preview["selected"] == 1
    applied = prune_history(db, older_than_days=1, dry_run=False)
    assert applied["deleted"] == 1
    assert list_runs(db) == []


def test_prune_reports_an_unreadable_timestamp(tmp_path):
    db = tmp_path / "h.sqlite3"
    record_run(reports()[0], db, "calm")
    connection = sqlite3.connect(db)
    connection.execute("UPDATE runs SET created_at = 'not-a-date'")
    connection.commit()
    connection.close()
    with pytest.raises(HistoryError, match="created_at"):
        prune_history(db, older_than_days=1)


def test_prune_can_vacuum(tmp_path):
    db = tmp_path / "h.sqlite3"
    for index in range(3):
        record_run(reports()[0], db, f"run-{index}")
    result = prune_history(db, keep_last=1, dry_run=False, vacuum=True)
    assert result["deleted"] == 2
    assert result["vacuumed"] is True
    assert len(list_runs(db)) == 1
