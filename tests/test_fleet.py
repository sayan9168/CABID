"""Tests for fleet aggregation and comparison."""
from __future__ import annotations

import json

import pytest

from cabid.fleet import (
    SILENT_HOST_DEGRADED_RATIO,
    FleetError,
    collect,
    compare,
    host_summary,
    render_markdown,
    summarize,
)


def _session(score: float = 0.1, status: str = "NO_ANOMALY_DETECTED") -> dict:
    return {
        "status": status,
        "anomaly_score": score,
        "event_count": 500,
        "completeness": {"completeness": 1.0},
        "reasons": [{"code": "no_heuristic_triggered"}],
    }


def _stream(suspicious: int = 0, quiet: int = 10) -> dict:
    return {
        "format": "cabid-stream-report/1",
        "status_counts": {"SUSPICIOUS": suspicious, "NO_ANOMALY_DETECTED": quiet},
        "flagged_window_rate": suspicious / (suspicious + quiet),
        "window_count": suspicious + quiet,
        "events_normalized": 9000,
    }


def _write(path, payload) -> str:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


# --------------------------------------------------------- host summary ----

def test_host_summary_reads_a_session_report():
    row = host_summary(_session(0.71, "SUSPICIOUS"), host="web-01")
    assert row["shape"] == "session"
    assert row["host"] == "web-01"
    assert row["anomaly_score"] == 0.71
    assert row["needs_attention"] is True
    assert row["coverage"] == 1.0


def test_host_summary_reads_a_stream_report():
    row = host_summary(_stream(suspicious=2), host="db-01")
    assert row["shape"] == "stream"
    assert row["status"] == "SUSPICIOUS"
    assert row["window_count"] == 12
    assert row["needs_attention"] is True


def test_host_summary_reads_a_drift_report():
    row = host_summary({"drifted": True, "features": [{"feature": "event_type_mix"}]},
                       host="cache-01")
    assert row["shape"] == "drift"
    assert row["drifted"] is True
    assert row["status"] == "DRIFT"
    assert row["reasons"] == ["event_type_mix"]


def test_host_summary_reads_a_baseline_validation_report():
    row = host_summary({"verdict": "NEEDS_REFIT", "coverage": 0.75, "session_count": 40},
                       host="edge-01")
    assert row["shape"] == "baseline-validation"
    assert row["baseline_verdict"] == "NEEDS_REFIT"
    assert row["needs_attention"] is True


def test_host_summary_rejects_an_unknown_shape():
    with pytest.raises(FleetError, match="unrecognized report shape"):
        host_summary({"something": 1}, host="x")


def test_host_summary_requires_a_host_identifier():
    with pytest.raises(FleetError, match="host identifier"):
        host_summary(_session())


def test_host_summary_derives_the_host_from_the_path():
    row = host_summary(_session(), path="/tmp/reports/web-07.json")
    assert row["host"] == "web-07"


def test_host_summary_does_not_flag_a_quiet_host():
    row = host_summary(_session(0.02), host="quiet")
    assert row["needs_attention"] is False


# --------------------------------------------------------------- collect ----

def test_collect_builds_a_fleet_view(tmp_path):
    entries = [
        ("web-01", _write(tmp_path / "a.json", _session(0.9, "HIGH_RISK"))),
        ("web-02", _write(tmp_path / "b.json", _session(0.02))),
        ("db-01", _write(tmp_path / "c.json", _stream(suspicious=1))),
    ]
    fleet = collect(entries)
    assert fleet["format"] == "cabid-fleet-report/1"
    assert fleet["host_count"] == 3
    assert fleet["status_counts"]["HIGH_RISK"] == 1
    assert [row["host"] for row in fleet["attention_hosts"]] == ["web-01", "db-01"]


def test_collect_rejects_duplicate_hosts(tmp_path):
    first = _write(tmp_path / "a.json", _session())
    second = _write(tmp_path / "b.json", _session())
    with pytest.raises(FleetError, match="more than once"):
        collect([("web-01", first), ("web-01", second)])


def test_collect_requires_input(tmp_path):
    with pytest.raises(FleetError, match="at least one"):
        collect([])


def test_collect_reports_missing_files_and_bad_json(tmp_path):
    with pytest.raises(FleetError, match="not found"):
        collect([("x", tmp_path / "absent.json")])
    broken = tmp_path / "broken.json"
    broken.write_text("{oops", encoding="utf-8")
    with pytest.raises(FleetError, match="invalid JSON"):
        collect([("x", broken)])
    array = tmp_path / "array.json"
    array.write_text("[]", encoding="utf-8")
    with pytest.raises(FleetError, match="JSON object"):
        collect([("x", array)])


# ------------------------------------------------------------- summarize ----

def test_summarize_ranks_hosts_by_their_own_scores(tmp_path):
    rows = [host_summary(_session(0.3), host="b"),
            host_summary(_session(0.8, "HIGH_RISK"), host="a"),
            host_summary(_session(0.1), host="c")]
    fleet = summarize(rows)
    assert [row["host"] for row in fleet["ranking"]] == ["a", "b", "c"]
    assert fleet["ranking"][0]["rank"] == 1
    assert fleet["score_spread"]["max"] == 0.8


def test_summarize_reports_silent_hosts(tmp_path):
    rows = [host_summary(_session(), host="web-01")]
    fleet = summarize(rows, expected_hosts=["web-01", "web-02", "web-03"])
    assert fleet["silent_hosts"] == ["web-02", "web-03"]
    assert fleet["silent_host_ratio"] == pytest.approx(2 / 3, abs=1e-6)
    assert fleet["degraded"] is True
    assert any("did not report" in finding for finding in fleet["findings"])


def test_summarize_is_not_degraded_below_the_silent_threshold():
    rows = [host_summary(_session(), host=f"h{index}") for index in range(20)]
    fleet = summarize(rows, expected_hosts=[f"h{index}" for index in range(21)])
    assert fleet["silent_host_ratio"] == pytest.approx(1 / 21, abs=1e-6)
    assert fleet["degraded"] is False
    assert SILENT_HOST_DEGRADED_RATIO == 0.10


def test_summarize_reports_unexpected_hosts():
    rows = [host_summary(_session(), host="surprise")]
    fleet = summarize(rows, expected_hosts=["web-01"])
    assert fleet["unexpected_hosts"] == ["surprise"]
    assert any("not expected" in finding for finding in fleet["findings"])


def test_summarize_without_expectations_is_not_degraded():
    fleet = summarize([host_summary(_session(), host="a")])
    assert fleet["expected_host_count"] == 0
    assert fleet["degraded"] is False


def test_summarize_rejects_empty_and_duplicate_rows():
    with pytest.raises(FleetError):
        summarize([])
    rows = [host_summary(_session(), host="a"), host_summary(_session(), host="a")]
    with pytest.raises(FleetError, match="duplicates"):
        summarize(rows)


def test_summarize_states_that_silence_matters():
    fleet = summarize([host_summary(_session(), host="a")])
    assert any("went dark" in note for note in fleet["notes"])


# --------------------------------------------------------------- compare ----

def _rows(**scores) -> list[dict]:
    return [host_summary(_session(score, "HIGH_RISK" if score > 0.7 else "NO_ANOMALY_DETECTED"),
                         host=name) for name, score in scores.items()]


def test_compare_reports_worsened_and_improved_hosts():
    before = _rows(a=0.1, b=0.8, c=0.4)
    after = _rows(a=0.9, b=0.2, c=0.4)
    result = compare(before, after)
    assert [row["host"] for row in result["worsened"]] == ["a"]
    assert [row["host"] for row in result["improved"]] == ["b"]
    assert result["unchanged_count"] == 1
    assert result["worsened"][0]["direction"] == "worse"


def test_compare_reports_appeared_and_disappeared_hosts():
    result = compare(_rows(a=0.1, b=0.2), _rows(a=0.1, c=0.3))
    assert result["appeared"] == ["c"]
    assert result["disappeared"] == ["b"]
    assert any("decommissioned" in note for note in result["notes"])


def test_compare_detects_a_status_change_at_equal_score():
    before = [host_summary(_session(0.5, "SUSPICIOUS"), host="a")]
    after = [host_summary(_session(0.5, "HIGH_RISK"), host="a")]
    result = compare(before, after)
    assert result["status_only_changes"]
    assert result["status_only_changes"][0]["direction"] == "status-only"


def test_compare_requires_both_snapshots():
    with pytest.raises(FleetError):
        compare([], _rows(a=0.1))
    with pytest.raises(FleetError):
        compare(_rows(a=0.1), [])


def test_compare_rejects_duplicates_within_a_snapshot():
    duplicated = _rows(a=0.1) + _rows(a=0.2)
    with pytest.raises(FleetError, match="duplicate"):
        compare(duplicated, _rows(a=0.1))


# -------------------------------------------------------------- markdown ----

def test_markdown_lists_silent_hosts_and_attention_rows():
    fleet = summarize(
        [host_summary(_session(0.9, "HIGH_RISK"), host="web-01"),
         host_summary(_session(0.02), host="web-02")],
        expected_hosts=["web-01", "web-02", "web-03"])
    text = render_markdown(fleet)
    assert "# CABID fleet report" in text
    assert "Silent hosts" in text and "web-03" in text
    assert "| web-01 | HIGH_RISK |" in text
    assert "not assessments of intent" in text


def test_markdown_handles_a_quiet_fleet():
    text = render_markdown(summarize([host_summary(_session(0.01), host="a")]))
    assert "None." in text
    assert "triages" not in text.lower()


def test_markdown_formats_missing_numbers():
    from cabid.fleet import _fmt

    assert _fmt(None) == "-"
    assert _fmt(0.5) == "0.500"
    assert _fmt("text") == "text"
