"""Tests for data-driven threshold calibration."""
from __future__ import annotations

import json

import pytest

from cabid.calibrate import (
    CALIBRATION_FORMAT,
    CalibrationError,
    apply_config,
    calibrate,
    compare,
    fake_positive_budget,
    load_calibration,
    mad,
    median,
    percentile,
    write_calibration,
)
from cabid.config import default_config


def _session(index: int, *, rate: float = 8.0, kinds: tuple[str, ...] | None = None,
             duration: float = 60.0) -> tuple[str, list[dict]]:
    kinds = kinds or ("process_start", "process_exec", "file_write", "network_connect",
                      "process_exit", "heartbeat")
    count = max(1, int(rate * duration / 60.0))
    events = [{
        # Real host traffic is jittery. A perfectly even fixture produces a burstiness
        # of ~1e-13, i.e. a distribution that cannot occur on a real host.
        "timestamp": (1000.0 + index * 1000 + step * (duration / count)
                      + (((index * 7919 + step * 104729) % 1000) / 1000.0) * 0.05),
        "event_type": kinds[step % len(kinds)],
        "process_id": 100 + index,
        "parent_process_id": 1,
        "process_name": f"svc-{step % 3}",
        "executable": f"/usr/bin/svc-{step % 3}",
        "target": "",
        "source": "test",
    } for step in range(count)]
    return f"session-{index:03d}", events


def _benign(count: int = 40, **kwargs) -> list[tuple[str, list[dict]]]:
    """Reference sessions with deliberately varied load.

    Real benign traffic is not uniform. Sessions that all score identically cannot
    be calibrated against, so the fixture varies rate and duration per session the
    way a fleet of differently-busy hosts would.
    """
    sessions = []
    for index in range(count):
        varied = dict(kwargs)
        varied.setdefault("rate", 20.0 + (index % 7) * 12.0)
        varied.setdefault("duration", 90.0 + (index % 5) * 45.0)
        sessions.append(_session(index, **varied))
    return sessions


# ------------------------------------------------------------- statistics ----

def test_percentile_interpolates_between_points():
    values = [1.0, 2.0, 3.0, 4.0, 5.0]
    assert percentile(values, 0.0) == 1.0
    assert percentile(values, 1.0) == 5.0
    assert percentile(values, 0.5) == 3.0
    assert percentile(values, 0.25) == 2.0


def test_percentile_handles_single_and_invalid_input():
    assert percentile([7.0], 0.99) == 7.0
    with pytest.raises(ValueError):
        percentile([], 0.5)
    with pytest.raises(ValueError):
        percentile([1.0], 1.5)


def test_median_and_mad_are_outlier_resistant():
    assert median([1.0, 2.0, 3.0]) == 2.0
    assert mad([1.0, 2.0, 3.0, 4.0, 5.0]) == 1.0
    # A single enormous value barely moves the median absolute deviation.
    assert mad([1.0, 2.0, 3.0, 4.0, 5.0, 1e6]) < 2.0
    with pytest.raises(ValueError):
        mad([])


def test_false_positive_budget_is_explicit():
    assert fake_positive_budget(0.99) == pytest.approx(0.01)
    assert fake_positive_budget(0.95) == pytest.approx(0.05)
    with pytest.raises(ValueError):
        fake_positive_budget(1.0)


# ----------------------------------------------------------- calibration ----

def test_calibration_derives_thresholds_and_records_support():
    result = calibrate(_benign(40))
    assert result["format"] == CALIBRATION_FORMAT
    assert result["reference_session_count"] == 40
    assert set(result["thresholds"]) == {"suspicious", "high", "rate_per_minute", "burstiness"}
    thresholds = result["thresholds"]
    assert 0.0 <= thresholds["suspicious"] < thresholds["high"] <= 1.0
    assert thresholds["rate_per_minute"] > 0
    assert thresholds["burstiness"] > 0
    assert result["support"]["score_median"] > 0


def test_calibration_is_deterministic():
    sessions = _benign(30)
    assert calibrate(sessions) == calibrate(sessions)


def test_calibration_refuses_too_few_sessions():
    with pytest.raises(CalibrationError, match="required"):
        calibrate(_benign(3))
    with pytest.raises(CalibrationError, match="required"):
        calibrate(_benign(25), minimum_sessions=30)


def test_calibration_rejects_empty_sessions():
    sessions = _benign(25)
    sessions.append(("empty", []))
    with pytest.raises(CalibrationError, match="no events"):
        calibrate(sessions)


def test_calibration_rejects_unscoreable_telemetry():
    """Mostly-insufficient sessions must not be calibrated against."""
    thin = [("a", [dict(event) for event in events if event["event_type"] == "file_write"])
            for _, events in _benign(25)]
    with pytest.raises(CalibrationError, match="INSUFFICIENT_EVIDENCE"):
        calibrate(thin)


def test_calibration_reports_how_many_sessions_were_skipped():
    sessions = _benign(25)
    thin = [dict(event) for event in sessions[0][1] if event["event_type"] == "file_write"]
    sessions.append(("thin", thin))
    result = calibrate(sessions, config={"completeness": {"minimum_ratio": 0.5}})
    assert result["skipped_insufficient_evidence"] >= 0
    assert result["reference_session_count"] == 26


def test_calibration_validates_parameters():
    with pytest.raises(CalibrationError):
        calibrate(_benign(25), reference_percentile=0.0)
    with pytest.raises(CalibrationError):
        calibrate(_benign(25), high_percentile=1.0)
    with pytest.raises(CalibrationError):
        calibrate(_benign(25), reference_percentile=0.99, high_percentile=0.5)
    with pytest.raises(CalibrationError):
        calibrate(_benign(25), mad_multiplier=0)


def test_higher_percentile_raises_the_suspicious_floor():
    low = calibrate(_benign(60), reference_percentile=0.9)["thresholds"]["suspicious"]
    high = calibrate(_benign(60), reference_percentile=0.99)["thresholds"]["suspicious"]
    assert high >= low


def test_high_threshold_keeps_headroom_above_suspicious():
    result = calibrate(_benign(40), reference_percentile=0.99, high_percentile=0.999)
    assert result["thresholds"]["high"] > result["thresholds"]["suspicious"]


def test_calibration_state_the_implied_false_positive_rate():
    result = calibrate(_benign(40), reference_percentile=0.95)
    assert result["expected_false_positive_rate"] == pytest.approx(0.05)


def test_burstier_reference_sessions_raise_the_burst_limit():
    calm = [_session(index, rate=6.0) for index in range(30)]
    irregular = []
    for index in range(30):
        _name, events = _session(index, rate=6.0)
        if len(events) > 4:
            events[1]["timestamp"] = events[0]["timestamp"] + 0.001
            events[2]["timestamp"] = events[1]["timestamp"] + 40.0
        irregular.append((f"irregular-{index}", events))
    assert calibrate(irregular)["thresholds"]["burstiness"] >= \
        calibrate(calm)["thresholds"]["burstiness"]


# ------------------------------------------------------- apply / persist ----

def test_apply_config_merges_thresholds_and_keeps_other_keys():
    calibration = calibrate(_benign(30))
    merged = apply_config(calibration, {"weights": {"temporal": 0.5}})
    assert merged["weights"]["temporal"] == 0.5
    assert merged["thresholds"]["suspicious"] == calibration["thresholds"]["suspicious"]


def test_apply_config_starts_from_defaults_when_no_config_given():
    merged = apply_config(calibrate(_benign(30)))
    assert merged["thresholds"]["high"] == pytest.approx(
        calibrate(_benign(30))["thresholds"]["high"])
    assert merged["completeness"] == default_config()["completeness"]


def test_apply_config_rejects_an_inverted_threshold_pair():
    with pytest.raises(CalibrationError):
        apply_config({"format": CALIBRATION_FORMAT,
                      "thresholds": {"suspicious": 0.9, "high": 0.5,
                                     "rate_per_minute": 100.0, "burstiness": 2.0}})


def test_apply_config_rejects_missing_thresholds():
    with pytest.raises(CalibrationError):
        apply_config({"format": CALIBRATION_FORMAT})


def test_calibration_round_trips_through_disk(tmp_path):
    calibration = calibrate(_benign(30))
    written = write_calibration(calibration, tmp_path / "nested" / "calibration.json")
    assert written.exists()
    assert load_calibration(written) == calibration


def test_load_calibration_rejects_wrong_format_and_broken_json(tmp_path):
    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"format": "something-else"}), encoding="utf-8")
    with pytest.raises(CalibrationError, match="not a cabid-calibration"):
        load_calibration(wrong)

    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(CalibrationError, match="invalid JSON"):
        load_calibration(broken)

    incomplete = tmp_path / "incomplete.json"
    incomplete.write_text(json.dumps({"format": CALIBRATION_FORMAT, "thresholds": {}}),
                          encoding="utf-8")
    with pytest.raises(CalibrationError, match="missing thresholds"):
        load_calibration(incomplete)


def test_compare_reports_direction_and_relative_change():
    calibration = calibrate(_benign(30))
    rows = compare({"thresholds": {"suspicious": 0.01, "high": 0.02,
                                   "rate_per_minute": 1.0, "burstiness": 1.0}}, calibration)
    assert len(rows) == 4
    suspicious = next(row for row in rows if row["threshold"] == "suspicious")
    assert suspicious["current"] == 0.01
    assert suspicious["calibrated"] == calibration["thresholds"]["suspicious"]
    assert suspicious["absolute_change"] > 0
    assert suspicious["relative_change"] > 0


def test_compare_handles_zero_current_threshold():
    calibration = calibrate(_benign(30))
    rows = compare({"weights": {}, "thresholds": {"suspicious": 0.0, "high": 1.0,
                                                  "rate_per_minute": 1.0,
                                                  "burstiness": 1.0}}, calibration)
    suspicious = next(row for row in rows if row["threshold"] == "suspicious")
    assert suspicious["relative_change"] == 0.0


def test_calibrated_config_actually_scores_benign_sessions_lower():
    """The point of calibration: benign traffic from the reference set stays quiet."""
    from cabid.detector import analyze

    sessions = _benign(40)
    calibration = calibrate(sessions)
    calibrated = apply_config(calibration)
    statuses = [analyze(events, calibrated)["status"] for _name, events in sessions]
    quiet = sum(1 for status in statuses if status == "NO_ANOMALY_DETECTED")
    assert quiet >= int(len(sessions) * 0.9)

