"""Tests for cabid.host_benchmark — real-host benchmark framework."""

from __future__ import annotations

import json

import pytest

from cabid.host_benchmark import (
    DEFAULT_COMPLETENESS_CLASSES,
    LABEL_ATTACK,
    LABEL_BENIGN,
    default_config,
    load_sessions,
    metrics,
    render_markdown,
    run_host_benchmark,
    wilson_interval,
)

KINDS = ("process_start", "process_exec", "file_write", "network_connect",
         "process_exit", "heartbeat")


def _session_event(index: int, kind: str, pid: int = 100,
                   executable: str = "/usr/bin/svc") -> dict:
    return {
        "timestamp": 1000.0 + index * 0.1,
        "event_type": kind,
        "process_id": pid,
        "parent_process_id": 1,
        "process_name": "svc",
        "executable": executable,
        "target": "",
        "source": "procfs-poll",
    }


def _benign_events(count: int = 20) -> list[dict]:
    return [_session_event(i, KINDS[i % len(KINDS)]) for i in range(count)]


def _attack_events(count: int = 20) -> list[dict]:
    return [_session_event(i, KINDS[i % len(KINDS)], pid=5000 + i,
                           executable="/tmp/.hidden/payload")
            for i in range(count)]


# ------------------------------------------------------------------ wilson ---


def test_wilson_interval_is_zero_for_zero_trials():
    assert wilson_interval(0, 0) == (0.0, 0.0)


def test_wilson_interval_stays_inside_unit_interval():
    for successes in range(0, 101):
        low, high = wilson_interval(successes, 100)
        assert 0.0 <= low <= high <= 1.0


def test_wilson_interval_perfect_score():
    low, high = wilson_interval(10, 10)
    assert low > 0.5 and high == 1.0


def test_wilson_interval_zero_score():
    low, high = wilson_interval(0, 10)
    assert low == 0.0 and high < 0.5


def test_wilson_interval_rejects_invalid():
    with pytest.raises(ValueError):
        wilson_interval(-1, 10)
    with pytest.raises(ValueError):
        wilson_interval(11, 10)


# -------------------------------------------------------------------- metrics ---


def test_metrics_perfect():
    result = metrics([1, 1, 0, 0], [1, 1, 0, 0])
    assert result["tp"] == 2 and result["tn"] == 2
    assert result["fp"] == 0 and result["fn"] == 0
    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["false_positive_rate"] == 0.0


def test_metrics_all_wrong():
    result = metrics([1, 0], [0, 1])
    assert result["tp"] == 0 and result["tn"] == 0
    assert result["fp"] == 1 and result["fn"] == 1
    assert result["precision"] == 0.0
    assert result["recall"] == 0.0


def test_metrics_wilson_intervals():
    result = metrics([1, 1, 0, 0, 0], [1, 0, 0, 0, 0])
    assert result["precision_ci95"][0] <= result["precision"] <= result["precision_ci95"][1]
    assert result["recall_ci95"][0] <= result["recall"] <= result["recall_ci95"][1]
    assert result["false_positive_rate_ci95"][0] <= result["false_positive_rate"] <= result["false_positive_rate_ci95"][1]


def test_metrics_rejects_mismatched_lengths():
    with pytest.raises(ValueError):
        metrics([1, 0], [1])


# -------------------------------------------------------------- default_config ---


def test_default_config_has_procfs_appropriate_classes():
    config = default_config()
    types = config["completeness"]["expected_event_types"]
    assert types == sorted(DEFAULT_COMPLETENESS_CLASSES)
    assert 0.0 < config["completeness"]["minimum_ratio"] <= 1.0


# --------------------------------------------------------------- load_sessions ---


def test_load_sessions_derives_label_from_filename(tmp_path):
    (tmp_path / "baseline.jsonl").write_text(
        "\n".join(json.dumps(e) for e in _benign_events()) + "\n")
    (tmp_path / "attack-nmap.jsonl").write_text(
        "\n".join(json.dumps(e) for e in _attack_events()) + "\n")
    sessions = load_sessions(tmp_path)
    labels = {s["session_id"]: s["label"] for s in sessions}
    assert labels["baseline"] == LABEL_BENIGN
    assert labels["attack-nmap"] == LABEL_ATTACK


def test_load_sessions_uses_sidecar_metadata(tmp_path):
    path = tmp_path / "s1.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in _benign_events()) + "\n")
    meta = tmp_path / "s1.meta.json"
    meta.write_text(json.dumps({"label": "attack", "scenario": "red-team-1"}))
    sessions = load_sessions(tmp_path)
    assert sessions[0]["label"] == LABEL_ATTACK
    assert sessions[0]["scenario"] == "red-team-1"


def test_load_sessions_rejects_empty_directory(tmp_path):
    with pytest.raises(ValueError, match="no session files found"):
        load_sessions(tmp_path)


def test_load_sessions_derives_scenario_from_stem(tmp_path):
    path = tmp_path / "nmap-attack.jsonl"
    path.write_text("\n".join(json.dumps(e) for e in _attack_events()) + "\n")
    sessions = load_sessions(tmp_path)
    assert sessions[0]["scenario"] == "nmap"


# ------------------------------------------------------------- run_host_benchmark ---


def test_run_host_benchmark_requires_enough_benign(tmp_path):
    # Only 1 benign session, default min is 3.
    (tmp_path / "baseline.jsonl").write_text(
        "\n".join(json.dumps(e) for e in _benign_events()) + "\n")
    (tmp_path / "attack-1.jsonl").write_text(
        "\n".join(json.dumps(e) for e in _attack_events()) + "\n")
    with pytest.raises(ValueError, match="at least 3 benign sessions"):
        run_host_benchmark(tmp_path)


def test_run_host_benchmark_requires_attack_sessions(tmp_path):
    for index in range(3):
        (tmp_path / f"baseline-{index}.jsonl").write_text(
            "\n".join(json.dumps(e) for e in _benign_events()) + "\n")
    with pytest.raises(ValueError, match="at least one attack session"):
        run_host_benchmark(tmp_path)


def test_run_host_benchmark_produces_report(tmp_path):
    for index in range(3):
        (tmp_path / f"baseline-{index}.jsonl").write_text(
            "\n".join(json.dumps(e) for e in _benign_events()) + "\n")
    (tmp_path / "attack-1.jsonl").write_text(
        "\n".join(json.dumps(e) for e in _attack_events()) + "\n")
    report = run_host_benchmark(tmp_path)
    assert report["format"] == "cabid-host-benchmark/1"
    assert report["corpus"]["total_sessions"] == 4
    assert report["corpus"]["benign_sessions"] == 3
    assert report["corpus"]["attack_sessions"] == 1
    assert "cabid" in report["models"]
    assert report["models"]["cabid"]["sample_count"] == 4
    assert 0.0 <= report["models"]["cabid"]["precision"] <= 1.0
    assert 0.0 <= report["models"]["cabid"]["recall"] <= 1.0
    assert 0.0 <= report["models"]["cabid"]["false_positive_rate"] <= 1.0
    assert 0.0 <= report["score_separation"]["anomaly_score_auc"] <= 1.0
    assert len(report["limitations"]) > 0


def test_run_host_benchmark_writes_output(tmp_path):
    for index in range(3):
        (tmp_path / f"baseline-{index}.jsonl").write_text(
            "\n".join(json.dumps(e) for e in _benign_events()) + "\n")
    (tmp_path / "attack-1.jsonl").write_text(
        "\n".join(json.dumps(e) for e in _attack_events()) + "\n")
    output = tmp_path / "out" / "report.json"
    report = run_host_benchmark(tmp_path, output=output)
    assert output.is_file()
    loaded = json.loads(output.read_text(encoding="utf-8"))
    assert loaded["format"] == report["format"]


def test_run_host_benchmark_per_scenario_metrics(tmp_path):
    for index in range(3):
        (tmp_path / f"benign-{index}.jsonl").write_text(
            "\n".join(json.dumps(e) for e in _benign_events()) + "\n")
    (tmp_path / "attack-1.jsonl").write_text(
        "\n".join(json.dumps(e) for e in _attack_events()) + "\n")
    report = run_host_benchmark(tmp_path)
    assert "attack-1" in report["scenario_metrics"]
    for name in ("benign-0", "benign-1", "benign-2"):
        assert name in report["scenario_metrics"]


# --------------------------------------------------------------- render_markdown ---


def test_render_markdown_contains_headline(tmp_path):
    for index in range(3):
        (tmp_path / f"baseline-{index}.jsonl").write_text(
            "\n".join(json.dumps(e) for e in _benign_events()) + "\n")
    (tmp_path / "attack-1.jsonl").write_text(
        "\n".join(json.dumps(e) for e in _attack_events()) + "\n")
    report = run_host_benchmark(tmp_path)
    markdown = render_markdown(report)
    assert "# Real-host benchmark report" in markdown
    assert "Headline result" in markdown
    assert "Limitations" in markdown
    assert "Precision" in markdown
    assert "Recall" in markdown
    assert "FPR" in markdown


# ------------------------------------------------------------------ default config values ---

def test_default_config_completeness_ratio_is_positive():
    config = default_config()
    assert 0.0 < config["completeness"]["minimum_ratio"] < 1.0
