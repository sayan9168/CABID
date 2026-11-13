import json

import pytest

from cabid.baseline import PROFILE_FORMAT, build_profile, load_profile, novelty_features, write_profile
from cabid.ingest import read_jsonl, normalize_many


def sessions(count=3):
    out = []
    for index in range(count):
        events = normalize_many([
            {"timestamp": 1000 + index * 50 + i * 5, "event_type": kind, "process_id": 100 + i,
             "parent_process_id": 1, "process_name": f"svc-{i}", "executable": f"/usr/bin/svc-{i}"}
            for i, kind in enumerate(["process_start", "process_exec", "file_write",
                                     "network_connect", "process_exit", "heartbeat"])
        ])
        out.append((f"benign-{index}", events))
    return out


def test_profile_is_built_without_storing_raw_content():
    profile = build_profile(sessions())
    assert profile["format"] == PROFILE_FORMAT
    assert profile["session_count"] == 3
    assert profile["rate_per_minute"]["scale"] > 0
    assert "svc-0" in profile["executables"]
    text = json.dumps(profile)
    assert "/tmp/" not in text and "example.invalid" not in text


def test_profile_round_trips_through_disk(tmp_path):
    profile = write_profile(build_profile(sessions()), tmp_path / "nested" / "profile.json")
    assert load_profile(profile)["session_count"] == 3


@pytest.mark.parametrize("payload", [
    {"format": "wrong/1"},
    {"format": PROFILE_FORMAT},
    {"format": PROFILE_FORMAT, "rate_per_minute": {"median": -1, "scale": 1}},
    {"format": PROFILE_FORMAT, "rate_per_minute": {"median": 10, "scale": 0}},
    {"format": PROFILE_FORMAT, "rate_per_minute": {"median": 10, "scale": 1}, "executables": []},
])
def test_invalid_profiles_are_rejected(tmp_path, payload):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError):
        load_profile(path)


def test_too_few_sessions_rejected():
    with pytest.raises(ValueError, match="at least 3"):
        build_profile(sessions(2), minimum_sessions=3)


def test_novelty_without_profile_is_explicit():
    result = novelty_features(normalize_many([
        {"timestamp": 1, "event_type": "heartbeat", "process_id": 1}]))
    assert result["novelty_available"] is False
    assert result["novelty_score"] == 0.0


def test_known_session_scores_lower_than_novel_executable():
    profile = build_profile(sessions())
    known = sessions()[0][1]
    novel = normalize_many([
        {"timestamp": 1000 + i * 5, "event_type": kind, "process_id": 100 + i,
         "parent_process_id": 1, "process_name": f"svc-{i}", "executable": "/tmp/.hidden/payload"}
        for i, kind in enumerate(["process_start", "process_exec", "file_write",
                                 "network_connect", "process_exit", "heartbeat"])
    ])
    baseline = novelty_features(known, profile)
    anomaly = novelty_features(novel, profile)
    assert baseline["novelty_available"] is True
    assert anomaly["novelty_score"] > baseline["novelty_score"]
    assert anomaly["novel_executable_processes"]


def test_high_rate_raises_novelty():
    profile = build_profile(sessions())
    storm = normalize_many([
        {"timestamp": 1000 + i * 0.001, "event_type": "heartbeat", "process_id": 5,
         "process_name": "svc-0", "executable": "/usr/bin/svc-0"} for i in range(200)
    ])
    assert novelty_features(storm, profile)["rate_z_score"] > 0.5


def test_build_baseline_from_sample_dataset(tmp_path):
    events = read_jsonl("datasets/synthetic/example.jsonl")
    profile = build_profile([("a", events), ("b", events), ("c", events)])
    assert profile["event_count"] == len(events) * 3
