import json

import pytest

from cabid.baseline import build_profile, drift_suggestions, write_profile


def session(processes, repeats=4, offset=0.0):
    rows = []
    stamp = 1000.0 + offset
    for _ in range(repeats):
        for pid, (name, executable) in processes.items():
            rows.append({"timestamp": stamp, "event_type": "process_start",
                         "process_id": pid, "parent_process_id": 1 if pid != 1 else 0,
                         "process_name": name, "executable": executable})
            stamp += 5
    return rows


BENIGN = {1: ("init", "/sbin/init"), 2: ("cron", "/usr/sbin/cron")}


def profile(tmp_path):
    sessions = [(f"benign{index}", session(BENIGN)) for index in range(3)]
    return build_profile(sessions, minimum_sessions=3)


def test_no_drift_when_sessions_match_the_profile(tmp_path):
    report = drift_suggestions(profile(tmp_path), [("new0", session(BENIGN))] * 2)
    assert report["suggestion_count"] == 0
    assert report["applied"] is False


def test_new_process_is_suggested_after_enough_support(tmp_path):
    drifted = dict(BENIGN)
    drifted[3] = ("snapd", "/usr/lib/snapd/snapd")
    report = drift_suggestions(profile(tmp_path), [("a", session(drifted)), ("b", session(drifted))])
    names = [item["process_name"] for item in report["new_processes"]]
    assert names == ["snapd"]
    assert report["new_processes"][0]["sessions"] == 2


def test_a_single_session_cannot_widen_the_baseline(tmp_path):
    drifted = dict(BENIGN)
    drifted[3] = ("snapd", "/usr/lib/snapd/snapd")
    report = drift_suggestions(profile(tmp_path), [("only", session(drifted))])
    assert report["suggestion_count"] == 0


def test_changed_executable_for_a_known_process_is_suggested(tmp_path):
    drifted = dict(BENIGN)
    drifted[2] = ("cron", "/usr/sbin/cron2")
    report = drift_suggestions(profile(tmp_path), [("a", session(drifted)), ("b", session(drifted))])
    assert report["new_executables"] == [
        {"process_name": "cron", "new_executables": ["/usr/sbin/cron2"], "sessions": 2}]


def test_new_parent_child_edge_is_suggested(tmp_path):
    drifted = dict(BENIGN)
    drifted[3] = ("snapd", "/usr/lib/snapd/snapd")
    report = drift_suggestions(profile(tmp_path), [("a", session(drifted)), ("b", session(drifted))])
    edges = [(item["parent"], item["child"]) for item in report["new_parent_child_edges"]]
    assert ("init", "snapd") in edges


def test_drift_never_rewrites_the_profile(tmp_path):
    target = tmp_path / "profile.json"
    write_profile(profile(tmp_path), target)
    before = target.read_text(encoding="utf-8")
    drifted = dict(BENIGN)
    drifted[3] = ("snapd", "/usr/lib/snapd/snapd")
    drift_suggestions(json.loads(before), [("a", session(drifted)), ("b", session(drifted))])
    assert target.read_text(encoding="utf-8") == before
    assert "snapd" not in before


def test_min_support_is_honoured(tmp_path):
    drifted = dict(BENIGN)
    drifted[3] = ("snapd", "/usr/lib/snapd/snapd")
    two = [("a", session(drifted)), ("b", session(drifted))]
    assert drift_suggestions(profile(tmp_path), two, min_support=3)["suggestion_count"] == 0
    assert drift_suggestions(profile(tmp_path), two, min_support=2)["suggestion_count"] >= 1


def test_report_states_that_review_is_required(tmp_path):
    report = drift_suggestions(profile(tmp_path), [("a", session(BENIGN))])
    assert any("never modified automatically" in note for note in report["notes"])
    assert any("compromise" in note for note in report["notes"])


def test_profile_must_be_an_object():
    with pytest.raises(ValueError):
        drift_suggestions(["not", "a", "profile"], [])  # type: ignore[arg-type]
