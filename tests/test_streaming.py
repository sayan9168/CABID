"""Tests for bounded-memory streaming analysis and glob-cache equivalence."""
from __future__ import annotations

import fnmatch
import json

import pytest

from cabid.rules import _glob_any, evaluate_rules, load_rules
from cabid.streaming import (
    MIN_WINDOW_SECONDS,
    PatternCache,
    StreamError,
    read_events,
    stream,
    stream_file,
)

KINDS = ("process_start", "process_exec", "file_write", "network_connect",
         "process_exit", "heartbeat")


def _events(count: int, *, start: float = 1000.0, step: float = 1.0,
            kinds: tuple[str, ...] = KINDS) -> list[dict]:
    return [{
        "timestamp": start + index * step,
        "event_type": kinds[index % len(kinds)],
        "process_id": 100 + index % 20,
        "parent_process_id": 1,
        "process_name": f"svc-{index % 4}",
        "executable": f"/usr/bin/svc-{index % 4}",
        "target": "",
        "source": "test",
    } for index in range(count)]


# ---------------------------------------------------------------- stream ----

def test_stream_scores_a_single_short_window():
    report = stream(_events(60), window_seconds=60.0)
    assert report["format"] == "cabid-stream-report/1"
    assert report["events_normalized"] == 60
    assert report["window_count"] == 1
    assert sum(report["status_counts"].values()) == 1


def test_stream_splits_on_the_window_boundary():
    report = stream(_events(300, step=1.0), window_seconds=60.0)
    assert report["window_count"] >= 4
    assert sum(report["status_counts"].values()) == report["window_count"]


def test_stream_bounds_the_retained_sample():
    report = stream(_events(500), window_seconds=60.0, sample_limit=25)
    assert report["sample_events_retained"] == 25
    # Analysis still covers everything, not just the retained sample.
    assert report["events_normalized"] == 500


def test_stream_accepts_a_generator_without_materializing():
    consumed = []

    def generator():
        for event in _events(200):
            consumed.append(event)
            yield event

    report = stream(generator(), window_seconds=30.0, sample_limit=10)
    assert len(consumed) == 200
    assert report["sample_events_retained"] == 10


def test_stream_rejects_malformed_events_and_continues():
    events = _events(100)
    events.insert(10, {"timestamp": 1.0, "event_type": "nonsense", "process_id": 5})
    events.insert(20, {"timestamp": -1.0, "event_type": "file_write", "process_id": 5})
    report = stream(events, window_seconds=60.0)
    assert report["events_rejected"] == 2
    assert report["events_normalized"] == 100
    assert report["rejected_examples"]


def test_stream_accepts_already_normalized_events():
    from cabid.ingest import normalize_many

    report = stream(normalize_many(_events(80)), window_seconds=60.0,
                    already_normalized=True)
    assert report["events_rejected"] == 0
    assert report["events_normalized"] == 80


def test_stream_reports_throughput():
    report = stream(_events(400), window_seconds=60.0)
    assert report["elapsed_seconds"] >= 0
    assert report["events_per_second"] >= 0


def test_stream_refuses_windows_too_small_to_be_meaningful():
    with pytest.raises(StreamError, match="causal chains"):
        stream(_events(10), window_seconds=MIN_WINDOW_SECONDS - 1)


def test_stream_rejects_a_negative_sample_limit():
    with pytest.raises(StreamError):
        stream(_events(10), sample_limit=-1)


def test_stream_on_empty_input_returns_an_empty_report():
    report = stream([], window_seconds=60.0)
    assert report["window_count"] == 0
    assert report["flagged_window_rate"] == 0.0
    assert report["status_counts"] == {}


def test_stream_separates_a_burst_window_from_quiet_windows():
    """A burst must stand out from the quiet windows around it.

    The burst here crosses no status threshold on its own, which is the point: the
    streaming report exposes the per-window score so a burst can still be seen. An
    assertion on ``flagged_windows`` would only test the threshold constant.
    """
    quiet = _events(60, step=10.0)
    burst = _events(400, start=quiet[-1]["timestamp"] + 10.0, step=0.01)
    report = stream(quiet + burst, window_seconds=60.0)
    assert report["window_count"] >= 2
    scores = [window["anomaly_score"] for window in report["windows_scored"]]
    assert max(scores) > 5 * min(scores)
    loudest = max(report["windows_scored"], key=lambda window: window["anomaly_score"])
    assert loudest["event_count"] == 400
    assert "temporal_rate_or_burst" in loudest["reason_codes"]


def test_stream_states_that_windows_weaken_the_verdict():
    report = stream(_events(60), window_seconds=60.0)
    assert any("causal chain spanning a window boundary" in note
               for note in report["notes"])


def test_stream_with_a_baseline_profile_scores_novelty():
    from cabid.baseline import build_profile

    profile = build_profile([("fit", _events(200))], minimum_sessions=1)
    report = stream(_events(120), window_seconds=60.0, profile=profile)
    assert report["window_count"] >= 1


# ------------------------------------------------------------ file input ----

def test_read_events_is_lazy_and_skips_blank_lines(tmp_path):
    path = tmp_path / "events.jsonl"
    lines = [json.dumps(event) for event in _events(3)]
    path.write_text("\n".join(lines) + "\n\n", encoding="utf-8")
    assert len(list(read_events(path))) == 3


def test_read_events_reports_the_line_number_on_bad_json(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps(_events(1)[0]) + "\n{oops\n", encoding="utf-8")
    with pytest.raises(StreamError, match=":2: invalid JSON"):
        list(read_events(path))


def test_read_events_rejects_non_object_records(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("[1, 2, 3]\n", encoding="utf-8")
    with pytest.raises(StreamError, match="JSON object"):
        list(read_events(path))


def test_stream_file_reports_missing_input(tmp_path):
    with pytest.raises(StreamError, match="cannot read"):
        stream_file(tmp_path / "absent.jsonl")


def test_stream_file_matches_stream_over_the_same_events(tmp_path):
    events = _events(150)
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n",
                    encoding="utf-8")
    from_file = stream_file(path, window_seconds=60.0)
    from_memory = stream(events, window_seconds=60.0)
    assert from_file["window_count"] == from_memory["window_count"]
    assert from_file["status_counts"] == from_memory["status_counts"]


# ---------------------------------------------------------- pattern cache ----

def test_pattern_cache_matches_fnmatch_semantics():
    original_values = ["/usr/bin/bash", "/tmp/.hidden/x", "BASH", "curl",
                       "/usr/sbin/curl", "a[bc]", "abc", "", "/etc/shadow"]
    patterns = ["*bash*", "/tmp/*", "curl", "*.sh", "a[b]c", "[/]usr*",
                "?url", "", "*", "/etc/*", "shadow"]
    cache = PatternCache()
    for value in original_values:
        for pattern in patterns:
            expected = fnmatch.fnmatch(value.lower(), pattern.lower())
            assert cache.match(value, pattern) is expected, (value, pattern)


def test_rule_glob_matcher_is_unchanged_for_literals_and_globs():
    """Regression: a literal pattern compared against the wrong string."""
    assert _glob_any("curl", ["curl"]) is True
    assert _glob_any("CURL", ["curl"]) is True
    assert _glob_any("curlx", ["curl"]) is False
    assert _glob_any("/usr/bin/bash", ["*bash*"]) is True
    assert _glob_any("", [""]) is True


def test_pattern_cache_tracks_hits_and_misses():
    cache = PatternCache()
    cache.match("curl", "curl")
    cache.match("bash", "curl")
    statistics = cache.statistics
    assert statistics["distinct_patterns"] == 1
    assert statistics["cache_misses"] == 1
    assert statistics["cache_hits"] == 1
    assert statistics["hit_rate"] == 0.5


def test_pattern_cache_any_match_short_circuits():
    cache = PatternCache()
    # A literal pattern matches the whole value, so it does not match a longer path.
    assert cache.any_match("/usr/bin/curl", ["nomatch", "*curl", "other"]) is True
    assert cache.any_match("/usr/bin/curl", ["nomatch", "curl"]) is False
    assert cache.any_match("/usr/bin/wget", ["nomatch", "curl"]) is False


def test_pattern_cache_handles_mixed_case_patterns():
    cache = PatternCache()
    assert cache.match("/USR/BIN/CURL", "/usr/bin/curl") is True
    assert cache.match("BASH", "*Bash*") is True


def test_rule_evaluation_agrees_with_and_without_a_warm_cache():
    from cabid.rules import _GLOB_CACHE

    events = [{
        "timestamp": 1000.0 + index,
        "timestamp_iso": "1970-01-01T00:16:40+00:00",
        "event_type": "process_exec",
        "process_id": 100 + index,
        "parent_process_id": 1,
        "process_name": "curl" if index % 2 else "bash",
        "executable": "/usr/bin/curl" if index % 2 else "/usr/bin/bash",
        "target": "",
        "source": "test",
    } for index in range(20)]
    rules = load_rules(None)
    _GLOB_CACHE.clear()
    cold = evaluate_rules(events, rules)
    warm = evaluate_rules(events, rules)
    assert cold == warm
