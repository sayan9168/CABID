"""Tests for baseline validation and drift tracking."""
from __future__ import annotations

import pytest

from cabid.baseline import build_profile
from cabid.novelty import (
    DEFAULT_DRIFT_THRESHOLD,
    NoveltyError,
    binomial_two_sided,
    drift,
    ks_critical_value,
    ks_statistic,
    rate_divergence,
    validate,
)

KINDS = ("process_start", "process_exec", "file_write", "network_connect",
         "process_exit", "heartbeat")


def _session(name: str, *, events: int = 60, duration: float = 60.0,
             seconds_offset: float = 0.0, name_prefix: str = "svc",
             kinds: tuple[str, ...] = KINDS) -> tuple[str, list[dict]]:
    events = max(events, 2)
    step = duration / events
    return name, [{
        "timestamp": 1000.0 + seconds_offset + index * step,
        "event_type": kinds[index % len(kinds)],
        "process_id": 100 + index,
        "parent_process_id": 1,
        "process_name": f"{name_prefix}-{index % 3}",
        "executable": f"/usr/bin/{name_prefix}-{index % 3}",
        "target": "",
        "source": "test",
    } for index in range(events)]


def _sessions(count: int, prefix: str = "s", **kwargs) -> list[tuple[str, list[dict]]]:
    return [_session(f"{prefix}-{index:03d}", seconds_offset=index * 1000.0, **kwargs)
            for index in range(count)]


def _profile(count: int = 40, **kwargs) -> dict:
    return build_profile(_sessions(count, prefix="fit", **kwargs), minimum_sessions=3)


# ------------------------------------------------------------------- KS ----

def test_ks_is_zero_for_identical_samples():
    assert ks_statistic([1, 2, 3], [1, 2, 3]) == 0.0
    assert ks_statistic([1, 1, 1], [1, 1, 1]) == 0.0


def test_ks_is_high_for_disjoint_samples():
    assert ks_statistic([1, 2, 3], [10, 11, 12]) == 1.0


def test_ks_measures_partial_shift():
    assert ks_statistic([1, 2, 3, 4], [3, 4, 5, 6]) == pytest.approx(0.5)


def test_ks_treats_ties_as_a_block():
    """Regression: advancing one sample at a time reported 0.333 for equal samples."""
    assert ks_statistic([2, 2, 2, 5], [2, 2, 2, 5]) == 0.0


def test_ks_rejects_empty_samples():
    with pytest.raises(ValueError):
        ks_statistic([], [1.0])
    with pytest.raises(ValueError):
        ks_statistic([1.0], [])


def test_ks_critical_value_shrinks_with_more_samples():
    assert ks_critical_value(20, 20) > ks_critical_value(2000, 2000)
    assert 0.0 < ks_critical_value(100, 100) < 1.0
    with pytest.raises(ValueError):
        ks_critical_value(0, 10)
    with pytest.raises(ValueError):
        ks_critical_value(10, 10, alpha=1.0)


# -------------------------------------------------------------- binomial ----

def test_binomial_is_symmetric_at_half():
    assert binomial_two_sided(5, 10) == pytest.approx(1.0)


def test_binomial_recognises_an_all_one_direction_split():
    assert binomial_two_sided(10, 10) == pytest.approx(2 / 1024, abs=1e-9)
    assert binomial_two_sided(0, 10) == pytest.approx(2 / 1024, abs=1e-9)


def test_binomial_validates_arguments():
    with pytest.raises(ValueError):
        binomial_two_sided(11, 10)
    with pytest.raises(ValueError):
        binomial_two_sided(1, 10, probability=0.0)


# ---------------------------------------------------------- rate compare ----

def test_rate_divergence_uses_two_sample_ks_when_samples_present():
    profile = _profile(30)
    assert len(profile["rate_samples"]) >= 2
    statistic, method = rate_divergence(profile, [60.0, 61.0, 62.0])
    assert method == "two_sample_ks"
    assert 0.0 <= statistic <= 1.0


def test_rate_divergence_falls_back_for_legacy_profiles():
    legacy = {"rate_per_minute": {"median": 60.0, "scale": 1.0}}
    statistic, method = rate_divergence(legacy, [10.0, 11.0, 60.0])
    assert method == "three_sigma_fraction"
    assert statistic == pytest.approx(2 / 3)


def test_rate_divergence_requires_observations():
    with pytest.raises(ValueError):
        rate_divergence(_profile(5), [])


# --------------------------------------------------------------- validate ----

def test_validate_accepts_a_sound_baseline():
    profile = _profile(60)
    report = validate(profile, _sessions(40, prefix="held"))
    assert report["verdict"] == "SOUND"
    assert report["coverage"] > 0.9
    assert report["verdict_semantics"].startswith("a judgement about the baseline")
    assert report["findings"]


def test_validate_detects_reused_fitting_sessions():
    sessions = _sessions(40, prefix="fit")
    profile = build_profile(sessions, minimum_sessions=3)
    report = validate(profile, sessions)
    assert report["verdict"] == "INVALID"
    assert report["fit_overlap"]
    assert any("not meaningful" in finding for finding in report["findings"])


def test_validate_flags_a_stale_baseline():
    profile = _profile(60, duration=600.0)
    # Same session count in a tenth of the time: a genuine workload change.
    faster = _sessions(40, prefix="fast", duration=60.0)
    report = validate(profile, faster)
    assert report["verdict"] in {"NEEDS_REFIT", "INVALID"}
    assert report["ks_rate_vs_baseline"] > DEFAULT_DRIFT_THRESHOLD


def test_validate_refuses_to_judge_from_too_few_sessions():
    with pytest.raises(NoveltyError, match="required"):
        validate(_profile(10), _sessions(5, prefix="held"))


def test_validate_rejects_a_non_profile():
    with pytest.raises(NoveltyError):
        validate([], _sessions(30))


def test_validate_requires_enough_measurable_rates():
    profile = _profile(30)
    thin = [(f"thin-{index}", [dict(event) for event in events[:1]])
            for index, (_name, events) in enumerate(_sessions(40))]
    with pytest.raises(NoveltyError, match="rate"):
        validate(profile, thin)


def test_validate_lists_unseen_process_names():
    profile = _profile(40, name_prefix="svc")
    unseen = _sessions(30, prefix="held", name_prefix="brandnew")
    report = validate(profile, unseen)
    assert report["unseen_process_name_count"] >= 3
    assert any("brandnew" in name for name in report["unseen_process_names"])


def test_validate_reports_its_limitations():
    report = validate(_profile(40), _sessions(30, prefix="held"))
    assert any("sound baseline can still be defeated" in item
               for item in report["limitations"])


# ------------------------------------------------------------------ drift ----

def test_drift_is_quiet_when_nothing_moved():
    profile = _profile(60)
    report = drift(profile, _sessions(40, prefix="held"))
    assert report["drifted"] is False
    assert report["features"] == []
    assert "No drift detected" in report["recommendation"]


def test_drift_detects_a_rate_change():
    profile = _profile(60, duration=600.0)
    faster = _sessions(40, prefix="fast", duration=60.0)
    report = drift(profile, faster)
    assert report["drifted"] is True
    features = {row["feature"] for row in report["features"]}
    assert "event_rate_per_minute" in features
    rate = next(row for row in report["features"] if row["feature"] == "event_rate_per_minute")
    assert rate["direction"] == "higher"
    assert rate["statistic"] >= report["threshold"]


def test_drift_detects_a_type_mix_shift():
    profile = _profile(40)
    skewed = _sessions(30, prefix="held", kinds=("file_write",))
    report = drift(profile, skewed, threshold=0.2)
    assert "event_type_mix" in {row["feature"] for row in report["features"]}


def test_drift_reports_new_ancestry_edges():
    profile = _profile(40)
    # Two distinct new ancestry edges: the report ignores a single novel edge as noise,
    # so one is deliberately not enough here.
    pairs = (("parentproc", "childproc"), ("otherparent", "otherchild"))
    novel = []
    for index in range(30):
        name, events = _session(f"novel-{index}", seconds_offset=index * 1000.0)
        for step, event in enumerate(events):
            group_index, role = divmod(step, 2)
            group = pairs[group_index % len(pairs)]
            child_pid = 300 + group_index * 2
            event["process_name"] = group[role]
            event["executable"] = f"/usr/bin/{event['process_name']}"
            event["process_id"] = child_pid - 1 if role == 0 else child_pid
            event["parent_process_id"] = 1 if role == 0 else child_pid - 1
        novel.append((name, events))
    report = drift(profile, novel, threshold=0.2)
    edges = [row for row in report["features"] if row["feature"] == "parent_child_edges"]
    assert edges
    assert any("->" in suggestion for suggestion in report["suggestions"])


def test_drift_never_emits_an_attack_verdict():
    profile = _profile(40)
    faster = _sessions(30, prefix="fast", duration=30.0)
    report = drift(profile, faster)
    assert "not about intent" in report["drift_is_not_an_attack_signal"]
    blob = str(report).lower()
    for banned in ("compromised", "malicious", "intrusion detected", "verdict: attack"):
        assert banned not in blob


def test_drift_proposes_rather_than_applies():
    profile = _profile(40)
    before = dict(profile)
    faster = _sessions(30, prefix="fast", duration=30.0)
    report = drift(profile, faster)
    assert "Nothing here is applied automatically" in report["recommendation"]
    assert profile == before


def test_drift_validates_its_inputs():
    profile = _profile(10)
    with pytest.raises(NoveltyError):
        drift(profile, [])
    with pytest.raises(NoveltyError):
        drift(profile, _sessions(3), threshold=0.0)
    with pytest.raises(NoveltyError):
        drift([], _sessions(3))


def test_drift_reports_flip_probability():
    profile = _profile(40)
    report = drift(profile, _sessions(30, prefix="held"))
    assert 0.0 <= report["flip_probability"] <= 1.0
    assert report["classification_flips"] >= 0


def test_drift_states_its_limitations():
    report = drift(_profile(10), _sessions(5))
    assert any("not sequences" in item for item in report["limitations"])
