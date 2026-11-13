import json

import pytest

from cabid.stix import build_bundle, write_bundle

FINDINGS = {
    "status": "SUSPICIOUS",
    "anomaly_score": 0.71,
    "score_semantics": "heuristic score; not a calibrated probability",
    "config_digest": "abc123",
    "completeness": {
        "completeness": 0.9,
        "missing_event_types": ["heartbeat"],
        "telemetry_sufficient": False,
    },
    "rules": {
        "findings": [
            {"rule_id": "shell-from-service", "severity": "high",
             "description": "service spawned a shell"},
            {"rule_id": "download-then-exec", "severity": "critical",
             "description": "fetch then run"},
        ]
    },
    "tree": {
        "findings": [
            {"kind": "interpreter_spawn", "process_name": "bash", "detail": "python spawned bash"},
        ]
    },
}


def _by_type(bundle, kind):
    return [item for item in bundle["objects"] if item["type"] == kind]


def test_bundle_is_stix_21_with_identity_and_report():
    bundle = build_bundle(FINDINGS, host="web-01")
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert bundle["id"].startswith("bundle--")
    assert len(_by_type(bundle, "identity")) == 1
    report = _by_type(bundle, "report")[0]
    assert report["x_cabid_status"] == "SUSPICIOUS"
    assert report["x_cabid_anomaly_score"] == 0.71
    assert report["x_cabid_coverage"] == 0.9
    assert report["x_cabid_missing_event_types"] == ["heartbeat"]


def test_one_indicator_per_rule_finding_with_heuristic_pattern_type():
    bundle = build_bundle(FINDINGS, host="web-01")
    indicators = _by_type(bundle, "indicator")
    assert len(indicators) == 2
    assert all(item["pattern_type"] == "cabid-heuristic" for item in indicators)
    patterns = {item["pattern"] for item in indicators}
    assert "cabid-rule:'shell-from-service'" in patterns
    confidence = {item["pattern"]: item["confidence"] for item in indicators}
    assert confidence["cabid-rule:'download-then-exec'"] == 90
    assert confidence["cabid-rule:'shell-from-service'"] == 70


def test_indicators_are_labelled_as_pattern_matches_not_verdicts():
    bundle = build_bundle(FINDINGS, host="web-01")
    for indicator in _by_type(bundle, "indicator"):
        assert indicator["x_cabid_semantics"] == "pattern match, not a verdict"
        assert "not a verdict" in indicator["description"]


def test_tree_findings_become_notes_not_indicators():
    bundle = build_bundle(FINDINGS, host="web-01")
    notes = _by_type(bundle, "note")
    assert len(notes) == 1
    assert "pattern match" in notes[0]["content"].lower()


def test_report_references_every_child_object():
    bundle = build_bundle(FINDINGS, host="web-01")
    report = _by_type(bundle, "report")[0]
    children = {item["id"] for item in bundle["objects"]
                if item["type"] in {"indicator", "note"}}
    assert set(report["object_refs"]) == children


def test_bundle_carries_the_caveat_and_no_attribution_claim():
    bundle = build_bundle(FINDINGS, host="web-01")
    caveat = bundle["x_cabid_caveat"].lower()
    assert "heuristic" in caveat
    assert "attribution" in caveat


def test_bundle_without_findings_is_still_valid():
    bundle = build_bundle({"status": "NO_ANOMALY_DETECTED", "anomaly_score": 0.1}, host="h")
    assert _by_type(bundle, "report")
    assert _by_type(bundle, "indicator") == []


def test_write_bundle_creates_parent_directories(tmp_path):
    bundle = build_bundle(FINDINGS, host="web-01")
    destination = write_bundle(bundle, tmp_path / "nested" / "bundle.json")
    assert destination.exists()
    assert json.loads(destination.read_text())["type"] == "bundle"


def test_bundle_rejects_non_object_report():
    with pytest.raises(ValueError):
        build_bundle(["not", "a", "report"])  # type: ignore[arg-type]
