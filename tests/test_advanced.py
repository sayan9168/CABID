import json
from pathlib import Path

from cabid.advanced import (
    correlate, fim_snapshot, fim_verify, intel_match, reproducibility_manifest,
    sensor_health,
)


def test_fim_detects_modified_added_and_missing(tmp_path):
    root = tmp_path / "root"; root.mkdir()
    (root / "a").write_text("one")
    manifest = tmp_path / "manifest.json"
    fim_snapshot(str(root), str(manifest))
    (root / "a").write_text("two")
    (root / "b").write_text("new")
    result = fim_verify(str(root), str(manifest))
    assert result["clean"] is False
    assert result["summary"] == {"changed": 1, "missing": 0, "added": 1}


def test_fim_detects_missing(tmp_path):
    root = tmp_path / "root"; root.mkdir()
    (root / "a").write_text("x")
    manifest = tmp_path / "manifest.json"
    fim_snapshot(str(root), str(manifest))
    (root / "a").unlink()
    assert fim_verify(str(root), str(manifest))["missing"] == ["a"]


def test_health_reports_gaps_and_bad_timestamps(tmp_path):
    p = tmp_path / "e.jsonl"
    p.write_text('{"timestamp":1,"event_type":"process_exec"}\n{"timestamp":10}\n{"timestamp":"bad"}\n')
    result = sensor_health(str(p), 2)
    assert result["health"] == "DEGRADED"
    assert result["malformed"] == 1
    assert len(result["timestamp_gaps"]) == 1


def test_correlation_is_heuristic(tmp_path):
    p = tmp_path / "e.jsonl"
    p.write_text('{"timestamp":1,"process_id":4,"event_type":"process_exec"}\n{"timestamp":2,"process_id":4,"event_type":"network_connect"}\n')
    result = correlate(str(p), 5)
    assert result["finding_count"] == 1
    assert result["findings"][0]["confidence"] == "low"


def test_intel_exact_match_only(tmp_path):
    events = tmp_path / "e.jsonl"
    events.write_text('{"timestamp":1,"process_id":1,"event_type":"network_connect","remote_ip":"203.0.113.8"}\n')
    indicators = tmp_path / "ioc.json"
    indicators.write_text(json.dumps({"ips":["203.0.113.8"],"sha256":[],"domains":[]}))
    assert intel_match(str(events), str(indicators))["match_count"] == 1


def test_repro_manifest_hashes_input(tmp_path):
    p = tmp_path / "input.jsonl"; p.write_text("{}\n")
    out = tmp_path / "manifest.json"
    result = reproducibility_manifest([str(p)], str(out))
    assert len(result["inputs"][0]["sha256"]) == 64
    assert json.loads(out.read_text())["schema"] == "cabid-reproducibility/1"
