import json
from pathlib import Path

from cabid.advanced import (
    correlate, fim_snapshot, fim_verify, intel_match, reproducibility_manifest,
    sensor_health, network_attribution, robustness_audit, performance_probe,
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



def test_network_attribution_only_uses_supplied_socket_metadata(tmp_path):
    p = tmp_path / "network.jsonl"
    p.write_text('{"timestamp":1,"process_id":7,"event_type":"network_connect","remote_ip":"192.0.2.5","remote_port":443}\n')
    result = network_attribution(str(p))
    assert result["connection_count"] == 1
    assert result["connections"][0]["process_id"] == 7


def test_robustness_audit_flags_bad_json_and_non_objects(tmp_path):
    p = tmp_path / "hostile.jsonl"
    p.write_text('not-json\n[]\n{"process_name":"ok"}\n')
    result = robustness_audit(str(p))
    assert result["malformed_json"] == 1
    assert result["non_object_json"] == 1


def test_performance_probe_reports_parse_rate(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text('{"timestamp":1,"event_type":"process_exec"}\n')
    result = performance_probe(str(p))
    assert result["events"] == 1
    assert result["events_per_second"] > 0
