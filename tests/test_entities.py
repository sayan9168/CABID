from cabid.baseline import build_profile
from cabid.entities import entity_features
from cabid.ingest import normalize_many
from cabid.policy import load_policy


def build(rows):
    return normalize_many(rows)


def test_ranking_puts_contradicting_process_first():
    events = build([
        {"timestamp": 1, "event_type": "process_start", "process_id": 10, "parent_process_id": 1,
         "process_name": "calm"},
        {"timestamp": 2, "event_type": "file_write", "process_id": 10, "parent_process_id": 1,
         "process_name": "calm", "target": "/tmp/x"},
        {"timestamp": 3, "event_type": "process_start", "process_id": 20, "parent_process_id": 1,
         "process_name": "chaos"},
        {"timestamp": 4, "event_type": "process_start", "process_id": 20, "parent_process_id": 1,
         "process_name": "chaos"},
        {"timestamp": 5, "event_type": "process_start", "process_id": 20, "parent_process_id": 20,
         "process_name": "chaos"},
    ])
    result = entity_features(events)
    assert result["entity_count"] == 2
    assert result["top_entities"][0]["process_id"] == 20
    assert result["top_entities"][0]["entity_risk"] > result["top_entities"][1]["entity_risk"]
    assert result["ranking_semantics"].startswith("triage hint")


def test_sensitive_hits_are_attributed_to_the_touching_process():
    events = build([
        {"timestamp": 1, "event_type": "file_write", "process_id": 10, "process_name": "quiet",
         "target": "/tmp/ok"},
        {"timestamp": 2, "event_type": "file_write", "process_id": 30, "process_name": "snoop",
         "target": "/etc/shadow"},
        {"timestamp": 3, "event_type": "network_connect", "process_id": 30, "process_name": "snoop",
         "target": "10.0.0.4:6379"},
    ])
    result = entity_features(events, load_policy(None))
    top = result["top_entities"][0]
    assert top["process_id"] == 30
    assert top["sensitive_hits"] == 2
    assert "shadow" not in " ".join(top["sensitive_refs"]) or top["sensitive_refs"]


def test_novel_executable_is_flagged_with_a_profile():
    rows = [{"timestamp": 1000 + i, "event_type": kind, "process_id": 10 + i,
             "parent_process_id": 1, "process_name": "agent", "executable": "/usr/bin/agent"}
            for i, kind in enumerate(["process_start", "process_exec", "file_write",
                                      "network_connect", "process_exit", "heartbeat"])]
    profile = build_profile([(f"s{i}", build(rows)) for i in range(3)])
    swapped = [dict(row, executable="/tmp/.hidden/agent") for row in rows]
    result = entity_features(build(swapped), profile=profile)
    assert any(entity["novel_executable"] for entity in result["top_entities"])
    assert result["flagged_entity_count"] >= 1


def test_clean_stream_has_no_flagged_entities():
    events = build([{"timestamp": 1, "event_type": "heartbeat", "process_id": 1,
                     "process_name": "systemd"}])
    result = entity_features(events)
    assert result["flagged_entity_count"] == 0
    assert result["top_entities"][0]["entity_risk"] == 0.0


def test_top_entities_are_capped():
    rows = [{"timestamp": index, "event_type": "heartbeat", "process_id": index + 1,
             "parent_process_id": index + 1} for index in range(40)]
    result = entity_features(build(rows))
    assert len(result["top_entities"]) == 25
    assert result["entities_truncated"] is True
