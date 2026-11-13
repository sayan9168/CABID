from cabid.baseline import build_profile
from cabid.ingest import normalize_many, read_jsonl
from cabid.tree import process_tree


def build(rows):
    return normalize_many(rows)


def test_chain_depth_and_edges():
    events = build([
        {"timestamp": 1, "event_type": "process_start", "process_id": 10, "parent_process_id": 1,
         "process_name": "systemd"},
        {"timestamp": 2, "event_type": "process_start", "process_id": 11, "parent_process_id": 10,
         "process_name": "nginx"},
        {"timestamp": 3, "event_type": "process_start", "process_id": 12, "parent_process_id": 11,
         "process_name": "sh"},
    ])
    result = process_tree(events)
    assert result["node_count"] == 3
    # pid 10 also records an edge to its own parent (pid 1), so 3 edges total
    assert result["edge_count"] == 3
    assert result["max_depth"] == 2
    assert {"parent": "nginx", "child": "sh", "count": 1} in result["common_edges"]
    assert result["semantics"].startswith("structural context")


def test_interpreter_spawned_by_network_service_is_high():
    events = read_jsonl("datasets/synthetic/tree-example.jsonl")
    result = process_tree(events)
    kinds = [(finding["kind"], finding["severity"]) for finding in result["findings"]]
    assert ("interpreter_spawn", "high") in kinds


def test_self_parent_is_not_treated_as_an_edge():
    events = build([{"timestamp": 1, "event_type": "process_start", "process_id": 7,
                     "parent_process_id": 7, "process_name": "loop"}])
    result = process_tree(events)
    assert result["edge_count"] == 0
    assert result["root_count"] == 1


def test_two_node_cycle_is_reported():
    events = build([
        {"timestamp": 1, "event_type": "process_start", "process_id": 10, "parent_process_id": 11,
         "process_name": "bash"},
        {"timestamp": 2, "event_type": "process_start", "process_id": 11, "parent_process_id": 10,
         "process_name": "dash"},
    ])
    result = process_tree(events)
    assert result["cycle_count"] >= 1
    assert any(finding["kind"] == "ancestry_cycle" for finding in result["findings"])


def test_cycle_detection_terminates_on_long_chains():
    rows = [{"timestamp": 1, "event_type": "process_start", "process_id": 1, "parent_process_id": 0,
             "process_name": "init"}]
    rows += [{"timestamp": 2 + index, "event_type": "process_start", "process_id": 100 + index,
              "parent_process_id": 99 + index, "process_name": f"p{index}"} for index in range(50)]
    result = process_tree(build(rows))
    assert result["cycle_count"] == 0
    assert result["max_depth"] >= 49


def test_deep_chain_finding():
    rows = [{"timestamp": 1, "event_type": "process_start", "process_id": 1, "parent_process_id": 0,
             "process_name": "init"}]
    rows += [{"timestamp": 2 + index, "event_type": "process_start", "process_id": 10 + index,
              "parent_process_id": 9 + index, "process_name": f"p{index}"} for index in range(8)]
    result = process_tree(build(rows))
    assert any(finding["kind"] == "deep_chain" for finding in result["findings"])


def test_baseline_edge_comparison_flags_drift():
    # a parent/child pair that the baseline records, so drift is detectable
    rows = [{"timestamp": 1000, "event_type": "process_start", "process_id": 50,
             "parent_process_id": 1, "process_name": "svc-parent"},
            {"timestamp": 1001, "event_type": "process_start", "process_id": 51,
             "parent_process_id": 50, "process_name": "svc-child"},
            {"timestamp": 1002, "event_type": "heartbeat", "process_id": 1,
             "parent_process_id": 0, "process_name": "init"}]
    profile = build_profile([(f"s{i}", build(rows)) for i in range(3)])
    assert profile["parent_child"]
    novel = build([
        {"timestamp": 1, "event_type": "process_start", "process_id": 90, "parent_process_id": 1,
         "process_name": "systemd"},
        {"timestamp": 2, "event_type": "process_start", "process_id": 91, "parent_process_id": 90,
         "process_name": "nginx"},
        {"timestamp": 3, "event_type": "process_start", "process_id": 92, "parent_process_id": 91,
         "process_name": "sh"},
    ])
    result = process_tree(novel, profile)
    assert result["baseline_compared"] is True
    novel_edges = [f for f in result["findings"] if f["kind"] == "novel_parent_child"]
    assert novel_edges
    assert any("systemd" in finding["detail"] and "nginx" in finding["detail"]
               for finding in novel_edges)


def test_unknown_names_do_not_produce_edges():
    events = build([
        {"timestamp": 1, "event_type": "process_start", "process_id": 10, "parent_process_id": 1},
    ])
    result = process_tree(events)
    assert result["edge_count"] == 1
    assert result["findings"] == []


def test_empty_stream_is_safe():
    result = process_tree([])
    assert result["node_count"] == 0 and result["max_depth"] == 0
    assert result["findings"] == []
