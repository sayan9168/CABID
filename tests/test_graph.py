import xml.etree.ElementTree as ET

import pytest

from cabid.baseline import build_profile
from cabid.graph import (FORMATS, GraphError, process_graph, render, render_dot,
                         render_graphml, render_mermaid)
from cabid.ingest import read_jsonl


def events():
    return read_jsonl("datasets/synthetic/tree-example.jsonl")


def test_graph_shape_and_metadata():
    graph = process_graph(events())
    assert graph["format"] == "cabid-process-graph/1"
    assert graph["node_count"] == 10
    assert graph["edge_count"] == 9
    assert graph["root_count"] == 1
    assert graph["max_depth"] == 4
    assert graph["truncated"] is False
    assert graph["semantics"].startswith("observed parent/child edges")


def test_nodes_carry_observed_attributes():
    graph = process_graph(events())
    by_name = {node["label"]: node for node in graph["nodes"]}
    nginx = by_name["nginx"]
    assert nginx["name"] == "nginx"
    assert nginx["writes"] == 0  # nginx only reads/connects in this fixture
    assert nginx["event_count"] >= 1
    assert nginx["in_cycle"] is False
    assert nginx["executable"] == ""
    assert "network_connect" in nginx["event_types"]


def test_root_is_the_only_parentless_node():
    graph = process_graph(events())
    roots = [node for node in graph["nodes"] if node["root"]]
    assert len(roots) == 1
    assert roots[0]["label"] == "init"
    assert roots[0]["id"] == 1


def test_dot_output_is_syntactically_closed():
    dot = render_dot(process_graph(events()))
    assert dot.startswith("// CABID process graph")
    assert "digraph cabid_process_graph {" in dot
    assert dot.rstrip().endswith("}")
    assert 'n401 -> n402 [label="2"]' in dot
    assert "pid=401" in dot


def test_mermaid_output_has_an_id_for_every_node():
    graph = process_graph(events())
    mermaid = render_mermaid(graph)
    assert "flowchart TD" in mermaid
    for node in graph["nodes"]:
        assert f'n{node["id"]}["' in mermaid
    assert "n401 -->|2| n402" in mermaid
    assert "b -> a" not in mermaid


def test_graphml_parses_and_matches_counts():
    graph = process_graph(events())
    payload = render_graphml(graph)
    root = ET.fromstring(payload)
    namespace = "{http://graphml.graphdrawing.org/xmlns}"
    nodes = root.findall(f".//{namespace}node")
    edges = root.findall(f".//{namespace}edge")
    assert len(nodes) == graph["node_count"]
    assert len(edges) == graph["edge_count"]


def test_json_render_roundtrips_without_reparsing_text():
    import json

    graph = process_graph(events())
    payload = render(graph, "json")
    assert json.loads(payload)["format"] == "cabid-process-graph/1"


def test_cycle_nodes_are_visually_marked():
    graph = process_graph(events())
    dot = render_dot(graph)
    mermaid = render_mermaid(graph)
    assert 'n410 [label="bash' in dot and 'color="#b22222"' in dot
    assert "style n410 fill:#ffe0e0,stroke:#b22222" in mermaid


def test_events_must_be_dicts():
    with pytest.raises(GraphError, match="event dicts"):
        process_graph(["not-a-dict"])


def test_formats_tuple_matches_renderer_dispatch():
    assert set(FORMATS) == {"json", "dot", "mermaid", "graphml"}
    graph = process_graph(events())
    for name in FORMATS:
        assert render(graph, name)
    with pytest.raises(GraphError, match="unsupported graph format"):
        render(graph, "svg")


def test_max_nodes_truncates_and_says_so():
    graph = process_graph(events(), max_nodes=3)
    assert graph["node_count"] == 3
    assert graph["truncated"] is True
    assert graph["omitted_nodes"] == 7
    assert any("omitted" in warning for warning in graph["warnings"])
    assert graph["edge_count"] <= 3


def test_baseline_marks_unseen_edges():
    profile = build_profile([("t", events())], minimum_sessions=1)
    graph = process_graph(events(), profile)
    assert graph["baseline"]["present"] is True
    assert all(edge["baseline_known"] is True for edge in graph["edges"])
    assert graph["novel_edge_count"] == 0
    assert graph["baseline"]["session_count"] == 1


def test_baseline_from_other_sessions_flags_novel_edges():
    calm = [{"timestamp": 1, "event_type": "process_start", "process_id": 1,
             "parent_process_id": 0, "process_name": "init", "executable": "/sbin/init",
             "target": "", "source": "test"},
            {"timestamp": 2, "event_type": "process_start", "process_id": 2,
             "parent_process_id": 1, "process_name": "systemd", "executable": "",
             "target": "", "source": "test"}]
    profile = build_profile([("calm", calm)], minimum_sessions=1)
    graph = process_graph(events(), profile)
    assert graph["novel_edge_count"] >= 1
    assert any(edge["baseline_known"] is False for edge in graph["edges"])
    assert any("never appeared in the baseline" in note for note in
               [graph["baseline"]["note"]])


def test_cycle_membership_is_detected():
    cyclic = [
        {"timestamp": 1, "event_type": "process_start", "process_id": 10,
         "parent_process_id": 11, "process_name": "a", "executable": "", "target": "",
         "source": "test"},
        {"timestamp": 2, "event_type": "process_start", "process_id": 11,
         "parent_process_id": 10, "process_name": "b", "executable": "", "target": "",
         "source": "test"},
        {"timestamp": 3, "event_type": "process_start", "process_id": 12,
         "parent_process_id": 10, "process_name": "c", "executable": "", "target": "",
         "source": "test"},
    ]
    graph = process_graph(cyclic)
    in_cycle = {node["label"] for node in graph["nodes"] if node["in_cycle"]}
    assert in_cycle == {"a", "b"}
    assert graph["root_count"] == 0
    assert any("cycle" in warning for warning in graph["warnings"])
    assert graph["cycle_node_count"] == 2
    assert graph["root_count"] == 0


def test_empty_input_yields_an_empty_but_valid_graph():
    graph = process_graph([])
    assert graph["node_count"] == 0
    assert graph["edges"] == []
    assert render(graph, "dot").strip().endswith("}")
    assert "flowchart TD" in render(graph, "mermaid")
    assert any("no process nodes" in warning for warning in graph["warnings"])


def test_events_must_be_a_list():
    with pytest.raises(GraphError, match="list of normalized event dicts"):
        process_graph({"event_type": "file_write"})


def test_max_nodes_must_be_positive():
    with pytest.raises(GraphError, match="max_nodes"):
        process_graph(events(), max_nodes=0)


def test_self_parent_is_not_an_edge():
    graph = process_graph([{"timestamp": 1, "event_type": "process_start",
                            "process_id": 7, "parent_process_id": 7,
                            "process_name": "loop", "executable": "", "target": "",
                            "source": "test"}])
    assert graph["edge_count"] == 0
    assert graph["root_count"] == 1


def test_mermaid_marks_baseline_novel_edges_dashed():
    calm = [
        {"timestamp": 1, "event_type": "process_start", "process_id": 1,
         "parent_process_id": 0, "process_name": "init", "executable": "/sbin/init",
         "target": "", "source": "test"},
        {"timestamp": 2, "event_type": "process_start", "process_id": 2,
         "parent_process_id": 1, "process_name": "systemd", "executable": "",
         "target": "", "source": "test"},
    ]
    profile = build_profile([("calm", calm)], minimum_sessions=1)
    mermaid = render_mermaid(process_graph(events(), profile))
    assert "-.->" in mermaid


def test_self_parent_is_marked_as_a_cycle():
    graph = process_graph([{"timestamp": 1, "event_type": "process_start",
                            "process_id": 7, "parent_process_id": 7,
                            "process_name": "loop", "executable": "", "target": "",
                            "source": "test"}])
    assert graph["nodes"][0]["in_cycle"] is True


def test_missing_process_names_fall_back_to_unknown():
    graph = process_graph([{"timestamp": 1, "event_type": "file_write",
                            "process_id": 5, "parent_process_id": 0,
                            "process_name": "", "executable": "", "target": "/tmp/x",
                            "source": "test"}])
    assert graph["nodes"][0]["label"] == "unknown"
    assert graph["nodes"][0]["last_target"] == "/tmp/x"


def test_every_node_rooting_is_reported_as_a_warning():
    graph = process_graph([{"timestamp": 1, "event_type": "process_start",
                            "process_id": 5, "parent_process_id": 5,
                            "process_name": "a", "executable": "", "target": "",
                            "source": "test"}])
    assert any("every node is a root" in warning for warning in graph["warnings"])


def test_orphan_nodes_are_not_cycles():
    graph = process_graph([{"timestamp": 1, "event_type": "file_write",
                            "process_id": 9, "parent_process_id": 99,
                            "process_name": "orphan", "executable": "", "target": "",
                            "source": "test"}])
    assert graph["nodes"][0]["in_cycle"] is False
    assert graph["cycle_node_count"] == 0
