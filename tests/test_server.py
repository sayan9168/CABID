import json
import threading
import urllib.error
import urllib.request

import pytest

from cabid.server import ApiError, analyze_payload, list_datasets, load_dataset, parse_events, serve


@pytest.fixture()
def live_server():
    httpd = serve("127.0.0.1", 0)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[:2]
    yield f"http://{host}:{port}"
    httpd.shutdown()
    httpd.server_close()


def call(url, method="GET", body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def test_health_and_index(live_server):
    status, body = call(live_server + "/api/health")
    payload = json.loads(body)
    assert status == 200 and payload["status"] == "ok"
    code, page = call(live_server + "/")
    assert code == 200 and b"CABID" in page


def test_dataset_listing_and_fetch(live_server):
    status, body = call(live_server + "/api/datasets")
    names = [item["name"] for item in json.loads(body)["datasets"]]
    assert "example.jsonl" in names
    status, body = call(live_server + "/api/datasets/example.jsonl")
    assert status == 200 and json.loads(body)["events"]


def test_path_traversal_is_blocked(live_server):
    for name in ("..%2F..%2Fpyproject.toml", "%2e%2e%2fsetup.py", "nope.jsonl"):
        status, _ = call(live_server + "/api/datasets/" + name)
        assert status in {400, 404}


def test_analyze_endpoint(live_server):
    body = {"events": '{"timestamp":1,"event_type":"heartbeat","process_id":1}', "window_seconds": 10}
    status, raw = call(live_server + "/api/analyze", "POST", body)
    payload = json.loads(raw)
    assert status == 200
    assert payload["status"] == "INSUFFICIENT_EVIDENCE"
    assert payload["windowed"]["summary"]["window_count"] == 1


def test_cross_origin_post_is_rejected(live_server):
    status, _ = call(live_server + "/api/analyze", "POST", {"events": []},
                     headers={"Origin": "https://evil.example"})
    assert status == 403


def test_invalid_events_return_422(live_server):
    status, raw = call(live_server + "/api/analyze", "POST",
                       {"events": [{"timestamp": 1, "event_type": "nope", "process_id": 1}]})
    assert status == 422 and b"unsupported event_type" in raw


def test_benchmark_endpoint_validates_range(live_server):
    assert call(live_server + "/api/benchmark?per_class=0")[0] == 422
    status, raw = call(live_server + "/api/benchmark?per_class=2&seed=1")
    assert status == 200
    assert json.loads(raw)["models"]["cabid_core"]["sample_count"] == 6


def test_proxy_prefixes_and_absolute_form_targets_are_supported(live_server):
    port = live_server.rsplit(":", 1)[1]
    status, raw = call(f"{live_server}/__proxy/{port}/api/health")
    assert status == 200 and json.loads(raw)["status"] == "ok"
    status, raw = call(f"{live_server}/__proxy/{port}/api/analyze", "POST",
                       {"events": [{"timestamp": 1, "event_type": "heartbeat", "process_id": 1}]})
    assert status == 200
    assert json.loads(raw)["status"] == "INSUFFICIENT_EVIDENCE"


def test_unknown_route_is_404(live_server):
    assert call(live_server + "/api/nothing")[0] == 404
    assert call(live_server + "/api/nothing", "POST", {})[0] == 404


def test_event_count_limit(monkeypatch):
    import cabid.server as server_module
    monkeypatch.setattr(server_module, "MAX_EVENTS", 2)
    with pytest.raises(ApiError) as excinfo:
        parse_events([{"timestamp": 1, "event_type": "heartbeat", "process_id": 1}] * 3)
    assert excinfo.value.status == 413


def test_baseline_endpoint(live_server):
    status, raw = call(live_server + "/api/baseline", "POST", {"datasets": ["example.jsonl"]})
    assert status == 200
    assert json.loads(raw)["format"] == "cabid-baseline/1"
    assert call(live_server + "/api/baseline", "POST", {"datasets": []})[0] == 422


def test_helpers_reject_bad_input():
    with pytest.raises(ApiError):
        load_dataset("../../etc/passwd")
    with pytest.raises(ApiError):
        analyze_payload({"events": [], "window_seconds": -1})
    assert list_datasets().count(list_datasets()[0]) == 1


def test_bundled_suspicious_fixture_drives_the_ui(live_server):
    status, raw = call(live_server + "/api/datasets/suspicious-example.jsonl")
    assert status == 200
    events = json.loads(raw)["events"]
    assert len(events) == 72
    status, raw = call(live_server + "/api/analyze", "POST", {"events": events, "window_seconds": 2})
    report = json.loads(raw)
    assert report["status"] in {"SUSPICIOUS", "HIGH_RISK"}
    assert report["policy"]["finding_count"] >= 1
    assert report["windowed"]["summary"]["window_count"] > 1


def test_multi_dataset_analysis_with_time_filter(live_server):
    status, raw = call(live_server + "/api/analyze", "POST",
                       {"datasets": ["example.jsonl", "suspicious-example.jsonl"],
                        "since": "2025-10-09T00:00:00Z", "until": "2025-10-20T00:00:00Z"})
    assert status == 200
    report = json.loads(raw)
    assert report["sources"]["source_count"] == 2
    assert report["time_filter"]["active"] is True
    assert report["entities"]["entity_count"] >= 1


def test_bad_time_range_and_dataset_list_are_422(live_server):
    assert call(live_server + "/api/analyze", "POST",
                {"events": [], "since": "2030-01-01", "until": "2020-01-01"})[0] == 422
    assert call(live_server + "/api/analyze", "POST", {"datasets": []})[0] == 422
    assert call(live_server + "/api/analyze", "POST", {"datasets": ["../pyproject.toml"]})[0] in {400, 404, 422}


def test_dashboard_exposes_the_scope_pane(live_server):
    """The containers block must be reachable in the UI, not only in JSON."""
    import urllib.request

    page = urllib.request.urlopen(live_server + "/").read().decode("utf-8")
    assert 'data-tab="containers"' in page
    assert "report.containers" in page
    # The pane must carry the "collisions are expected" caveat, not just a count.
    assert "expected, not suspicious" in page


def test_analyze_endpoint_returns_scope_information(live_server):
    import json
    import urllib.request

    rows = [
        {"timestamp": 1, "event_type": "process_start", "process_id": 1,
         "parent_process_id": 0, "process_name": "nginx", "container_id": "abc123"},
        {"timestamp": 2, "event_type": "process_start", "process_id": 42,
         "parent_process_id": 1, "process_name": "php", "container_id": "abc123"},
        {"timestamp": 3, "event_type": "process_start", "process_id": 42,
         "parent_process_id": 0, "process_name": "java", "container_id": "def456"},
    ]
    body = json.dumps({"events": rows}).encode()
    request = urllib.request.Request(live_server + "/api/analyze", data=body,
                                    headers={"Content-Type": "application/json"})
    report = json.load(urllib.request.urlopen(request))
    assert report["containers"]["container_aware"] is True
    assert report["containers"]["scope_count"] == 2
    assert report["containers"]["collision_count"] == 1


# ----------------------------------------------------------- graph endpoint ----

def _graph_events(count: int = 30) -> list[dict]:
    return [{
        "timestamp": 1760000000.0 + index,
        "event_type": "file_write",
        "process_id": 100 + index % 5,
        "parent_process_id": 1 if index % 5 else 0,
        "process_name": f"svc-{index % 5}",
        "executable": "",
        "target": "",
        "source": "test",
    } for index in range(count)]


def test_graph_payload_resolves_one_parent_per_pid():
    from cabid.server import graph_payload

    graph = graph_payload(_graph_events())
    pids = [node["pid"] for node in graph["nodes"]]
    assert len(pids) == len(set(pids))
    assert graph["node_count"] == 5
    for node in graph["nodes"]:
        assert node["parent"] is None or isinstance(node["parent"], int)


def test_graph_payload_bins_cover_the_window():
    from cabid.server import graph_payload

    graph = graph_payload(_graph_events())
    assert sum(bin_["count"] for bin_ in graph["bins"]) == 30
    assert graph["window"]["start"] == 1760000000.0
    assert graph["window"]["end"] >= graph["window"]["start"]
    assert all(0.0 <= bin_["share"] <= 1.0 for bin_ in graph["bins"])


def test_graph_payload_caps_nodes_and_reports_truncation():
    from cabid.server import graph_payload

    events = _graph_events(600)
    for index, event in enumerate(events):
        event["process_id"] = 1000 + index
    graph = graph_payload(events, max_nodes=50)
    assert graph["truncated"] is True
    assert graph["rendered_nodes"] == 50
    assert graph["node_count"] == 600


def test_graph_payload_handles_empty_input():
    from cabid.server import graph_payload

    graph = graph_payload([])
    assert graph["nodes"] == [] and graph["bins"] == []
    assert graph["notes"]


def test_graph_payload_keeps_a_parent_outside_the_window_dangling():
    from cabid.server import graph_payload

    events = [{"timestamp": 1.0, "event_type": "process_exec", "process_id": 5,
               "parent_process_id": 999, "process_name": "child", "executable": "",
               "target": "", "source": "t"}]
    graph = graph_payload(events)
    assert graph["nodes"][0]["parent"] == 999
    assert graph["edges"][0]["source"] == 999


def test_graph_endpoint_serves_bundled_dataset(live_server):
    status, body = call(f"{live_server}/api/graph?dataset=tree-example.jsonl")
    assert status == 200
    payload = json.loads(body)
    assert payload["node_count"] >= 1
    assert payload["bins"]


def test_graph_endpoint_requires_a_dataset(live_server):
    status, body = call(f"{live_server}/api/graph")
    assert status == 422
    assert "dataset is required" in json.loads(body)["error"]


def test_graph_endpoint_accepts_posted_events(live_server):
    status, body = call(f"{live_server}/api/graph", "POST", {"events": _graph_events(10)})
    assert status == 200
    assert json.loads(body)["node_count"] == 5


def test_graph_endpoint_rejects_malformed_events(live_server):
    status, body = call(f"{live_server}/api/graph", "POST", {"events": "not jsonl"})
    assert status == 422


def test_dashboard_page_exposes_the_new_tabs(live_server):
    status, body = call(f"{live_server}/")
    assert status == 200
    text = body.decode("utf-8")
    for tab in ("Process graph", "Timeline", "Filter"):
        assert tab in text
    assert "/api/graph" in text
    assert 'id="build-graph"' in text
