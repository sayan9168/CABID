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
