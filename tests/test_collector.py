import json

from cabid.collector import collect_to_jsonl


def test_collect_to_jsonl_writes_valid_heartbeat(tmp_path):
    output = tmp_path / "events.jsonl"
    count = collect_to_jsonl(output, interval=0.01, duration=0.02, proc_root="/proc")
    assert count >= 1
    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert any(row["event_type"] == "heartbeat" for row in rows)
