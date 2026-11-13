import json
import pytest
from cabid.ingest import read_jsonl
from cabid.normalize import EventError

def test_jsonl_sorted(tmp_path):
    path = tmp_path / "events.jsonl"
    rows = [{"timestamp": 2, "event_type": "process_exec", "process_id": 2}, {"timestamp": 1, "event_type": "process_start", "process_id": 1}]
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    assert [e["timestamp"] for e in read_jsonl(path)] == [1, 2]

def test_bad_jsonl_has_line_number(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text('{"timestamp": 1, "event_type": "bad", "process_id": 1}\n', encoding="utf-8")
    with pytest.raises(EventError, match=r":1:"):
        read_jsonl(path)
