import json

import pytest

from cabid.aggregate import IngestError, ingest_sources


def write(path, rows):
    path.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
    return path


def row(timestamp, kind="heartbeat", pid=1, target=""):
    return {"timestamp": timestamp, "event_type": kind, "process_id": pid,
            "parent_process_id": 0, "target": target}


def test_merge_tags_sources_and_sorts(tmp_path):
    first = write(tmp_path / "a.jsonl", [row(30), row(10)])
    second = write(tmp_path / "b.jsonl", [row(20)])
    result = ingest_sources([first, second])
    assert [event["timestamp"] for event in result["events"]] == [10.0, 20.0, 30.0]
    assert result["events_total"] == 3
    assert {item["source"] for item in result["sources"]} == {"a.jsonl", "b.jsonl"}
    assert result["events"][0]["source_file"] == "a.jsonl"
    assert result["first_timestamp"] == 10.0 and result["last_timestamp"] == 30.0


def test_duplicates_are_counted_not_dropped(tmp_path):
    first = write(tmp_path / "a.jsonl", [row(10), row(20)])
    second = write(tmp_path / "b.jsonl", [row(10), row(20)])
    result = ingest_sources([first, second])
    assert result["duplicate_events"] == 2
    assert result["events_after_merge"] == 4


def test_overlapping_ranges_are_reported(tmp_path):
    first = write(tmp_path / "a.jsonl", [row(10), row(50)])
    second = write(tmp_path / "b.jsonl", [row(30), row(70)])
    result = ingest_sources([first, second])
    assert result["overlapping_sources"] == [{"sources": ["a.jsonl", "b.jsonl"], "overlap_seconds": 20.0}]


def test_disjoint_ranges_have_no_overlap(tmp_path):
    first = write(tmp_path / "a.jsonl", [row(10), row(20)])
    second = write(tmp_path / "b.jsonl", [row(30), row(40)])
    assert ingest_sources([first, second])["overlapping_sources"] == []


def test_empty_input_rejected():
    with pytest.raises(IngestError):
        ingest_sources([])


def test_invalid_file_reports_line_number(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"timestamp": 1, "event_type": "nope", "process_id": 1}\n', encoding="utf-8")
    with pytest.raises(IngestError, match=":1:"):
        ingest_sources([bad])


def test_no_inputs_is_an_error():
    import pytest

    from cabid.aggregate import IngestError, ingest_sources

    with pytest.raises(IngestError, match="at least one input"):
        ingest_sources([])


def test_a_malformed_source_aborts_the_whole_merge(tmp_path):
    import pytest

    from cabid.aggregate import IngestError, ingest_sources

    good = tmp_path / "good.jsonl"
    good.write_text('{"timestamp":1,"event_type":"heartbeat","process_id":1,'
                    '"parent_process_id":0,"process_name":"a"}\n', encoding="utf-8")
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"timestamp":"not-a-time"}\n', encoding="utf-8")
    with pytest.raises(IngestError):
        ingest_sources([good, bad])


def test_empty_source_is_reported_not_ignored(tmp_path):
    from cabid.aggregate import ingest_sources

    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    merged = ingest_sources([empty])
    assert merged["source_count"] == 1
    assert merged["events"] == []
    assert merged["events_total"] == 0
    assert merged["first_timestamp"] is None
