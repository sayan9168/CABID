import pytest

from cabid.detector import analyze
from cabid.ingest import normalize_many, read_jsonl
from cabid.rules import load_rules
from cabid.timeline import build_timeline, render_timeline_markdown, render_timeline_text


def stream():
    return read_jsonl("datasets/synthetic/tree-example.jsonl")


def test_rows_are_chronological_and_iso_rendered():
    timeline = build_timeline(stream(), analyze(stream()))
    stamps = [row["timestamp"] for row in timeline["rows"]]
    assert stamps == sorted(stamps)
    assert timeline["rows"][0]["timestamp_iso"].endswith("+00:00")
    assert timeline["row_count"] == len(timeline["rows"])


def test_rule_hits_annotate_the_offending_rows():
    events = stream()
    report = analyze(events)
    timeline = build_timeline(events, report)
    ids = {item["id"] for row in timeline["rows"] for item in row["annotations"]}
    assert "shell-from-service" in ids
    assert timeline["annotated_rows"] > 0


def test_policy_hits_annotate_rows():
    from cabid.policy import evaluate_policy

    events = stream()
    report = analyze(events)
    report["policy"] = evaluate_policy(events)
    timeline = build_timeline(events, report)
    kinds = {item["kind"] for row in timeline["rows"] for item in row["annotations"]}
    assert "policy" in kinds


def test_limit_truncates_and_flags():
    timeline = build_timeline(stream(), {}, limit=3)
    assert timeline["row_count"] == 3
    assert timeline["truncated"] is True
    assert timeline["total_events"] > 3


def test_limit_is_validated():
    for bad in (0, -1, True, 2.5):
        with pytest.raises(ValueError):
            build_timeline(stream(), {}, limit=bad)


def test_empty_events_are_safe():
    timeline = build_timeline([], {})
    assert timeline["row_count"] == 0
    assert timeline["truncated"] is False
    assert "0 of 0" in render_timeline_markdown(timeline)


def test_markdown_includes_annotation_legend_and_rows():
    timeline = build_timeline(stream(), analyze(stream()), limit=5)
    markdown = render_timeline_markdown(timeline)
    assert "CABID timeline" in markdown
    assert "not proven intent" in markdown
    assert "| # | Time (UTC) |" in markdown


def test_markdown_escapes_pipes_in_targets():
    events = normalize_many([{"timestamp": 1, "event_type": "file_write", "process_id": 1,
                              "target": "/tmp/a|b|c"}])
    markdown = render_timeline_markdown(build_timeline(events, {}))
    row = [line for line in markdown.splitlines() if "/tmp/a" in line][0]
    # pipes inside the target are escaped, so they cannot break the table
    assert r"/tmp/a\|b\|c" in row


def test_text_renderer_is_plain_and_annotated():
    text = render_timeline_text(build_timeline(stream(), analyze(stream()), limit=5))
    assert "pid=" in text
    assert text.count("\n") >= 5


def test_report_annotations_not_required():
    timeline = build_timeline(stream())
    assert timeline["annotated_rows"] == 0


def test_custom_rules_flow_into_timeline():
    events = normalize_many([
        {"timestamp": 1, "event_type": "process_exec", "process_id": 5,
         "parent_process_id": 1, "process_name": "curl", "executable": "/usr/bin/curl"},
        {"timestamp": 2, "event_type": "process_exec", "process_id": 6,
         "parent_process_id": 5, "process_name": "payload", "executable": "/tmp/x"},
    ])
    report = analyze(events, rules=load_rules(None))
    timeline = build_timeline(events, report)
    ids = {item["id"] for row in timeline["rows"] for item in row["annotations"]}
    assert "download-then-exec" in ids
