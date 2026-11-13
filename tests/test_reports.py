import csv
import io
import json

import pytest

from cabid.detector import analyze, analyze_windows
from cabid.explain import FORMATS, render, render_csv, render_html, render_markdown, render_sarif
from cabid.ingest import normalize_many, read_jsonl
from cabid.policy import evaluate_policy


def sample_report():
    events = read_jsonl("datasets/synthetic/example.jsonl")
    report = analyze(events)
    report["policy"] = evaluate_policy(events)
    return report


def test_every_format_renders():
    report = sample_report()
    for fmt in FORMATS:
        output = render(report, fmt, "events.jsonl")
        assert isinstance(output, str) and output.strip()


def test_unknown_format_is_rejected():
    with pytest.raises(ValueError, match="unsupported report format"):
        render(sample_report(), "xml")


def test_markdown_mentions_status_and_limits():
    text = render_markdown(sample_report())
    assert "CABID analysis report" in text
    assert "NO_ANOMALY_DETECTED" in text
    assert "not a probability" in text


def test_sarif_document_is_well_formed():
    report = analyze(normalize_many([
        {"timestamp": 1, "event_type": "process_start", "process_id": 5, "parent_process_id": 5}]))
    document = json.loads(render_sarif(report, "input.jsonl"))
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    assert run["tool"]["driver"]["name"] == "CABID"
    assert run["results"], "a self-parent stream must produce a SARIF result"
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert {result["ruleId"] for result in run["results"]} <= rule_ids


def test_sarif_includes_policy_findings():
    events = normalize_many([{"timestamp": 1, "event_type": "network_connect", "process_id": 5,
                              "target": "10.0.0.4:22"}])
    report = analyze(events)
    report["policy"] = evaluate_policy(events)
    document = json.loads(render_sarif(report))
    assert any(result["ruleId"] == "sensitive_port_connect" for result in document["runs"][0]["results"])


def test_csv_has_one_row_per_component():
    rows = list(csv.reader(io.StringIO(render_csv(sample_report()))))
    assert rows[0][0] == "record_type"
    components = [row for row in rows[1:] if row[0] == "component"]
    assert [row[3] for row in components] == ["temporal", "causal", "sequence", "telemetry_gap", "novelty"]


def test_html_escapes_untrusted_event_content():
    events = normalize_many([{"timestamp": 1, "event_type": "file_write", "process_id": 5,
                              "process_name": "<script>alert(1)</script>",
                              "target": "/etc/shadow"}])
    report = analyze(events)
    report["policy"] = evaluate_policy(events)
    html = render_html(report, '<svg onload="alert(1)">')
    assert report["policy"]["findings"], "expected a policy finding so process names are rendered"
    assert "<script>alert(1)</script>" not in html
    assert "<svg onload=" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;svg onload=&quot;alert(1)&quot;&gt;" in html


def test_windowed_report_renders_all_formats():
    events = read_jsonl("datasets/synthetic/example.jsonl")
    windowed = analyze_windows(events, 20)
    for fmt in FORMATS:
        assert render(windowed, fmt).strip()
    assert "Window summary only" not in render_markdown(windowed)


def test_nested_window_block_renders_in_every_format():
    events = read_jsonl("datasets/synthetic/example.jsonl")
    report = analyze(events)
    report["windowed"] = analyze_windows(events, 20)
    markdown = render_markdown(report)
    assert "## Time windows" in markdown
    assert "## Component breakdown" in markdown
    rows = list(csv.reader(io.StringIO(render_csv(report))))
    assert any(row[0] == "window" for row in rows)
    document = json.loads(render_sarif(report))
    assert document["runs"][0]["results"]
    assert "Time windows" in render_html(report)
