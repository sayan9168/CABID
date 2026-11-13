import json

from cabid.detector import analyze, explain_score, render_score_explanation
from cabid.ingest import normalize_many, read_jsonl


def suspicious_stream():
    return read_jsonl("datasets/synthetic/tree-example.jsonl")


def test_explanation_recomputes_the_reported_score():
    report = analyze(suspicious_stream())
    explanation = explain_score(report)
    assert explanation["recomputes_consistently"] is True
    assert explanation["recomputed_score"] == report["anomaly_score"]


def test_every_component_appears_exactly_once():
    report = analyze(suspicious_stream())
    names = [step["component"] for step in explain_score(report)["steps"]]
    assert sorted(names) == ["causal", "novelty", "sequence", "telemetry_gap", "temporal"]


def test_steps_are_sorted_highest_contribution_first():
    report = analyze(suspicious_stream())
    products = [step["product"] for step in explain_score(report)["steps"]]
    assert products == sorted(products, reverse=True)


def test_product_equals_weight_times_value():
    report = analyze(suspicious_stream())
    for step in explain_score(report)["steps"]:
        assert abs(step["product"] - step["normalized_weight"] * step["component_value"]) < 1e-6


def test_inactive_novelty_weight_is_redistributed_not_scored():
    report = analyze(suspicious_stream())
    explanation = explain_score(report)
    novelty = next(step for step in explanation["steps"] if step["component"] == "novelty")
    assert novelty["normalized_weight"] == 0.0
    assert novelty["product"] == 0.0
    assert "redistributed" in novelty["note"]


def test_denominator_excludes_the_inactive_component():
    report = analyze(suspicious_stream())
    explanation = explain_score(report)
    assert explanation["weight_denominator"] != 1.0 or not report["baseline_used"]


def test_insufficient_evidence_is_explained_as_a_gate_not_a_score():
    stream = normalize_many([
        {"timestamp": 1, "event_type": "heartbeat", "process_id": 1,
         "parent_process_id": 0, "process_name": "a"}])
    report = analyze(stream)
    assert report["status"] == "INSUFFICIENT_EVIDENCE"
    explanation = explain_score(report)
    assert "telemetry_sufficient is false" in explanation["decision"][0]
    assert explanation["final_status"] == "INSUFFICIENT_EVIDENCE"


def test_threshold_decision_is_listed_for_a_sufficient_stream():
    report = analyze(suspicious_stream() + suspicious_stream())
    explanation = explain_score(report)
    if report["completeness"]["telemetry_sufficient"]:
        assert any("threshold" in line or ">=" in line for line in explanation["decision"])


def test_semantics_caveat_is_always_present():
    explanation = explain_score(analyze(suspicious_stream()))
    assert "not a probability" in explanation["caveat"]
    assert "heuristic" in explanation["semantics"]


def test_human_renderer_contains_the_arithmetic():
    text = render_score_explanation(explain_score(analyze(suspicious_stream())))
    assert "Score arithmetic" in text
    assert "product" in text
    assert "final status" in text
    assert "not a probability" in text


def test_cli_embeds_the_explanation_in_json(tmp_path):
    from cabid.cli import main

    destination = tmp_path / "report.json"
    code = main(["analyze", "datasets/synthetic/tree-example.jsonl",
                 "--explain-score", "-o", str(destination), "--quiet"])
    assert code == 0
    document = json.loads(destination.read_text(encoding="utf-8"))
    assert document["score_explanation"]["recomputes_consistently"] is True


def test_cli_prints_the_walkthrough_to_stderr_for_markdown(tmp_path, capsys):
    from cabid.cli import main

    destination = tmp_path / "report.md"
    code = main(["analyze", "datasets/synthetic/tree-example.jsonl", "--explain-score",
                 "--format", "md", "-o", str(destination), "--quiet"])
    assert code == 0
    assert "Score arithmetic" in capsys.readouterr().err
    assert "Score arithmetic" not in destination.read_text(encoding="utf-8")
