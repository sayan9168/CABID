from cabid.benchmark import evaluate, generate_cases


def test_synthetic_benchmark_is_reproducible():
    first = generate_cases(seed=7, per_class=2)
    assert first == generate_cases(seed=7, per_class=2)
    report = evaluate(first)
    assert report["models"]["cabid_telemetry_aware"]["sample_count"] == 6
    assert "Synthetic-only" in report["warning"]


def test_benchmark_reports_confusion_matrix_metrics():
    metrics = evaluate(generate_cases(seed=9, per_class=3))["models"]["cabid_telemetry_aware"]
    assert metrics["tp"] + metrics["tn"] + metrics["fp"] + metrics["fn"] == 9
    assert 0.0 <= metrics["precision"] <= 1.0
