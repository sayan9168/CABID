from cabid.benchmark import evaluate, generate_cases


def test_synthetic_benchmark_is_reproducible():
    first = generate_cases(seed=7, per_class=2)
    assert first == generate_cases(seed=7, per_class=2)
    report = evaluate(first)
    assert report["models"]["cabid_with_baseline"]["sample_count"] == 6
    assert "Synthetic-only" in report["warning"]


def test_benchmark_reports_confusion_matrix_metrics():
    metrics = evaluate(generate_cases(seed=9, per_class=3))["models"]["cabid_core"]
    assert metrics["tp"] + metrics["tn"] + metrics["fp"] + metrics["fn"] == 9
    assert 0.0 <= metrics["precision"] <= 1.0


def test_telemetry_aware_model_never_scores_below_temporal_baseline():
    report = evaluate(generate_cases(seed=11, per_class=4))
    baseline = report["models"]["temporal_only"]
    aware = report["models"]["cabid_core"]
    assert aware["recall"] >= baseline["recall"]
    assert aware["false_safe_rate"] <= baseline["false_safe_rate"]


def test_benchmark_reports_every_scenario():
    report = evaluate(generate_cases(seed=5, per_class=2))
    assert set(report["scenario_metrics"]) == {
        "benign_regular", "synthetic_behavior_anomaly", "telemetry_loss"
    }
