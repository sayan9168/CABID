"""Deterministic synthetic benchmark; not a real-world effectiveness claim.

Three models are compared on the same generated fixtures:

``temporal_only``        a single temporal threshold (baseline).
``cabid_core``           temporal + ancestry + lifecycle + completeness gate.
``cabid_with_baseline``  the same engine with novelty against a benign profile
                         fitted from the generated benign splits only.

The baseline profile is fitted on benign cases and applied to all cases, so the
first benign sample is scored after the profile is built (no self-leakage of
that sample's own executable set into its own score beyond its family).
"""
from __future__ import annotations

import json
import random
from collections import defaultdict
from pathlib import Path

from .baseline import build_profile
from .detector import analyze
from .temporal import temporal_features, temporal_score

EVENT_TYPES = ["process_start", "process_exec", "file_write", "network_connect", "process_exit", "heartbeat"]
_SCENARIOS = ("benign_regular", "synthetic_behavior_anomaly", "telemetry_loss")


def generate_cases(seed: int = 20261113, per_class: int = 50) -> list[dict]:
    if per_class < 1:
        raise ValueError("per_class must be at least 1")
    rng = random.Random(seed)
    cases = []
    for index in range(per_class):
        events = [{"timestamp": 1000.0 + index * 100 + i * 8.0 + rng.random() * 0.2,
                   "event_type": kind, "process_id": 100 + i, "parent_process_id": 1,
                   "process_name": f"svc-{i}", "executable": f"/usr/bin/svc-{i}",
                   "source": "synthetic"} for i, kind in enumerate(EVENT_TYPES)]
        cases.append({"case_id": f"benign-{index:04d}", "label": 0, "scenario": "benign_regular", "events": events})
        start = 10000.0 + index * 100
        attack = [{"timestamp": start + i * 0.001, "event_type": EVENT_TYPES[i % 6],
                   "process_id": 500 + (i % 3), "parent_process_id": 500 + (i % 3),
                   "process_name": f"worker-{i % 3}", "executable": f"/tmp/.hidden/{i % 7}",
                   "target": "/etc/shadow" if EVENT_TYPES[i % 6] == "file_write" and i % 18 == 2 else ("" if EVENT_TYPES[i % 6] != "network_connect" else "10.0.0.9:6379"),
                   "source": "synthetic"} for i in range(120)]
        cases.append({"case_id": f"behavior-{index:04d}", "label": 1,
                      "scenario": "synthetic_behavior_anomaly", "events": attack})
        degraded = [dict(event) for event in events if event["event_type"] not in {"network_connect", "file_write"}]
        cases.append({"case_id": f"loss-{index:04d}", "label": 1, "scenario": "telemetry_loss", "events": degraded})
    return cases


def _metrics(labels: list[int], predictions: list[int]) -> dict:
    tp = sum(y == 1 and p == 1 for y, p in zip(labels, predictions))
    tn = sum(y == 0 and p == 0 for y, p in zip(labels, predictions))
    fp = sum(y == 0 and p == 1 for y, p in zip(labels, predictions))
    fn = sum(y == 1 and p == 0 for y, p in zip(labels, predictions))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn, "precision": round(precision, 6),
            "recall": round(recall, 6), "f1": round(f1, 6),
            "false_positive_rate": round(fp / (fp + tn), 6) if fp + tn else 0.0,
            "false_safe_rate": round(fn / (fn + tp), 6) if fn + tp else 0.0,
            "sample_count": len(labels)}


def _fit_profile(cases: list[dict]) -> dict | None:
    benign = [(case["case_id"], case["events"]) for case in cases if int(case["label"]) == 0]
    if len(benign) < 2:
        return None
    try:
        return build_profile(benign, minimum_sessions=2)
    except ValueError:
        return None


def evaluate(cases: list[dict], config: dict | None = None, profile: dict | None = None) -> dict:
    labels, temporal_preds, core_preds, wide_preds = [], [], [], []
    groups = defaultdict(lambda: {"labels": [], "predictions": [], "core": []})
    fitted = profile if profile is not None else _fit_profile(cases)
    thresholds = (config or {}).get("thresholds", {})
    temporal_cutoff = float(thresholds.get("suspicious", 0.55))
    for case in cases:
        events, label = case["events"], int(case["label"])
        labels.append(label)
        temporal_preds.append(int(temporal_score(temporal_features(events), thresholds) >= temporal_cutoff))
        core = int(analyze(events, config)["status"] != "NO_ANOMALY_DETECTED")
        wide = int(analyze(events, config, fitted)["status"] != "NO_ANOMALY_DETECTED")
        core_preds.append(core)
        wide_preds.append(wide)
        groups[case["scenario"]]["labels"].append(label)
        groups[case["scenario"]]["predictions"].append(wide)
        groups[case["scenario"]]["core"].append(core)
    models = {
        "temporal_only": _metrics(labels, temporal_preds),
        "cabid_core": _metrics(labels, core_preds),
        "cabid_with_baseline": _metrics(labels, wide_preds),
    }
    report = {
        "benchmark": "CABID synthetic scenario benchmark",
        "warning": "Synthetic-only diagnostic; not evidence of real-world detection performance.",
        "models": models,
        "scenario_metrics": {name: _metrics(v["labels"], v["predictions"]) for name, v in sorted(groups.items())},
        "scenario_metrics_core_only": {name: _metrics(v["labels"], v["core"]) for name, v in sorted(groups.items())},
        "baseline_fitted": fitted is not None,
        "temporal_decision_threshold": temporal_cutoff,
        "decision_rule": "any status other than NO_ANOMALY_DETECTED counts as a positive detection",
    }
    if fitted:
        report["baseline_profile_summary"] = {
            "session_count": fitted.get("session_count"),
            "rate_per_minute": fitted.get("rate_per_minute"),
        }
    return report


def run_benchmark(output: str | Path, seed: int = 20261113, per_class: int = 50,
                  config: dict | None = None, profile: dict | None = None) -> dict:
    report = evaluate(generate_cases(seed, per_class), config, profile)
    report["configuration"] = {"seed": seed, "samples_per_scenario": per_class,
                              "profiles_are_synthetic": True}
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report
