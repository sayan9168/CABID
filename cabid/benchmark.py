"""Deterministic synthetic benchmark; not a real-world effectiveness claim."""
from __future__ import annotations
import json
import random
from collections import defaultdict
from pathlib import Path
from .detector import analyze
from .temporal import temporal_features, temporal_score

EVENT_TYPES = ["process_start", "process_exec", "file_write", "network_connect", "process_exit", "heartbeat"]


def generate_cases(seed: int = 20261113, per_class: int = 50) -> list[dict]:
    if per_class < 1:
        raise ValueError("per_class must be at least 1")
    rng = random.Random(seed)
    cases = []
    for index in range(per_class):
        events = [{"timestamp": 1000.0 + index * 100 + i * 8.0 + rng.random() * 0.2,
                   "event_type": kind, "process_id": 100 + i, "parent_process_id": 1,
                   "source": "synthetic"} for i, kind in enumerate(EVENT_TYPES)]
        cases.append({"case_id": f"benign-{index:04d}", "label": 0, "scenario": "benign_regular", "events": events})
        start = 10000.0 + index * 100
        attack = [{"timestamp": start + i * 0.001, "event_type": EVENT_TYPES[i % 6],
                   "process_id": 500 + (i % 3), "parent_process_id": 500 + (i % 3),
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
    return {"tp":tp,"tn":tn,"fp":fp,"fn":fn,"precision":round(precision,6),"recall":round(recall,6),
            "f1":round(f1,6),"false_positive_rate":round(fp/(fp+tn),6) if fp+tn else 0.0,
            "false_safe_rate":round(fn/(fn+tp),6) if fn+tp else 0.0,"sample_count":len(labels)}


def evaluate(cases: list[dict]) -> dict:
    labels, temporal_preds, cabid_preds = [], [], []
    groups = defaultdict(lambda: {"labels": [], "predictions": []})
    for case in cases:
        events, label = case["events"], int(case["label"])
        labels.append(label)
        temporal_preds.append(int(temporal_score(temporal_features(events)) >= 0.55))
        prediction = int(analyze(events)["status"] != "NO_ANOMALY_DETECTED")
        cabid_preds.append(prediction)
        groups[case["scenario"]]["labels"].append(label)
        groups[case["scenario"]]["predictions"].append(prediction)
    return {"benchmark":"CABID synthetic scenario benchmark",
            "warning":"Synthetic-only diagnostic; not evidence of real-world detection performance.",
            "models":{"temporal_only":_metrics(labels,temporal_preds),
                      "cabid_telemetry_aware":_metrics(labels,cabid_preds)},
            "scenario_metrics":{name:_metrics(v["labels"],v["predictions"]) for name,v in sorted(groups.items())}}


def run_benchmark(output: str | Path, seed: int = 20261113, per_class: int = 50) -> dict:
    report = evaluate(generate_cases(seed, per_class))
    report["configuration"] = {"seed":seed,"samples_per_scenario":per_class}
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return report
