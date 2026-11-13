"""Real-data benchmark over the ADFA-LD syscall corpus.

This measures CABID's behaviour on a genuine public intrusion dataset rather than
on generated fixtures. It exists to answer one narrow question — *does the engine
separate the corpus's benign traces from its attack traces, reproducibly?* — and it
is deliberately built so the answer cannot be inflated:

* the benign profile is fitted on ``Training_Data_Master`` only;
* everything reported is scored on held-out data (``Validation_Data_Master`` for
  benign, ``Attack_Data_Master`` for attack);
* a corpus-appropriate reference model (syscall n-gram novelty) is scored alongside,
  so a CABID number can be read against what the literature already achieves;
* every headline metric carries a Wilson 95% interval, because these sets are small.

What this benchmark cannot show is stated in ``limitations`` and reproduced in the
report itself: ADFA-LD has no timestamps, no pids, and no paths, so CABID's ancestry,
lifecycle, and temporal detectors are either bypassed or exercised on synthetic
context. A strong score here says the event-class and novelty components behave
sensibly on 2013 syscall traces. It does not say CABID detects real intrusions.
"""
from __future__ import annotations

import math
import random
from collections import defaultdict
from pathlib import Path

from .adfa import (
    ADFA_EVENT_CLASSES,
    NgramNovelty,
    corpus_sessions,
    read_trace,
    technique_of,
    trace_to_events,
)
from .baseline import build_profile
from .config import config_digest, validate_config
from .detector import analyze

BENCHMARK_FORMAT = "cabid-realworld-benchmark/1"

#: Classes the syscall adapter can emit at all. Declaring these instead of CABID's
#: default six prevents a corpus that structurally cannot produce ``heartbeat`` or
#: ``process_exit`` from being scored as permanently under-instrumented.
ADFA_COMPLETENESS_CLASSES = [
    "file_write", "kernel_state_change", "network_connect",
    "privilege_change", "process_exec", "process_start",
]

LIMITATIONS = [
    "ADFA-LD traces carry no timestamps, process ids, paths, or user identity. The adapter "
    "synthesises a 20-second window and a single synthetic process per trace, so CABID's "
    "ancestry, lifecycle, and rate detectors are not meaningfully exercised.",
    "The corpus is from 2013 and records 32-bit userspace syscalls. Its six attack "
    "techniques are well known and appear throughout the intrusion-detection literature, "
    "so high scores are expected and are not evidence of real-world detection quality.",
    "Only a minority of syscalls map to a CABID event class; unmapped calls are dropped. "
    "Reported event counts are therefore far smaller than trace lengths.",
    "Attack classes are small (75-338 traces each). Confidence intervals are reported "
    "because point estimates on these sizes are unstable.",
    "Traces are scored independently. ADFA-LD provides no notion of a host or a fleet, so "
    "no multi-host behaviour is measured here.",
]


def wilson_interval(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion.

    Preferred over the normal approximation because it stays inside [0, 1] and
    behaves sensibly at the small counts and extreme proportions this corpus
    produces (for example 0 false positives out of 4,372 traces).
    """
    if trials <= 0:
        return 0.0, 0.0
    if successes < 0 or successes > trials:
        raise ValueError("successes must be between 0 and trials")
    phat = successes / trials
    denominator = 1.0 + z * z / trials
    centre = (phat + z * z / (2 * trials)) / denominator
    margin = (z * math.sqrt(phat * (1 - phat) / trials + z * z / (4 * trials * trials))
              / denominator)
    return max(0.0, centre - margin), min(1.0, centre + margin)


def metrics(labels: list[int], predictions: list[int]) -> dict:
    """Confusion-matrix metrics with Wilson intervals on the headline rates."""
    if len(labels) != len(predictions):
        raise ValueError("labels and predictions must be the same length")
    tp = sum(y == 1 and p == 1 for y, p in zip(labels, predictions))
    tn = sum(y == 0 and p == 0 for y, p in zip(labels, predictions))
    fp = sum(y == 0 and p == 1 for y, p in zip(labels, predictions))
    fn = sum(y == 1 and p == 0 for y, p in zip(labels, predictions))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    precision_ci = wilson_interval(tp, tp + fp) if tp + fp else (0.0, 0.0)
    recall_ci = wilson_interval(tp, tp + fn) if tp + fn else (0.0, 0.0)
    fpr_ci = wilson_interval(fp, fp + tn) if fp + tn else (0.0, 0.0)
    return {
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "precision": round(precision, 6), "recall": round(recall, 6), "f1": round(f1, 6),
        "precision_ci95": [round(value, 6) for value in precision_ci],
        "recall_ci95": [round(value, 6) for value in recall_ci],
        "false_positive_rate": round(fp / (fp + tn), 6) if fp + tn else 0.0,
        "false_positive_rate_ci95": [round(value, 6) for value in fpr_ci],
        "false_negative_rate": round(fn / (fn + tp), 6) if fn + tp else 0.0,
        "accuracy": round((tp + tn) / len(labels), 6) if labels else 0.0,
        "sample_count": len(labels),
        "positive_count": tp + fn,
        "negative_count": tn + fp,
    }


def default_config(completeness_ratio: float = 1.0) -> dict:
    """A benchmark config that does not ask for telemetry the corpus cannot emit."""
    return validate_config({
        "completeness": {
            "expected_event_types": ADFA_COMPLETENESS_CLASSES,
            "minimum_ratio": completeness_ratio,
        },
    })


def _predict_ngram(scores: list[float], cutoff: float) -> list[int]:
    return [int(score >= cutoff) for score in scores]


def _threshold_sweep(labels: list[int], scores: list[float], steps: int = 40) -> list[dict]:
    """Recall/FPR trade-off across candidate cut-offs on a decision score."""
    if not scores:
        return []
    ordered = sorted(set(scores))
    if len(ordered) > steps:
        picks = [ordered[int(i * (len(ordered) - 1) / (steps - 1))] for i in range(steps)]
    else:
        picks = ordered
    curve = []
    for cutoff in sorted(set(picks)):
        row = metrics(labels, [int(score >= cutoff) for score in scores])
        curve.append({
            "threshold": round(cutoff, 6),
            "recall": row["recall"],
            "false_positive_rate": row["false_positive_rate"],
            "precision": row["precision"],
        })
    return curve


def _percentile(values: list[float], fraction: float) -> float:
    """Linear-interpolated percentile; ``fraction`` in [0, 1]."""
    if not values:
        return 0.0
    if not 0.0 <= fraction <= 1.0:
        raise ValueError("fraction must be between 0 and 1")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = fraction * (len(ordered) - 1)
    low = int(math.floor(position))
    high = min(low + 1, len(ordered) - 1)
    weight = position - low
    return ordered[low] * (1 - weight) + ordered[high] * weight


def _split(groups: dict[str, list], holdout_fraction: float, seed: int) -> dict[str, list]:
    """Hold back a slice of the benign training traces for calibration.

    Calibration data must be disjoint from both the profile-fitting traces and the
    evaluation traces, or the thresholds are fitted on the same noise they are
    meant to suppress.
    """
    training = list(groups["training"])
    rng = random.Random(seed)
    rng.shuffle(training)
    cut = int(round(len(training) * holdout_fraction))
    cut = max(1, min(cut, len(training) - 1)) if len(training) > 1 else 0
    return {"fit": training[cut:], "calibration": training[:cut]}


def _session_events(entries: list[tuple[str, str, int]], window_seconds: float) -> list[dict]:
    sessions = []
    for session_id, path, label in entries:
        events = trace_to_events(path, window_seconds=window_seconds)
        sessions.append({
            "session_id": session_id,
            "label": label,
            "technique": technique_of(session_id),
            "events": events,
            "mapped_events": len(events),
        })
    return sessions


def run_adfa_benchmark(root: str | Path, *, window_seconds: float = 20.0,
                       ngram_size: int = 3, calibration_fraction: float = 0.25,
                       seed: int = 20261113, calibration_percentile: float = 0.99,
                       config: dict | None = None) -> dict:
    """Score CABID and an n-gram reference model on a fetched ADFA-LD corpus.

    ``calibration_percentile`` picks the completeness floor: the ratio that
    ``calibration_percentile`` of held-out benign traces meet. This replaces a
    hand-picked ``minimum_ratio`` with a number derived from benign data.
    """
    if not 0.0 < calibration_fraction < 1.0:
        raise ValueError("calibration_fraction must be between 0 and 1")
    if not 0.0 < calibration_percentile < 1.0:
        raise ValueError("calibration_percentile must be between 0 and 1")
    groups = corpus_sessions(root)
    if not groups["training"] or not groups["validation"] or not groups["attack"]:
        raise ValueError("corpus must contain training, validation and attack traces")
    split = _split(groups, calibration_fraction, seed)

    fit_sessions = _session_events(split["fit"], window_seconds)
    calibration_sessions = _session_events(split["calibration"], window_seconds)
    evaluation_sessions = (_session_events(groups["validation"], window_seconds)
                          + _session_events(groups["attack"], window_seconds))

    profile = build_profile(
        [(session["session_id"], session["events"]) for session in fit_sessions
         if session["events"]],
        minimum_sessions=3,
    )

    # --- completeness floor, derived from held-out benign traces -----------
    cfg = validate_config(config) if config is not None else None
    base_config = cfg or default_config(0.0)
    calibration_reports = [
        analyze(session["events"], base_config) for session in calibration_sessions
        if session["events"]
    ]
    observed_coverages = [report["completeness"]["completeness"] for report in calibration_reports]
    calibrated_ratio = _percentile(observed_coverages, calibration_percentile)
    working_config = dict(base_config)
    working_config["completeness"] = dict(base_config["completeness"])
    working_config["completeness"]["minimum_ratio"] = calibrated_ratio
    working_config = validate_config(working_config)

    # --- n-gram reference model ------------------------------------------
    ngram = NgramNovelty(ngram_size).fit(
        [read_trace(path) for _, path, _ in split["fit"]]
    )
    calibration_ngram = [ngram.score(read_trace(path)) for _, path, _ in split["calibration"]]
    ngram_cutoff = _percentile(calibration_ngram, calibration_percentile) if calibration_ngram else 0.0

    # A second pass with the telemetry-sufficiency gate switched off. On this corpus
    # every trace carries only a subset of the declared classes, so the gate alone can
    # drive the decision. Separating the two shows which part of the score is doing the
    # work, instead of reporting one unexamined number.
    ungated_config = validate_config({
        "completeness": {
            "expected_event_types": working_config["completeness"]["expected_event_types"],
            "minimum_ratio": 0.0,
        },
    })
    component_samples: dict[int, dict[str, list[float]]] = {0: {}, 1: {}}
    labels: list[int] = []
    cabid_core: list[int] = []
    cabid_baseline: list[int] = []
    cabid_ungated: list[int] = []
    cabid_scores: list[float] = []
    ngram_scores: list[float] = []
    mappable: list[int] = []
    ngram_preds: list[int] = []
    by_technique: dict[str, dict[str, list[int]]] = defaultdict(
        lambda: {"labels": [], "cabid": [], "ngram": [], "mappable": []})
    insufficient_core = insufficient_baseline = 0

    for session in evaluation_sessions:
        events, label = session["events"], int(session["label"])
        # A trace whose every syscall falls outside CABID's event classes is not a
        # clean session, it is an unobservable one. It is scored as "not detected"
        # so the headline recall reflects what the pipeline can actually do, and
        # excluded from the mappable-only view so the gap stays visible either way.
        is_mappable = bool(events)
        if is_mappable:
            core_report = analyze(events, working_config)
            wide_report = analyze(events, working_config, profile)
            ungated_report = analyze(events, ungated_config, profile)
            core_positive = int(core_report["status"] != "NO_ANOMALY_DETECTED")
            wide_positive = int(wide_report["status"] != "NO_ANOMALY_DETECTED")
            ungated_positive = int(ungated_report["status"] != "NO_ANOMALY_DETECTED")
            insufficient_core += int(core_report["status"] == "INSUFFICIENT_EVIDENCE")
            insufficient_baseline += int(wide_report["status"] == "INSUFFICIENT_EVIDENCE")
            cabid_scores.append(float(ungated_report["anomaly_score"]))
            for name, value in ungated_report["components"].items():
                if name == "telemetry_gap":
                    continue
                component_samples[label].setdefault(name, []).append(float(value))
            component_samples[label].setdefault("class_diversity", []).append(
                float(ungated_report["temporal"]["type_diversity"]))
        else:
            core_positive = wide_positive = ungated_positive = 0
            cabid_scores.append(0.0)
        ngram_score = ngram.score(read_trace(_path_for(groups, session["session_id"])))
        ngram_positive = int(ngram_score >= ngram_cutoff)
        ngram_scores.append(ngram_score)
        labels.append(label)
        cabid_core.append(core_positive)
        cabid_baseline.append(wide_positive)
        cabid_ungated.append(ungated_positive)
        ngram_preds.append(ngram_positive)
        mappable.append(int(is_mappable))
        key = session["technique"] if label == 1 else "benign"
        by_technique[key]["labels"].append(label)
        by_technique[key]["cabid"].append(wide_positive)
        by_technique[key]["ngram"].append(ngram_positive)
        by_technique[key]["mappable"].append(int(is_mappable))

    models = {
        "cabid_core": metrics(labels, cabid_core),
        "cabid_with_baseline": metrics(labels, cabid_baseline),
        f"syscall_ngram_{ngram_size}gram": metrics(labels, ngram_preds),
        "cabid_gate_disabled": metrics(labels, cabid_ungated),
    }
    diagnostics = {
        "mean_components_by_class": {
            "benign" if label == 0 else "attack": {
                name: round(sum(values) / len(values), 6)
                for name, values in sorted(components.items()) if values
            }
            for label, components in sorted(component_samples.items())
        },
        "note": (
            "Means of each scoring component, computed with the telemetry gate "
            "disabled so the gate cannot mask the underlying signal. Class diversity "
            "is reported alongside because on this corpus it is what the gate reacts to."
        ),
    }
    separation = {
        "cabid_anomaly_score_auc": round(roc_auc(labels, cabid_scores), 6),
        "syscall_ngram_auc": round(roc_auc(labels, ngram_scores), 6),
        "note": (
            "Threshold-free class separation. 0.5 means the score is uninformative on "
            "this corpus; 1.0 means perfect ranking. Where the gated metrics are poor "
            "but the AUC is also near 0.5, the problem is the score, not the threshold."
        ),
    }
    mappable_labels = [y for y, m in zip(labels, mappable) if m]
    mappable_models = {
        "cabid_core": metrics(mappable_labels, [p for p, m in zip(cabid_core, mappable) if m]),
        "cabid_with_baseline": metrics(
            mappable_labels, [p for p, m in zip(cabid_baseline, mappable) if m]),
    }
    coverage = {
        "mappable_benign": _fraction(sum(m for y, m in zip(labels, mappable) if y == 0),
                                     sum(1 for y in labels if y == 0)),
        "mappable_attack": _fraction(sum(m for y, m in zip(labels, mappable) if y == 1),
                                     sum(1 for y in labels if y == 1)),
        "mappable_overall": _fraction(sum(mappable), len(mappable)),
        "unmappable_attack_traces": sum(1 for y, m in zip(labels, mappable) if y == 1 and not m),
        "unmappable_benign_traces": sum(1 for y, m in zip(labels, mappable) if y == 0 and not m),
        "note": (
            "A trace is unmappable when none of its syscalls belongs to a CABID event "
            "class. Unmappable traces are counted as undetected in 'models' and dropped "
            "from 'models_mappable_only'. The gap between the two is the recall this "
            "pipeline structurally cannot reach on syscall-only data."
        ),
    }

    evidence = {
        "insufficient_evidence_rate_core": round(insufficient_core / len(evaluation_sessions), 6),
        "insufficient_evidence_rate_with_baseline": round(
            insufficient_baseline / len(evaluation_sessions), 6),
        "note": (
            "INSUFFICIENT_EVIDENCE counts as a positive detection in every model above, "
            "because a session the engine refuses to judge is not a cleared session. "
            "These rates bound how much of the score is that refusal rather than a "
            "behavioural match."
        ),
    }

    return {
        "format": BENCHMARK_FORMAT,
        "corpus": {
            "name": "adfa-ld",
            "root": str(root),
            "window_seconds": window_seconds,
            "trace_counts": {
                "training": len(groups["training"]),
                "validation": len(groups["validation"]),
                "attack": len(groups["attack"]),
            },
            "split": {
                "profile_fit_traces": len(split["fit"]),
                "calibration_traces": len(split["calibration"]),
                "evaluation_benign_traces": len(groups["validation"]),
                "evaluation_attack_traces": len(groups["attack"]),
                "seed": seed,
            },
            "event_classes_available": list(ADFA_EVENT_CLASSES),
        },
        "models": models,
        "models_mappable_only": mappable_models,
        "score_separation": separation,
        "component_diagnostics": diagnostics,
        "coverage": coverage,
        "per_technique_recall": {
            name: {
                "recall": metrics(v["labels"], v["cabid"])["recall"],
                "ngram_recall": metrics(v["labels"], v["ngram"])["recall"],
                "traces": len(v["labels"]),
                "mappable_traces": sum(v["mappable"]),
            }
            for name, v in sorted(by_technique.items())
        },
        "calibration": {
            "method": "percentile of held-out benign coverage and novelty scores",
            "calibration_percentile": calibration_percentile,
            "completeness_minimum_ratio": round(calibrated_ratio, 6),
            "ngram_cutoff": round(ngram_cutoff, 6),
            "calibration_traces": len(calibration_sessions),
        },
        "evidence_sufficiency": evidence,
        "config_digest": config_digest(working_config),
        "completeness_classes_used": list(working_config["completeness"]["expected_event_types"]),
        "decision_rule": (
            "cabid_* models count any status other than NO_ANOMALY_DETECTED as positive; "
            "the n-gram model compares novel-ngram fraction against its calibrated cutoff."
        ),
        "limitations": LIMITATIONS,
        "reproduce": (
            "cabid benchmark-real --corpus-cache <dir> --output results/adfa-realworld.json"
        ),
    }


def roc_auc(labels: list[int], scores: list[float]) -> float:
    """Area under the ROC curve via the rank statistic (ties averaged).

    Threshold-free, so it answers "does the score separate the classes at all?"
    without inheriting whatever cut-off an operator happened to pick. This is the
    honest headline for a corpus where the correct threshold is unknown.
    """
    if len(labels) != len(scores):
        raise ValueError("labels and scores must be the same length")
    positives = sum(1 for y in labels if y == 1)
    negatives = len(labels) - positives
    if not positives or not negatives:
        return 0.0
    order = sorted(range(len(scores)), key=lambda i: scores[i])
    ranks = [0.0] * len(scores)
    index = 0
    while index < len(order):
        end = index
        while end + 1 < len(order) and scores[order[end + 1]] == scores[order[index]]:
            end += 1
        average = (index + end) / 2.0 + 1.0
        for position in range(index, end + 1):
            ranks[order[position]] = average
        index = end + 1
    positive_rank_sum = sum(rank for rank, y in zip(ranks, labels) if y == 1)
    return (positive_rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)


def _fraction(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _path_for(groups: dict[str, list], session_id: str) -> str:
    """Look up the on-disk path for a session id."""
    bucket = session_id.split("/", 1)[0]
    key = {"training": "training", "validation": "validation", "attack": "attack"}[bucket]
    for candidate_id, path, _label in groups[key]:
        if candidate_id == session_id:
            return path
    raise KeyError(f"unknown session id: {session_id}")


def threshold_curve(root: str | Path, *, window_seconds: float = 20.0,
                    calibration_fraction: float = 0.25, seed: int = 20261113) -> dict:
    """Recall/FPR trade-off for the n-gram score across all threshold choices.

    Used by the documentation to show *why* a percentile cut-off was chosen instead
    of an arbitrary constant.
    """
    groups = corpus_sessions(root)
    split = _split(groups, calibration_fraction, seed)
    ngram = NgramNovelty(3).fit([read_trace(path) for _, path, _ in split["fit"]])
    labels: list[int] = []
    scores: list[float] = []
    for bucket in ("validation", "attack"):
        for _session_id, path, label in groups[bucket]:
            labels.append(int(label))
            scores.append(ngram.score(read_trace(path)))
    return {
        "corpus": "adfa-ld",
        "model": "syscall_ngram_3gram",
        "curve": _threshold_sweep(labels, scores),
    }
