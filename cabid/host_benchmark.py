"""Real-host benchmark: measure CABID on live telemetry from one host.

This addresses the gap that every published CABID number comes from synthetic
fixtures or a 2013 syscall corpus, and none from real enterprise telemetry on a
live host. It is a framework, not a claim: an operator runs it on their own
host, labels sessions as benign or attack, and gets back precision/recall/FPR
with confidence intervals.

Workflow:

    # 1. Collect a benign baseline over a quiet period.
    cabid benchmark-host collect --scenario benign-baseline \
        --label benign --duration 900 --output sessions/baseline.jsonl

    # 2. Collect labeled attack scenarios (operator runs the attacks).
    cabid benchmark-host collect --scenario nmap-scan \
        --label attack --duration 300 --output sessions/attack-nmap.jsonl

    # 3. Score everything and publish the report.
    cabid benchmark-host run --sessions-dir sessions/ \
        --output results/host-benchmark.json --format md

Every headline number carries a Wilson 95% interval because real-host samples
are small and unstable. Unfavourable results are published, not tuned away:

    | Model | Precision | Recall | FPR |
    | cabid | 0.040 | 0.500 | 0.200 |

The report's limitations section states exactly what the number does and does
not mean: single host, operator-labeled ground truth, procfs-only telemetry,
short observation windows, no root / no auditd unless the operator arranges it.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from .baseline import build_profile
from .config import config_digest, validate_config
from .detector import analyze
from .ingest import read_jsonl

BENCHMARK_FORMAT = "cabid-host-benchmark/1"

#: Default completeness classes for a procfs-only host sensor.
#: A procfs collector cannot emit privilege_change / kernel_state_change /
#: permission_change / network_accept, and it does not reliably observe
#: file_write, network_connect or process_exit either. Only the classes it
#: actually produces are required, and the completeness floor is set below 1.0
#: so a session missing one class is not automatically under-instrumented.
DEFAULT_COMPLETENESS_CLASSES = ["heartbeat", "process_exec", "process_start"]

LABEL_BENIGN = "benign"
LABEL_ATTACK = "attack"


def wilson_interval(successes: int, trials: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion."""
    if trials <= 0:
        return 0.0, 0.0
    if successes < 0 or successes > trials:
        raise ValueError("successes must be between 0 and trials")
    phat = successes / trials
    denominator = 1.0 + z * z / trials
    centre = (phat + z * z / (2 * trials)) / denominator
    margin = (
        z
        * math.sqrt(phat * (1 - phat) / trials + z * z / (4 * trials * trials))
        / denominator
    )
    return max(0.0, centre - margin), min(1.0, centre + margin)


def metrics(labels: list[int], predictions: list[int]) -> dict:
    """Confusion-matrix metrics with Wilson intervals on headline rates."""
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
    fnr_ci = wilson_interval(fn, fn + tp) if fn + tp else (0.0, 0.0)
    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "precision_ci95": [round(v, 6) for v in precision_ci],
        "recall_ci95": [round(v, 6) for v in recall_ci],
        "false_positive_rate": round(fp / (fp + tn), 6) if fp + tn else 0.0,
        "false_positive_rate_ci95": [round(v, 6) for v in fpr_ci],
        "false_negative_rate": round(fn / (fn + tp), 6) if fn + tp else 0.0,
        "false_negative_rate_ci95": [round(v, 6) for v in fnr_ci],
        "accuracy": round((tp + tn) / len(labels), 6) if labels else 0.0,
        "sample_count": len(labels),
        "positive_count": tp + fn,
        "negative_count": tn + fp,
    }


def default_config(completeness_ratio: float = 0.67) -> dict:
    """A benchmark config suited to procfs-only host telemetry.

    The default floor (2/3) means a session must cover at least 2 of the 3
    classes procfs can produce (heartbeat, process_exec, process_start). This
    is intentionally lenient: procfs-only telemetry is sparse and short windows
    will miss classes.
    """
    return validate_config(
        {
            "completeness": {
                "expected_event_types": DEFAULT_COMPLETENESS_CLASSES,
                "minimum_ratio": completeness_ratio,
            },
        }
    )


def _score_session(
    events: list[dict], config: dict, profile: dict | None
) -> tuple[str, float, dict[str, float]]:
    """Score one session; return (status, anomaly_score, components)."""
    report = analyze(events, config, profile)
    return (
        report.get("status", "UNKNOWN"),
        float(report.get("anomaly_score", 0.0)),
        {k: float(v) for k, v in report.get("components", {}).items()},
    )


def load_sessions(
    sessions_dir: str | Path,
) -> list[dict[str, Any]]:
    """Load all labeled session files from a directory.

    Each ``*.jsonl`` file must contain events. The scenario and label are read
    from a sidecar ``<name>.meta.json`` file if present, otherwise derived from
    the file name: a file whose stem contains ``attack`` is labeled attack,
    everything else is benign. The scenario is the stem minus a trailing
    ``-benign``/``-attack`` suffix if present.
    """
    sessions: list[dict[str, Any]] = []
    directory = Path(sessions_dir)
    if not directory.is_dir():
        raise ValueError(f"sessions directory not found: {directory}")
    for path in sorted(directory.glob("*.jsonl")):
        stem = path.stem
        meta_path = path.with_suffix(".meta.json")
        label = None
        scenario = stem
        if meta_path.is_file():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                label = str(meta.get("label", "")).strip().lower()
                scenario = str(meta.get("scenario", stem))
            except (json.JSONDecodeError, OSError) as exc:
                raise ValueError(f"unreadable sidecar {meta_path}: {exc}") from exc
        if label not in {LABEL_BENIGN, LABEL_ATTACK}:
            lowered = stem.lower()
            if "attack" in lowered or "intrusion" in lowered:
                label = LABEL_ATTACK
            else:
                label = LABEL_BENIGN
            for suffix in ("-benign", "-attack", "-intrusion"):
                if lowered.endswith(suffix):
                    scenario = stem[: -len(suffix)]
                    break
        events = read_jsonl(path)
        sessions.append(
            {
                "session_id": stem,
                "path": str(path),
                "label": label,
                "scenario": scenario,
                "events": events,
                "event_count": len(events),
            }
        )
    if not sessions:
        raise ValueError(f"no session files found in {directory}")
    return sessions


def run_host_benchmark(
    sessions_dir: str | Path,
    *,
    output: str | Path | None = None,
    config: dict | None = None,
    calibration_percentile: float = 0.99,
    min_benign_sessions: int = 3,
) -> dict:
    """Score labeled host sessions and return a benchmark report.

    The benign profile is fitted on benign sessions only; every session
    (benign and attack) is then scored against it. Precision, recall and FPR
    are reported overall and per scenario with Wilson 95% intervals.
    """
    sessions = load_sessions(sessions_dir)
    benign_sessions = [s for s in sessions if s["label"] == LABEL_BENIGN]
    attack_sessions = [s for s in sessions if s["label"] == LABEL_ATTACK]
    if len(benign_sessions) < min_benign_sessions:
        raise ValueError(
            f"need at least {min_benign_sessions} benign sessions, "
            f"found {len(benign_sessions)}"
        )
    if not attack_sessions:
        raise ValueError("need at least one attack session")
    working_config = config or default_config()
    # Fit the benign baseline on benign sessions only.
    profile = build_profile(
        [(s["session_id"], s["events"]) for s in benign_sessions],
        minimum_sessions=min_benign_sessions,
    )

    labels: list[int] = []
    predictions: list[int] = []
    scores: list[float] = []
    insufficient = 0
    per_scenario: dict[str, dict[str, list]] = defaultdict(
        lambda: {"labels": [], "predictions": [], "scores": []}
    )
    component_samples: dict[int, dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for session in sessions:
        status, anomaly_score, components = _score_session(
            session["events"], working_config, profile
        )
        label = 1 if session["label"] == LABEL_ATTACK else 0
        positive = int(status != "NO_ANOMALY_DETECTED")
        labels.append(label)
        predictions.append(positive)
        scores.append(anomaly_score)
        if status == "INSUFFICIENT_EVIDENCE":
            insufficient += 1
        key = session["scenario"]
        per_scenario[key]["labels"].append(label)
        per_scenario[key]["predictions"].append(positive)
        per_scenario[key]["scores"].append(anomaly_score)
        for name, value in components.items():
            component_samples[label][name].append(value)

    overall = metrics(labels, predictions)
    scenario_metrics = {
        name: metrics(vals["labels"], vals["predictions"])
        for name, vals in sorted(per_scenario.items())
    }

    # Threshold-free separation of the anomaly score.
    positives = sum(1 for y in labels if y == 1)
    negatives = len(labels) - positives
    auc = 0.0
    if positives and negatives:
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
        positive_rank_sum = sum(
            rank for rank, y in zip(ranks, labels) if y == 1
        )
        auc = (
            positive_rank_sum - positives * (positives + 1) / 2.0
        ) / (positives * negatives)

    diagnostics = {
        "mean_components_by_class": {
            "benign" if label == 0 else "attack": {
                name: round(sum(values) / len(values), 6)
                for name, values in sorted(components.items())
                if values
            }
            for label, components in sorted(component_samples.items())
        },
        "note": (
            "Means of each scoring component per class. On real host telemetry "
            "these show which component drives the score; they are not an attack "
            "verdict."
        ),
    }

    result = {
        "format": BENCHMARK_FORMAT,
        "corpus": {
            "name": "live-host",
            "sessions_dir": str(sessions_dir),
            "total_sessions": len(sessions),
            "benign_sessions": len(benign_sessions),
            "attack_sessions": len(attack_sessions),
            "min_benign_sessions": min_benign_sessions,
        },
        "models": {"cabid": overall},
        "scenario_metrics": scenario_metrics,
        "score_separation": {
            "anomaly_score_auc": round(auc, 6),
            "note": (
                "Threshold-free class separation on the anomaly score. 0.5 means "
                "the score is uninformative on this host; 1.0 means perfect ranking."
            ),
        },
        "component_diagnostics": diagnostics,
        "evidence_sufficiency": {
            "insufficient_evidence_count": insufficient,
            "insufficient_evidence_rate": round(insufficient / len(sessions), 6),
            "note": (
                "INSUFFICIENT_EVIDENCE counts as a positive detection: a session "
                "the engine refuses to judge has not been cleared."
            ),
        },
        "calibration": {
            "method": "percentile-of-benign completeness and rate floors",
            "calibration_percentile": calibration_percentile,
            "benign_profile_sessions": len(benign_sessions),
        },
        "config_digest": config_digest(working_config),
        "completeness_classes_used": list(
            working_config["completeness"]["expected_event_types"]
        ),
        "decision_rule": (
            "any status other than NO_ANOMALY_DETECTED counts as a positive "
            "detection; INSUFFICIENT_EVIDENCE counts as positive"
        ),
        "limitations": [
            "Single host: one machine, one kernel, one user base. Numbers do not "
            "generalize to other hosts or fleets.",
            "Operator-labeled ground truth: benign/attack labels come from the "
            "person who ran the benchmark, not from an independent red team. "
            "Mislabeled sessions corrupt the metrics.",
            "Procfs-only telemetry unless the operator also supplies auditd "
            "exports: privilege_change, kernel_state_change, permission_change "
            "and network_accept are never observed, so the completeness gate "
            "exempts them.",
            "Short observation windows: collection is bounded by --duration, so "
            "slow, low-and-slow activity is under-represented.",
            "No root: without root the procfs collector sees only this user's "
            "processes and cannot see kernel-level activity.",
            "Small samples: real-host samples are small, so Wilson intervals are "
            "wide and point estimates unstable. Do not act on a single run.",
            "The score is a transparent heuristic, not a probability or a claim "
            "of malware attribution.",
        ],
        "reproduce": (
            "cabid benchmark-host run --sessions-dir <dir> --output "
            "results/host-benchmark.json --format md"
        ),
    }
    if output is not None:
        destination = Path(output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(result, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return result


def render_markdown(report: dict) -> str:
    """Render the benchmark report as Markdown."""
    lines: list[str] = []
    lines.append("# Real-host benchmark report")
    lines.append("")
    lines.append(f"Format: {report['format']}")
    lines.append("")
    lines.append("## Sessions")
    corpus = report["corpus"]
    lines.append("")
    lines.append(f"- Total sessions: {corpus['total_sessions']}")
    lines.append(f"- Benign sessions: {corpus['benign_sessions']}")
    lines.append(f"- Attack sessions: {corpus['attack_sessions']}")
    lines.append("")
    lines.append("## Headline result")
    lines.append("")
    model = report["models"]["cabid"]
    lines.append("| Metric | Value | 95% CI |")
    lines.append("| --- | --- | --- |")
    lines.append(
        f"| Precision | {model['precision']} | "
        f"{model['precision_ci95'][0]} – {model['precision_ci95'][1]} |"
    )
    lines.append(
        f"| Recall | {model['recall']} | "
        f"{model['recall_ci95'][0]} – {model['recall_ci95'][1]} |"
    )
    lines.append(
        f"| FPR | {model['false_positive_rate']} | "
        f"{model['false_positive_rate_ci95'][0]} – "
        f"{model['false_positive_rate_ci95'][1]} |"
    )
    lines.append(
        f"| FNR | {model['false_negative_rate']} | "
        f"{model['false_negative_rate_ci95'][0]} – "
        f"{model['false_negative_rate_ci95'][1]} |"
    )
    lines.append(f"| Samples | {model['sample_count']} | — |")
    lines.append("")
    lines.append("## Score separation")
    sep = report["score_separation"]
    lines.append(f"- Anomaly-score AUC: {sep['anomaly_score_auc']}")
    lines.append(f"- {sep['note']}")
    lines.append("")
    lines.append("## Per-scenario results")
    lines.append("")
    lines.append("| Scenario | Precision | Recall | FPR | Samples |")
    lines.append("| --- | --- | --- | --- | --- |")
    for name, sm in sorted(report["scenario_metrics"].items()):
        lines.append(
            f"| {name} | {sm['precision']} | {sm['recall']} | "
            f"{sm['false_positive_rate']} | {sm['sample_count']} |"
        )
    lines.append("")
    lines.append("## Component diagnostics")
    lines.append("")
    diag = report["component_diagnostics"]
    for class_name, components in diag["mean_components_by_class"].items():
        lines.append(f"### {class_name}")
        for name, value in sorted(components.items()):
            lines.append(f"- {name}: {value}")
        lines.append("")
    lines.append(f"{diag['note']}")
    lines.append("")
    lines.append("## Evidence sufficiency")
    ev = report["evidence_sufficiency"]
    lines.append(f"- Sessions with INSUFFICIENT_EVIDENCE: {ev['insufficient_evidence_count']}")
    lines.append(f"- Rate: {ev['insufficient_evidence_rate']}")
    lines.append(f"- {ev['note']}")
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    for item in report["limitations"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Reproduce")
    lines.append("")
    lines.append("```")
    lines.append(report["reproduce"])
    lines.append("```")
    return "\n".join(lines) + "\n"


def collect_host_events(
    output: str | Path,
    *,
    scenario: str,
    label: str,
    duration: float,
    interval: float = 2.0,
    proc_root: str | Path = "/proc",
) -> int:
    """Collect host telemetry for one labeled scenario.

    Thin wrapper around the procfs collector that tags every event with the
    scenario name and label so the benchmark run can group sessions.
    """
    if label not in {LABEL_BENIGN, LABEL_ATTACK}:
        raise ValueError(f"label must be '{LABEL_BENIGN}' or '{LABEL_ATTACK}'")
    from .collector import collect_to_jsonl

    # Collect raw events via the procfs collector, then tag them.
    collector_count = collect_to_jsonl(
        output, interval=interval, duration=duration, proc_root=proc_root
    )
    # Re-read, tag, and rewrite so every event carries scenario/label metadata.
    raw_events = read_jsonl(output)
    tagged: list[dict[str, Any]] = []
    for event in raw_events:
        tagged_event = dict(event)
        tagged_event["scenario"] = scenario
        tagged_event["label"] = label
        tagged.append(tagged_event)
    destination = Path(output)
    with destination.open("w", encoding="utf-8") as handle:
        for event in tagged:
            handle.write(json.dumps(event, sort_keys=True) + "\n")
    return collector_count
