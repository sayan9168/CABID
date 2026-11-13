"""Data-driven threshold calibration.

CABID's thresholds used to be constants chosen by hand: ``suspicious = 0.55``,
``high = 0.80``, ``rate_per_minute = 120``. Hand-picked numbers carry an unstated
assumption — that the score distribution is the same on every host and every
deployment. It is not. A busy build server and a quiet jump host have completely
different benign score distributions, so a constant that gives 2% false positives
on one gives 40% on the other.

This module derives thresholds from a *reference set of benign sessions* instead:

* the anomaly floor is a percentile of the benign score distribution, so the
  expected false-positive rate is chosen explicitly rather than discovered in
  production;
* the rate and burstiness limits are robust order statistics (median and
  median absolute deviation, escalated by a multiplier), so a handful of unusual
  benign sessions cannot drag the limits away from normal behaviour;
* every derived threshold records the support it was computed from.

Two properties matter and are tested: calibration is deterministic, and it refuses
to guess when it has too little data. A calibration fitted on four sessions is
worse than no calibration, because it looks authoritative and is not.
"""
from __future__ import annotations

import json
import math
from pathlib import Path

from .config import ConfigError, validate_config
from .detector import analyze

CALIBRATION_FORMAT = "cabid-calibration/1"

#: Below this many reference sessions a percentile is guesswork.
MIN_REFERENCE_SESSIONS = 20

#: The multiplier applied to the median absolute deviation for rate limits.
DEFAULT_MAD_MULTIPLIER = 3.0

#: Smallest spread ever used for a derived limit, in the unit of that limit. Without
#: these a perfectly regular reference set produces a threshold of ~0 and flags
#: itself; with them the limit always sits above observed normal behaviour.
MIN_RATE_SCALE = 1.0
MIN_BURSTINESS_SCALE = 0.5


class CalibrationError(ValueError):
    """Raised when calibration cannot be performed responsibly."""


def percentile(values: list[float], fraction: float) -> float:
    """Linear-interpolated percentile, ``fraction`` in [0, 1]."""
    if not 0.0 <= fraction <= 1.0:
        raise ValueError("fraction must be between 0 and 1")
    if not values:
        raise ValueError("at least one value is required")
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = fraction * (len(ordered) - 1)
    low = math.floor(position)
    high = min(low + 1, len(ordered) - 1)
    weight = position - low
    return ordered[low] * (1 - weight) + ordered[high] * weight


def quantile_floor(values: list[float], fraction: float) -> float:
    """Nearest-rank quantile: the smallest value with at least ``fraction`` below it.

    Linear interpolation is the right choice for *describing* a distribution, but
    the wrong one for *thresholding* it. When many reference sessions tie on the
    same score — common, because most benign sessions score identically — an
    interpolated 99th percentile lands between two ties and ends up below the tied
    bulk, so the floor flags most of the traffic it was fitted on. Nearest-rank
    guarantees that at most ``1 - fraction`` of the reference set lies above the
    chosen value, ties included.
    """
    if not 0.0 < fraction < 1.0:
        raise ValueError("fraction must be between 0 and 1")
    if not values:
        raise ValueError("at least one value is required")
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered))) - 1
    return ordered[min(rank, len(ordered) - 1)]


def median(values: list[float]) -> float:
    return percentile(values, 0.5)


def mad(values: list[float]) -> float:
    """Median absolute deviation — a spread estimate that resists outliers."""
    if not values:
        raise ValueError("at least one value is required")
    centre = median(values)
    return median([abs(value - centre) for value in values])


def fake_positive_budget(percentile_fraction: float) -> float:
    """Expected false-positive rate implied by using ``fraction`` as the floor.

    A 99th-percentile floor means 1% of benign sessions sit above it *by
    construction*. Stated up front so nobody is surprised by it later.
    """
    if not 0.0 < percentile_fraction < 1.0:
        raise ValueError("percentile fraction must be between 0 and 1")
    return round(1.0 - percentile_fraction, 6)


def calibrate(sessions: list[tuple[str, list[dict]]], *,
              reference_percentile: float = 0.99,
              high_percentile: float = 0.999,
              mad_multiplier: float = DEFAULT_MAD_MULTIPLIER,
              config: dict | None = None,
              minimum_sessions: int = MIN_REFERENCE_SESSIONS) -> dict:
    """Derive thresholds from benign reference sessions.

    ``sessions`` must be benign. Passing attack sessions here would calibrate the
    thresholds to fire on the attacks, which is the opposite of the intent, so the
    caller is responsible for the labels and the docstring says so plainly rather
    than pretending the function can detect the mistake.
    """
    if not 0.0 < reference_percentile < 1.0:
        raise CalibrationError("reference_percentile must be between 0 and 1")
    if not 0.0 < high_percentile < 1.0:
        raise CalibrationError("high_percentile must be between 0 and 1")
    if not reference_percentile <= high_percentile:
        raise CalibrationError("reference_percentile must not exceed high_percentile")
    if mad_multiplier <= 0:
        raise CalibrationError("mad_multiplier must be positive")
    empty = [name for name, events in sessions if not events]
    if empty:
        raise CalibrationError(
            f"{len(empty)} session(s) have no events (first: {empty[0]}); "
            "an empty session has no score to calibrate against"
        )
    if len(sessions) < minimum_sessions:
        raise CalibrationError(
            f"{len(sessions)} reference session(s) supplied but {minimum_sessions} are "
            "required. A threshold fitted on fewer sessions is a guess wearing a "
            "computed number; gather more benign data or keep the defaults."
        )

    base = validate_config(config or {})
    scores: list[float] = []
    rates: list[float] = []
    bursts: list[float] = []
    for _name, events in sessions:
        report = analyze(events, base)
        if report["status"] == "INSUFFICIENT_EVIDENCE":
            # A session the engine cannot judge has no meaningful score; including
            # it would calibrate the floor against a refusal rather than a behaviour.
            continue
        scores.append(float(report["anomaly_score"]))
        rates.append(float(report["temporal"]["rate_per_minute"]))
        bursts.append(float(report["temporal"]["burstiness"]))
    if len(scores) < minimum_sessions:
        raise CalibrationError(
            f"only {len(scores)} of {len(sessions)} reference sessions produced a "
            f"scoreable result ({minimum_sessions} required); most sessions were "
            "reported as INSUFFICIENT_EVIDENCE, so the telemetry is too sparse to "
            "calibrate against"
        )

    if max(scores) == min(scores):
        raise CalibrationError(
            "every reference session produced the same anomaly score, so no threshold "
            "can separate them; calibration needs benign sessions that differ"
        )

    suspicious = quantile_floor(scores, reference_percentile)
    high = quantile_floor(scores, high_percentile)
    # A degenerate distribution (every session scoring identically) would produce
    # suspicious == high, which makes HIGH_RISK unreachable. Leave a floor of headroom.
    if high <= suspicious:
        high = min(1.0, suspicious + 0.05)
    if suspicious >= high:
        raise CalibrationError(
            "calibrated thresholds are degenerate: the reference distribution has no "
            "spread, so no score can be distinguished as high risk"
        )

    rate_center = median(rates)
    rate_scale = mad(rates)
    burst_center = median(bursts)
    burst_scale = mad(bursts)
    # MAD collapses to zero (or to a floating-point speck) when most reference
    # sessions share a value, which would make the derived limit sit on top of the
    # reference set and flag it. Floor the scale explicitly rather than relying on a
    # truthiness test, because 1e-13 is truthy and is not a usable scale.
    rate_scale = max(rate_scale, rate_center * 0.5, MIN_RATE_SCALE)
    burst_scale = max(burst_scale, abs(burst_center) * 0.5, MIN_BURSTINESS_SCALE)
    rate_limit = rate_center + mad_multiplier * rate_scale
    burst_limit = burst_center + mad_multiplier * burst_scale

    calibrated = validate_config({
        "thresholds": {
            "suspicious": round(suspicious, 6),
            "high": round(high, 6),
            "rate_per_minute": round(max(rate_limit, 1e-6), 6),
            "burstiness": round(max(burst_limit, 1e-6), 6),
        },
    })

    return {
        "format": CALIBRATION_FORMAT,
        "method": "percentile floor plus median/MAD rate limits over benign sessions",
        "reference_session_count": len(sessions),
        "scored_session_count": len(scores),
        "skipped_insufficient_evidence": len(sessions) - len(scores),
        "thresholds": calibrated["thresholds"],
        "expected_false_positive_rate": fake_positive_budget(reference_percentile),
        "parameters": {
            "reference_percentile": reference_percentile,
            "high_percentile": high_percentile,
            "mad_multiplier": mad_multiplier,
        },
        "support": {
            "score_min": round(min(scores), 6),
            "score_median": round(median(scores), 6),
            "score_max": round(max(scores), 6),
            "score_mad": round(mad(scores), 6),
            "rate_median": round(rate_center, 6),
            "rate_mad": round(rate_scale, 6),
            "burstiness_median": round(burst_center, 6),
            "burstiness_mad": round(burst_scale, 6),
        },
        "notes": [
            "Thresholds describe the benign population they were fitted on and do not "
            "transfer automatically to a host with a different workload.",
            "The expected false-positive rate is implied by the chosen percentile, not "
            "measured in production.",
            "Re-run calibration after significant workload change; the drift command "
            "reports when the profile itself has moved.",
        ],
    }


def apply_config(calibration: dict, config: dict | None = None) -> dict:
    """Merge calibrated thresholds into a configuration, validating the result."""
    if not isinstance(calibration, dict) or "thresholds" not in calibration:
        raise CalibrationError("a calibration object with thresholds is required")
    merged = json.loads(json.dumps(config or {}))
    thresholds = dict(merged.get("thresholds") or {})
    for key, value in calibration["thresholds"].items():
        thresholds[key] = value
    merged["thresholds"] = thresholds
    try:
        return validate_config(merged)
    except ConfigError as exc:
        raise CalibrationError(f"calibrated thresholds are not usable: {exc}") from exc


def write_calibration(calibration: dict, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(calibration, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    return destination


def load_calibration(path: str | Path) -> dict:
    source = Path(path)
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CalibrationError(f"{source}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict) or data.get("format") != CALIBRATION_FORMAT:
        raise CalibrationError(f"{source}: not a {CALIBRATION_FORMAT} document")
    thresholds = data.get("thresholds")
    if not isinstance(thresholds, dict):
        raise CalibrationError(f"{source}: missing thresholds object")
    missing = {"suspicious", "high", "rate_per_minute", "burstiness"} - set(thresholds)
    if missing:
        raise CalibrationError(f"{source}: missing thresholds: {', '.join(sorted(missing))}")
    return data


def compare(current: dict, calibrated: dict) -> list[dict]:
    """Show how far each threshold moves, so the change can be reviewed."""
    resolved = validate_config(current)
    rows = []
    for key in ("suspicious", "high", "rate_per_minute", "burstiness"):
        before = float(resolved["thresholds"][key])
        after = float(calibrated["thresholds"][key])
        change = after - before
        rows.append({
            "threshold": key,
            "current": round(before, 6),
            "calibrated": round(after, 6),
            "absolute_change": round(change, 6),
            "relative_change": round((change / before) if before else 0.0, 6),
        })
    return rows
