"""Versioned analysis configuration with strict validation.

A configuration file is optional. When supplied it is deep-merged over the
documented defaults and validated before use, so an invalid experiment
configuration fails loudly instead of silently changing detection behaviour.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from .normalize import ALLOWED, CORE_EVENT_TYPES

CONFIG_FORMAT = "cabid-config/1"

DEFAULT_CONFIG: dict = {
    "weights": {
        "temporal": 0.30,
        "causal": 0.25,
        "sequence": 0.15,
        "telemetry_gap": 0.20,
        # Only participates in the weighted sum when a baseline profile is used.
        "novelty": 0.20,
    },
    "thresholds": {
        "suspicious": 0.55,
        "high": 0.80,
        "rate_per_minute": 120.0,
        "burstiness": 3.0,
    },
    "completeness": {
        # Only classes a generic sensor can produce. Auditd-only classes are
        # accepted on input but never required, or a procfs stream would always
        # look insufficient. See cabid/completeness.py.
        "expected_event_types": sorted(CORE_EVENT_TYPES),
        "minimum_ratio": 1.0,
    },
    "sequence": {
        # Contradiction density is amplified before capping; a single
        # contradiction in a short window is still worth review.
        "amplification": 4.0,
    },
    "window_seconds": None,
    "baseline": None,
}

COMPONENTS = ("temporal", "causal", "sequence", "telemetry_gap", "novelty")


class ConfigError(ValueError):
    """Raised when an analysis configuration is malformed or contradictory."""


def default_config() -> dict:
    return copy.deepcopy(DEFAULT_CONFIG)


def _merge(base: dict, override: dict, path: str = "") -> dict:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key not in result:
            location = f"{path}{key}"
            raise ConfigError(f"unknown configuration key: {location}")
        if isinstance(result[key], dict):
            if not isinstance(value, dict):
                raise ConfigError(f"{path}{key} must be an object")
            result[key] = _merge(result[key], value, path=f"{path}{key}.")
        else:
            result[key] = value
    return result


def _number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{field} must be a number")
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")):
        raise ConfigError(f"{field} must be finite")
    return number


def validate_config(config: dict) -> dict:
    """Return a validated deep copy of ``config`` or raise ConfigError."""
    if not isinstance(config, dict):
        raise ConfigError("configuration must be a JSON object")
    resolved = _merge(DEFAULT_CONFIG, config)

    weights = resolved["weights"]
    for name in COMPONENTS:
        resolved["weights"][name] = _number(weights[name], f"weights.{name}")
        if resolved["weights"][name] < 0:
            raise ConfigError(f"weights.{name} must be non-negative")
    if sum(resolved["weights"][name] for name in COMPONENTS if name != "novelty") <= 0:
        raise ConfigError("at least one scoring weight must be positive")

    thresholds = resolved["thresholds"]
    for name in ("suspicious", "high"):
        thresholds[name] = _number(thresholds[name], f"thresholds.{name}")
    if not 0.0 <= thresholds["suspicious"] <= thresholds["high"] <= 1.0:
        raise ConfigError("thresholds must satisfy 0 <= suspicious <= high <= 1")
    for name in ("rate_per_minute", "burstiness"):
        thresholds[name] = _number(thresholds[name], f"thresholds.{name}")
        if thresholds[name] <= 0:
            raise ConfigError(f"thresholds.{name} must be positive")

    completeness = resolved["completeness"]
    expected = completeness["expected_event_types"]
    if not isinstance(expected, list) or not expected:
        raise ConfigError("completeness.expected_event_types must be a non-empty list")
    unknown = sorted({str(item) for item in expected} - ALLOWED)
    if unknown:
        raise ConfigError(f"unsupported expected event types: {', '.join(unknown)}")
    resolved["completeness"]["expected_event_types"] = sorted({str(item) for item in expected})
    minimum = _number(completeness["minimum_ratio"], "completeness.minimum_ratio")
    if not 0.0 <= minimum <= 1.0:
        raise ConfigError("completeness.minimum_ratio must be between 0 and 1")
    resolved["completeness"]["minimum_ratio"] = minimum

    amplification = _number(resolved["sequence"]["amplification"], "sequence.amplification")
    if amplification <= 0:
        raise ConfigError("sequence.amplification must be positive")
    resolved["sequence"]["amplification"] = amplification

    window = resolved["window_seconds"]
    if window is not None:
        window = _number(window, "window_seconds")
        if window <= 0:
            raise ConfigError("window_seconds must be positive or null")
        resolved["window_seconds"] = window

    baseline = resolved["baseline"]
    if baseline is not None and not isinstance(baseline, str):
        raise ConfigError("baseline must be a path string or null")
    return resolved


def load_config(path: str | Path | None) -> dict:
    """Load, merge and validate a configuration file (or return defaults)."""
    if path is None:
        return validate_config({})
    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{source}: invalid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{source}: configuration must be a JSON object")
    raw.pop("$schema", None)
    raw.pop("format", None)
    return validate_config(raw)


def config_template() -> dict:
    """A documented starting point for experiments; not auto-applied."""
    template = default_config()
    template.update(
        {
            "$schema": "https://github.com/sayan9168/CABID/blob/main/docs/configuration.md",
            "format": CONFIG_FORMAT,
        }
    )
    return template


def config_digest(config: dict) -> str:
    import hashlib

    payload = json.dumps(config, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
