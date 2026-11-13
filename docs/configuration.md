# Analysis configuration

CABID ships with documented defaults. A configuration file is optional, but any
experiment that changes defaults should publish the file it used: every report
embeds a `config_digest` (SHA-256 of the resolved configuration) so results can
be traced back to exact settings.

## Generate a template

    cabid init-config --output cabid-config.json

The template is a starting point only; nothing is applied automatically.

## Schema

```json
{
  "weights": {
    "temporal": 0.30,
    "causal": 0.25,
    "sequence": 0.15,
    "telemetry_gap": 0.20,
    "novelty": 0.20
  },
  "thresholds": {
    "suspicious": 0.55,
    "high": 0.80,
    "rate_per_minute": 120.0,
    "burstiness": 3.0
  },
  "completeness": {
    "expected_event_types": ["file_write", "heartbeat", "network_connect",
                             "process_exec", "process_exit", "process_start"],
    "minimum_ratio": 1.0
  },
  "sequence": {"amplification": 4.0},
  "window_seconds": null,
  "baseline": null
}
```

| Key | Meaning |
| --- | --- |
| `weights.*` | Relative influence of each component. Weights are normalised at runtime; they are not percentages of a probability. |
| `weights.novelty` | Ignored unless a baseline profile is available (`--baseline` or `baseline`). |
| `thresholds.suspicious` / `thresholds.high` | Status cut points for the weighted score. Must satisfy `0 <= suspicious <= high <= 1`. |
| `thresholds.rate_per_minute`, `thresholds.burstiness` | Bounds used to normalise temporal features. |
| `completeness.expected_event_types` | Event classes the sensor is expected to produce. |
| `completeness.minimum_ratio` | Coverage fraction required for a conclusive verdict. Lowering it must be stated in the write-up. |
| `sequence.amplification` | Multiplier applied to contradictory-event density before capping at 1.0. |
| `window_seconds` | Default window size for `analyze --window` when the flag is omitted. |
| `baseline` | Path to a baseline profile (CLI `--baseline` takes precedence). |

## Validation rules

Unknown keys are rejected, weights must be finite and non-negative, at least one
non-novelty weight must be positive, thresholds must be ordered, event types must
be supported, and paths must be strings. Invalid files exit with status `2`
instead of silently falling back to defaults.

## Reproducible experiment record

    cabid analyze events.jsonl --config cabid-config.json --baseline profile.json \
        --window 300 --format md --output reports/run-01.md

The report records `config_digest`, `baseline_used`, per-component values, and
the ordered reasons that produced the verdict.
