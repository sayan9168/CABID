# CABID

**Context-Aware Behavioral Integrity Detection** — a lightweight, explainable Linux security research prototype.

CABID combines three signals over normalized event streams: temporal activity, process-parent consistency, and telemetry-class completeness. Its goal is to avoid treating an incomplete event stream as proof of benign activity.

> Research status: early prototype (v0.1.0). Novelty and detection performance are not established. Scores are heuristics, not probabilities. No real-world benchmark claims are made.

## Features

- Dependency-free Python core (Python 3.10+)
- Strict JSONL event validation and deterministic normalization
- Temporal rate and burstiness features
- Window-local process ancestry consistency checks
- Missing-event-class reporting and insufficient-evidence status
- Explainable JSON output and CLI
- Unit tests and GitHub Actions CI

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
```

## Run

```bash
cabid analyze datasets/synthetic/example.jsonl
# or without installing the console script:
python -m cabid.cli analyze datasets/synthetic/example.jsonl
```

The report contains `status`, `anomaly_score`, component scores, missing telemetry classes, and reasons. Status values are `NO_ANOMALY_DETECTED`, `SUSPICIOUS`, `HIGH_RISK`, and `INSUFFICIENT_EVIDENCE`. `NO_ANOMALY_DETECTED` does not mean a system is safe.

## Test

```bash
python -m pip install -e '.[test]'
pytest
```

## Event input

One JSON object per line. Required: `timestamp`, `event_type`, and `process_id`. See [event schema](docs/event-schema.md). This version reads supplied logs only; it does not collect Linux telemetry itself.

## Research plan

See [methodology](docs/methodology.md) for a falsifiable hypothesis, baselines, split strategy, and metrics. Default weights and thresholds are initial heuristics and must be tuned only on training/validation data, then evaluated on held-out scenarios.

## Safety and limitations

See [limitations](docs/limitations.md). Use only on systems and logs you own or are authorized to analyze. CABID is a research aid, not an endpoint protection product.

## License

MIT. See [LICENSE](LICENSE).
