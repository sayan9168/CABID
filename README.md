# CABID

**Context-Aware Behavioral Integrity Detection** — a lightweight, explainable Linux security research prototype.

CABID combines temporal activity, process-parent consistency, and telemetry-class completeness over normalized event streams. Its goal is to avoid treating an incomplete event stream as proof of benign activity.

> Research status: early prototype (v0.2.0). Novelty and detection performance are not established. Scores are heuristics, not probabilities. No real-world benchmark claims are made.

## Features

- Dependency-free Python core (Python 3.10+)
- Strict JSONL event validation and deterministic normalization
- Temporal event-rate and burstiness features
- Window-local process ancestry consistency checks
- Missing-event-class reporting and insufficient-evidence status
- Explainable JSON output and CLI
- Unprivileged Linux `/proc` polling collector for process observations
- Unit tests and GitHub Actions CI

## Install

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
```

## Collect Linux process observations

On Linux, collect visible process snapshots without root:

```bash
cabid collect-proc --output /tmp/cabid-events.jsonl --interval 2 --duration 30
```

The collector reports first-observed processes and later executable/cmdline changes. It also writes a heartbeat for each poll. This is best-effort polling, not kernel event tracing; short-lived processes may be missed and process start/exec times are not exact. It does not capture file writes, network connections, or syscalls. See [Linux collector notes](docs/linux-collector.md).

## Analyze events

```bash
cabid analyze /tmp/cabid-events.jsonl
cabid analyze datasets/synthetic/example.jsonl
cabid analyze datasets/synthetic/example.jsonl --output report.json
```

The report contains status, a heuristic anomaly score, component scores, missing telemetry classes, and explanations. Status values are `NO_ANOMALY_DETECTED`, `SUSPICIOUS`, `HIGH_RISK`, and `INSUFFICIENT_EVIDENCE`. `NO_ANOMALY_DETECTED` does not mean a system is safe.

## Test

```bash
python -m pip install -e '.[test]'
pytest
```

## Event input

One JSON object per line. Required: `timestamp` (Unix seconds), `event_type`,
and positive `process_id`. Supported event types: `process_start`,
`process_exec`, `file_write`, `network_connect`, `process_exit`, and
`heartbeat`. See [event schema](docs/event-schema.md).

## Research plan

See [methodology](docs/methodology.md) for a falsifiable hypothesis, baselines,
split strategy, and metrics. Default weights and thresholds are initial heuristics
and must be tuned only on training/validation data, then evaluated on held-out
scenarios.

## Safety and limitations

See [limitations](docs/limitations.md). Use only on systems and logs you own or
are authorized to analyze. CABID is a research aid, not an endpoint protection
product.

## License

MIT. See [LICENSE](LICENSE).
