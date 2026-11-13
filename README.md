# CABID

**Context-Aware Behavioral Integrity Detection** — a lightweight, explainable Linux security research prototype.

CABID combines temporal activity, conservative process ancestry checks, and telemetry-class completeness over normalized event streams. It reports insufficient evidence when required event classes are absent.

> Research status: alpha prototype (v0.3.0). Novelty and real-world detection performance are not established. Scores are heuristics, not probabilities.

## Features

- Dependency-free Python core (Python 3.10+)
- Strict JSONL event validation
- Temporal rate and burstiness features
- Conservative process ancestry checks (unseen parents are context, not automatic alerts)
- Telemetry completeness gate
- Best-effort unprivileged Linux /proc polling
- Limited Linux auditd raw-log importer for x86_64 and aarch64
- Deterministic synthetic benchmark with temporal-only baseline comparison
- JSON reports, CLI, automated tests and GitHub Actions

## Install

    python -m venv .venv
    source .venv/bin/activate
    python -m pip install -e '.[test]'
    pytest

## Collect visible process snapshots

    cabid collect-proc --output /tmp/cabid-events.jsonl --interval 2 --duration 30
    cabid analyze /tmp/cabid-events.jsonl

The procfs collector can miss short-lived processes and does not collect file,
network, or exit events. It is not an EDR sensor.

## Import Linux auditd records

On a host where auditd is configured, export records:

    sudo ausearch --start today --format raw > /tmp/audit.raw

Then parse:

    cabid import-audit /tmp/audit.raw --output /tmp/audit-events.jsonl --report /tmp/import-report.json
    cabid analyze /tmp/audit-events.jsonl

The importer recognizes only a limited syscall subset. It does not configure
audit rules or synthesize heartbeat events. See docs/auditd-ingestion.md.

## Run synthetic benchmark

    cabid benchmark --output results/synthetic-benchmark.json --seed 20261113 --per-class 50

This compares a temporal-only baseline with the telemetry-aware CABID status
gate on generated benign, synthetic behavior-anomaly, and telemetry-loss cases.
Synthetic metrics are software diagnostics, not real-world detection claims.
See docs/benchmark.md.

## Event input

One JSON object per line. Required fields: timestamp (Unix seconds), event_type,
and positive process_id. Supported event types: process_start, process_exec,
file_write, network_connect, process_exit, heartbeat. See docs/event-schema.md.

## Research and limitations

See docs/methodology.md, docs/limitations.md, docs/telemetry-policy.md,
docs/auditd-ingestion.md, and docs/benchmark.md. Use only on systems and logs
you own or are authorized to analyze.

## License

MIT. See LICENSE.
