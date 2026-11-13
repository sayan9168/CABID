# CABID

**Context-Aware Behavioral Integrity Detection** — a lightweight, explainable Linux security research prototype.

CABID combines temporal activity, conservative process ancestry checks, and telemetry-class completeness over normalized event streams. It reports insufficient evidence when required event classes are absent.

> Research status: alpha prototype (v0.4.0). Novelty and real-world detection performance are not established. Scores are heuristics, not probabilities.

## Features

- Dependency-free Python core (Python 3.10+), standard library only
- Strict JSONL event validation with line-aware errors
- Five weighted, explainable components: temporal rate/burstiness, ancestry
  consistency, process-lifecycle contradictions, telemetry completeness, and
  optional novelty against a benign baseline
- Conservative anomaly logic: unseen parents and unseen process names are
  reported as context, never scored as malicious on their own
- Telemetry completeness gate — missing classes produce `INSUFFICIENT_EVIDENCE`,
  never "safe"
- Declarative detection policy: sensitive paths/ports, allow-lists, suppressions
- Versioned, validated configuration with a reproducible `config_digest`
- Windowed analysis (`--window`) and streaming `watch` mode
- Reports in JSON, Markdown, CSV, SARIF 2.1.0, and self-contained HTML
- Local read-only dashboard (`cabid dashboard`) with no external assets
- Best-effort unprivileged Linux /proc polling
- Limited Linux auditd raw-log importer for x86_64 and aarch64
- Deterministic synthetic benchmark comparing temporal-only, CABID core, and
  baseline-aware models
- CI-friendly exit codes (`--exit-code`, `--fail-on`), automated tests, GitHub Actions

## Install

    python -m venv .venv
    source .venv/bin/activate
    python -m pip install -e '.[test]'
    pytest

## Quick start

    cabid doctor
    cabid analyze datasets/synthetic/example.jsonl
    cabid analyze datasets/synthetic/example.jsonl --format md -o report.md
    cabid analyze datasets/synthetic/example.jsonl --window 20 --format html -o report.html

## Interactive dashboard

    cabid dashboard --port 8765
    # open http://127.0.0.1:8765/

Loopback-only by default; see docs/dashboard.md before changing `--host`.

## Tune and reproduce an experiment

    cabid init-config -o cabid-config.json          # documented template
    cabid build-baseline benign-1.jsonl benign-2.jsonl benign-3.jsonl -o baseline.json
    cabid analyze events.jsonl -c cabid-config.json -b baseline.json -p policy.json \
        --window 300 --format md -o report.md

Every report embeds a `config_digest` and the ordered reasons behind the verdict.
See docs/configuration.md, docs/baseline.md, and docs/policy.md.

## Stage it in CI

    cabid analyze events.jsonl --format sarif -o cabid.sarif --fail-on SUSPICIOUS

`--fail-on` fails the job when the verdict is at or above the named severity;
`--exit-code` maps status to 0/1/2. See docs/reports.md.

## Collect visible process snapshots

    cabid collect-proc --output /tmp/cabid-events.jsonl --interval 2 --duration 30
    cabid analyze /tmp/cabid-events.jsonl

The procfs collector can miss short-lived processes and does not collect file,
network, or exit events. It is not an EDR sensor.

## Import Linux auditd records

Review docs/cabid-audit.rules.example with an administrator before enabling
audit collection. Audit rules can increase log volume and capture sensitive
process/path metadata. They are not installed automatically.

    sudo ausearch --start today --format raw > /tmp/audit.raw
    cabid import-audit /tmp/audit.raw --output /tmp/audit-events.jsonl --report /tmp/import-report.json
    cabid analyze /tmp/audit-events.jsonl

The importer recognizes only a limited syscall subset and does not synthesize
heartbeat events. A file_write event means a write-capable open intent, not
proof that bytes were written. See docs/auditd-ingestion.md.

## Run synthetic benchmark

    cabid benchmark --output results/synthetic-benchmark.json --seed 20261113 --per-class 50

This compares three models on generated benign, synthetic behavior-anomaly, and
telemetry-loss cases: a temporal-only threshold, the telemetry-aware CABID core,
and the core plus a baseline profile fitted from the benign splits. Synthetic
metrics are software diagnostics, not real-world detection claims. See
docs/benchmark.md.

## Event input

One JSON object per line. Required fields: timestamp (Unix seconds), event_type,
and positive process_id. Supported event types: process_start, process_exec,
file_write, network_connect, process_exit, heartbeat. See docs/event-schema.md.

## Documentation

| Document | Contents |
| --- | --- |
| docs/methodology.md | research question, hypothesis, experimental design |
| docs/configuration.md | configuration schema, validation, reproducibility |
| docs/baseline.md | benign profiles and novelty scoring |
| docs/policy.md | operator policy: sensitive targets, allow-lists, suppressions |
| docs/reports.md | JSON/Markdown/CSV/SARIF/HTML reports and exit codes |
| docs/dashboard.md | local dashboard and its HTTP API |
| docs/watch-mode.md | streaming analysis of a growing JSONL file |
| docs/telemetry-policy.md | completeness gate rationale |
| docs/auditd-ingestion.md | auditd importer scope |
| docs/linux-collector.md | procfs collector limits |
| docs/benchmark.md | synthetic benchmark caveats |
| docs/limitations.md | safe-use notes |

## Research and limitations

This is an alpha research prototype. The score is a heuristic, not a probability
or an attribution. Missing telemetry is reported as insufficient evidence, never
as safety. Use only on systems and logs you own or are authorized to analyze.

## License

MIT. See LICENSE.
