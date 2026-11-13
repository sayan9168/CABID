# CABID

**Context-Aware Behavioral Integrity Detection** — a lightweight, explainable Linux security research prototype.

CABID combines temporal activity, conservative process ancestry checks, and telemetry-class completeness over normalized event streams. It reports insufficient evidence when required event classes are absent.

> Research status: alpha prototype (v0.7.0). Novelty and real-world detection performance are not established. Scores are heuristics, not probabilities.

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
- Declarative detection policy: sensitive paths/ports, allow-lists, global and
  per-process suppressions
- Versioned, validated configuration with a reproducible `config_digest`
- Windowed analysis (`--window`) and streaming `watch` mode
- Per-process entity rollup that ranks which process to inspect first
- Multi-source merge with provenance, duplicate counts, and overlap warnings
- Inclusive time filtering (`--since`/`--until`, ISO-8601 or epoch)
- Local SQLite run history and run-to-run comparison (`cabid history`)
- Declarative correlation rules (sequence + count) with a ten-rule built-in pack
- Process-tree reconstruction: depth, cycles, interpreter-spawn and baseline edge drift
- Chronological investigation timeline export (Markdown, plain text, JSON)
- Term-by-term score arithmetic with `--explain-score`
- Sigma rule import (optional PyYAML extra) that lists everything it could not map
- STIX 2.1 bundle export for handing findings to another platform
- Container/namespace-aware analysis: pid scopes, collisions, no bogus cross-scope parents
- Cross-source clock-skew estimation (reported, never applied automatically)
- Baseline drift suggestions: proposed profile updates the operator reviews
- Tamper-evident report sealing (SHA-256 digest, optional HMAC) with `cabid seal`
- Reports in JSON, Markdown, CSV, SARIF 2.1.0, and self-contained HTML
- Local read-only dashboard (`cabid dashboard`) with no external assets
- Best-effort unprivileged Linux /proc polling
- Linux auditd raw-log importer covering exec/fork/exit, file writes, connects,
  accepts, the setuid family, ptrace/mount/pivot_root/mknod, and chmod/chown on
  both x86_64 and aarch64, with a per-reason `skipped` breakdown
- Deterministic synthetic benchmark comparing temporal-only, CABID core, and
  baseline-aware models
- CI-friendly exit codes (`--exit-code`, `--fail-on`), automated tests, GitHub Actions
  with lint, type and coverage (>=90%) gates, and a container image

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

## Investigate a window

    # merge artifacts, trim to the incident window, record the run
    cabid analyze procfs.jsonl audit.jsonl \
        --since 2026-11-13T00:00:00Z --until 2026-11-13T06:00:00Z \
        --save-history --label "incident-42" --format md -o incident-42.md

    # later: is this host better or worse than that run?
    cabid analyze procfs.jsonl --compare-history 4 --format md -o compare.md
    cabid history --compare 4 9

The report ranks processes so triage starts at the right pid, and states the
source files, duplicate counts, and any time-range trim. See docs/entities.md,
docs/multi-source.md, and docs/history.md.

## Correlate and hand off

    cabid analyze events.jsonl --rules my-rules.json --format md -o report.md
    cabid timeline events.jsonl -f txt --limit 500 > timeline.txt
    cabid analyze events.jsonl --sign -o sealed.json && cabid seal sealed.json --verify

Rules are JSON, so a new check needs no code. A rule match means the shape
occurred, not that the host is compromised — see docs/rules.md. Report seals detect
later edits; they are hash/HMAC integrity, not digital signatures — see
docs/report-integrity.md.

## See the score as arithmetic

    cabid analyze events.jsonl --explain-score --format md -o report.md

Prints every component's value, its *normalized* weight, and the product that went
into the total, then states which threshold decided the status. Useful when a
weight in your config does not look like the weight in the report: the engine
renormalizes over active components, and inactive novelty is redistributed rather
than scored as zero. JSON output gets the same walkthrough under
`score_explanation`. See docs/scoring-explained.md.

## Import Sigma rules and export STIX

    python -m pip install 'cabid[sigma]'
    cabid import-sigma my-rule.yml -o imported-pack.json
    cabid analyze events.jsonl -r imported-pack.json
    cabid export-stix report.json -o bundle.json --host web-01

Sigma translation is partial and says so: anything it cannot map is listed in
`provenance.unsupported` rather than dropped silently, and two Sigma fields that
would collapse into one CABID slot are reported because the AND would otherwise
become an OR. STIX indicators use `pattern_type: cabid-heuristic` — they describe
a CABID rule match, not a pattern another tool can sweep for. See
docs/integrations.md.

## Merge sources that disagree about the time

    cabid analyze hostA.jsonl hostB.jsonl -o merged.json

A merged report includes `sources.clock_skew` with a per-source offset estimate
and the evidence behind it. Nothing is corrected automatically: a wrong correction
reorders your evidence, and a reordered timeline is worse than a known-skewed one.
See docs/multi-source.md.

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

The importer translates the exec/fork/exit, file-write, connect, accept, setuid,
ptrace/mount/pivot_root/mknod, and chmod/chown families for x86_64 and aarch64. It
does not synthesize heartbeat events, and a `file_write` event means a
write-capable open intent, not proof that bytes were written. Anything it does not
understand is counted under a reason in `skipped` — a large `unmapped_syscall`
figure means the stream is only partly understood, not that the host was quiet.
See docs/auditd-ingestion.md.

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
| docs/entities.md | per-process rollup and its triage semantics |
| docs/multi-source.md | merging artifacts and time filtering |
| docs/history.md | local run history and comparisons |
| docs/rules.md | correlation rule format and built-in pack |
| docs/process-tree.md | tree reconstruction and structural findings |
| docs/timeline.md | investigation timeline export |
| docs/report-integrity.md | report sealing and what it does not prove |
| docs/scoring-explained.md | `--explain-score`: the arithmetic, term by term |
| docs/integrations.md | Sigma rule import and STIX 2.1 export |
| docs/containers.md | pid namespaces, scope collisions, what is not done |
| docs/repo-metadata.md | repository topics and description (apply with `gh repo edit`) |
| docs/policy.md | operator policy: sensitive targets, allow-lists, suppressions |
| docs/reports.md | JSON/Markdown/CSV/SARIF/HTML reports and exit codes |
| docs/dashboard.md | local dashboard and its HTTP API |
| docs/watch-mode.md | streaming analysis of a growing JSONL file |
| docs/telemetry-policy.md | completeness gate rationale |
| docs/auditd-ingestion.md | auditd importer scope |
| docs/linux-collector.md | procfs collector limits |
| docs/benchmark.md | synthetic benchmark caveats |
| docs/limitations.md | safe-use notes |
| docs/releasing.md | release checklist and the PyPI trusted-publisher setup |

## Research and limitations

This is an alpha research prototype. The score is a heuristic, not a probability
or an attribution. Missing telemetry is reported as insufficient evidence, never
as safety. Use only on systems and logs you own or are authorized to analyze.

## License

MIT. See LICENSE.
