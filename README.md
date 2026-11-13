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
- **Gated containment plans** (`cabid respond`): kill-chain corroboration, protected-process
  and telemetry gates, digest-bound human approval, audited execution of `SIGSTOP`/`SIGKILL`
  only — network and account actions are emitted as commands, never run
- Tamper-evident report sealing (SHA-256 digest, optional HMAC) with `cabid seal`
- Reports in JSON, Markdown, CSV, SARIF 2.1.0, and self-contained HTML
- Local read-only dashboard (`cabid dashboard`) with no external assets
- Best-effort unprivileged Linux /proc polling
- Linux auditd raw-log importer covering exec/fork/exit, file writes, connects,
  accepts, the setuid family, ptrace/mount/pivot_root/mknod, and chmod/chown on
  both x86_64 and aarch64, with a per-reason `skipped` breakdown
- Deterministic synthetic benchmark comparing temporal-only, CABID core, and
  baseline-aware models
- **Real-world benchmark** (`cabid benchmark-real`) on a pinned, checksum-verified
  public corpus (ADFA-LD: 5,951 traces), reporting precision/recall/FPR with Wilson
  intervals, a threshold-free ROC-AUC, and a gate-disabled ablation — including the
  unfavourable result
- **Data-driven calibration** (`cabid calibrate`): percentile floor plus median/MAD
  rate limits over benign sessions, with the implied false-positive budget stated
- **Baseline validation and drift** (`cabid validate-baseline`, `cabid drift-report`):
  two-sample KS, exact binomial flip test, three-state verdict, proposed (never
  applied) profile updates
- **Fleet view** (`cabid fleet`): rank and compare hosts across reports, with silent
  hosts reported as findings rather than omitted
- **Alerting** (`cabid alert`): Slack, Discord, email, webhooks; dry-run by default;
  dedup and rate limiting with every suppression counted
- **Bounded-memory streaming** (`cabid analyze-stream`): 22.9 MB peak at 1M events
- **Kernel sensor** (`cabid ebpf`): bpftrace program for process/network/file events
  with a strict parser and a capability check (program not executed in this repo —
  see the docs)
- **Interactive dashboard tabs**: process graph with search/collapse/tooltips,
  event-density timeline, name-level filters
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

## Contain something, carefully

    cabid analyze events.jsonl -o report.json
    cabid respond report.json -o report.response.json   # review this first
    cabid respond report.json --apply --dry-run         # what would happen
    cabid respond report.json --apply --confirm <plan_digest>

CABID will not block anything on its own, and that is deliberate: a heuristic that
can be triggered by an attacker is a weapon pointed the wrong way. A containment
action needs kill-chain corroboration (two independent phases, not one noisy rule),
sufficient telemetry, a process that is not infrastructure, and a human who passed
the plan's digest back. Suspension is preferred over killing; network and account
actions are printed as commands for you to run. Every step is written to an audit
trail *before* it executes. See docs/response.md.

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

## Run the real-world benchmark

The corpus is fetched on demand and verified against a pinned digest; nothing is
vendored.

```bash
cabid corpus list                 # pinned digests, licences, caveats
cabid corpus fetch adfa-ld        # verify + extract + cache
cabid benchmark-real --corpus-cache ~/.cache/cabid -o results/adfa.json -f md
```

The published result is deliberately unfavourable: **93.8% false-positive rate**, and
an anomaly-score AUC of **0.356** (below chance) once the telemetry gate is disabled.
The report's ablation explains why — attack traces are `socketcall`-dominated, so they
show *fewer* event classes and the completeness gate reads that as worse telemetry.
See [docs/realworld-benchmark.md](docs/realworld-benchmark.md). A benchmark that only
reports favourable numbers is not a benchmark.

## Calibrate thresholds instead of guessing

```bash
cabid calibrate benign/*.jsonl --output calibration.json --apply-to config.json
cabid calibrate --compare calibration.json benign/first.jsonl
```

The 99th percentile of benign scores becomes the `suspicious` floor, so the
false-positive budget (1%) is stated rather than discovered in production. See
[docs/calibration.md](docs/calibration.md).

## Validate the baseline, then watch it drift

```bash
cabid validate-baseline baseline.json withheld/*.jsonl
cabid drift-report baseline.json recent/*.jsonl
```

Both judge the *model*, not the host: drift is caused by benign change constantly.
See [docs/novelty.md](docs/novelty.md).

## Watch a fleet

```bash
cabid fleet web-01=reports/web-01.json db-01=reports/db-01.json             --expected hosts.txt --format md
```

Hosts that did not report are listed explicitly and mark the view degraded — the host
that went dark is often the interesting one. See [docs/fleet.md](docs/fleet.md).

## Alert, without training people to ignore the channel

```bash
cabid alert report.json --channel slack --host web-01          # dry run: previews payload
CABID_SLACK_WEBHOOK=... cabid alert report.json --channel slack --host web-01 \
    --state alert-state.json --send
```

Dry-run is the default; dedup keys on host + status + reason codes, not score. See
[docs/alerting.md](docs/alerting.md).

## Stream at lakhs of events per minute

```bash
cabid analyze-stream sensor.jsonl --window-seconds 60 --output stream.json
```

Measured: **22.9 MB peak RSS at 1,000,000 events**, versus 1,115 MB for one-shot
analysis, at comparable throughput — roughly 32× the 10⁵/min requirement. See
[docs/performance.md](docs/performance.md).

## Read kernel events (with a caveat)

```bash
cabid ebpf check                                   # can this host run it?
cabid ebpf script --output cabid-sensor.bt         # review, then run as root
cabid ebpf parse sensor.log --output events.jsonl
```

The bpftrace program in this repository has **never been executed against a live
kernel** in this environment. [docs/ebpf-sensor.md](docs/ebpf-sensor.md) states
precisely what is and is not verified.

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
| docs/realworld-benchmark.md | ADFA-LD benchmark: method, the unfavourable result, and why |
| docs/calibration.md | deriving thresholds from benign sessions |
| docs/novelty.md | baseline validation and drift tracking |
| docs/fleet.md | multi-host aggregation, silent-host accounting |
| docs/alerting.md | delivery channels and suppression |
| docs/performance.md | measured throughput, bounded memory, the rule-pack fix |
| docs/ebpf-sensor.md | kernel sensor, and what was never verified |
| docs/limitations.md | safe-use notes |
| docs/releasing.md | release checklist and the PyPI trusted-publisher setup |
| docs/response.md | containment plans, the gates, and why this is not an auto-blocker |

## Research and limitations

This is an alpha research prototype. The score is a heuristic, not a probability
or an attribution. Missing telemetry is reported as insufficient evidence, never
as safety. Use only on systems and logs you own or are authorized to analyze.

## License

MIT. See LICENSE.
