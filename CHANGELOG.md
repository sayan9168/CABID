# Changelog

All notable changes to CABID are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Status:** alpha research prototype. Minor versions may change scoring
> behaviour; every report carries a `config_digest` so results remain traceable.

## [Unreleased]

### Added

- **Response plans** (`cabid/response.py`, `cabid respond`): turn a report into a
  containment plan. Evidence from rules, tree, entities, and policy is mapped to
  kill-chain phases; every piece keeps its source. Phases are graded
  `single_signal` / `corroborated` / `strong`.
- **Five gates** before anything destructive: protected processes (including pid 1
  and the tree root), kill-chain corroboration (2+ phases), telemetry sufficiency,
  a per-plan budget that counts suspension, and containment-loop detection.
- **Escalation ladder**: `monitor` → `snapshot` → `suspend_process` →
  `quarantine_file` → `kill_process` → `block_address` / `isolate_host` /
  `disable_account`. The lowest permitted rung is always chosen; suspension is
  preferred over killing because it stops the activity and keeps the memory image.
- **Audited execution** (`cabid/executor.py`, `cabid respond --apply`): digest-bound
  human approval, `SIGSTOP`/`SIGKILL` only, evidence capture, quarantine copies.
  Every step is audited *before* it runs; skips are audited too. Network and account
  actions are emitted as commands, never executed.
- **Containment history**: executed actions are recorded (pid, action, time only) so
  a containment loop can be detected on the next run.
- `docs/response.md`.

### Changed

- Suspension is reported as a **reversible outage**, not as observe-only. A count
  that hides an outage behind a tidy number is the wrong count.
- The per-plan budget counts every action that takes a process down, not only the
  irreversible ones.

## [0.7.0] — 2026-11-13

Detection depth, distribution hygiene, and two integrations. No change to the
weighted score for a given configuration, except where noted under "Fixed".

### Added

- **Expanded auditd coverage**: syscall tables grew from 13 to 35 entries on
  x86_64 and 14 to 26 on aarch64, covering the setuid family, `ptrace`,
  `mount`/`umount2`/`pivot_root`, `mknod`, `chmod`/`chown`, and `accept4`. New
  event classes `privilege_change`, `kernel_state_change`, `permission_change`,
  and `network_accept`, plus `event_type_counts` and a per-reason `skipped`
  breakdown in the import result.
- **Five new built-in rules** (pack now 10): `privilege-escalation-to-exec`,
  `ptrace-then-credential-read`, `permission-relaxed-on-credential`,
  `kernel-state-then-persistence`, `bulk-accept-then-exec`.
- **Container awareness** (`cabid/containers.py`): pid scopes from event
  `container_id`/`pid_ns` metadata, per-scope summaries, and cross-scope pid
  collision reporting. A `containers` block now appears in every report.
- **Clock-skew estimation** (`cabid/skew.py`): per-source offset estimates from
  repeated cross-source events, surfaced in `sources.clock_skew` and in the
  report notes. Never applied automatically.
- **Sigma rule import** (`cabid/sigma.py`, `cabid import-sigma`): field and
  modifier mapping to CABID rules, with everything unmappable listed in
  `provenance.unsupported`. Uses an optional `cabid[sigma]` extra; core stays
  dependency-free.
- **STIX 2.1 export** (`cabid/stix.py`, `cabid export-stix`): bundle with
  identity, report, one `cabid-heuristic` indicator per rule finding, and one note
  per tree finding.
- **Baseline drift suggestions** (`cabid baseline-drift`): proposed profile
  updates from newer benign sessions, requiring multi-session support. The profile
  is never modified.
- **`--explain-score`**: prints the score as arithmetic — component values,
  normalized weights, products, the denominator, and the threshold decision.
- `python -m cabid` entry point.
- `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, `Makefile`, `Dockerfile`,
  issue and pull-request templates, and a PyPI trusted-publishing workflow.
- `docs/scoring-explained.md`, `docs/integrations.md`, `docs/containers.md`, and a
  bundled `docs/cabid-sigma.example.yml`.
- `parent_executable` rule step, so a translated Sigma AND is not flattened to OR.

### Changed

- `completeness.expected_event_types` defaults to the six core classes only.
  Auditd-only classes are accepted but never required, because a procfs sensor
  cannot emit them.
- `temporal.type_diversity` is computed over the core set, so an optional class
  cannot push it above 1.0 or inflate a score.
- CI now gates on mypy, pyflakes, and coverage ≥90%, and builds the distribution.

### Fixed

- `completeness.expected_event_types` still listed auditd-only classes, marking
  every procfs stream `INSUFFICIENT_EVIDENCE` while an auditd stream looked
  complete. Any existing procfs report may change status as a result.
- `permission-relaxed-on-credential` had its steps reversed and could never match.
- Sigma import silently coerced an unknown `level` to `medium`; it is now an error.
- Sigma import flattened `Image` + `ParentImage` into one OR'd field, weakening
  every AND rule; `ParentImage` now has its own slot.
- The Windows-only detection hint used a doubled-escape regex that could never
  match, so the "approximate translation" warning never fired.
- STIX reports did not reference their own `note` objects.
- `cabid` with no subcommand exited 2; it now prints help and exits 0.

## [0.6.0] — 2026-11-13

### Added
- **Correlation rules** (`cabid/rules.py`): JSON rule files with `sequence` and
  `count` kinds, glob filters, `within` and `same_process` bounds. Five-rule
  built-in pack: `shell-from-service`, `download-then-exec`,
  `sensitive-write-then-egress`, `rapid-restart-loop`, `exit-then-activity`.
  Strict validation at file, rule, and step level.
- **Process tree** (`cabid/tree.py`): observed ancestry structure with resolved
  edges, BFS depth, cycle detection, and findings for interpreter spawn,
  baseline edge drift, cycles, and deep chains.
- **Timeline export** (`cabid/timeline.py`): `cabid timeline` in Markdown, plain
  text, or JSON, annotating rows where rules or policy fired.
- **Report sealing** (`cabid/signature.py`): canonical SHA-256 digest plus
  optional HMAC, `cabid seal --verify` with `0`/`1` exit codes.
- Baseline profiles now record `parent_child` name pairs for tree drift.
- Default policy covers persistence paths: `/etc/cron*`, `/etc/rc.local`,
  `/etc/ld.so.preload`, `/etc/passwd`, `/var/spool/cron/`.

### Changed
- Rule matches and tree findings stay **outside** the weighted score, so the
  headline number remains comparable with v0.5.0 for the same configuration.

### Fixed
- Rule findings were sorted worst-**last** because the severity rank was inverted.
- Count rules emitted one finding per matching event instead of one per burst.
- `--no-rules` still emitted a `rules` block, including inside `--window` reports.
- Timeline showed duplicate badges when overlapping matches shared an evidence row.
- A patch duplicated the SARIF rule block into `render_csv` and twice into
  `_sarif_results`; consolidated to a single copy.

## [0.5.0] — 2026-11-13

### Added
- **Per-process entity rollup** (`cabid/entities.py`): ranks which pid to inspect
  first from contradictions, self-parent events, sensitive hits, and novelty.
  Explicitly a triage hint, not an attribution.
- **Multi-source merge** (`cabid/aggregate.py`): per-event provenance, duplicate
  counts by fingerprint, and overlap warnings. No clock correction is attempted.
- **Time filtering** (`cabid/filters.py`): inclusive `--since`/`--until` accepting
  ISO-8601 or epoch; naive timestamps are read as UTC.
- **Run history** (`cabid/history.py`): local SQLite store, `cabid history`
  list/show/compare, `--compare-history` with score and reason deltas. Only
  summary metrics are stored — no paths, command lines, or addresses.
- Policy format `cabid-policy/2` with per-process suppression; v1 files still load.
- Dashboard: Merge all, Since/Until inputs, Processes tab.

### Fixed
- History database is now git-ignored (`*.sqlite3`).

## [0.4.0] — 2026-11-13

### Added
- Five-component explainable scoring: temporal, causal, sequence,
  telemetry_gap, and opt-in novelty, with normalised weights and per-component
  contribution shares.
- Lifecycle contradiction detection: activity after exit, duplicate start/exit.
- Versioned configuration (`cabid/config.py`) with strict validation and a
  `config_digest` embedded in every report.
- Benign baseline profiles (`cabid/baseline.py`) storing aggregate statistics only.
- Declarative policy (`cabid/policy.py`): sensitive paths/ports, allow-lists,
  reason-code suppression.
- Reports in JSON, Markdown, CSV, SARIF 2.1.0, and self-contained HTML.
- Windowed analysis (`--window`) and streaming `watch` mode.
- `cabid dashboard`: stdlib-only read-only web console with a same-origin JSON API.
- `cabid doctor`, `cabid init-config`, `cabid build-baseline`.
- CI exit codes: `--exit-code`, `--fail-on`.

### Changed
- Default weights rebalanced to accommodate the new components, so scores from
  0.3.0 are not directly comparable. `config_digest` makes this visible.

## [0.3.0]

### Added
- Limited Linux auditd raw-log importer for x86_64 and aarch64.
- Unprivileged `/proc` polling collector.
- Deterministic synthetic benchmark with a temporal-only baseline comparison.
- Documentation for methodology, limitations, telemetry policy, auditd ingestion,
  and the Linux collector.

## [0.2.0]

### Added
- Telemetry completeness gate: missing event classes produce
  `INSUFFICIENT_EVIDENCE` rather than a "safe" verdict.

## [0.1.0]

### Added
- Initial strict JSONL ingestion, temporal features, conservative ancestry
  checks, JSON reports, CLI, and test suite.

[Unreleased]: https://github.com/sayan9168/CABID/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/sayan9168/CABID/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/sayan9168/CABID/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/sayan9168/CABID/compare/v0.3.0...v0.4.0
