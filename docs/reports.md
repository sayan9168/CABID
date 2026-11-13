# Reports

`cabid analyze` renders one report in five formats. Pick with `--format` or by
file extension (`--format` wins).

| Format | Flag | Typical use |
| --- | --- | --- |
| `json` | `--format json` | machine pipelines, archives, diffs |
| `md` | `--format md` | pull-request or experiment notes |
| `csv` | `--format csv` | spreadsheets, metric extraction |
| `sarif` | `--format sarif` | GitHub code scanning / CI annotations |
| `html` | `--format html` | offline, self-contained review page |

Examples:

    cabid analyze events.jsonl -o reports/run.json
    cabid analyze events.jsonl --format md -o reports/run.md
    cabid analyze events.jsonl --format sarif -o reports/cabid.sarif
    cabid analyze events.jsonl --format html -o reports/run.html
    cabid analyze events.jsonl --window 300 --format md -o reports/windows.md

## JSON report

Stable, sorted keys. Fields worth knowing:

- `status` — `NO_ANOMALY_DETECTED`, `SUSPICIOUS`, `HIGH_RISK`, or `INSUFFICIENT_EVIDENCE`.
- `anomaly_score` — weighted heuristic in `[0, 1]`; `score_semantics` repeats that it is not a probability.
- `components` — raw value per component (`temporal`, `causal`, `sequence`, `telemetry_gap`, `novelty`).
- `normalized_weights` — weights actually used after normalisation.
- `contribution` — each component's share of the weighted sum; these sum to `anomaly_score`.
- `reasons` — ordered by weighted impact, each with `code`, `detail`, `weight`, `component_value`.
- `completeness` — observed and missing event classes plus the sufficiency gate.
- `sequence` — lifecycle contradictions and the most common transitions.
- `novelty` — baseline comparison when a profile is supplied.
- `policy` — findings and suppressions when a policy is evaluated.
- `windowed` — per-window results when `--window` is used.
- `config_digest` — SHA-256 of the resolved configuration.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | analysis completed (default) |
| `1` | `--exit-code` mapped a `SUSPICIOUS` status, or `--fail-on` threshold reached |
| `2` | input, configuration, policy, or I/O error |

`--fail-on` accepts `NO_ANOMALY_DETECTED`, `INSUFFICIENT_EVIDENCE`, `SUSPICIOUS`,
or `HIGH_RISK` and fails when the verdict is at or above that severity. Note that
`INSUFFICIENT_EVIDENCE` ranks above `NO_ANOMALY_DETECTED` so a CI job can refuse
to certify a stream it could not actually evaluate.

## SARIF

`--format sarif` emits SARIF 2.1.0 with one rule per reason code plus policy
rules. Results carry the status and score in `properties`. The file is designed
for upload as a build artifact; uploading it to a code-scanning service will
publish heuristic research output, so review the target repository's visibility
first.

## HTML

The HTML report is a single self-contained file with no scripts and no external
requests. Collected values (process names, paths) are HTML-escaped, so untrusted
log content cannot inject markup.
