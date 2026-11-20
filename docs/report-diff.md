# Comparing two reports

    cabid analyze before.jsonl -o before.json
    cabid analyze after.jsonl  -o after.json
    cabid diff before.json after.json
    cabid diff before.json after.json --fail-on-regression   # CI gate

`cabid diff` answers the question a single report cannot: *what changed between
these two analyses, and is the change real?* It compares a whole report — status,
score, components, reason codes, rule matches, policy findings, process sets,
missing event classes — and refuses to read a score change as improvement or
regression when the two reports were not produced by the same configuration.

## Verdicts

| Verdict | Meaning |
| --- | --- |
| `unchanged` | Nothing moved beyond `--epsilon`. |
| `regression` | Score rose by more than `--epsilon`, or a rule/policy finding appeared. |
| `improvement` | Score fell by more than `--epsilon`. |
| `changed` | Metrics moved (new event classes, rule sets, processes) but the score did not. |
| `not-comparable` | The two reports cannot be meaningfully compared (see below). Never reported as a regression. |
| `evidence-lost` | The newer report is `INSUFFICIENT_EVIDENCE` where the older one was not. |
| `evidence-gained` | The opposite: the newer report finally has enough telemetry to score. |

`evidence-lost` is *not* an improvement even though the score usually drops —
the number went down because there is less to measure. It counts as a
regression for `--fail-on-regression`, with a warning that says so.

## Comparability

A score is only comparable when both reports carry the same `config_digest`.
Change a weight, a policy allow-list, or a threshold and every score moves;
comparing across that boundary would report a config edit as a security event.
So when the digests differ (or are missing) the diff has `"comparable": false`,
`"score_delta": null`, verdict `not-comparable`, and a warning naming the cause.
The remaining blocks — processes, rule ids, event classes — are still shown,
because those are facts about the inputs rather than the scoring config.

Session reports and streaming reports are also not compared against each other:
one scores a session, the other scores windows, and their "score" fields are not
the same quantity. Mixed kinds get `not-comparable` with an explanation.

## What the diff contains

- `status` — before/after, `changed`, and `risk_direction`
  (`worsened` / `improved` / `unchanged` / `unknown`).
- `score_delta`, `component_delta` — per-component movement, so "why did it go
  up" has an answer.
- `rules` — `new`, `cleared`, and per-rule match-count deltas.
- `policy` — newly appearing and cleared findings, keyed by `code|process|target`.
- `processes` — `new`, `disappeared` (using the report's entity rollup).
- `event_classes` — `newly_missing` / `newly_present`, i.e. telemetry drift.
- `warnings` — every reason the comparison is weaker than it looks.

## Formats and exit codes

    cabid diff a.json b.json                 # text (default)
    cabid diff a.json b.json -f md -o d.md
    cabid diff a.json b.json -f json
    cabid diff a.json b.json --epsilon 0.05  # treat < 0.05 as noise
    cabid diff a.json b.json --fail-on-change

Exit `1` on `--fail-on-regression` (regression or evidence lost) or
`--fail-on-change` (anything other than `unchanged`); exit `2` when a file is
missing, is not JSON, or is not a CABID report at all.

## Limitations

- A diff describes two reports, not two hosts. Identical metrics can hide
  completely different events, and the diff cannot see what the reports did not
  record.
- Score deltas are only as meaningful as the scoring config is identical. A
  `config_digest` match proves the *configuration* matched, not that the sensor
  did — events may have been collected differently run to run.
- The process and policy set diffs are keyed on names and codes. A process that
  was renamed, or a finding whose target changed slightly, appears as one
  removed and one added.
- `--epsilon` is a raw score distance, not a statistical significance test. There
  is no calibrated noise band; pick the value from repeated runs of your own
  workload, not from this document.
- Fleet reports (`cabid fleet`) are not diffed. Comparing hosts is a different
  question with different units; use `cabid fleet --baseline` for that.
