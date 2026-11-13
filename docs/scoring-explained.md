# Reading the score: `--explain-score`

    cabid analyze events.jsonl --explain-score
    cabid analyze events.jsonl --explain-score --format md -o report.md

The anomaly score is a weighted mean of five components. That sentence hides two
things that surprise people reading a report, so this flag prints the arithmetic
instead of asking you to trust it.

## The walkthrough

```
Score arithmetic (highest term first)
  formula: anomaly_score = sum(normalized_weight_i * component_value_i) over active components

  component           value   weight   product  note
  sequence           1.0000   0.1667    0.1667
  temporal           0.3841   0.3333    0.1280
  telemetry_gap      0.1667   0.2222    0.0370
  causal             0.0000   0.2778    0.0000
  novelty            0.0000   0.0000    0.0000  inactive: no baseline profile, weight redistributed
  sum                         1.0000    0.3317

  reported score 0.33173 recomputes consistently: True

  decision: telemetry_sufficient is false (completeness 0.833333 < 1.0), so the
  score is not used and the status is INSUFFICIENT_EVIDENCE
  final status: INSUFFICIENT_EVIDENCE
```

## The two things it explains

**Weights are renormalized.** The number in your config is not the number used.
The engine divides by the sum of *active* weights, so with novelty inactive the
other four are scaled up. `normalized_weights` in the report is the one that was
actually applied — and the explanation prints that one.

**An inactive component is redistributed, not zeroed.** Without a baseline
profile, novelty has no value to contribute. Treating that as a zero would drag
every score down and make an unbaselined run look calmer than a baselined one.
Instead its weight leaves the denominator, and the explanation says so on the
novelty row.

It also states which branch decided the status. `INSUFFICIENT_EVIDENCE` is a gate,
not a score: when telemetry is incomplete the number is computed, printed, and
then ignored. A report can therefore show a high score and a safe-looking status,
which is exactly the intended behaviour — the score is not trustworthy without the
telemetry it was computed from.

`recomputes_consistently` is a self-check: the explanation recomputes the total
from the reported components and weights and compares it with the reported score.
If those ever disagree, the report is internally inconsistent and should not be
used — that is a bug, not a rounding artefact.

## Machine-readable form

In JSON output the same walkthrough appears under `score_explanation`:

| Field | Meaning |
| --- | --- |
| `formula` | the expression, as text |
| `steps[]` | per component: `component_value`, `normalized_weight`, `product`, `note` |
| `weight_denominator` | sum of active weights |
| `recomputed_score` | total recomputed from the steps |
| `reported_score` | what the report says |
| `recomputes_consistently` | whether those two agree |
| `thresholds` | `suspicious` and `high` actually in force |
| `decision[]` | the status decision, in the order the code took it |
| `final_status` | the resulting status |
| `caveat` | the standing note that this is not a probability |

For Markdown, CSV, SARIF, and HTML output the walkthrough goes to stderr instead of
being embedded, so exported reports keep their existing shape.

## What it still does not tell you

Every term is a documented heuristic in `[0,1]`. The sum is not a probability of
attack, and no amount of arithmetic makes it one. The explanation shows *why the
number is what it is*; whether that number means anything on your hosts is an
empirical question CABID has not answered.
