# Threshold calibration

CABID's decision thresholds used to be constants chosen by hand: `suspicious = 0.55`,
`high = 0.80`, `rate_per_minute = 120`, `burstiness = 3.0`. Those defaults still
exist, but they are now a starting point rather than an answer. This document
explains why, and what replaces them.

## The problem with hand-picked constants

A fixed threshold carries an unstated assumption: that the score distribution is the
same on every host. It is not.

| Host | Benign event rate | What `120/min` means |
| --- | --- | --- |
| Quiet jump box | ~6/min | Never exceeded. The rate term contributes ~0.05. |
| CI build agent | ~900/min | Exceeded constantly. Every session is "fast". |
| Busy database | ~400/min | Exceeded under normal load. |

The same constant therefore produces near-zero false positives on one host and
near-total false positives on another. On the [ADFA-LD benchmark](realworld-benchmark.md)
the hand-tuned completeness floor alone drove a **93.8% false-positive rate**,
because the floor was set for host telemetry, not for the corpus at hand.

There is a second, quieter problem: a constant hides its own false-positive budget.
Nobody knows whether `0.55` means 1%, 10%, or 40% of benign traffic until it is
deployed.

## What calibration does instead

```bash
cabid calibrate sessions/*.jsonl --output calibration.json
cabid calibrate sessions/*.jsonl --output calibration.json --apply-to config.json
```

Calibration reads a reference set of **benign** sessions and derives four numbers:

| Threshold | Derived from | Why |
| --- | --- | --- |
| `suspicious` | 99th percentile of benign anomaly scores | Makes the false-positive budget explicit |
| `high` | 99.9th percentile of benign anomaly scores | Keeps `HIGH_RISK` meaningfully rarer |
| `rate_per_minute` | median + 3 × MAD of benign rates | Resists a few unusual benign sessions |
| `burstiness` | median + 3 × MAD of benign burstiness | Same |

Every output records the support it was computed from, so the number can be audited
rather than trusted:

```json
{
  "format": "cabid-calibration/1",
  "thresholds": {
    "suspicious": 0.518691,
    "high": 0.576132,
    "rate_per_minute": 269.993,
    "burstiness": 2.550978
  },
  "expected_false_positive_rate": 0.01,
  "reference_session_count": 833,
  "scored_session_count": 605,
  "skipped_insufficient_evidence": 228,
  "support": {
    "score_min": 0.172369, "score_median": 0.333469, "score_max": 0.576132,
    "score_mad": 0.052029, "rate_median": 99.934, "rate_mad": 56.686
  }
}
```

That example is real output from the ADFA-LD benign training split. Note the derived
`suspicious` floor of **0.519** against the shipped default of **0.55** — and the
derived rate limit of **270/min** against the default **120/min**. On that corpus the
defaults were both too strict on rate and slightly too strict on score.

## The false-positive budget is stated, not implied

`expected_false_positive_rate` is `1 − reference_percentile`. Choosing a 99th
percentile floor means **1% of benign sessions sit above it by construction**. That
is arithmetic, not a measurement, and the report labels it that way:

> "The expected false-positive rate is implied by the chosen percentile, not measured
> in production."

If you want 5% headroom, pass `--reference-percentile 0.95`. You get 5% by design and
the report says 5%.

## Statistical choices, and why

**Nearest-rank, not interpolated, quantiles for thresholds.** Linear interpolation
describes a distribution well but thresholds it badly. When many sessions tie on the
same score — the common case, since most benign sessions look alike — an interpolated
99th percentile lands *between* two ties and ends up **below** the tied bulk. The
floor then flags the very traffic it was fitted on. Measuring this on a test fixture
produced a `suspicious` floor of `0.015` and flagged 33 of 40 benign sessions. Nearest-
rank guarantees at most `1 − fraction` of the reference set lies above the chosen
value, ties included. Describing a distribution and cutting it are different jobs.

**Median and MAD for rate limits, not mean and standard deviation.** One build job
running at 20,000 events/min would inflate a mean by orders of magnitude and drag a
standard-deviation-based limit out of usefulness. The median moves barely at all, and
MAD — the median of absolute deviations — is equally resistant.

**A floor on the scale.** MAD collapses to zero when most sessions share a value,
which would place the derived limit directly on top of normal behaviour. The scale is
floored at half the median (and at 1 event/min and 0.5 burstiness respectively). An
early implementation used `scale or fallback`, which silently failed because a
floating-point residue of `1.7e-13` is truthy — the limit came out at `6.8e-13` and
flagged everything. Explicit `max()` with a documented constant replaced it.

**Guaranteed headroom between `suspicious` and `high`.** If the reference distribution
is compressed, the two percentiles can collapse onto the same value and `HIGH_RISK`
becomes unreachable. A minimum 0.05 gap is enforced.

## What calibration refuses to do

Calibration fails loudly rather than producing a confident-looking guess:

| Condition | Behaviour |
| --- | --- |
| Fewer than 20 reference sessions | `CalibrationError`: "a threshold fitted on fewer sessions is a guess wearing a computed number" |
| Any session with zero events | `CalibrationError` naming the session |
| Fewer than 20 *scoreable* sessions (most reported `INSUFFICIENT_EVIDENCE`) | `CalibrationError` explaining the telemetry is too sparse |
| Every session scores identically | `CalibrationError`: no threshold can separate them |
| Degenerate percentile pair | `CalibrationError` rather than an unreachable `HIGH_RISK` |

This is why the ADFA-LD calibration above shows `skipped_insufficient_evidence: 228`
out of 833 — a third of the reference traces could not be judged by the engine, and
pretending otherwise would have calibrated the floor against a refusal rather than a
behaviour.

## Reviewing a calibration before adopting it

```bash
cabid calibrate --compare calibration.json sessions/first.jsonl
```

```json
{"comparison": [
  {"threshold": "suspicious", "current": 0.55, "calibrated": 0.519,
   "absolute_change": -0.031, "relative_change": -0.056},
  {"threshold": "rate_per_minute", "current": 120.0, "calibrated": 270.0,
   "absolute_change": 150.0, "relative_change": 1.25}
]}
```

The relative change is what matters: a −0.03 move on a 0.55 threshold is a 6% shift,
which is a different decision from a 6% shift on a 0.05 threshold.

## Limitations

- **Calibration is per-deployment.** Thresholds describe the sessions they were fitted
  on. They do not transfer automatically to a host with a different workload; a
  fleet-wide calibration will be too loose for quiet hosts and too tight for busy
  ones. Re-calibrate per role when that matters.
- **The reference set must be benign, and the tool cannot verify that.** Passing
  attack sessions calibrates the thresholds to fire on the attacks, which is the
  opposite of the intent. Labels are the caller's responsibility.
- **Calibration does not fix a bad score.** If the underlying score cannot separate
  the classes, no choice of cut-off will. This is exactly what happened in
  [the ADFA-LD benchmark](realworld-benchmark.md): calibration lowered the floor to
  0.519, but the score's AUC stayed at 0.356. Calibration moves the operating point
  along a curve; it does not change the curve.
- **A percentile floor is a statement about the past.** New workloads, new software,
  or a change in what "normal" means will invalidate it silently. See
  [novelty.md](novelty.md) for drift detection, which is the complementary tool.
- **No calibration is fitted on attack data.** There is deliberately no
  "maximise detection" mode, because a threshold optimised against known attacks does
  not generalise to unknown ones.

## Files

| Path | Purpose |
| --- | --- |
| `cabid/calibrate.py` | Quantiles, calibration, config application, comparison. |
| `tests/test_calibrate.py` | 24 tests, including the tie-handling and zero-scale regressions. |
| `cabid calibrate` | CLI with `--apply-to` and `--compare`. |
