# Baseline validation and concept drift

CABID's novelty score compares a session against a profile of labelled-benign
sessions. Two things could go wrong with that and neither used to be checkable:

1. the **profile itself is a bad fit** — fitted on too few sessions, or on sessions
   that disagree with each other;
2. the profile **stopped describing the host** — software upgrades, role changes,
   seasonal load.

Both failures are silent in the same direction: ordinary activity starts scoring as
novel. This document covers the two commands that make them visible.

```bash
cabid validate-baseline profile.json held-out/*.jsonl
cabid drift-report profile.json recent/*.jsonl
```

Neither command judges the host. Both judge the *model*. That distinction is load-
bearing: drift is caused by benign change constantly, and treating it as an attack
signal is how normal operations become incidents.

## Validating a baseline

```bash
cabid validate-baseline baseline.json withheld/*.jsonl --min-sessions 20
```

```json
{
  "format": "cabid-baseline-validation/1",
  "verdict": "NEEDS_REFIT",
  "verdict_semantics": "a judgement about the baseline profile, not about the host or any event",
  "coverage": 0.749,
  "ks_rate_vs_baseline": 0.055,
  "rate_divergence_method": "two_sample_ks",
  "findings": [
    "only 74.9% of held-out benign sessions scored below the novelty cutoff 0.25; a benign-only baseline should describe most benign traffic"
  ]
}
```

That is real output from the ADFA-LD corpus: the profile was fitted on 300 benign
training traces and validated on the remaining ~470. Event rates agree closely
(KS 0.055) but a quarter of held-out benign traces still score as novel, so the
verdict is `NEEDS_REFIT`. Reporting that is more useful than a green check.

### Verdicts

| Verdict | Meaning |
| --- | --- |
| `SOUND` | Held-out benign sessions are consistent with the baseline. |
| `NEEDS_REFIT` | The baseline has drifted from current benign behaviour. |
| `INVALID` | The validation itself cannot be trusted — usually because the held-out sessions were also used to fit the profile. |

### How the checks work

| Check | Method | Why this method |
| --- | --- | --- |
| Rate divergence | Two-sample Kolmogorov–Smirnov against the profile's stored rate sample | Distribution-free, and event rates are skewed and bounded at zero, where a t-test misleads |
| Coverage | Fraction of held-out sessions scoring below the novelty cutoff | Directly measures the quantity that matters: how often benign traffic alerts |
| Unseen processes | Set difference, with a tolerance | One new binary is a package install; dozens is a role change |
| Fit overlap | Session-name intersection with `profile["sessions"]` | Catches the most common methodological error |

### Two implementation notes, because they were bugs first

**Storing rate samples.** The first version compared held-out rates against the
profile's single median rate. That is degenerate by construction: an empirical CDF
is always about 0.5 away from a step function, so the statistic was pinned near 0.5
regardless of the data and carried no information. Profiles now store the reference
rate sample (`rate_samples`), enabling a real two-sample test. Rates are scalars and
reveal no paths or command lines, so this adds no exposure. Older profiles without
the field fall back to a "fraction outside three scales" measure and say so in
`rate_divergence_method`.

**Rounding at the stored precision.** Profile rates are stored to six decimals.
Comparing unrounded held-out rates against them made KS return **1.0** — total
disjointness — for two samples describing the same workload, because the values
differed in the ninth decimal. Both sides are now rounded to the stored precision
before comparison. A distance measure is only as meaningful as the precision of the
data behind it.

## Detecting drift

```bash
cabid drift-report baseline.json recent/*.jsonl
```

```json
{
  "format": "cabid-drift-report/1",
  "drifted": true,
  "threshold": 0.3,
  "features": [
    {"feature": "event_rate_per_minute", "statistic": 0.575,
     "baseline": 60.0, "observed": 300.0, "direction": "higher"}
  ],
  "suggestions": ["consider widening rate_per_minute around 300.0/min (baseline median 60.0, current scale 6.0)"],
  "recommendation": "Review the proposed updates and refit the baseline deliberately with cabid build-baseline. Nothing here is applied automatically.",
  "drift_is_not_an_attack_signal": "Drift means the baseline no longer describes the host..."
}
```

### What is compared

| Feature | Statistic | Fires when |
| --- | --- | --- |
| `event_rate_per_minute` | Two-sample KS | ≥ 0.30 |
| `event_type_mix` | Total-variation distance | ≥ threshold |
| `parent_child_edges` | New benign edges | ≥ 2 novel edges |

A single new ancestry edge is ignored: one new child process is a package install.

### Why drift proposes and never applies

It would be trivial to write the updated profile automatically. That is exactly the
failure mode to avoid: an auto-widening baseline quietly absorbs whatever happens
next, including attack behaviour, and novelty detection degrades into a rubber stamp.
The command emits a diff for review; `cabid build-baseline` is a separate,
deliberate act.

### Drift is not an attack signal

Attacks frequently do *not* cause drift, and drift is frequently not caused by
attacks. Verified against real data: running the drift report over 200 ADFA-LD
**attack** traces against a benign profile returned `drifted: false` — attacks here
look like benign traffic in aggregate rate and mix. Conversely an ordinary software
rollout shifts the mix and fires the report.

The honest reading of `drifted: true` is: *the baseline no longer describes this
host, so novelty scores computed against it are unreliable until it is refitted.*

### Threshold choice, and a caveat

The default 0.30 is a magnitude threshold, not a p-value. The report also returns
`ks_critical_value` so the statistic can be read against sampling noise for the
number of sessions available. Both are needed: a p-value alone makes a large sample
flag a trivial difference, and a magnitude alone ignores how much data is behind it.
For deliberately gradual drift — small changes each window, each below threshold —
the detection is late by design. Catching that needs a reference window rather than
a fixed profile, which CABID does not yet do.

## Limitations

- **Both judge the model, not the host.** A statistically sound baseline can still
  be defeated by an attacker who behaves like the baseline.
- **Labels are the caller's responsibility.** `validate-baseline` and `drift-report`
  trust that the sessions passed to them are benign. Passing attack sessions
  validates a baseline against attacks.
- **Rate and mix only.** Event ordering is not compared, so behaviour that changed
  only in sequence is not detected here.
- **Drift detection is retrospective.** It needs recently-collected benign-labelled
  sessions, so it fires after an operator has already noticed something.
- **One verdict per window.** Drift spread gradually across many windows may stay
  under the threshold at every step.
- **`rate_samples` is capped at 5,000 entries**, the most recent of which are kept,
  so a very long-lived profile's sample is a recency window rather than all history.

## Files

| Path | Purpose |
| --- | --- |
| `cabid/novelty.py` | KS statistic and critical values, exact binomial test, `validate`, `drift`. |
| `cabid/baseline.py` | Now stores `rate_samples` for two-sample comparison. |
| `tests/test_novelty.py` | 29 tests, including both statistical regressions above. |
| `cabid validate-baseline`, `cabid drift-report` | CLI entry points. |
