# Benign baseline profiles

A baseline profile answers *"is this session shaped like the activity we have
already labelled benign?"*. It is optional: without a profile, novelty is not
scored and `analyze` output says so (`novelty_available: false`).

## Build a profile

Pass sessions (JSONL files) that you have labelled benign:

    cabid build-baseline runs/benign-01.jsonl runs/benign-02.jsonl runs/benign-03.jsonl \
        --min-sessions 3 --output baseline-profile.json

    cabid analyze new-run.jsonl --baseline baseline-profile.json --format md

A minimum of three sessions is enforced by default because a two-session
"normal" is not a distribution. `--min-sessions 1` exists for smoke tests only.

## What is stored

`cabid-baseline/1` profiles contain aggregate statistics only:

- `rate_per_minute.median` and a robust `scale` (median absolute deviation × 1.4826)
- `type_mix` — the fraction of events per class
- `executables` — executable paths grouped by process name
- `sessions` — session identifiers, not event content

No command lines, addresses, file targets, or timestamps are retained, so a
profile can be reviewed or shared more safely than raw logs. Profiles are still
metadata about your hosts; treat them as internal.

## How novelty is scored

```
novelty = 0.5 * min(1, |observed_rate - baseline_median| / (6 * scale))
        + 0.3 * (fraction of known process names running an unseen executable)
        + 0.2 * half of the L1 distance between observed and baselined type mix
```

Interpretation:

- A rate within ±6 MADs of the baseline contributes nothing; the band is
  deliberately wide because event rate is noisy on real hosts.
- A process name seen in the baseline but running a *different* executable is
  the strongest signal (`novel_executable_processes` in the report).
- Completely unseen process names are **reported** (`unseen_process_names`) but
  **not scored**, mirroring the ancestry policy: absence of history is context,
  not proof of malice.

## Limitations

- Profiles are only as good as their labels. Contaminated benign data hides
  real anomalies.
- A profile is a snapshot in time; rebuild it after planned deployments, or the
  new binaries look novel forever.
- Novelty weights the score only when a profile is supplied. Comparing runs with
  and without a profile is an experiment change, not a bug fix.
