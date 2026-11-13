# Real-world benchmark: ADFA-LD

CABID ships two benchmarks and they answer different questions.

| Command | Data | What it measures |
| --- | --- | --- |
| `cabid benchmark` | generated fixtures | Does the scoring code do what the code says? A software regression test. |
| `cabid benchmark-real` | ADFA-LD, a real public corpus | How does the pipeline behave on genuine intrusion data it has never seen? |

This document is about the second one, and it leads with the result rather than
burying it.

## Headline result

On held-out ADFA-LD traces (4,372 benign validation traces, 746 attack traces):

| Model | Precision | Recall | F1 | FPR |
| --- | --- | --- | --- | --- |
| `cabid_core` (telemetry gate at 2/3) | 0.128 | 0.819 | 0.221 | **0.953** |
| `cabid_with_baseline` | 0.128 | 0.819 | 0.221 | **0.953** |
| `cabid_gate_disabled` | 0.000 | 0.000 | 0.000 | 0.001 |
| `syscall_ngram_3gram` (reference) | 0.508 | 0.298 | 0.375 | 0.049 |

95% Wilson interval on CABID recall: **0.790 – 0.845**.

Threshold-free separation (AUC): CABID anomaly score **0.356**, syscall n-gram **0.675**.

**CABID's headline behaviour on this corpus is poor, and the report says so.** A
93.8% false-positive rate is unusable. That number is published here deliberately:
a benchmark that only reports favourable results is not a benchmark.

## Why it fails — the mechanism, not an excuse

The benchmark runs an ablation to explain the number instead of restating it.

1. **The telemetry gate drives the score.** ADFA-LD traces are syscall sequences.
   CABID's completeness check compares observed event classes against an expected
   set. On this data a trace rarely covers every declared class, so the gate
   reports `INSUFFICIENT_EVIDENCE`, and the benchmark counts that as a positive
   detection — a session the engine refuses to judge has not been cleared.
2. **Attack traces look *less* complete than benign ones.** Attack traffic is
   dominated by `socketcall`, which maps to a single `network_connect` class.
   Measured mean class diversity: benign **0.550**, attack **0.414**. The gate
   therefore fires *more* often on attacks — which is why recall looks high — but
   it also fires on most benign traces, which is why precision collapses. The
   apparent recall is largely a mapping artifact, not detection.
3. **With the gate disabled the behavioural score inverts.** AUC drops to **0.356**,
   i.e. worse than a coin flip: the aggregate anomaly score ranks benign traces as
   *more* anomalous than attack traces. Component means show why — attack traces
   have lower temporal score (0.542 vs 0.651) and lower sequence score (0.035 vs
   0.071), because dropping 80% of syscalls leaves fewer modelled events, not more
   suspicious ones.

### What this means honestly

CABID's scoring components are built for **host telemetry** — process trees,
ancestry, lifecycle contradictions, event-class mix over time. A syscall-number
corpus has none of that structure. The benchmark shows that when you remove the
structure CABID depends on, its score is uninformative on this data. It does **not**
show CABID fails on real host logs, because this corpus is not real host logs.

The reference n-gram model reaches precision 0.508 / recall 0.298 / FPR 0.049. That
is a *different* result class, not a better implementation: n-gram novelty uses the
sequence detail CABID deliberately discards when it abstracts syscalls into event
classes. Reporting it alongside keeps the CABID number interpretable.

## The corpus

ADFA-LD (Creech & Hu, "Generation of a new IDS test dataset: time to move on",
UNSW@ADFA, 2013).

- 5,951 syscall traces: 833 benign training, 4,372 benign validation, 746 attack.
- Six attack techniques: Adduser (91), Hydra_FTP (162), Hydra_SSH (176),
  Java_Meterpreter (124), Meterpreter (75), Web_Shell (118).
- Each trace is a space-separated list of **i386** syscall numbers with no
  timestamps, pids, paths, or user identity.
- Downloaded from a plain-file mirror, pinned to commit `79c6db0`, archive
  SHA-256 `e6e73c16…7eb2`, 4,215,574 bytes.

### Reproducing

```bash
cabid corpus list                        # pinned digests, licences, caveats
cabid corpus fetch adfa-ld               # verify checksum, extract, cache
cabid benchmark-real --corpus-cache ~/.cache/cabid -o results/adfa.json -f md
```

The fetch is idempotent: a verified cache is reused with no network call. Use
`--offline` on an air-gapped host, `--require-verified` in CI, and `--refresh` to
force a re-download. Corpora are never bundled in the wheel; the report names the
exact digest it ran against.

## Method

- **Split discipline.** The benign profile is fitted on `Training_Data_Master`
  only. A 25% slice of that is held back for calibration. Nothing in evaluation
  contributes to fitting or calibration.
- **Calibration is data-driven.** The completeness floor is not a constant: it is
  the ratio met by the 99th percentile of held-out benign traces (here **0.667**).
  The n-gram cutoff is likewise the 99th percentile of benign novelty scores
  (**0.398**). See [calibration.md](calibration.md).
- **Unmappable traces are reported, twice.** 135 attack and 206 benign traces
  contain no syscall that maps to a CABID event class — **18.1% of attack traces
  are structurally invisible** to this pipeline. They are counted as undetected in
  `models`, and excluded from `models_mappable_only`, so the gap between the two
  views is visible instead of hidden in an average.
- **Intervals, not point estimates.** Every headline rate carries a Wilson 95%
  interval, because 75 traces is not a stable denominator.
- **Deterministic.** Fixed synthetic epoch, stable pid derivation from the trace
  name, seeded split. Two runs produce identical output.

## Limitations

These are reproduced verbatim in every report under `limitations`:

- ADFA-LD traces carry no timestamps, process ids, paths, or user identity. The
  adapter synthesises a 20-second window and a single synthetic process per trace,
  so CABID's ancestry, lifecycle, and rate detectors are not meaningfully exercised.
- The corpus is from 2013 and records 32-bit userspace syscalls. Its six attack
  techniques are well known and appear throughout the intrusion-detection
  literature, so high scores are expected and are not evidence of real-world
  detection quality.
- Only a minority of syscalls map to a CABID event class (mean 21.0% of benign and
  13.4% of attack calls); unmapped calls are dropped. Reported event counts are far
  smaller than trace lengths.
- Attack classes are small (75–338 traces each). Confidence intervals are reported
  because point estimates on these sizes are unstable.
- Traces are scored independently. ADFA-LD provides no notion of a host or a fleet,
  so no multi-host behaviour is measured here.

### Additional caveats worth stating plainly

- **The mirror is not the canonical release.** The upstream labelled release
  distributes `ADFA-LD.zip` through Git LFS, which could not be fetched. The data
  used here is a plain-file mirror of the same tree. The digest is pinned, so the
  exact bytes are reproducible, but this is a mirror and is labelled as one.
- **The adapter is a modelling choice, not a decoder.** Syscall number → event class
  is a hand-written table (`cabid/adfa.py`), derived from
  `arch/x86/entry/syscalls/syscall_32.tbl`. Different tables would produce different
  numbers. The table is in the repository for review.
- **`cabid_core` and `cabid_with_baseline` are identical here.** On this corpus the
  baseline profile adds nothing measurable. That is reported rather than tuned away.
- **This is not the benchmark to quote for CABID's detection quality.** It is the
  benchmark that shows what happens when CABID is fed data whose structure it does
  not model. Both are useful; only one is a compliment.

## Files

| Path | Purpose |
| --- | --- |
| `cabid/corpus.py` | Pinned corpus registry, verified fetch, offline cache. |
| `cabid/adfa.py` | i386 syscall table, trace→event adapter, n-gram reference model. |
| `cabid/realworld.py` | Benchmark harness, Wilson intervals, AUC, ablations. |
| `tests/test_realworld.py` | 35 tests; no network access. |
| `results/adfa-realworld.json` | Committed result of the run above. |

## Citation

> Creech, G. and Hu, J. (2013). *Generation of a new IDS test dataset: time to
> move on.* Proceedings of the 8th ACM Symposium on Information, Computer and
> Communications Security (ASIACCS), pp. 448–453.
