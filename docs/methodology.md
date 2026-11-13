# Research methodology

## Research question
Can a lightweight Linux event-stream detector that combines temporal summaries,
conservative process ancestry and lifecycle checks, and explicit telemetry
completeness communicate suspicious behavior more reliably than a detector that
treats missing observations as benign?

## Falsifiable hypothesis
On a preregistered, held-out dataset with independently labelled benign and attack
sessions, a telemetry-aware detector will reduce false-safe classifications under
event loss compared with an otherwise identical detector that ignores completeness,
without materially reducing recall on complete telemetry. This remains untested.

## Scoring model (v0.4.0)

The anomaly score is a normalised weighted sum of five transparent components:

| Component | Input | Normalised by |
| --- | --- | --- |
| `temporal` | event rate and inter-arrival burstiness | configured `rate_per_minute` / `burstiness` bounds |
| `causal` | share of events reporting a process as its own parent | event count |
| `sequence` | share of events contradicting the observed lifecycle | event count, amplified, capped at 1 |
| `telemetry_gap` | `1 - observed/expected event-class coverage` | expected class list |
| `novelty` | rate deviation, novel executables, type-mix divergence | benign baseline profile (opt-in) |

The completeness gate is applied *after* scoring: if coverage is below the
required ratio the verdict is `INSUFFICIENT_EVIDENCE` regardless of score. A
component's contribution (`weight × value / Σ active weights`) is reported
alongside every verdict, so a reader can audit why a stream scored as it did.

## Experimental design
1. Define event schema, sensor coverage, and label policy before collection.
2. Split by host/session/scenario family, not random individual events.
3. Compare static rules, frequency, temporal-only, ancestry-only, sequence-only,
   combined scoring, combined scoring with a completeness gate, and combined
   scoring with a baseline profile.
4. Report precision, recall, F1, false-positive rate, false-safe rate under loss,
   CPU time, peak RSS, dataset composition, and missing-event rates.
5. Repeat with fixed seeds and publish raw fixtures, the resolved configuration
   (`config_digest`), the baseline profile, commands, and environment.
6. Include benign updates, bursty workloads, process re-parenting, event loss,
   clock skew, and adversarial mimicry.

## Current status
CABID v0.4.0 is an alpha research prototype. It adds policy evaluation, baseline
profiles, windowed and streaming analysis, and multi-format reporting to the
v0.3.0 auditd importer and synthetic benchmark. It still has no validated
real-world benchmark, calibrated thresholds, complete kernel telemetry sensor, or
verified novelty claim. Synthetic benchmark metrics are not operational IDS results.
