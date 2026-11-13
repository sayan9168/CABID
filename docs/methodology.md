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

## Scoring model (v0.7.0)

The anomaly score is a normalised weighted sum of five transparent components:

| Component | Input | Normalised by |
| --- | --- | --- |
| `temporal` | event rate and inter-arrival burstiness | configured `rate_per_minute` / `burstiness` bounds |
| `causal` | share of events reporting a process as its own parent | event count |
| `sequence` | share of events contradicting the observed lifecycle | event count, amplified, capped at 1 |
| `telemetry_gap` | `1 - observed/expected event-class coverage` | expected class list |
| `novelty` | rate deviation, novel executables, type-mix divergence | benign baseline profile (opt-in) |

Additional analysis surfaces, none of which modify the score:

| Surface | Purpose | Where |
| --- | --- | --- |
| `entities` | per-pid triage ranking | every report |
| `policy` | operator-declared sensitive targets and allow-lists | `--policy` |
| `sources` | provenance, duplicates, overlap for multi-file input | 2+ inputs |
| `time_filter` | what was trimmed and how much | `--since`/`--until` |
| `history_comparison` | metric delta against a stored run | `--compare-history` |
| `rules` | declarative pattern matches with evidence rows | `--rules` / built-in pack |
| `tree` | ancestry structure, cycles, baseline edge drift | every report (`--no-tree` to skip) |

A per-process rollup (`entities`) attributes contradictions, self-parent events,
sensitive-target touches, and novelty to individual PIDs. It is a *triage aid*
with no weight in the window score: the score answers "does this stream look
unusual?", the rollup answers "which pid should I open first?". Keeping them
separate prevents a single chatty process from dominating the stream verdict.

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
CABID v0.7.0 is an alpha research prototype. On top of the v0.6.0 surfaces it
widens auditd coverage, adds container scoping and clock-skew estimation, and
integrates with Sigma and STIX. It still has no validated real-world benchmark,
calibrated thresholds, complete kernel telemetry sensor, or verified novelty
claim. Synthetic benchmark metrics are not operational IDS results. Rules, tree
findings, container scopes, and Sigma imports are deliberately outside the
weighted score, so the headline number remains comparable across v0.4.0–v0.7.0 for
the same configuration.

### The one scoring change in v0.7.0

`completeness.expected_event_types` used to list the four auditd-only classes
alongside the six core ones. A procfs stream could never satisfy that, so it was
always `INSUFFICIENT_EVIDENCE` while an auditd stream with the same real coverage
could look complete. The default is now the six core classes, and
`temporal.type_diversity` is likewise computed over the core set.

This is a correctness fix, not a tuning change, but it does mean a procfs report
from v0.7.0 can carry a different status than the same input under v0.6.0. Any
comparison across that boundary should re-run both sides.

### What is still missing

An honest list, because a missing benchmark is not a detail:

- **No real-host benchmark.** Every number in the repository comes from synthetic
  fixtures. Precision, recall, and false-positive rate against real enterprise
  telemetry are unmeasured.
- **No calibrated thresholds.** `suspicious` and `high` are hand-set defaults.
- **No sensor.** CABID reads logs; it does not collect kernel events.
- **No validated novelty claim.** Baseline novelty is a heuristic distance, not a
  statistically validated detector, and it depends entirely on operator labels.
