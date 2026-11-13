# Research methodology

## Research question
Can a lightweight Linux event-stream detector that combines temporal summaries, process-parent consistency, and explicit telemetry completeness communicate suspicious behavior more reliably than a detector that treats missing observations as benign?

## Falsifiable hypothesis
On a pre-registered, held-out synthetic and then independently collected benign/attack-labelled dataset, a telemetry-aware detector will reduce false-safe classifications under event loss compared with an otherwise identical detector that ignores completeness, without materially reducing recall on complete telemetry. This is a hypothesis, not an established result.

## Experimental design
1. Define event schema and label policy before collecting evaluation data.
2. Split by scenario family and host/session, not random individual events, to reduce leakage.
3. Compare static rules, event-frequency, temporal-only, ancestry-only, combined score, and combined score with completeness gate.
4. Report precision, recall, F1, false-positive rate, false-safe rate under telemetry loss, CPU time, peak RSS, and dataset composition.
5. Repeat with fixed seeds and publish raw event fixtures, configuration, commands, and environment details.
6. Include benign software updates, bursty legitimate workloads, process re-parenting edge cases, missing event classes, clock skew, and adversarial mimicry.

## Current status
Version 0.1.0 is a functional heuristic prototype with unit tests and a tiny synthetic fixture. It does not yet contain a validated benchmark, production telemetry collector, calibrated thresholds, or a novelty claim. Default weights and thresholds are engineering starting points only.
