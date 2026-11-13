# Research methodology

## Research question
Can a lightweight Linux event-stream detector that combines temporal summaries,
conservative process ancestry checks, and explicit telemetry completeness communicate
suspicious behavior more reliably than a detector that treats missing observations
as benign?

## Falsifiable hypothesis
On a preregistered, held-out dataset with independently labelled benign and attack
sessions, a telemetry-aware detector will reduce false-safe classifications under
event loss compared with an otherwise identical detector that ignores completeness,
without materially reducing recall on complete telemetry. This remains untested.

## Experimental design
1. Define event schema, sensor coverage, and label policy before collection.
2. Split by host/session/scenario family, not random individual events.
3. Compare static rules, frequency, temporal-only, ancestry-only, combined scoring,
   and combined scoring with a completeness gate.
4. Report precision, recall, F1, false-positive rate, false-safe rate under loss,
   CPU time, peak RSS, dataset composition, and missing-event rates.
5. Repeat with fixed seeds and publish raw fixtures, configuration, commands, and environment.
6. Include benign updates, bursty workloads, process re-parenting, event loss,
   clock skew, and adversarial mimicry.

## Current status
CABID v0.3.0 is an alpha research prototype. It includes a limited auditd raw-log
importer and a deterministic synthetic regression benchmark. It has no validated
real-world benchmark, calibrated thresholds, complete kernel telemetry sensor, or
verified novelty claim. Synthetic benchmark metrics are not operational IDS results.
