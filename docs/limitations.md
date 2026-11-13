# Limitations and safe-use notes

- CABID analyzes supplied JSONL; it does not install a kernel sensor, eBPF
  program, audit rule, or background service.
- The score is a transparent heuristic, not a probability or a claim of malware
  attribution. Weights are hand-set defaults, not fitted parameters.
- Parent-process checks are window-local. A parent may legitimately have started
  before the observed window; that can produce an orphan reference, which is
  reported as context and never scored.
- Lifecycle checks only flag *internally contradictory* histories. Missing
  predecessors are treated as window-boundary artefacts.
- Event-class completeness is a coarse proxy. Real sensor coverage requires
  source-specific sequence numbers, drop counters, clock quality, and health
  telemetry.
- Baseline novelty depends entirely on the quality of the "benign" labels. A
  contaminated baseline hides anomalies; a stale baseline over-flags routine
  deployments.
- Policy findings are operator-defined patterns. `file_write` from auditd means a
  write-capable open, not proof that bytes changed.
- Suppressing a reason code changes governance output, not detection behaviour.
- Thresholds are not trained or calibrated. Do not use this prototype as the sole
  security control or for automated blocking.
- Watch mode and the procfs collector are polling designs: they add latency and
  can miss short-lived activity. They are not real-time sensors.
- The dashboard has no authentication and binds to loopback by default. Do not
  expose `--host 0.0.0.0` on an untrusted network.
- Reports may include basenames of touched paths and process names from untrusted
  logs. Review before sharing, even though full command lines and targets are
  truncated.
- The entity rollup is a triage hint, not an attribution. High-ranked processes are
  those least consistent with the observed baseline; noisy-but-benign services look
  the same way.
- Multi-source merge assumes a shared clock. Cross-host skew reorders events and can
  change lifecycle and sequence results; duplicates are counted by fingerprint, not
  removed, and overlapping ranges may double-count the same activity.
- Time filtering is inclusive and UTC-first for naive timestamps. A filtered report
  is always marked with the trimmed event counts.
- The history database is a local convenience store, not a tamper-evident audit log.
  It contains summary metrics only (no paths, command lines, or addresses), but
  anyone with write access can alter it.
- Test only on systems and logs you own or are authorized to analyze. The sample
  dataset uses the reserved `.invalid` domain.
