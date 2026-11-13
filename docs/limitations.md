# Limitations and safe-use notes

- CABID 0.1.0 analyzes supplied JSONL; it does not install a kernel sensor, eBPF program, audit rule, or background service.
- The score is a transparent heuristic, not a probability or a claim of malware attribution.
- Parent-process checks are window-local. A parent may legitimately have started before the observed window; that can produce an orphan reference.
- Event-class completeness is a coarse proxy. Real sensor coverage requires source-specific sequence numbers, drop counters, clock quality, and health telemetry.
- Thresholds are not trained or calibrated. Do not use this prototype as the sole security control or for automated blocking.
- Test only on systems and logs you own or are authorized to analyze. The sample dataset uses the reserved `.invalid` domain.
