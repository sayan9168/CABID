# CABID advanced research utilities

Install with \`pip install -e '.[test]'\`. The optional \`cabid-research\` command
adds offline-first utilities without changing the core detector's event schema.

## Commands

- \`cabid-research fim-snapshot ROOT -o manifest.json\`: SHA-256 inventory.
- \`cabid-research fim-verify ROOT manifest.json\`: report changed, missing and added paths.
- \`cabid-research health events.jsonl --expected-interval 2\`: timestamp-gap and malformed-row health hints.
- \`cabid-research correlate events.jsonl --window 60\`: conservative per-PID event co-occurrence rules.
- \`cabid-research intel-match events.jsonl indicators.json\`: exact matching against local user-supplied IP/domain/SHA-256 indicators.
- \`cabid-research explain report.json\`: evidence-oriented explanation summary.
- \`cabid-research benchmark-dashboard results.json -o dashboard.html\`: static HTML view of an existing benchmark JSON.
- \`cabid-research reproduce events.jsonl -o manifest.json\`: input hashes and environment manifest.

IOC file schema: \`{"ips":[],"domains":[],"sha256":[]}\`.

## Important limits

FIM is a point-in-time inventory; it is not a real-time kernel watcher and does
not protect its manifest. Store signed manifests separately. Timestamp gaps are
not exact event-drop counters. Correlation reports co-occurrence, not causation.
Threat-intelligence matching is exact and local; no reputation is inferred.
The dashboard renders supplied metrics and does not run experiments. The
reproducibility manifest does not yet capture Git revision, lockfile, kernel
configuration or hardware counters. No feature blocks or quarantines activity.
