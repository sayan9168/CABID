# Watch mode

`cabid watch` streams a growing JSONL file and re-scores a trailing time window
as data arrives.

    # one terminal: collect
    cabid collect-proc --output /tmp/events.jsonl --interval 2 --duration 600

    # another: watch the trailing 5 minutes
    cabid watch /tmp/events.jsonl --window 300 --interval 2

    # machine-readable, one JSON report per poll
    cabid watch /tmp/events.jsonl --json --iterations 20

Output per poll:

    [  7] INSUFFICIENT_EVIDENCE score=0.412 events=318   buffered=318  top=telemetry_gap

## Behaviour

- Only bytes appended since the last poll are read (`seek` to the previous
  offset), so cost scales with new data, not file size.
- A trailing partial line is buffered until it is complete; malformed lines are
  counted in `watch.invalid_lines` instead of aborting the run.
- The window is bounded twice: by `--window` seconds relative to the newest
  event, and by a hard `max_events` cap (20 000 by default) to keep memory flat.
- `--iterations N` stops after N polls and forces one report per poll.
- `--config`, `--baseline`, and `--policy` work exactly as in `analyze`.

## Why this is not a real-time detector

CABID re-reads and re-analyzes the whole window on every poll and the underlying
collector polls procfs. Both introduce latency measured in seconds, and both can
miss short-lived activity. Treat watch mode as a research convenience for short
collection runs, not as an alerting sensor. `INSUFFICIENT_EVIDENCE` will be the
normal verdict for procfs-only streams because file, network, and exit events are
not observed.
