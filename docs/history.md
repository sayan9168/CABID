# Run history and comparisons

`cabid` can record each analysis in a local SQLite database and diff runs later.
This is how you answer "is this host worse than it was yesterday?" without
re-analyzing archived JSONL.

## Record a run

    cabid analyze events.jsonl --save-history --label "pre-deploy" -o report.json
    cabid analyze events.jsonl --save-history --label "post-deploy" --history-db /srv/cabid/history.sqlite3

`--history-db` defaults to `./cabid-history.sqlite3`. The database path is created
on first use, including parent directories.

## Inspect

    cabid history                       # table of recent runs
    cabid history --limit 50 --format json
    cabid history --show 4              # stored summary for one run
    cabid history --compare 3 7         # diff two stored runs

## Compare an analysis against history

    cabid analyze events.jsonl --compare-history 3 --format md -o report.md

The report gains a `history_comparison` block: `score_delta`, `status_changed`,
`component_delta`, `new_reason_codes`, `cleared_reason_codes`,
`new_processes`, `disappeared_processes`, and `config_changed` (true when the
`config_digest` differs, so a scoring change is never mistaken for a behaviour
change).

## What is stored

Summary metrics only: status, score, event count, coverage, config digest, the
component values, reason codes, missing event classes, and the top-ranked
entities (pid, names, risk, sensitive-hit count).

**Not** stored: event rows, command lines, file targets, network addresses, or
source content. A test enforces this (`test_history.py::test_history_stores_no_raw_event_content`),
so the history database is materially safer to retain than the input logs.

## Limitations

- History is a local convenience store, not a tamper-evident audit log. Anyone
  with write access to the file can rewrite it.
- Labels and timestamps come from the analyst's clock; there is no signature.
- Comparisons are metric-level. Two runs with identical metrics can still differ
  in the events behind them.
- Deleting the database loses trend context; back it up if a study depends on it.
