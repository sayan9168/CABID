# Event schema

Each JSONL record is a JSON object with required fields:

- `timestamp`: Unix time in seconds (number)
- `event_type`: `process_start`, `process_exec`, `file_write`, `network_connect`, `process_exit`, or `heartbeat`
- `process_id`: positive integer

Optional fields: `parent_process_id` (non-negative integer), `process_name`, `executable`, `target`, `source`, and `event_id`.

The included fixture is synthetic. `heartbeat` is an explicit source-health signal, not an event that this prototype collects automatically. Completeness measures presence of event classes in the supplied analysis window; it is not a calibrated measurement of kernel-level sensor coverage.
