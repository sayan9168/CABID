# Telemetry completeness policy

The default detector expects six event classes: process start, process exec, file
write, network connect, process exit, and heartbeat. By default all six must be
observed before a stream is classified as telemetry-sufficient. This intentionally
means the current procfs polling collector produces `INSUFFICIENT_EVIDENCE`:
it does not observe file writes, network connections, or process exits.

A research experiment may choose a lower minimum coverage ratio or a subset of
expected classes through the configuration file (`completeness.minimum_ratio`,
`completeness.expected_event_types`), but must state that choice and sensor
coverage explicitly. The resolved values are embedded in every report, and the
`config_digest` changes when they do, so a lowered bar cannot be hidden in a
results table.

Missing event classes are not evidence that those activities did not occur.

## Ordering of verdicts

`INSUFFICIENT_EVIDENCE` outranks `NO_ANOMALY_DETECTED` in the CLI severity order
used by `--fail-on`. A CI job can therefore refuse to certify a stream it could
not evaluate, instead of treating silence as a pass.
