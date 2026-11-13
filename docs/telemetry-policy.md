# Telemetry completeness policy

The default detector expects six event classes: process start, process exec, file
write, network connect, process exit, and heartbeat. By default all six must be
observed before a stream is classified as telemetry-sufficient. This intentionally
means the current procfs polling collector produces `INSUFFICIENT_EVIDENCE`:
it does not observe file writes, network connections, or process exits.

A research experiment may choose a lower minimum coverage ratio, but must state
that choice and sensor coverage explicitly. Missing event classes are not evidence
that those activities did not occur.
