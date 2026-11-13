# Linux auditd ingestion

CABID translates a limited subset of raw Linux audit records into normalized JSONL.
It does not install audit rules or alter audit configuration.

Export on a host where auditd is already configured:

    sudo ausearch --start today --format raw > /tmp/audit.raw
    cabid import-audit /tmp/audit.raw --output /tmp/audit-events.jsonl --report /tmp/import-report.json
    cabid analyze /tmp/audit-events.jsonl

The parser recognizes selected x86_64 and aarch64 syscall IDs for exec, process
creation/exit, successful connect, and write-capable open/creat calls. Unknown
syscalls are ignored. File-write extraction depends on PATH records and raw
hexadecimal syscall arguments. Process creation uses the successful syscall
return value as the child PID.

Protect exported logs: they may contain usernames, paths, process arguments,
and other sensitive information. Configure audit rules independently and verify
coverage. Heartbeat is never synthesized, so completeness remains insufficient
when required sensor-health evidence is absent. Validate parsed output against
your distribution's audit tooling before research use.
