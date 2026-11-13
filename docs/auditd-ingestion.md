# Linux auditd ingestion

CABID translates a limited subset of raw Linux audit records into normalized
JSONL. It does not install audit rules or alter audit configuration.

## Configure auditd separately

Review the example rules in docs/cabid-audit.rules.example. They are intentionally
not installed automatically. Have an administrator review event volume and
privacy implications before enabling them. The optional exit/exit_group rule can
be high-volume. The example covers b64 syscalls on supported x86_64/aarch64 hosts;
it does not cover 32-bit compatibility processes.

## Export and convert

On a host where auditd is already configured:

    sudo ausearch --start today --format raw > /tmp/audit.raw
    cabid import-audit /tmp/audit.raw --output /tmp/audit-events.jsonl --report /tmp/import-report.json
    cabid analyze /tmp/audit-events.jsonl

The importer reports records seen, unparsed records, ignored audit events, and
normalized events written. A successful import does not prove that the audit
rules captured every relevant syscall.

The parser recognizes selected x86_64 and aarch64 syscall IDs for exec,
process creation/exit, successful connect, and write-capable open/creat calls.
Unknown syscalls are ignored. File-write extraction depends on PATH records and
raw hexadecimal syscall arguments; it indicates write-capable open intent, not
proof that bytes were actually written. Process creation uses the successful
syscall return value as the child PID.

Protect exported logs: they may contain usernames, paths, process arguments,
and other sensitive information. Configure audit rules independently and verify
coverage. Heartbeat is never synthesized, so completeness remains insufficient
when required sensor-health evidence is absent. Validate parsed output against
your distribution's audit tooling before research use.
