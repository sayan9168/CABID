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

The importer reports records seen, unparsed records, ignored audit events,
normalized events written, and a per-reason `skipped` breakdown. A successful
import does not prove that the audit rules captured every relevant syscall.

## What is translated

| Family | Syscalls | Emitted class | `target` |
| --- | --- | --- | --- |
| exec | `execve`, `execveat` | `process_exec` | — |
| process creation | `fork`, `vfork`, `clone`, `clone3` | `process_start` | — |
| exit | `exit`, `exit_group` | `process_exit` | — |
| file write | `open`, `openat`, `creat` | `file_write` | PATH record |
| network | `connect` | `network_connect` | — |
| accept | `accept`, `accept4` | `network_accept` | — |
| privilege | `setuid`, `setgid`, `setreuid`, `setresuid`, `setfsuid`, ... | `privilege_change` | syscall name |
| kernel state | `ptrace`, `mount`, `umount2`, `pivot_root`, `mknod` | `kernel_state_change` | syscall name |
| permissions | `chmod`, `fchmod`, `fchmodat`, `chown`, `lchown`, `fchown` | `permission_change` | PATH record |

Syscall numbering differs per architecture and the tables are per-arch: 35
translated syscalls for x86_64 (`c000003e`) and 26 for aarch64 (`c00000b7`). An
unrecognised `arch` is never guessed — those records are counted under
`unsupported_arch`.

## Why `skipped` matters

Ignored records are broken out by reason rather than lumped into one number:

- `unmapped_syscall` — a syscall this importer does not translate.
- `unsupported_arch` — an architecture with no table.
- `failed_syscall` — `success=no` or `success=0`.
- `no_syscall_record`, `missing_pid` — unusable record.

A large `unmapped_syscall` count means the stream is only partly understood. That
is not evidence that the host was quiet, and it should not be read as one.

File-write extraction depends on PATH records and raw hexadecimal syscall
arguments; it indicates write-capable open intent, not proof that bytes were
actually written. Process creation uses the successful syscall return value as the
child PID. `privilege_change` records that a setuid-family call succeeded, not why
it was made.

Protect exported logs: they may contain usernames, paths, process arguments,
and other sensitive information. Configure audit rules independently and verify
coverage. Heartbeat is never synthesized, so completeness remains insufficient
when required sensor-health evidence is absent. Validate parsed output against
your distribution's audit tooling before research use.
