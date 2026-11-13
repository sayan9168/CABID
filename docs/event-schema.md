# Event schema

Each JSONL record is a JSON object. CABID validates it strictly and reports the
line number on failure; an unknown field is an error, not something to ignore.

## Required

| Field | Type | Notes |
| --- | --- | --- |
| `timestamp` | number | Unix seconds. Finite, non-negative. Booleans are rejected. |
| `event_type` | string | One of the classes below. |
| `process_id` | positive integer | Numeric strings that round-trip (`"7"`) are accepted. |

## Optional

| Field | Type | Notes |
| --- | --- | --- |
| `parent_process_id` | non-negative integer | Defaults to `0`. |
| `process_name` | string | Short name (`nginx`). Used for rules and trees. |
| `executable` | string | Full path (`/usr/sbin/nginx`). |
| `target` | string | Path, address, or syscall name, depending on the class. |
| `source` | string | `linux-auditd`, `linux-procfs`, ... |
| `event_id` | string | Sensor-assigned id. |
| `container_id` | string | Container identifier; any `[A-Za-z0-9_.:-]` up to 128 chars. |
| `pid_ns` / `namespace_pid` | non-negative integer | The pid as seen inside the namespace. |

Container fields are only read, never invented: if no `container_id` is present,
every event is treated as one host scope and the report says so.

## Event classes

### Core (a generic sensor can produce these)

- `process_start`, `process_exec`, `process_exit`
- `file_write`
- `network_connect`
- `heartbeat` — an explicit source-health signal, not something CABID collects
  automatically.

These six are what the telemetry-completeness gate requires. Missing any of them
yields `INSUFFICIENT_EVIDENCE`.

### Optional (auditd-only)

- `privilege_change` — a successful setuid/setgid/setreuid/setresuid call.
  `target` is the syscall name.
- `kernel_state_change` — `ptrace`, `mount`, `umount2`, `pivot_root`, `mknod`.
  `target` is the syscall name.
- `permission_change` — `chmod`, `fchmod`, `chown`, and friends. `target` is the path.
- `network_accept` — `accept`/`accept4` on a listening socket.

These are accepted on input and used by rules, but **never required**. A
procfs-based sensor cannot emit them at all, so requiring them would make every
procfs stream look insufficient while every auditd stream looked complete. That
comparison would be an artefact of the sensor, not the host.

The optional classes also cannot inflate `temporal.type_diversity`: diversity is
computed over the core set only, so adding an auditd-only class does not move a
score it was never part of.

## A record

```json
{"timestamp": 1700000000.5, "event_type": "privilege_change", "process_id": 4211,
 "parent_process_id": 1, "process_name": "sudo", "executable": "/usr/bin/sudo",
 "target": "setuid", "source": "linux-auditd", "container_id": "abc123",
 "pid_ns": 42}
```

## What the fixture is not

`datasets/synthetic/` is generated. Completeness measures the presence of event
classes in the supplied window; it is not a calibrated measurement of
kernel-level sensor coverage. A stream that contains every class can still be
missing events within those classes.
