# Linux procfs collector

CABID includes an unprivileged polling collector for Linux `/proc`.

## Run

```bash
cabid collect-proc --output /tmp/cabid-events.jsonl --interval 2 --duration 30
cabid analyze /tmp/cabid-events.jsonl
```

The collector reads process metadata from `/proc/PID/stat`, `/proc/PID/exe`,
and `/proc/PID/cmdline`. It compares snapshots to emit `process_start` and
`process_exec` observations and writes a heartbeat for each poll. It does not
need root for ordinary visible processes; protected processes may be skipped.

## Interpretation and limitations

- The first poll is a baseline: every visible process is reported as first observed.
  This does **not** establish its actual creation or exec time.
- Polling can miss short-lived processes between samples.
- Process metadata can be hidden by procfs mount options, permissions, containers,
  namespaces, or process exit races.
- It does not capture file writes, network connections, syscalls, or process exits.
  CABID must therefore report incomplete telemetry rather than treating missing
  event classes as benign.
- This is not an auditd/eBPF replacement and is not a production EDR sensor.

Use only on systems you own or are authorized to monitor.
