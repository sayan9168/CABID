# Kernel sensor (eBPF)

CABID's original collector polls `/proc` on an interval. That is cheap and needs no
privileges, but it is structurally lossy: a process that starts and exits between two
polls is never observed. A kernel-side sensor closes that gap because the kernel emits
the event when it happens.

```bash
cabid ebpf check                                  # can this host run it?
cabid ebpf script --output cabid-sensor.bt        # review the program
bpftrace cabid-sensor.bt | tee sensor.log         # manual capture (as root)
cabid ebpf parse sensor.log --output events.jsonl # normalize

# Or use a bounded capture session:
cabid ebpf capture --duration 30 --output events.jsonl \
    --raw-output sensor.log --report capture-report.json
```

## Verification status — read this first

**The sensor program in this repository has never been executed against a live
kernel.** The development environment has no `bpftrace`, no kernel BTF, an
unprivileged uid, and `unprivileged_bpf_disabled=2`. `cabid ebpf check` on that host
correctly reports:

```json
{
  "available": false,
  "reasons": [
    "bpftrace is not installed",
    "running as uid 1001; eBPF tracepoints require root or CAP_BPF+CAP_PERFMON",
    "no kernel BTF at /sys/kernel/btf/vmlinux; bpftrace cannot resolve kernel types on this build"
  ]
}
```

So, precisely, what is established and what is not:

| Established | Not established |
| --- | --- |
| The parser handles the documented output format correctly (33 tests). | That the bpftrace program compiles on any given kernel. |
| Parsed output normalizes into valid CABID events. | That the probes fire with the field values assumed. |
| The capability check detects each prerequisite independently. | That throughput is adequate under real load. |
| End-to-end format handling from script text to JSONL. | That the sensor is stable over hours. |

The gap is not a formality. Tracepoint field names differ across kernel versions
(`args->old_pid`, `args->filename`), `str()` truncation behaviour depends on
`BPFTRACE_MAX_STRLEN`, and a probe that fails to attach may report success on some
bpftrace builds. **Run `cabid ebpf check` and then attach the program manually before
trusting it.** A first deployment should be validated against `cabid collect-proc`
running simultaneously: anything the poller sees and the sensor does not is a broken
probe.

## What it traces

| Probe | Emits | Purpose |
| --- | --- | --- |
| `sched_process_exec` | `process_exec` | Every `execve`, with the binary path |
| `sched_process_fork` | `process_start` | Every fork, with child and parent pid |
| `sched_process_exit` | `process_exit` | Every exit — this is what polling cannot see |
| `sys_enter_connect` | `network_connect` | Outbound connection attempts |
| `sys_enter_openat` | `file_write` | Path opened by `openat` |
| `sys_enter_unlinkat` | `file_write` | Path removed by `unlinkat` |

### Deliberate omissions, and why

- **`openat` does not distinguish read from write.** The flags are in `args->flags`
  but mapping the flag set to "modifies disk" correctly needs care (`O_RDWR`,
  `O_CREAT`, `O_TMPFILE`, `O_APPEND`), and getting it wrong either invents file writes
  that never happened or loses real ones. It is mapped to `file_write` with that
  caveat documented rather than guessed at silently.
- **`connect` carries no address.** `sockaddr` lives in userspace memory at that
  probe, and reading it safely needs a per-syscall map. The event records *that* a
  connection was attempted from a process, not where to. Address-level detection
  needs the auditd path.
- **No `bind`/`listen`/`accept`.** Inbound handling is a separate concern with a
  different noise profile.
- **No payload inspection.** Paths and names only.

## Output format

One tab-separated line per event, prefixed by kind, opened by a version banner:

```
cabid-bpf/1
exec	1760000000	4242	1	nginx	/usr/sbin/nginx
fork	1760000000	4243	4242	nginx
exit	1760000001	4242	0	nginx
connect	1760000002	4242	4242	curl
open	1760000003	4242	4242	bash	/etc/passwd
unlink	1760000004	4242	4242	bash	/tmp/x
```

Line-oriented text rather than a binary struct dump, deliberately: it survives
bpftrace upgrades, can be captured with `tee`, replayed offline, and tested without a
kernel.

## The parser refuses to guess

An unrecognized line becomes a `ParseError` naming the text — never an invented event
type. A parser that fabricates events for input it does not understand produces
telemetry that looks complete and is not, which is worse than a visible gap.

```
cabid-bpf/1                                    → format banner, not an event
mmap	1	2	3	bash                          → unknown probe kind
exec	1760000000	4242	1	nginx                 → exec expects 5 fields, got 4
exec	soon	4242	1	nginx	/x                    → timestamp is not a number
```

`--keep-errors` records failures in the summary and keeps going, which matters for
real captures: a killed bpftrace leaves a partial final line, and one truncated line
should not end a collection run. Without it, any parse error exits non-zero.

## Capability check

`cabid ebpf check` verifies, independently and in the order that usually fails:

1. `bpftrace` on `PATH`;
2. effective uid 0 (or the capabilities to attach tracepoints);
3. kernel BTF at `/sys/kernel/btf/vmlinux`;
4. unprivileged BPF not disabled.

Each failed prerequisite is listed, not just the first, and the command exits 1. It
**never falls back to polling silently** — the two sensors have different blind spots,
and an operator who believes eBPF is running when it is not has a false picture of
coverage.

## Bounded capture

`cabid ebpf capture` checks prerequisites, runs the sensor for a maximum of
3600 seconds, sends SIGINT when the duration expires, and writes normalized JSONL.
Use `--raw-output` to preserve the original bpftrace stream and `--report` to
save event counts and parse/normalization errors. A fake bpftrace executable tests
the complete subprocess-to-JSONL path in CI; CI does not attach to a real kernel.
Live probe compatibility, loss rate, and overhead remain unverified until tested
on the target host.

## Using it with the rest of CABID

```bash
bpftrace cabid-sensor.bt | tee sensor.log
cabid ebpf parse sensor.log --output events.jsonl
cabid analyze-stream events.jsonl --window-seconds 60 --output stream.json
```

The sensor can also feed `cabid analyze`, `cabid alert`, and `cabid fleet` directly,
since its output normalizes to ordinary CABID events.

## Limitations

- **Requires root or `CAP_BPF`+`CAP_PERFMON`.** This is a real deployment cost, not a
  detail; there is no unprivileged mode.
- **Kernel-version dependent.** Tracepoint argument names and `bpftrace` syntax change.
  Pin the bpftrace version and re-verify after kernel upgrades.
- **Not executed here.** See the verification table above. Treat the shipped program
  as a reviewed starting point, not a validated artifact.
- **`comm` is truncated to 16 bytes by the kernel.** A process name longer than that
  is already truncated before CABID sees it; the original name is unrecoverable.
- **No address for network events**, no file-read/write distinction, no payloads.
- **No ring-buffer or map aggregation.** Output is plain stdio text, so very high
  event rates on a busy host will lose events in the pipe rather than buffering them.
  For a truly high-rate host, add a `BPF_MAP`-based aggregation step — not implemented.
- **Overhead is unmeasured.** No benchmark was run, because the sensor could not be
  run.
- **Complement, not replacement.** `/proc` polling and auditd remain supported and
  cover different gaps.

## Files

| Path | Purpose |
| --- | --- |
| `cabid/ebpf.py` | bpftrace program, capability check, strict parser. |
| `cabid ebpf check\|script\|parse` | CLI. |
| `tests/test_ebpf.py` | 33 tests over the format and capability logic; none execute bpftrace. |
