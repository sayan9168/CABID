# Performance and streaming

CABID's `analyze` command loads a file, normalizes it, and scores it as one session.
That is correct for an investigation and wrong for a sensor collecting lakhs of
events per minute. `analyze-stream` is the other shape: consume an iterator, score
bounded windows, hold bounded memory.

## Measured numbers

All figures below come from `tools/perf_benchmark.py` on the development machine.
Every mode runs in a fresh subprocess, because measuring several paths in one
process reports the high-water mark of all of them. Raw output is committed:
`results/perf-100k.json`, `results/perf-1m.json`.

### 100,000 events (19 MB JSONL), median of 3 runs

| Mode | Throughput | Peak RSS |
| --- | --- | --- |
| `analyze` (one-shot) | 49,375 ev/s | 123.3 MB |
| `analyze-stream` | 58,930 ev/s | **22.9 MB** |

### 1,000,000 events (192 MB JSONL)

| Mode | Throughput | Peak RSS |
| --- | --- | --- |
| `analyze` (one-shot) | 43,747 ev/s | **1,115.3 MB** |
| `analyze-stream` | 53,228 ev/s | **22.9 MB** |

The headline is the second column, not the first: streaming memory is **flat**.
One-shot memory scales with the file (1.1 GB for a million events); streaming stays
at 22.9 MB for both 100k and 1M because it never holds more than one window plus a
bounded sample.

### Against the stated requirement

The requirement was 10⁵ events per minute, i.e. **1,667 ev/s**.

| Mode | Headroom over 10⁵/min |
| --- | --- |
| `analyze-stream` | **~32×** |
| `analyze` (one-shot, ignores latency) | ~26× |

That headroom is on synthetic uniform events with the default rule pack. Real traffic
is less uniform and the rule pack is configurable, so this is a floor. It is measured
rather than asserted, and the harness ships so it can be re-measured on the hardware
that matters.

## Where the time actually goes

Profiling 20,000 events showed the scoring engine was not the bottleneck:

| Component | Share of analysis time |
| --- | --- |
| Rule-pack glob matching (`fnmatch`) | **62%** |
| Entity rollup | 14% |
| Container scopes | 13% |
| Sequence features | 4% |

`fnmatch` translates a glob to a regular expression **on every call**, and the
matcher also lowercased both sides each time. With a few hundred patterns evaluated
against every event, that is the same work repeated hundreds of thousands of times.

Two changes, both semantics-preserving:

1. **Translate each pattern once.** `cabid/rules.py` now caches
   `fnmatch.translate(pattern)` in a module-level dict capped at 4,096 entries.
   Translation is the same function `fnmatch` uses internally, so behaviour cannot
   diverge by construction.
2. **Skip the regex when a pattern is simple.** A literal pattern or a pure
   `prefix*` form needs no regular expression, and `prefix*` becomes a
   `str.startswith` call.

Measured effect: **47,060 → 54,779 ev/s** in an early run (about 16%), with all 545
tests passing unchanged.

### The bug this exposed

The first cached implementation stripped the last character of every pattern before
storing it as a prefix, which is right for `prefix*` and wrong for a literal. A rule
matching the literal `curl` then compared a value against `cu`, so it silently
stopped matching. The equivalence test against the original implementation caught it
in two cases (`curl` and the empty pattern). Both `cabid/rules.py` and
`cabid/streaming.PatternCache` carry the same correctness test, run against
`fnmatch` itself rather than a remembered expectation.

This is the real risk in a performance change to a security tool: a 16% speedup is
worthless next to a silently disabled rule.

## What streaming gives up

Bounded windows are not free, and the report says so in-band:

| Cost | Consequence |
| --- | --- |
| Window boundaries split causal chains | A chain spanning a boundary may be missed. Windows default to 60 s; below 5 s the engine refuses, because fragments cannot be scored meaningfully. |
| Rate components are per-window | A steady rate that is high across the run does not trigger a per-window rate alarm. |
| Verdicts are per-window | A finding concerns the window, not the session. |
| Ordering across windows is not tracked | Slow multi-stage behaviour spread over many windows is not correlated. |

The trade is explicit: `analyze` for depth over a known incident, `analyze-stream`
for continuous coverage at rate. Neither replaces the other.

## Usage

```bash
# bounded-memory continuous analysis
cabid analyze-stream sensor.jsonl --window-seconds 60 --output stream.json

# with a fitted baseline and an explicit configuration
cabid analyze-stream sensor.jsonl -b baseline.json -c config.json

# re-measure on your hardware
python tools/perf_benchmark.py --events 100000 --repeat 3
```

The stream report includes throughput, per-window verdicts with reason codes,
status counts, and the retained-sample size, so a run can be audited after the fact.

## Limitations

- **Synthetic measurement.** Uniform events, one machine, no I/O contention. Real
  sensor input is bursty and the rule pack may be much larger.
- **Rule pack dominates.** Throughput falls roughly with the number of enabled
  correlation rules. Disabling the pack raises the ceiling; the numbers above are
  with the built-in pack enabled.
- **Memory is bounded by window size, not event count.** A single window holding
  millions of events still costs memory proportional to that window. `window_seconds`
  is the control.
- **No backpressure.** If the producer outpaces the consumer, `stream` blocks — it
  does not drop events. That is the safe default for security data, and it means
  sustained overload shows up as latency rather than as silent loss.
- **No persistence.** The stream report is written at the end; there is no on-disk
  window journal, so a crash mid-run loses the run's windows.
- **Python.** This is CPython single-process. Multi-core scale-out is not
  implemented; run several streams partitioned by host.

## Files

| Path | Purpose |
| --- | --- |
| `cabid/streaming.py` | Lazy reader, windowed stream scoring, `PatternCache`. |
| `cabid/rules.py` | Cached glob translation in the hot path. |
| `tools/perf_benchmark.py` | Subprocess-isolated throughput and RSS measurement. |
| `tests/test_streaming.py` | 24 tests, including fnmatch-equivalence regression. |
| `results/perf-100k.json`, `results/perf-1m.json` | Committed measurements. |
