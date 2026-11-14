# Real-host benchmark

`cabid benchmark-host` measures CABID on live telemetry collected from a real
Linux host. It closes the gap that every previously published CABID number came
from synthetic fixtures (`cabid benchmark`) or a 2013 syscall corpus
(`cabid benchmark-real`) — none from a live enterprise host.

## The gap it fills

The [limitations](limitations.md) state plainly: there is no real-host benchmark,
and precision/recall/FPR against real enterprise telemetry are unknown. This
command is the framework for producing those numbers, on your own host, with
your own labels.

## Workflow

### 1. Collect a benign baseline

Run during a quiet period when the host is doing normal work:

```bash
cabid benchmark-host collect \
    --scenario benign-baseline \
    --label benign \
    --duration 900 \
    --output sessions/baseline-01.jsonl
```

Repeat for multiple benign sessions (at least 3 recommended).

### 2. Collect labeled attack scenarios

Run the attacks you want to measure against, in a controlled environment:

```bash
cabid benchmark-host collect \
    --scenario nmap-scan \
    --label attack \
    --duration 300 \
    --output sessions/attack-nmap.jsonl
```

The `--label` is your ground-truth assertion. CABID does not verify it —
mislabeled sessions corrupt the metrics, which is why the report lists
operator labeling as a limitation.

Optionally, add a `scenario.meta.json` sidecar to override the label or
scenario name derived from the file name:

```json
{
  "label": "attack",
  "scenario": "red-team-lateral-movement"
}
```

### 3. Score and publish

```bash
cabid benchmark-host run \
    --sessions-dir sessions/ \
    --output results/host-benchmark.json \
    --format md
```

This builds a benign profile from the benign sessions, scores every session,
and writes both a JSON report and a Markdown summary.

## What the report contains

| Section | What it tells you |
| --- | --- |
| Headline result | Precision, recall, FPR, FNR with Wilson 95% intervals |
| Score separation | Threshold-free AUC of the anomaly score |
| Per-scenario results | Breakdown by scenario name |
| Component diagnostics | Mean component scores per class (not a verdict) |
| Evidence sufficiency | How often the engine refused to judge |
| Limitations | Honest caveats on what the number means |

## Honest limitations

The report's limitations section is generated automatically and includes:

- **Single host.** One machine, one kernel, one user base. Numbers do not
  generalize to other hosts or fleets.
- **Operator-labeled ground truth.** Benign/attack labels come from the person
  who ran the benchmark, not an independent red team. Mislabeled sessions
  corrupt the metrics.
- **Procfs-only telemetry** unless you also supply auditd exports.
  `privilege_change`, `kernel_state_change`, `permission_change` and
  `network_accept` are never observed by procfs, so the completeness gate
  exempts them.
- **Short observation windows.** Collection is bounded by `--duration`, so
  slow, low-and-slow activity is under-represented.
- **No root.** Without root the procfs collector sees only this user's
  processes and cannot see kernel-level activity.
- **Small samples.** Real-host samples are small, so Wilson intervals are wide
  and point estimates unstable. Do not act on a single run.
- **The score is a heuristic**, not a probability or a claim of malware
  attribution.

## Example output

```
# Real-host benchmark report

## Headline result

| Metric | Value | 95% CI |
| --- | --- | --- |
| Precision | 0.040 | 0.001 – 0.204 |
| Recall | 0.500 | 0.013 – 0.987 |
| FPR | 0.200 | 0.005 – 0.717 |
| Samples | 10 | — |

## Score separation

- Anomaly-score AUC: 0.625
```

A benchmark that only reports favourable results is not a benchmark. Publish
the unfavourable numbers too — they tell you where the detector needs work.

## Reproducing

```bash
cabid benchmark-host run --sessions-dir sessions/ \
    --output results/host-benchmark.json --format md
```
