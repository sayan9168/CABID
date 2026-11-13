"""Measure one-shot versus streaming throughput and memory.

Each measurement runs in a fresh subprocess so peak RSS is the peak of that run
alone; measuring several paths in one process reports the high-water mark of all
of them, which overstates every number after the first.

Usage:
    python tools/perf_benchmark.py --events 100000 --repeat 3
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

KINDS = ("process_start", "process_exec", "file_write", "network_connect",
         "process_exit", "heartbeat")


def generate(path: Path, count: int) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for index in range(count):
            handle.write(json.dumps({
                "timestamp": 1760000000.0 + index * 0.01,
                "event_type": KINDS[index % len(KINDS)],
                "process_id": 100 + index % 500,
                "parent_process_id": 1,
                "process_name": f"svc-{index % 40}",
                "executable": f"/usr/bin/svc-{index % 40}",
                "target": "",
                "source": "perf",
            }) + "\n")


_CHILD = r"""
import json, resource, sys, time
mode, path = sys.argv[1], sys.argv[2]
if mode == "oneshot":
    from cabid.ingest import read_jsonl, normalize_many
    from cabid.detector import analyze
    started = time.perf_counter()
    events = normalize_many(read_jsonl(path))
    report = analyze(events)
    count = len(events)
    windows = 1
else:
    from cabid.streaming import stream_file
    started = time.perf_counter()
    report = stream_file(path, window_seconds=60.0)
    count = report["events_normalized"]
    windows = report["window_count"]
elapsed = time.perf_counter() - started
print(json.dumps({
    "mode": mode,
    "events": count,
    "seconds": round(elapsed, 3),
    "events_per_second": round(count / elapsed),
    "peak_rss_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
    "windows": windows,
}))
"""


def measure(mode: str, path: Path) -> dict:
    completed = subprocess.run([sys.executable, "-c", _CHILD, mode, str(path)],
                               capture_output=True, text=True, check=True)
    return json.loads(completed.stdout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=100000)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--output", help="write the measurements as JSON")
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "perf.jsonl"
        generate(path, args.events)
        size_mb = round(path.stat().st_size / (1024 * 1024), 1)
        results: dict[str, list[dict]] = {"oneshot": [], "stream": []}
        for _ in range(args.repeat):
            for mode in ("oneshot", "stream"):
                results[mode].append(measure(mode, path))

    def summarise(rows: list[dict]) -> dict:
        return {
            "median_events_per_second": sorted(row["events_per_second"] for row in rows)[len(rows) // 2],
            "max_peak_rss_mb": max(row["peak_rss_mb"] for row in rows),
            "runs": rows,
        }

    summary = {
        "events": args.events,
        "file_size_mb": size_mb,
        "repeat": args.repeat,
        "oneshot": summarise(results["oneshot"]),
        "stream": summarise(results["stream"]),
        "note": (
            "Synthetic uniform events on one machine. Throughput depends on rule "
            "complexity, window size, and event shape; treat these as a floor, not "
            "as a specification."
        ),
    }
    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
