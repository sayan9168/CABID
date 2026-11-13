import json
from pathlib import Path
from cabid.cli import main


def test_benchmark_cli_writes_json(tmp_path):
    output = tmp_path / "nested" / "benchmark.json"
    assert main(["benchmark", "--output", str(output), "--seed", "3", "--per-class", "2"]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["models"]["cabid_telemetry_aware"]["sample_count"] == 6


def test_audit_import_cli_writes_normalized_jsonl(tmp_path):
    raw = tmp_path / "audit.raw"
    output = tmp_path / "events.jsonl"
    raw.write_text('type=SYSCALL msg=audit(1700000000.123:42): arch=c000003e syscall=59 success=yes exit=0 ppid=10 pid=11 comm="python" exe="/usr/bin/python"\n', encoding="utf-8")
    assert main(["import-audit", str(raw), "--output", str(output)]) == 0
    event = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
    assert event["event_type"] == "process_exec"
    assert event["source"] == "linux-auditd"
