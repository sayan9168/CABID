import json

from cabid.cli import main


def test_benchmark_cli_writes_json(tmp_path):
    output = tmp_path / "nested" / "benchmark.json"
    assert main(["benchmark", "--output", str(output), "--seed", "3", "--per-class", "2"]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["models"]["cabid_with_baseline"]["sample_count"] == 6


def test_audit_import_cli_writes_normalized_jsonl(tmp_path):
    raw = tmp_path / "audit.raw"
    output = tmp_path / "events.jsonl"
    raw.write_text('type=SYSCALL msg=audit(1700000000.123:42): arch=c000003e syscall=59 success=yes exit=0 ppid=10 pid=11 comm="python" exe="/usr/bin/python"\n', encoding="utf-8")
    assert main(["import-audit", str(raw), "--output", str(output)]) == 0
    event = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
    assert event["event_type"] == "process_exec"
    assert event["source"] == "linux-auditd"


def test_analyze_writes_markdown_report(tmp_path):
    output = tmp_path / "report.md"
    assert main(["analyze", "datasets/synthetic/example.jsonl", "-o", str(output)]) == 0
    assert "CABID analysis report" in output.read_text(encoding="utf-8")


def test_exit_code_and_fail_on_threshold(tmp_path):
    fixture = "datasets/synthetic/example.jsonl"
    out = tmp_path / "r.json"
    assert main(["analyze", fixture, "-o", str(out), "--fail-on", "HIGH_RISK", "-q"]) == 0
    assert main(["analyze", fixture, "-o", str(out), "--exit-code", "-q"]) == 0
    stream = tmp_path / "suspicious.jsonl"
    kinds = ["process_start", "process_exec", "file_write", "network_connect", "process_exit", "heartbeat"]
    times = [100 + i * 0.5 for i in range(40)] + [125 + i * 0.001 for i in range(40)]
    rows = [{"timestamp": time, "event_type": kinds[index % 6], "process_id": 7,
             "parent_process_id": 7} for index, time in enumerate(times)]
    stream.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    assert main(["analyze", str(stream), "-o", str(out), "--fail-on", "SUSPICIOUS", "-q"]) == 1


def test_init_config_and_build_baseline(tmp_path):
    config = tmp_path / "cfg.json"
    assert main(["init-config", "-o", str(config)]) == 0
    assert json.loads(config.read_text(encoding="utf-8"))["format"] == "cabid-config/1"
    assert main(["init-config", "-o", str(config)]) == 2  # refuses to overwrite
    assert main(["init-config", "-o", str(config), "--force"]) == 0
    profile = tmp_path / "profile.json"
    fixture = "datasets/synthetic/example.jsonl"
    assert main(["build-baseline", fixture, fixture, fixture, "-o", str(profile), "-q"]) == 0
    assert json.loads(profile.read_text(encoding="utf-8"))["session_count"] == 3
    assert main(["analyze", fixture, "-c", str(config), "-b", str(profile),
                 "-o", str(tmp_path / "r.json"), "-q"]) == 0


def test_doctor_reports_json(tmp_path, capsys):
    assert main(["doctor", "-f", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ready"] is True
    assert any(check["check"] == "procfs readable" for check in payload["checks"])


def test_analyze_failure_is_reported_on_stderr(tmp_path, capsys):
    bad = tmp_path / "bad.jsonl"
    bad.write_text("{oops\n", encoding="utf-8")
    assert main(["analyze", str(bad)]) == 2
    assert "cabid: error" in capsys.readouterr().err


def test_config_error_is_reported(tmp_path, capsys):
    bad = tmp_path / "cfg.json"
    bad.write_text(json.dumps({"unknown": 1}), encoding="utf-8")
    assert main(["analyze", "datasets/synthetic/example.jsonl", "-c", str(bad)]) == 2
    assert "unknown configuration key" in capsys.readouterr().err


def test_watch_cli_bounded_iterations(tmp_path, capsys):
    stream = tmp_path / "stream.jsonl"
    stream.write_text(json.dumps({"timestamp": 1, "event_type": "heartbeat", "process_id": 1}) + "\n",
                      encoding="utf-8")
    assert main(["watch", str(stream), "--iterations", "1", "--interval", "0", "--json"]) == 0
    assert json.loads(capsys.readouterr().out.splitlines()[0])["status"] == "INSUFFICIENT_EVIDENCE"
