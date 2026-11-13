import json

import pytest

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


def test_analyze_merges_multiple_inputs_with_provenance(tmp_path):
    output = tmp_path / "merged.json"
    assert main(["analyze", "datasets/synthetic/example.jsonl",
                 "datasets/synthetic/suspicious-example.jsonl", "-o", str(output), "-q"]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["sources"]["source_count"] == 2
    assert report["sources"]["events_total"] == 78
    assert report["event_count"] == 78


def test_analyze_time_filter_and_empty_result(tmp_path):
    output = tmp_path / "filtered.json"
    assert main(["analyze", "datasets/synthetic/example.jsonl",
                 "--since", "2025-10-09T00:00:00Z", "--until", "2025-10-09T23:59:59Z",
                 "-o", str(output), "-q"]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["time_filter"]["active"] is True
    assert report["time_filter"]["events_out"] == 6

    empty = tmp_path / "empty.json"
    assert main(["analyze", "datasets/synthetic/example.jsonl", "--since", "2100-01-01T00:00:00Z",
                 "-o", str(empty), "-q"]) == 0
    assert json.loads(empty.read_text(encoding="utf-8"))["status"] == "INSUFFICIENT_EVIDENCE"


def test_invalid_time_range_is_an_error(tmp_path, capsys):
    assert main(["analyze", "datasets/synthetic/example.jsonl", "--since", "2030-01-01",
                 "--until", "2020-01-01"]) == 2
    assert "earlier" in capsys.readouterr().err


def test_history_round_trip(tmp_path, capsys):
    db = tmp_path / "history.sqlite3"
    fixture = "datasets/synthetic/example.jsonl"
    assert main(["analyze", fixture, "--history-db", str(db), "--save-history",
                 "--label", "first", "-o", str(tmp_path / "r.json"), "-q"]) == 0
    assert main(["analyze", "datasets/synthetic/suspicious-example.jsonl",
                 "--history-db", str(db), "--save-history", "--label", "second",
                 "-o", str(tmp_path / "r2.json"), "-q"]) == 0
    capsys.readouterr()
    assert main(["history", "--db", str(db), "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [run["label"] for run in payload["runs"]] == ["second", "first"]

    assert main(["history", "--db", str(db), "--compare", "1", "2", "--format", "json"]) == 0
    comparison = json.loads(capsys.readouterr().out)["comparison"]
    assert comparison["status_changed"] is True
    assert comparison["score_delta"] > 0

    report = tmp_path / "cmp.json"
    assert main(["analyze", "datasets/synthetic/suspicious-example.jsonl",
                 "--history-db", str(db), "--compare-history", "1", "-o", str(report), "-q"]) == 0
    assert json.loads(report.read_text(encoding="utf-8"))["history_comparison"]["status_changed"] is True


def test_history_with_no_records(tmp_path, capsys):
    assert main(["history", "--db", str(tmp_path / "none.sqlite3")]) == 0
    assert "No runs recorded" in capsys.readouterr().out


def test_report_contains_entity_rollup(tmp_path):
    output = tmp_path / "rollup.md"
    assert main(["analyze", "datasets/synthetic/suspicious-example.jsonl", "-o", str(output), "-q"]) == 0
    assert "Process rollup" in output.read_text(encoding="utf-8")


def test_no_rules_and_no_tree_flags(tmp_path):
    output = tmp_path / "r.json"
    assert main(["analyze", "datasets/synthetic/tree-example.jsonl", "--no-rules", "--no-tree",
                 "-o", str(output), "-q"]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert "rules" not in report and "tree" not in report


def test_custom_rules_file_is_used(tmp_path):
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"rules": [{
        "id": "nginx-curl", "title": "nginx spawned curl", "severity": "critical",
        "steps": [{"event_type": "process_start", "process_name": "nginx"},
                  {"event_type": "process_start", "process_name": "curl", "within": 30}]}]}),
        encoding="utf-8")
    output = tmp_path / "r.json"
    assert main(["analyze", "datasets/synthetic/tree-example.jsonl", "-r", str(rules),
                 "-o", str(output), "-q"]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert [f["rule_id"] for f in report["rules"]["findings"]] == ["nginx-curl"]


def test_invalid_rules_file_is_an_error(tmp_path, capsys):
    rules = tmp_path / "bad.json"
    rules.write_text('{"rules":[{"id":"X"}]}', encoding="utf-8")
    assert main(["analyze", "datasets/synthetic/example.jsonl", "-r", str(rules)]) == 2
    assert "id must match" in capsys.readouterr().err


def test_timeline_all_formats(tmp_path, capsys):
    for fmt in ("md", "json", "txt"):
        output = tmp_path / f"tl.{fmt}"
        assert main(["timeline", "datasets/synthetic/tree-example.jsonl", "-f", fmt,
                     "--limit", "5", "-o", str(output)]) == 0
        assert output.read_text(encoding="utf-8").strip()
    payload = json.loads((tmp_path / "tl.json").read_text(encoding="utf-8"))
    assert payload["row_count"] == 5 and payload["truncated"] is True
    assert any(row["annotations"] for row in payload["rows"])


def test_seal_and_verify_cli(tmp_path, capsys, monkeypatch):
    output = tmp_path / "sealed.json"
    assert main(["analyze", "datasets/synthetic/example.jsonl", "--sign", "-o", str(output), "-q"]) == 0
    assert "seal" in json.loads(output.read_text(encoding="utf-8"))

    assert main(["seal", str(output), "--verify"]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True

    tampered = json.loads(output.read_text(encoding="utf-8"))
    tampered["anomaly_score"] = 0.99
    (tmp_path / "t.json").write_text(json.dumps(tampered), encoding="utf-8")
    assert main(["seal", str(tmp_path / "t.json"), "--verify"]) == 1
    assert json.loads(capsys.readouterr().out)["verified"] is False

    monkeypatch.setenv("CABID_TEST_KEY", "k")
    assert main(["seal", str(output), "--key-env", "CABID_TEST_KEY", "-q"]) == 0
    assert main(["seal", str(output), "--verify", "--key-env", "CABID_TEST_KEY"]) == 0
    assert json.loads(capsys.readouterr().out)["verified"] is True


def test_missing_key_env_is_an_error(tmp_path, capsys):
    output = tmp_path / "r.json"
    assert main(["analyze", "datasets/synthetic/example.jsonl", "--sign",
                 "--seal-key-env", "CABID_NO_SUCH_VAR", "-o", str(output)]) == 2
    assert "not set" in capsys.readouterr().err


# --- command coverage: every subcommand must be reachable from the CLI ---------

def test_import_sigma_and_export_stix_cli(tmp_path, capsys):
    pack = tmp_path / "pack.json"
    assert main(["import-sigma", "docs/cabid-sigma.example.yml", "-o", str(pack)]) == 0
    provenance = json.loads(capsys.readouterr().out)
    assert provenance["unsupported"] == []

    assert main(["import-sigma", "docs/cabid-sigma.example.yml",
                 "-o", str(tmp_path / "q.json"), "--quiet"]) == 0

    report = tmp_path / "report.json"
    assert main(["analyze", "datasets/synthetic/tree-example.jsonl",
                 "-r", str(pack), "-o", str(report), "--quiet"]) == 0
    assert json.loads(report.read_text())["rules"]["rule_count"] == 1

    bundle = tmp_path / "bundle.json"
    assert main(["export-stix", str(report), "-o", str(bundle), "--host", "web-01"]) == 0
    assert json.loads(bundle.read_text())["spec_version"] == "2.1"
    assert main(["export-stix", str(report), "-o", str(tmp_path / "q2.json"),
                 "--quiet"]) == 0


def test_baseline_drift_cli(tmp_path, capsys):
    profile = tmp_path / "profile.json"
    assert main(["build-baseline", "datasets/synthetic/example.jsonl",
                 "datasets/synthetic/example.jsonl", "-o", str(profile),
                 "--min-sessions", "2", "--quiet"]) == 0
    assert main(["baseline-drift", str(profile), "datasets/synthetic/example.jsonl",
                 "--min-support", "1"]) == 0
    assert json.loads(capsys.readouterr().out)["applied"] is False

    destination = tmp_path / "drift.json"
    assert main(["baseline-drift", str(profile), "datasets/synthetic/example.jsonl",
                 "--min-support", "1", "-o", str(destination)]) == 0
    assert "profile unchanged" in capsys.readouterr().out
    assert destination.exists()
    assert main(["baseline-drift", str(profile), "datasets/synthetic/example.jsonl",
                 "--min-support", "1", "-o", str(destination), "--quiet"]) == 0


def test_drift_rejects_an_empty_input_file(tmp_path, capsys):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    profile = tmp_path / "profile.json"
    assert main(["build-baseline", "datasets/synthetic/example.jsonl",
                 "datasets/synthetic/example.jsonl", "-o", str(profile),
                 "--min-sessions", "2", "--quiet"]) == 0
    assert main(["baseline-drift", str(profile), str(empty)]) == 2
    assert "no events found" in capsys.readouterr().err


def test_explain_score_markdown_path(tmp_path, capsys):
    report = tmp_path / "report.md"
    assert main(["analyze", "datasets/synthetic/tree-example.jsonl", "--explain-score",
                 "-f", "md", "-o", str(report), "--quiet"]) == 0
    assert "Score arithmetic" in capsys.readouterr().err


def test_timeline_markdown_and_text(tmp_path):
    for fmt in ("md", "txt"):
        destination = tmp_path / f"tl.{fmt}"
        assert main(["timeline", "datasets/synthetic/tree-example.jsonl",
                     "-f", fmt, "-o", str(destination)]) == 0
        assert destination.stat().st_size > 0


def test_seal_command_signs_and_verifies(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CABID_TEST_KEY", "k" * 40)
    report = tmp_path / "plain.json"
    assert main(["analyze", "datasets/synthetic/example.jsonl",
                 "-o", str(report), "--quiet"]) == 0
    signed = tmp_path / "signed.json"
    assert main(["seal", str(report), "-o", str(signed),
                 "--key-env", "CABID_TEST_KEY"]) == 0
    seal = json.loads(capsys.readouterr().out)
    assert seal["format"] == "cabid-seal/1"
    assert seal["hmac_sha256"]
    # The seal must never be described as a digital signature.
    assert "non-repudiable signature" in seal["note"]
    assert main(["seal", str(signed), "--verify", "--key-env", "CABID_TEST_KEY",
                 "--quiet"]) == 0


def test_doctor_markdown_and_bad_input(tmp_path, capsys):
    assert main(["doctor"]) == 0
    assert "CABID" in capsys.readouterr().out
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"not":"an event"}\n', encoding="utf-8")
    assert main(["doctor", "--input", str(bad)]) != 0


def test_watch_on_a_growing_file(tmp_path):
    stream = tmp_path / "live.jsonl"
    stream.write_text("", encoding="utf-8")
    with open(stream, "a", encoding="utf-8") as handle:
        handle.write('{"timestamp":1,"event_type":"heartbeat","process_id":1,'
                     '"parent_process_id":0,"process_name":"a"}\n')
    assert main(["watch", str(stream), "--iterations", "1", "--interval", "0"]) == 0


def test_init_config_refuses_to_overwrite_without_force(tmp_path, capsys):
    destination = tmp_path / "config.json"
    assert main(["init-config", "-o", str(destination)]) == 0
    assert main(["init-config", "-o", str(destination)]) == 2
    assert "already exists" in capsys.readouterr().err
    assert main(["init-config", "-o", str(destination), "--force"]) == 0


def test_unknown_command_is_an_error(capsys):
    with pytest.raises(SystemExit):
        main(["definitely-not-a-command"])


def test_no_command_prints_help(capsys):
    assert main([]) == 0
    assert "usage: cabid" in capsys.readouterr().out


def test_module_entry_point_exists():
    """`python -m cabid` must work, including from the installed package."""
    import subprocess
    import sys

    result = subprocess.run([sys.executable, "-m", "cabid", "--version"],
                            capture_output=True, text=True)
    assert result.returncode == 0
    assert "CABID" in result.stdout


def test_main_module_entry_point():
    """`python -m cabid` must work without the console script on PATH."""
    import runpy

    import pytest

    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("cabid", run_name="__main__", alter_sys=True)
    assert exit_info.value.code in (0, 2)


# --- respond: planning and the apply gate ------------------------------------

def _chain_report(tmp_path, *rule_ids, sufficient=True):
    """Write a small report file with the given rule findings on pid 401."""
    from cabid.response import build_plan

    report = {
        "status": "SUSPICIOUS",
        "anomaly_score": 0.7,
        "score_semantics": "heuristic score; not a calibrated probability",
        "completeness": {"completeness": 1.0 if sufficient else 0.5,
                         "telemetry_sufficient": sufficient,
                         "missing_event_types": [] if sufficient else ["process_exit"]},
        "rules": {"findings": [
            {"rule_id": rule_id, "severity": "high", "process_ids": [401],
             "title": rule_id, "description": "", "start_timestamp": 1.0}
            for rule_id in rule_ids]},
        "tree": {"findings": [], "common_edges": []},
        "entities": {"top_entities": []},
        "policy": {"findings": []},
    }
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path, build_plan(report)


def test_respond_plans_from_a_report_file(tmp_path, capsys):
    path, plan = _chain_report(tmp_path, "shell-from-service", "download-then-exec")
    assert main(["respond", str(path)]) == 0
    out = capsys.readouterr().out
    assert "CABID response plan" in out
    assert "suspend_process" in out
    assert "Nothing has been executed" in out


def test_respond_json_output_is_a_plan(tmp_path, capsys):
    path, _ = _chain_report(tmp_path, "shell-from-service", "download-then-exec")
    assert main(["respond", str(path), "-f", "json"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert plan["format"] == "cabid-response/1"
    assert plan["plan_digest"]


def test_respond_writes_the_plan_next_to_the_report(tmp_path, capsys):
    path, _ = _chain_report(tmp_path, "shell-from-service", "download-then-exec")
    destination = tmp_path / "plan.json"
    assert main(["respond", str(path), "-o", str(destination)]) == 0
    assert "plan written" in capsys.readouterr().out
    assert json.loads(destination.read_text())["plan_digest"]


def test_respond_rejects_unknown_actions(tmp_path, capsys):
    path, _ = _chain_report(tmp_path, "shell-from-service")
    assert main(["respond", str(path), "--allow", "monitor,rm_rf"]) == 2
    assert "unknown actions" in capsys.readouterr().err


def test_respond_allow_list_narrows_the_plan(tmp_path, capsys):
    path, _ = _chain_report(tmp_path, "shell-from-service", "download-then-exec")
    assert main(["respond", str(path), "--allow", "monitor", "-f", "json"]) == 0
    plan = json.loads(capsys.readouterr().out)
    assert all(d["recommended_action"] == "monitor" for d in plan["decisions"])


def test_apply_without_a_plan_file_is_refused(tmp_path, capsys):
    path, _ = _chain_report(tmp_path, "shell-from-service", "download-then-exec")
    assert main(["respond", str(path), "--apply"]) == 2
    assert "does not exist" in capsys.readouterr().err


def test_apply_without_confirm_is_refused(tmp_path, capsys):
    path, plan = _chain_report(tmp_path, "shell-from-service", "download-then-exec")
    (tmp_path / "report.response.json").write_text(json.dumps(plan), encoding="utf-8")
    assert main(["respond", str(path), "--apply"]) == 2
    assert "refusing to apply without --confirm" in capsys.readouterr().err


def test_apply_with_a_wrong_digest_is_refused(tmp_path, capsys):
    path, plan = _chain_report(tmp_path, "shell-from-service", "download-then-exec")
    (tmp_path / "report.response.json").write_text(json.dumps(plan), encoding="utf-8")
    assert main(["respond", str(path), "--apply", "--confirm", "0" * 64]) == 2
    assert "does not match this plan" in capsys.readouterr().err


def test_dry_run_needs_no_confirmation_and_touches_nothing(tmp_path, capsys):
    path, plan = _chain_report(tmp_path, "shell-from-service", "download-then-exec")
    (tmp_path / "report.response.json").write_text(json.dumps(plan), encoding="utf-8")
    assert main(["respond", str(path), "--apply", "--dry-run"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["executed"] is False
    assert not (tmp_path / "report.response-audit.jsonl").exists()


def test_apply_writes_an_audit_trail(tmp_path, capsys):
    path, plan = _chain_report(tmp_path, "shell-from-service", "download-then-exec",
                               sufficient=False)
    (tmp_path / "report.response.json").write_text(json.dumps(plan), encoding="utf-8")
    audit = tmp_path / "audit.jsonl"
    assert main(["respond", str(path), "--apply", "--confirm", plan["plan_digest"],
                 "--audit", str(audit), "-q"]) == 0
    assert audit.exists()
    entries = [json.loads(line) for line in audit.read_text().splitlines()]
    assert entries[0]["event"] == "plan_start"
    assert entries[-1]["event"] == "plan_end"


def test_corpus_list_cli_prints_pinned_digests(capsys):
    assert main(["corpus", "list"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["corpora"][0]["name"] == "adfa-ld"


def test_corpus_cli_requires_a_name_for_fetch(capsys):
    assert main(["corpus", "fetch"]) == 2
    assert "corpus name" in capsys.readouterr().err


def test_corpus_cli_reports_missing_cache_without_network(tmp_path, capsys):
    assert main(["corpus", "fetch", "adfa-ld", "--cache", str(tmp_path), "--offline"]) == 1
    assert "offline" in capsys.readouterr().err


def test_benchmark_real_cli_errors_when_corpus_absent(tmp_path, capsys):
    assert main(["benchmark-real", "--corpus-cache", str(tmp_path)]) == 1
    err = capsys.readouterr().err
    assert "cabid corpus fetch adfa-ld" in err


def test_benchmark_real_cli_runs_on_extracted_corpus(tmp_path, capsys):
    from tests.test_realworld import _write_tree

    root = _write_tree(tmp_path / "corpus")
    output = tmp_path / "out" / "real.json"
    assert main(["benchmark-real", "--corpus-root", str(root), "--output", str(output),
                 "--format", "md"]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["format"] == "cabid-realworld-benchmark/1"
    assert output.with_suffix(".md").exists()
    assert "not evidence of real-world" in output.with_suffix(".md").read_text(encoding="utf-8")


def _benign_jsonl(directory, count=25):
    """Write one JSONL file per session: a session is a file, as elsewhere in CABID."""
    from tests.test_calibrate import _benign

    directory.mkdir(parents=True, exist_ok=True)
    paths = []
    for name, events in _benign(count):
        path = directory / f"{name}.jsonl"
        path.write_text("\n".join(json.dumps(event) for event in events) + "\n",
                        encoding="utf-8")
        paths.append(str(path))
    return paths


def test_calibrate_cli_writes_calibration(tmp_path, capsys):
    sources = _benign_jsonl(tmp_path / "sessions")
    output = tmp_path / "out" / "calibration.json"
    assert main(["calibrate", *sources, "--output", str(output)]) == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["format"] == "cabid-calibration/1"
    assert json.loads(capsys.readouterr().out)["thresholds"] == payload["thresholds"]


def test_calibrate_cli_can_emit_an_applied_config(tmp_path):
    sources = _benign_jsonl(tmp_path / "sessions")
    output = tmp_path / "calibration.json"
    applied = tmp_path / "config.json"
    assert main(["calibrate", *sources, "--output", str(output),
                 "--apply-to", str(applied)]) == 0
    written = json.loads(applied.read_text(encoding="utf-8"))
    calibration = json.loads(output.read_text(encoding="utf-8"))
    assert written["thresholds"] == calibration["thresholds"]
    assert written["format"] == "cabid-config/1"


def test_calibrate_cli_refuses_to_few_sessions(tmp_path, capsys):
    sources = _benign_jsonl(tmp_path / "sessions", count=3)
    assert main(["calibrate", *sources, "--output", str(tmp_path / "c.json")]) == 1
    assert "required" in capsys.readouterr().err


def test_calibrate_cli_compare_mode(tmp_path, capsys):
    calibration = tmp_path / "calibration.json"
    sources = _benign_jsonl(tmp_path / "sessions")
    assert main(["calibrate", *sources, "--output", str(calibration)]) == 0
    capsys.readouterr()
    assert main(["calibrate", "--compare", str(calibration), sources[0]]) == 0
    rows = json.loads(capsys.readouterr().out)["comparison"]
    assert {row["threshold"] for row in rows} == {
        "suspicious", "high", "rate_per_minute", "burstiness"}


def test_calibrate_cli_rejects_missing_input(tmp_path, capsys):
    assert main(["calibrate", str(tmp_path / "absent.jsonl")]) == 2
    assert "No such file" in capsys.readouterr().err


def test_validate_baseline_cli_reports_a_verdict(tmp_path, capsys):
    from cabid.baseline import build_profile, write_profile
    from tests.test_novelty import _sessions

    profile = build_profile(_sessions(40, prefix="fit"), minimum_sessions=3)
    profile_path = write_profile(profile, tmp_path / "profile.json")
    sources = []
    for name, events in _sessions(30, prefix="held"):
        path = tmp_path / f"{name}.jsonl"
        path.write_text("\n".join(json.dumps(event) for event in events) + "\n",
                        encoding="utf-8")
        sources.append(str(path))
    output = tmp_path / "validation.json"
    assert main(["validate-baseline", str(profile_path), *sources,
                 "--output", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["verdict"] in {"SOUND", "NEEDS_REFIT"}
    assert json.loads(capsys.readouterr().out)["verdict"] == report["verdict"]


def test_validate_baseline_cli_errors_on_too_few_sessions(tmp_path, capsys):
    from cabid.baseline import build_profile, write_profile
    from tests.test_novelty import _sessions

    profile = build_profile(_sessions(40, prefix="fit"), minimum_sessions=3)
    profile_path = write_profile(profile, tmp_path / "profile.json")
    name, events = _sessions(1, prefix="held")[0]
    source = tmp_path / "one.jsonl"
    source.write_text("\n".join(json.dumps(event) for event in events) + "\n",
                      encoding="utf-8")
    assert main(["validate-baseline", str(profile_path), str(source)]) == 1
    assert "required" in capsys.readouterr().err


def test_drift_report_cli_detects_a_rate_change(tmp_path, capsys):
    from cabid.baseline import build_profile, write_profile
    from tests.test_novelty import _sessions

    profile = build_profile(_sessions(40, prefix="fit", duration=600.0),
                            minimum_sessions=3)
    profile_path = write_profile(profile, tmp_path / "profile.json")
    sources = []
    for name, events in _sessions(30, prefix="fast", duration=60.0):
        path = tmp_path / f"{name}.jsonl"
        path.write_text("\n".join(json.dumps(event) for event in events) + "\n",
                        encoding="utf-8")
        sources.append(str(path))
    output = tmp_path / "drift.json"
    assert main(["drift-report", str(profile_path), *sources, "--output", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["drifted"] is True
    assert "not about intent" in report["drift_is_not_an_attack_signal"]


def test_analyze_stream_cli_reports_throughput(tmp_path, capsys):
    from tests.test_streaming import _events

    source = tmp_path / "stream.jsonl"
    source.write_text("\n".join(json.dumps(event) for event in _events(120)) + "\n",
                      encoding="utf-8")
    output = tmp_path / "out" / "stream.json"
    assert main(["analyze-stream", str(source), "--window-seconds", "60",
                 "--output", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["format"] == "cabid-stream-report/1"
    assert report["events_normalized"] == 120
    assert json.loads(capsys.readouterr().out)["window_count"] == report["window_count"]


def test_analyze_stream_cli_rejects_a_tiny_window(tmp_path, capsys):
    source = tmp_path / "stream.jsonl"
    source.write_text(json.dumps({"timestamp": 1.0, "event_type": "file_write",
                                  "process_id": 1}) + "\n", encoding="utf-8")
    assert main(["analyze-stream", str(source), "--window-seconds", "1"]) == 1
    assert "at least" in capsys.readouterr().err


def test_fleet_cli_collects_and_marks_silence(tmp_path, capsys):
    first = tmp_path / "a.json"
    first.write_text(json.dumps({"status": "HIGH_RISK", "anomaly_score": 0.9,
                                 "event_count": 10,
                                 "completeness": {"completeness": 1.0},
                                 "reasons": [{"code": "temporal_rate_or_burst"}]}),
                     encoding="utf-8")
    expected = tmp_path / "expected.txt"
    expected.write_text("web-01\nweb-02\n", encoding="utf-8")
    output = tmp_path / "fleet.json"
    assert main(["fleet", f"web-01={first}", "--expected", str(expected),
                 "--output", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["silent_hosts"] == ["web-02"]
    assert report["degraded"] is True
    capsys.readouterr()


def test_fleet_cli_renders_markdown(tmp_path, capsys):
    source = tmp_path / "a.json"
    source.write_text(json.dumps({"status": "NO_ANOMALY_DETECTED", "anomaly_score": 0.01,
                                  "event_count": 5,
                                  "completeness": {"completeness": 1.0},
                                  "reasons": []}), encoding="utf-8")
    assert main(["fleet", f"web-01={source}", "--format", "md"]) == 0
    assert "# CABID fleet report" in capsys.readouterr().out


def test_fleet_cli_rejects_a_malformed_pair(tmp_path, capsys):
    assert main(["fleet", "no-equals-sign"]) == 1
    assert "HOST=REPORT.json" in capsys.readouterr().err


def test_fleet_cli_compare_requires_both_snapshots(tmp_path, capsys):
    source = tmp_path / "a.json"
    source.write_text(json.dumps({"status": "NO_ANOMALY_DETECTED", "anomaly_score": 0.0,
                                  "event_count": 1, "completeness": {"completeness": 1.0},
                                  "reasons": []}), encoding="utf-8")
    assert main(["fleet", "--compare", "--baseline", f"web-01={source}"]) == 1
    assert "--baseline and --current" in capsys.readouterr().err


def test_fleet_cli_compare_reports_a_regression(tmp_path, capsys):
    before = tmp_path / "before.json"
    before.write_text(json.dumps({"status": "NO_ANOMALY_DETECTED", "anomaly_score": 0.1,
                                  "event_count": 1,
                                  "completeness": {"completeness": 1.0}, "reasons": []}),
                      encoding="utf-8")
    after = tmp_path / "after.json"
    after.write_text(json.dumps({"status": "HIGH_RISK", "anomaly_score": 0.9,
                                 "event_count": 1,
                                 "completeness": {"completeness": 1.0}, "reasons": []}),
                     encoding="utf-8")
    assert main(["fleet", "--compare", "--baseline", f"web-01={before}",
                 "--current", f"web-01={after}"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["worsened"][0]["host"] == "web-01"


def test_alert_cli_defaults_to_a_dry_run(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("CABID_SLACK_WEBHOOK", raising=False)
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"status": "HIGH_RISK", "anomaly_score": 0.9,
                                  "event_count": 100,
                                  "reasons": [{"code": "temporal_rate_or_burst",
                                               "detail": "rate exceeded"}]}),
                      encoding="utf-8")
    assert main(["alert", str(report), "--channel", "slack", "--host", "web-01"]) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["dry_run"] is True
    assert receipt["sent"] == 1
    assert "HIGH_RISK" in receipt["preview"][0]["text"]


def test_alert_cli_rejects_an_unknown_report_file(tmp_path, capsys):
    assert main(["alert", str(tmp_path / "absent.json"), "--channel", "slack"]) == 1
    assert "error" in capsys.readouterr().err


def test_alert_cli_rejects_a_non_object_report(tmp_path, capsys):
    report = tmp_path / "r.json"
    report.write_text("[]", encoding="utf-8")
    assert main(["alert", str(report), "--channel", "slack"]) == 1
    assert "JSON object" in capsys.readouterr().err


def test_alert_cli_state_file_persists_suppression(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("CABID_SLACK_WEBHOOK", raising=False)
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"status": "HIGH_RISK", "anomaly_score": 0.9,
                                  "event_count": 100,
                                  "reasons": [{"code": "temporal_rate_or_burst"}]}),
                      encoding="utf-8")
    state = tmp_path / "state.json"
    args = ["alert", str(report), "--channel", "slack", "--host", "h", "--state", str(state)]
    # With no destination, delivery fails but the receipt records it and the command
    # itself succeeds; a failed channel is an operational fact, not a CLI error.
    assert main([*args, "--send"]) == 0
    failed = json.loads(capsys.readouterr().out)
    assert failed["sent"] == 0
    assert failed["errors"]
    assert not state.exists() or json.loads(state.read_text(encoding="utf-8"))["total_sent"] == 0
    assert main(args) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["dry_run"] is True
    assert receipt["preview"]


def test_alert_cli_persists_state_and_suppresses_on_the_next_run(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("CABID_WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setattr("cabid.alerting.UrllibTransport.post_json",
                        lambda self, url, payload, timeout: 200)
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"status": "HIGH_RISK", "anomaly_score": 0.9,
                                  "event_count": 100,
                                  "reasons": [{"code": "temporal_rate_or_burst"}]}),
                      encoding="utf-8")
    state = tmp_path / "state.json"
    args = ["alert", str(report), "--channel", "webhook", "--host", "h",
            "--state", str(state), "--send"]
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["sent"] == 1
    assert main(args) == 0
    assert json.loads(capsys.readouterr().out)["suppressed"]["duplicate_within_window"] == 1


def test_alert_cli_sends_with_a_fake_env_destination(tmp_path, capsys, monkeypatch):
    sent = {}

    def fake_post(self, url, payload, timeout):
        sent["url"] = url
        sent["payload"] = payload
        return 200

    monkeypatch.setenv("CABID_WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setattr("cabid.alerting.UrllibTransport.post_json", fake_post)
    report = tmp_path / "r.json"
    report.write_text(json.dumps({"status": "SUSPICIOUS", "anomaly_score": 0.6,
                                  "event_count": 10,
                                  "reasons": [{"code": "telemetry_gap"}]}),
                      encoding="utf-8")
    output = tmp_path / "receipt.json"
    assert main(["alert", str(report), "--channel", "webhook", "--host", "h",
                 "--send", "--output", str(output)]) == 0
    receipt = json.loads(output.read_text(encoding="utf-8"))
    assert receipt["sent"] == 1
    assert sent["payload"]["reason_codes"] == ["telemetry_gap"]
    assert "https://example.com/hook" not in output.read_text(encoding="utf-8")
