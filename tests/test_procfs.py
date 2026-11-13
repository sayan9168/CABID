from cabid.procfs import parse_proc_stat
from cabid.collector import ProcfsCollector


def test_parse_proc_stat_handles_spaces_and_parentheses_in_comm():
    # Tail starts at field 3: state, ppid, pgrp ... starttime is tail index 19.
    tail = ["S", "12"] + ["0"] * 17 + ["9876"]
    text = "42 (name with ) parens) " + " ".join(tail)
    assert parse_proc_stat(text) == (12, 9876)


def test_parse_proc_stat_rejects_short_input():
    try:
        parse_proc_stat("1 (x) S 0")
    except ValueError:
        pass
    else:
        raise AssertionError("expected malformed stat to fail")


def test_collector_emits_baseline_and_heartbeat(tmp_path):
    proc = tmp_path / "proc"
    proc.mkdir()
    # proc stat with ppid 1 and starttime 500
    tail = ["S", "1"] + ["0"] * 17 + ["500"]
    p = proc / "123"
    p.mkdir()
    (p / "stat").write_text("123 (demo) " + " ".join(tail), encoding="utf-8")
    (p / "cmdline").write_bytes(b"/usr/bin/demo\0--test\0")
    collector = ProcfsCollector(proc)
    first = collector.poll(100.0)
    assert [e["event_type"] for e in first].count("process_start") == 1
    assert [e["event_type"] for e in first].count("process_exec") == 1
    assert first[-1]["event_type"] == "heartbeat"
    second = collector.poll(101.0)
    assert [e for e in second if e["process_id"] == 123] == []
