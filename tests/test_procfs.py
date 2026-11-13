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


def _fake_proc(tmp_path, processes):
    """Build a fake /proc tree: processes maps pid -> (comm, ppid, start_ticks)."""
    root = tmp_path / "proc"
    root.mkdir()
    for pid, (comm, ppid, start) in processes.items():
        entry = root / str(pid)
        entry.mkdir()
        # Field layout after the comm field: state ppid ... starttime (field 22).
        tail = ["S", str(ppid)] + ["0"] * 17 + [str(start)] + ["0"] * 5
        (entry / "stat").write_text(f"{pid} ({comm}) " + " ".join(tail) + "\n",
                                    encoding="utf-8")
        (entry / "cmdline").write_bytes(b"\0".join(part.encode() for part in comm.split())
                                        + b"\0")
    return root


def test_iter_processes_reads_a_proc_tree(tmp_path):
    from cabid.procfs import iter_processes

    root = _fake_proc(tmp_path, {1: ("systemd", 0, 10), 42: ("nginx worker", 1, 99)})
    found = {item["pid"]: item for item in iter_processes(root)}
    assert set(found) == {1, 42}
    assert found[1]["name"] == "systemd"
    assert found[1]["ppid"] == 0
    # Parentheses and spaces inside comm must survive parsing.
    assert found[42]["name"] == "nginx worker"
    assert found[42]["start_ticks"] == 99


def test_iter_processes_skips_non_numeric_entries(tmp_path):
    from cabid.procfs import iter_processes

    root = _fake_proc(tmp_path, {7: ("init", 0, 5)})
    (root / "cpuinfo").write_text("not a process\n", encoding="utf-8")
    (root / "self").mkdir()
    assert [item["pid"] for item in iter_processes(root)] == [7]


def test_iter_processes_skips_a_process_that_vanished(tmp_path):
    from cabid.procfs import iter_processes

    root = _fake_proc(tmp_path, {7: ("init", 0, 5), 8: ("gone", 1, 6)})
    # A directory with no readable stat: the process exited between readdir and read.
    (root / "8" / "stat").unlink()
    assert [item["pid"] for item in iter_processes(root)] == [7]


def test_iter_processes_skips_malformed_stat(tmp_path):
    from cabid.procfs import iter_processes

    root = _fake_proc(tmp_path, {7: ("init", 0, 5)})
    (root / "7" / "stat").write_text("7 (short)\n", encoding="utf-8")
    assert list(iter_processes(root)) == []


def test_unreadable_proc_root_is_reported(tmp_path):
    import pytest

    from cabid.procfs import iter_processes

    with pytest.raises(OSError, match="cannot read procfs"):
        list(iter_processes(tmp_path / "does-not-exist"))


def test_missing_exe_and_cmdline_degrade_to_empty(tmp_path):
    from cabid.procfs import iter_processes

    root = _fake_proc(tmp_path, {7: ("init", 0, 5)})
    (root / "7" / "cmdline").unlink()
    event = next(iter(iter_processes(root)))
    assert event["cmdline"] == ""
    assert event["executable"] == ""


def test_parse_proc_stat_rejects_negative_values():
    import pytest

    from cabid.procfs import parse_proc_stat

    with pytest.raises(ValueError, match="negative"):
        parse_proc_stat("1 (init) S -5 " + " ".join(["0"] * 18) + "\n")
