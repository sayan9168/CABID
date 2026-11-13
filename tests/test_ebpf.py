"""Tests for the kernel sensor's capability check, script, and parser.

No test executes bpftrace. The parser is validated against representative output
lines, and the capability check is validated against synthetic host states. That
establishes the wire format handling, not the kernel-side behaviour -- the docs say
so explicitly.
"""
from __future__ import annotations

import pytest

from cabid.ebpf import (
    BPFTRACE_SCRIPT,
    FIELD_COUNTS,
    SENSOR_FORMAT,
    ParseError,
    SensorError,
    capabilities,
    parse_line,
    parse_stream,
    run,
    write_script,
)

EXEC = "exec\t1760000000\t4242\t1\tnginx\t/usr/sbin/nginx"
FORK = "fork\t1760000000\t4243\t4242\tnginx"
EXIT = "exit\t1760000001\t4242\t0\tnginx"
CONNECT = "connect\t1760000002\t4242\t4242\tcurl"
OPEN = "open\t1760000003\t4242\t4242\tbash\t/etc/passwd"
UNLINK = "unlink\t1760000004\t4242\t4242\tbash\t/tmp/x"


# ------------------------------------------------------------- capabilities ----

def test_capabilities_reports_this_host_cannot_run_the_sensor(monkeypatch):
    monkeypatch.setattr("cabid.ebpf.shutil.which", lambda _name: None)
    monkeypatch.setattr("cabid.ebpf.Path.exists", lambda self: False)
    report = capabilities()
    assert report["available"] is False
    assert any("not installed" in reason for reason in report["reasons"])
    assert any("uid" in reason for reason in report["reasons"])


def test_capabilities_is_positive_on_a_configured_host(monkeypatch):
    monkeypatch.setattr("cabid.ebpf.shutil.which", lambda _name: "/usr/bin/bpftrace")
    monkeypatch.setattr("cabid.ebpf._current_uid", lambda: 0)
    monkeypatch.setattr("cabid.ebpf.Path.exists", lambda self: True)
    monkeypatch.setattr("cabid.ebpf._read_first", lambda _path: "0")
    report = capabilities()
    assert report["available"] is True
    assert report["reasons"] == []
    assert report["uid"] == 0


def test_capabilities_names_every_blocker(monkeypatch):
    monkeypatch.setattr("cabid.ebpf.shutil.which", lambda _name: "/usr/bin/bpftrace")
    monkeypatch.setattr("cabid.ebpf._current_uid", lambda: 1000)
    monkeypatch.setattr("cabid.ebpf.Path.exists", lambda self: False)
    monkeypatch.setattr("cabid.ebpf._read_first", lambda _path: "0")
    report = capabilities()
    assert report["available"] is False
    # Both the privilege problem and the missing BTF are reported, not just the first.
    assert len(report["reasons"]) == 2


def test_capabilities_states_why_silence_is_wrong(monkeypatch):
    monkeypatch.setattr("cabid.ebpf.shutil.which", lambda _name: None)
    report = capabilities()
    assert "different blind spots" in report["note"]


def test_read_first_tolerates_missing_files():
    from cabid.ebpf import _read_first

    assert _read_first("/proc/definitely/not/here") is None


# ------------------------------------------------------------------- script ----

def test_script_declares_its_format_and_probes():
    assert SENSOR_FORMAT in BPFTRACE_SCRIPT
    for probe in ("sched_process_exec", "sched_process_fork", "sched_process_exit",
                  "sys_enter_connect", "sys_enter_openat", "sys_enter_unlinkat"):
        assert probe in BPFTRACE_SCRIPT


def test_script_prints_every_kind_the_parser_accepts():
    for kind in FIELD_COUNTS:
        assert f'printf("{kind}\\t' in BPFTRACE_SCRIPT


def test_script_is_balanced_because_bpftrace_will_not_start_otherwise():
    assert BPFTRACE_SCRIPT.count("{") == BPFTRACE_SCRIPT.count("}")


def test_write_script_materializes_reviewable_text(tmp_path):
    path = write_script(tmp_path / "nested" / "sensor.bt")
    text = path.read_text(encoding="utf-8")
    assert text.startswith("/* CABID kernel sensor")
    assert "tracepoint:sched:sched_process_exec" in text


# ------------------------------------------------------------------- parser ----

@pytest.mark.parametrize("line,event_type,pid,parent,target", [
    (EXEC, "process_exec", 4242, 1, "/usr/sbin/nginx"),
    (FORK, "process_start", 4243, 4242, ""),
    (EXIT, "process_exit", 4242, 0, ""),
    (CONNECT, "network_connect", 4242, 0, ""),
    (OPEN, "file_write", 4242, 0, "/etc/passwd"),
    (UNLINK, "file_write", 4242, 0, "/tmp/x"),
])
def test_parse_line_maps_each_probe(line, event_type, pid, parent, target):
    event = parse_line(line)
    assert event["event_type"] == event_type
    assert event["process_id"] == pid
    assert event["parent_process_id"] == parent
    assert event["target"] == target
    assert event["timestamp"] == 1760000000.0 or event["timestamp"] >= 1760000000.0
    assert event["source"] == "ebpf"


def test_exec_sets_the_executable_and_others_do_not():
    assert parse_line(EXEC)["executable"] == "/usr/sbin/nginx"
    assert parse_line(OPEN)["executable"] == ""


def test_parse_line_preserves_comm():
    assert parse_line(EXEC)["process_name"] == "nginx"
    assert parse_line("exec\t1\t2\t1\tsystemd-journald\t/usr/bin/x")["process_name"] == \
        "systemd-journald"


def test_parse_line_rejects_the_format_banner():
    with pytest.raises(ParseError, match="format banner"):
        parse_line(SENSOR_FORMAT)


def test_parse_line_rejects_empty_lines():
    with pytest.raises(ParseError, match="empty"):
        parse_line("   \n")


def test_parse_line_rejects_an_unknown_kind():
    with pytest.raises(ParseError, match="unknown probe kind"):
        parse_line("mmap\t1\t2\t3\tbash")


def test_parse_line_rejects_a_wrong_field_count():
    with pytest.raises(ParseError, match="expects 5 field"):
        parse_line("exec\t1760000000\t4242\t1\tnginx")


def test_parse_line_rejects_non_numeric_fields():
    with pytest.raises(ParseError, match="timestamp"):
        parse_line("exec\tsoon\t4242\t1\tnginx\t/x")
    with pytest.raises(ParseError, match="pid"):
        parse_line("exec\t1760000000\tmany\t1\tnginx\t/x")


def test_parse_line_rejects_negative_values():
    with pytest.raises(ParseError, match="non-negative"):
        parse_line("exec\t-1\t4242\t1\tnginx\t/x")
    with pytest.raises(ParseError, match="non-negative"):
        parse_line("fork\t1760000000\t-5\t1\tnginx")


def test_parse_line_rejects_pid_zero():
    with pytest.raises(ParseError, match="positive"):
        parse_line("fork\t1760000000\t0\t1\tkthreadd")


def test_parse_line_does_not_invent_a_process_name():
    assert parse_line("exit\t1760000001\t4242\t0\t")["process_name"] == "unknown"


def test_parse_line_truncates_comm_to_the_kernel_limit():
    long_comm = "a" * 40
    event = parse_line(f"exit\t1760000001\t4242\t0\t{long_comm}")
    assert len(event["process_name"]) <= 16


def test_parse_line_keeps_trailing_newline_out_of_fields():
    event = parse_line(OPEN + "\n")
    assert event["target"] == "/etc/passwd"


def test_parse_line_tolerates_paths_with_spaces():
    event = parse_line("open\t1760000003\t4242\t4242\tbash\t/tmp/a b/c d")
    assert event["target"] == "/tmp/a b/c d"


# ------------------------------------------------------------------- stream ----

def test_parse_stream_yields_events_and_raises_by_default():
    lines = [EXEC, FORK, "nonsense"]
    with pytest.raises(ParseError):
        list(parse_stream(lines))


def test_parse_stream_can_record_errors_instead_of_stopping():
    items = list(parse_stream([EXEC, "nonsense", FORK], keep_errors=True))
    assert sum(1 for item in items if "error" in item) == 1
    assert sum(1 for item in items if "event_type" in item) == 2
    failure = next(item for item in items if "error" in item)
    assert failure["line"] == "nonsense"


def test_parse_stream_accepts_a_file_like_iterator(tmp_path):
    path = tmp_path / "sensor.log"
    path.write_text("\n".join([SENSOR_FORMAT, EXEC, OPEN]) + "\n", encoding="utf-8")
    events = list(parse_stream(path.read_text(encoding="utf-8").splitlines(),
                               keep_errors=True))
    assert sum(1 for event in events if "event_type" in event) == 2


def test_parsed_events_normalize_cleanly():
    from cabid.normalize import normalize_event

    for line in (EXEC, FORK, EXIT, CONNECT, OPEN, UNLINK):
        normalized = normalize_event(parse_line(line))
        assert normalized["event_type"] in {
            "process_exec", "process_start", "process_exit", "network_connect",
            "file_write"}


# ---------------------------------------------------------------------- run ----

def test_run_refuses_when_the_sensor_cannot_run(monkeypatch):
    monkeypatch.setattr("cabid.ebpf.capabilities",
                        lambda _binary="bpftrace": {"available": False,
                                                    "reasons": ["no bpftrace"]})
    with pytest.raises(SensorError, match="cannot run here: no bpftrace"):
        run("/tmp/sensor.bt")
