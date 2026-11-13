from cabid.audit import parse_audit_raw


def test_audit_execve_record_is_translated():
    lines = ['type=SYSCALL msg=audit(1700000000.123:42): arch=c000003e syscall=59 success=yes exit=0 ppid=10 pid=11 comm="python" exe="/usr/bin/python"',
             'type=EXECVE msg=audit(1700000000.123:42): argc=1 a0="python"']
    result = parse_audit_raw(lines)
    assert result["events_emitted"] == 1
    assert result["events"][0]["event_type"] == "process_exec"
    assert result["events"][0]["process_id"] == 11


def test_failed_syscall_is_not_emitted():
    lines = ['type=SYSCALL msg=audit(1700000000.123:43): arch=c000003e syscall=59 success=no exit=-13 ppid=10 pid=11']
    assert parse_audit_raw(lines)["events"] == []


def test_open_read_only_is_not_file_write():
    lines = ['type=SYSCALL msg=audit(1700000000.123:44): arch=c000003e syscall=2 success=yes exit=3 a1=0 ppid=1 pid=22 exe="/usr/bin/cat"',
             'type=PATH msg=audit(1700000000.123:44): name="/etc/hosts"']
    assert parse_audit_raw(lines)["events"] == []


def test_open_write_flags_emit_file_write():
    lines = ['type=SYSCALL msg=audit(1700000000.123:45): arch=c000003e syscall=2 success=yes exit=3 a1=1 ppid=1 pid=22 exe="/usr/bin/tee"',
             'type=PATH msg=audit(1700000000.123:45): name="/tmp/output"']
    result = parse_audit_raw(lines)
    assert result["events"][0]["event_type"] == "file_write"
    assert result["events"][0]["target"] == "/tmp/output"


def test_open_append_hex_flag_is_decoded():
    lines = ['type=SYSCALL msg=audit(1700000000.123:46): arch=c000003e syscall=2 success=yes exit=3 a1=400 ppid=1 pid=22',
             'type=PATH msg=audit(1700000000.123:46): name="/tmp/output"']
    assert parse_audit_raw(lines)["events"][0]["event_type"] == "file_write"


def test_fork_uses_returned_child_pid():
    lines = ['type=SYSCALL msg=audit(1700000000.123:47): arch=c000003e syscall=57 success=yes exit=321 ppid=1 pid=22 comm="worker"']
    event = parse_audit_raw(lines)["events"][0]
    assert event["event_type"] == "process_start"
    assert event["process_id"] == 321
    assert event["parent_process_id"] == 22
