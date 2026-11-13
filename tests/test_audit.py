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


_serial = [900]


def _syscall_line(syscall: int, arch: str = "c000003e", pid: int = 77, extra: str = "") -> str:
    """One SYSCALL record with a unique audit serial (records are grouped by id)."""
    _serial[0] += 1
    return (f'type=SYSCALL msg=audit(1700000000.500:{_serial[0]}): arch={arch} syscall={syscall} '
            f'success=yes exit=0 ppid=1 pid={pid} comm="tool" exe="/usr/bin/tool" {extra}')


def test_privilege_change_family_is_mapped():
    # setuid 105, setgid 106, setreuid 113, setresuid 117 on x86_64
    for syscall, name in ((105, "setuid"), (106, "setgid"), (113, "setreuid"), (117, "setresuid")):
        event = parse_audit_raw([_syscall_line(syscall)])["events"][0]
        assert event["event_type"] == "privilege_change"
        assert event["target"] == name


def test_kernel_state_change_family_is_mapped():
    # ptrace 101, mount 165, umount2 166, pivot_root 155, mknod 133
    for syscall, name in ((101, "ptrace"), (165, "mount"), (166, "umount2"),
                          (155, "pivot_root"), (133, "mknod")):
        event = parse_audit_raw([_syscall_line(syscall)])["events"][0]
        assert event["event_type"] == "kernel_state_change"
        assert event["target"] == name


def test_permission_change_carries_the_path():
    _serial[0] += 1
    serial = _serial[0]
    lines = [f'type=SYSCALL msg=audit(1700000000.500:{serial}): arch=c000003e syscall=90 '
             f'success=yes exit=0 ppid=1 pid=77 comm="chmod" exe="/bin/chmod"',
             f'type=PATH msg=audit(1700000000.500:{serial}): name="/etc/shadow"']
    event = parse_audit_raw(lines)["events"][0]
    assert event["event_type"] == "permission_change"
    assert event["target"] == "/etc/shadow"


def test_network_accept_is_mapped():
    assert parse_audit_raw([_syscall_line(288)])["events"][0]["event_type"] == "network_accept"


def test_aarch64_syscall_numbers_are_translated():
    # aarch64 setuid 146, ptrace 117, mount 162, pivot_root 40
    for syscall, event_type in ((146, "privilege_change"), (117, "kernel_state_change"),
                                (162, "kernel_state_change"), (40, "kernel_state_change")):
        event = parse_audit_raw([_syscall_line(syscall, arch="c00000b7")])["events"][0]
        assert event["event_type"] == event_type


def test_unknown_arch_is_reported_not_guessed():
    result = parse_audit_raw([_syscall_line(59, arch="40000003")])
    assert result["events"] == []
    assert result["skipped"].get("unsupported_arch", 0) >= 1


def test_unknown_syscall_on_a_known_arch_is_skipped():
    result = parse_audit_raw([_syscall_line(4000)])
    assert result["events"] == []
    assert result["skipped"].get("unmapped_syscall", 0) >= 1


def test_event_type_counts_are_reported():
    lines = [_syscall_line(59), _syscall_line(105), _syscall_line(165)]
    counts = parse_audit_raw(lines)["event_type_counts"]
    assert counts["process_exec"] == 1
    assert counts["privilege_change"] == 1
    assert counts["kernel_state_change"] == 1


def test_optional_events_do_not_make_telemetry_sufficient_alone():
    """A procfs sensor can never emit these, so they must not be required."""
    from cabid.completeness import completeness_features

    events = [{"event_type": "privilege_change"}, {"event_type": "kernel_state_change"}]
    result = completeness_features(events)
    assert result["telemetry_sufficient"] is False
    assert "privilege_change" not in result["missing_event_types"]


def test_skip_reasons_distinguish_ignored_from_understood():
    result = parse_audit_raw([
        _syscall_line(4000),                                    # unmapped on a known arch
        _syscall_line(59, arch="40000003"),                      # unsupported arch
        'type=SYSCALL msg=audit(1700000000.700:1): arch=c000003e syscall=59 success=no exit=-13 ppid=1 pid=9',
    ])
    assert result["events"] == []
    assert result["skipped"]["unmapped_syscall"] == 1
    assert result["skipped"]["unsupported_arch"] == 1
    assert result["skipped"]["failed_syscall"] == 1
    assert result["audit_events_ignored"] == 3


def test_number_and_arg_helpers_are_defensive():
    from cabid.audit import _audit_arg, _number, _syscall_name

    assert _number(None) is None
    assert _number("not-a-number") is None
    assert _number("42") == 42
    assert _audit_arg(None) is None
    assert _audit_arg("0x10") == 16
    assert _audit_arg("10") == 16          # bare audit args are hexadecimal
    assert _audit_arg("zz") is None
    # A named syscall (some audit configurations log names) is lowercased.
    assert _syscall_name({"syscall": "EXECVE"}) == "execve"
    assert _syscall_name({}) == ""
