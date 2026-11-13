import pytest

from cabid.containers import ScopeError, analyse_scopes, group_key, namespaced_events
from cabid.ingest import normalize_many


def events(*spec):
    """spec items: (ts, pid, ppid, name[, container_id])"""
    rows = []
    for item in spec:
        ts, pid, ppid, name = item[:4]
        row = {"timestamp": ts, "event_type": "process_start", "process_id": pid,
               "parent_process_id": ppid, "process_name": name}
        if len(item) > 4:
            row["container_id"] = item[4]
        rows.append(row)
    return normalize_many(rows)


def test_no_metadata_means_one_host_scope():
    scopes = analyse_scopes(events((1, 1, 0, "init"), (2, 2, 1, "cron")))
    assert scopes["container_aware"] is False
    assert scopes["scope_count"] == 1
    assert scopes["host_event_count"] == 2
    assert scopes["namespaced_event_count"] == 0
    assert scopes["pid_collisions"] == []
    assert "no container metadata" in scopes["notes"][0].lower()


def test_container_metadata_is_kept_by_normalization():
    stream = events((1, 1, 0, "nginx", "abc123"))
    assert stream[0]["container_id"] == "abc123"


def test_scopes_are_counted_separately():
    stream = events((1, 1, 0, "nginx", "abc123"), (2, 42, 1, "php", "abc123"),
                    (3, 42, 0, "java", "def456"), (4, 9, 1, "sshd"))
    scopes = analyse_scopes(stream)
    assert scopes["container_aware"] is True
    assert scopes["scope_count"] == 3
    assert scopes["namespaced_event_count"] == 3
    assert scopes["host_event_count"] == 1


def test_pid_collision_across_scopes_is_reported():
    stream = events((1, 42, 1, "php", "abc123"), (2, 42, 0, "java", "def456"))
    scopes = analyse_scopes(stream)
    assert scopes["collision_count"] == 1
    assert scopes["pid_collisions"][0]["pid"] == 42
    assert sorted(scopes["pid_collisions"][0]["scopes"]) == ["abc123", "def456"]
    assert any("expected, not suspicious" in note for note in scopes["notes"])


def test_scope_summary_carries_window_and_names():
    stream = events((10, 1, 0, "nginx", "abc123"), (40, 2, 1, "php", "abc123"))
    entry = analyse_scopes(stream)["scopes"][0]
    assert entry["scope"] == "abc123"
    assert entry["events"] == 2
    assert entry["process_count"] == 2
    assert entry["process_names"] == ["nginx", "php"]
    assert entry["first_timestamp"] == 10 and entry["last_timestamp"] == 40


def test_namespace_pid_must_be_a_non_negative_integer():
    stream = normalize_many([{"timestamp": 1, "event_type": "heartbeat", "process_id": 1,
                              "parent_process_id": 0, "process_name": "a"}])
    stream[0]["pid_ns"] = -1
    with pytest.raises(ScopeError):
        analyse_scopes(stream)


def test_invalid_container_id_is_rejected():
    stream = normalize_many([{"timestamp": 1, "event_type": "heartbeat", "process_id": 1,
                              "parent_process_id": 0, "process_name": "a"}])
    stream[0]["container_id"] = "bad id with spaces"
    with pytest.raises(ScopeError):
        analyse_scopes(stream)


def test_group_key_separates_colliding_pids():
    stream = events((1, 42, 1, "php", "abc123"), (2, 42, 0, "java", "def456"))
    keys = {group_key(event) for event in stream}
    assert keys == {("abc123", 42), ("def456", 42)}


def test_namespaced_events_preserves_the_host_pid():
    stream = events((1, 42, 1, "php", "abc123"))
    rewritten = namespaced_events(stream)[0]
    assert rewritten["_host_process_id"] == 42
    assert rewritten["_scope"] == "abc123"
    assert rewritten["_scoped_pid"] == 42


def test_host_events_pass_through_unchanged():
    stream = events((1, 9, 1, "sshd"))
    assert "_scope" not in namespaced_events(stream)[0]


def test_report_includes_container_block():
    from cabid.detector import analyze

    report = analyze(events((1, 1, 0, "nginx"), (2, 2, 1, "cron")))
    assert report["containers"]["container_aware"] is False
    assert report["containers"]["scope_count"] == 1
