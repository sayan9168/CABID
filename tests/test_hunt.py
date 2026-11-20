import pytest

from cabid.hunt import (HuntError, describe_query, matches, parse_query, render_table,
                        resolve_field, run_query)


def events():
    return [
        {"timestamp": 100.0, "event_type": "process_start", "process_id": 10,
         "parent_process_id": 1, "process_name": "nginx", "executable": "/usr/sbin/nginx",
         "target": "", "source": "test"},
        {"timestamp": 101.5, "event_type": "process_exec", "process_id": 11,
         "parent_process_id": 10, "process_name": "sh", "executable": "/bin/sh",
         "target": "", "source": "test"},
        {"timestamp": 102.0, "event_type": "file_write", "process_id": 11,
         "parent_process_id": 10, "process_name": "sh", "executable": "/bin/sh",
         "target": "/etc/cron.d/persist", "source": "test"},
        {"timestamp": 103.0, "event_type": "network_connect", "process_id": 12,
         "parent_process_id": 11, "process_name": "curl", "executable": "/usr/bin/curl",
         "target": "203.0.113.9:443", "source": "test"},
        {"timestamp": 104.0, "event_type": "file_write", "process_id": 12,
         "parent_process_id": 11, "process_name": "curl", "executable": "/usr/bin/curl",
         "target": "/tmp/out", "source": "test"},
    ]


def matched(query):
    node = parse_query(query)
    return [event["process_id"] for event in events() if matches(node, event)]


def test_equality_and_and_or():
    assert matched('event_type = file_write') == [11, 12]
    assert matched('event_type = file_write and process_name = curl') == [12]
    assert matched('process_name = nginx or process_name = sh') == [10, 11, 11]


def test_and_binds_tighter_than_or():
    # sh OR (curl AND network_connect)
    assert matched('process_name = sh or process_name = curl and '
                   'event_type = network_connect') == [11, 11, 12]


def test_parentheses_override_precedence():
    assert matched('(process_name = sh or process_name = curl) and '
                   'event_type = file_write') == [11, 12]


def test_not_and_glob_negation():
    assert matched('not process_name = sh') == [10, 12, 12]
    assert matched('process_name !~ "*sh"') == [10, 12, 12]
    assert matched('target ~ "/etc/*"') == [11]


def test_numeric_comparisons_and_aliases():
    assert matched('pid = 11') == [11, 11]
    assert matched('pid >= 11 and pid < 12') == [11, 11]
    assert matched('timestamp > 102') == [12, 12]
    assert matched('ppid = 11') == [12, 12]


def test_in_and_contains():
    assert matched('event_type in [file_write, network_connect]') == [11, 12, 12]
    assert matched('target contains "cron.d"') == [11]
    assert matched('process_name in [nginx, curl]') == [10, 12, 12]


def test_numeric_literal_against_string_field_compares_text():
    assert matched('target = 443') == []  # exact string, not a suffix match
    assert matched('target ~ "*:443"') == [12]


def test_case_insensitive_keywords_and_field_names():
    assert matched('EVENT_TYPE = file_write AND PID = 11') == [11]
    assert matched('not (pid = 12)') == [10, 11, 11]


def test_quoted_values_may_contain_operators():
    assert matched('target = "/etc/cron.d/persist"') == [11]
    assert matched("target = '/tmp/out'") == [12]


def test_triple_negation_returns_the_original_predicate():
    assert matched('not not not event_type = file_write') == [10, 11, 12]


def test_missing_field_never_satisfies_positive_comparison():
    node = parse_query('container_id = abc')
    assert matches(node, events()[0]) is False
    assert matches(parse_query('container_id != abc'), events()[0]) is True
    assert matches(parse_query('container_id !~ "abc*"'), events()[0]) is True
    assert matches(parse_query('container_id ~ "abc*"'), events()[0]) is False


def test_missing_field_is_reported_in_the_receipt():
    result = run_query(events(), 'container_id = abc')
    assert result["field_presence"]["container_id"] == {"present": 0, "missing": 5}
    assert any("absent from every event" in note for note in result["notes"])


def test_unknown_field_is_an_error_with_a_suggestion():
    with pytest.raises(HuntError, match="unknown field: proc_name"):
        parse_query('proc_name = bash')
    with pytest.raises(HuntError, match="did you mean process_name"):
        parse_query('processname = bash')


def test_parse_errors_are_specific():
    with pytest.raises(HuntError, match="query is empty"):
        parse_query("   ")
    with pytest.raises(HuntError, match="expected an operator"):
        parse_query("event_type")
    with pytest.raises(HuntError, match="expected a value"):
        parse_query("event_type =")
    with pytest.raises(HuntError, match="string field"):
        parse_query("event_type > 3")
    with pytest.raises(HuntError, match="numeric"):
        parse_query("process_id = abc")
    with pytest.raises(HuntError, match="needs at least one value"):
        parse_query("event_type in []")
    with pytest.raises(HuntError, match="unexpected"):
        parse_query("event_type = bash ;")
    with pytest.raises(HuntError, match="unexpected"):
        parse_query("event_type = bash process_name = sh")
    with pytest.raises(HuntError, match=r"expected \)"):
        parse_query("(event_type = bash")
    with pytest.raises(HuntError, match="cannot be a value|expected a value"):
        parse_query("event_type = (")


def test_query_must_be_a_string():
    with pytest.raises(HuntError, match="must be a string"):
        parse_query(None)


def test_numeric_field_accepts_quoted_number():
    assert matched('pid = "11"') == [11, 11]


def test_describe_query_reports_shape():
    described = describe_query('event_type in [file_write] and pid != 3')
    assert described["fields"] == ["event_type", "process_id"]
    assert described["operators"] == ["!=", "in"]
    assert described["uses_negation"] is True


def test_unknown_node_kind_is_rejected():
    from cabid.hunt import matches as evaluate

    with pytest.raises(HuntError, match="unknown query node"):
        evaluate(("xor",), events()[0])


def test_run_query_counts_and_limit():
    result = run_query(events(), "event_type = process_start or event_type = file_write",
                       limit=1)
    assert result["events_scanned"] == 5
    assert result["events_matched"] == 3
    assert result["returned"] == 1
    assert result["truncated"] is True
    assert any("only 1 of 3 matches" in note for note in result["notes"])
    everything = run_query(events(), "process_id >= 10", limit=0)
    assert everything["returned"] == 5
    assert everything["truncated"] is False


def test_run_query_ratio_and_empty_input():
    result = run_query([], "event_type = file_write")
    assert result["events_scanned"] == 0
    assert result["match_ratio"] == 0.0
    assert any("proves nothing" in note for note in result["notes"])


def test_run_query_groups_are_sorted_by_count_then_value():
    result = run_query(events(), "process_id >= 10", group_by="event_type", limit=0)
    assert result["group_by"] == "event_type"
    assert result["groups"][0] == {"value": "file_write", "count": 2}
    values = [row["value"] for row in result["groups"]]
    assert values == sorted(values, key=lambda value: (-dict(
        (row["value"], row["count"]) for row in result["groups"])[value], value))


def test_run_query_rejects_bad_inputs():
    with pytest.raises(HuntError, match="must be a list"):
        run_query({"not": "a list"}, "event_type = file_write")
    with pytest.raises(HuntError, match="must be dictionaries"):
        run_query(["not-a-dict"], "event_type = file_write")


def test_resolve_field_aliases_and_unknown():
    assert resolve_field("PID") == "process_id"
    assert resolve_field("name") == "process_name"
    with pytest.raises(HuntError, match="unknown field"):
        resolve_field("nope")


def test_render_table_default_and_custom_columns():
    result = run_query(events(), "event_type = file_write", limit=0)
    table = render_table(result)
    assert "query: event_type = file_write" in table
    assert "matched 2 of 5 events" in table
    assert "/etc/cron.d/persist" in table
    custom = render_table(result, ["process_id", "target"])
    header = custom.splitlines()[3]
    assert header.startswith("process_id")
    assert "event_type" not in header


def test_render_table_with_no_matches():
    table = render_table(run_query(events(), "process_name = nothing"))
    assert "no matching events" in table


def test_escape_sequences_inside_strings():
    node = parse_query(r'target = "a\tb\"c\\d"')
    assert node[3] == 'a\tb"c\\d'
    # Windows-style paths survive because \\w is not a known escape.
    assert matched(r'target = "C:\\tasks\\job"') == []


def test_ordering_operators_on_numeric_plural_fields():
    assert matched('timestamp <= 101.5') == [10, 11]
    assert matched('process_id > 11') == [12, 12]


def test_numeric_field_rejects_non_numeric_literal():
    with pytest.raises(HuntError, match="unknown field|numeric"):
        parse_query('process_id = sh')


def test_quoted_numeric_is_accepted_for_ordering():
    assert matched('pid >= "11"') == [11, 11, 12, 12]


def test_contains_on_numeric_field_is_rejected():
    with pytest.raises(HuntError, match="not defined for numeric"):
        parse_query('process_id contains 1')


def test_group_by_unknown_field_is_rejected():
    with pytest.raises(HuntError, match="unknown field"):
        run_query(events(), 'pid > 0', group_by="nope")


def test_quoted_value_for_numeric_field_parses():
    assert parse_query('pid = "10"')[3] == 10.0


def test_equal_op_on_string_field_with_quoted_value():
    assert matched('event_type = "network_connect"') == [12]


def test_sort_of_groups_is_stable_for_equal_counts():
    result = run_query(events(), "event_type ~ '*'", group_by="process_name", limit=0)
    counts = [row["count"] for row in result["groups"]]
    assert counts == sorted(counts, reverse=True)
