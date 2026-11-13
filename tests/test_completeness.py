from cabid.completeness import completeness_features, EXPECTED


def test_all_expected_event_classes_are_sufficient():
    events = [{"event_type": kind} for kind in EXPECTED]
    result = completeness_features(events)
    assert result["completeness"] == 1.0
    assert result["telemetry_sufficient"] is True


def test_partial_procfs_stream_is_insufficient_by_default():
    events = [{"event_type": kind} for kind in ("process_start", "process_exec", "heartbeat")]
    result = completeness_features(events)
    assert result["completeness"] == 0.5
    assert result["telemetry_sufficient"] is False
    assert "network_connect" in result["missing_event_types"]


def test_custom_threshold_is_explicit_and_validated():
    events = [{"event_type": "heartbeat"}]
    assert completeness_features(events, minimum_ratio=0.1)["telemetry_sufficient"]
    try:
        completeness_features(events, minimum_ratio=1.1)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid threshold must fail")
