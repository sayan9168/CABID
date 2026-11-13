"""Telemetry completeness estimation based on expected event classes."""
EXPECTED = {"process_start", "process_exec", "file_write", "network_connect", "process_exit", "heartbeat"}

def completeness_features(events: list[dict], expected_event_types: set[str] | None = None) -> dict:
    expected = set(expected_event_types or EXPECTED)
    observed = {event["event_type"] for event in events}
    ratio = len(observed & expected) / len(expected) if expected else 1.0
    missing = sorted(expected - observed)
    return {"completeness": round(ratio, 6), "observed_event_types": sorted(observed),
            "missing_event_types": missing, "telemetry_sufficient": ratio >= 0.5}
