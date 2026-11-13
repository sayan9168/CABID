"""Telemetry coverage estimation over configured event classes.

Only the core classes a generic sensor can produce are required by default.
Auditd-only classes (``privilege_change``, ``kernel_state_change``,
``permission_change``, ``network_accept``) are accepted input but never required,
because a procfs-based sensor cannot emit them at all. Requiring them would mark
every auditd stream insufficient while a procfs stream looked complete.
"""
EXPECTED = {
    "process_start",
    "process_exec",
    "file_write",
    "network_connect",
    "process_exit",
    "heartbeat",
}


def completeness_features(
    events: list[dict],
    expected_event_types: set[str] | None = None,
    minimum_ratio: float = 1.0,
) -> dict:
    """Report observed coverage; default requires every expected class.

    A caller may lower minimum_ratio for a deliberately partial sensor, but
    that threshold must be documented in the experiment configuration.
    """
    if not 0.0 <= minimum_ratio <= 1.0:
        raise ValueError("minimum_ratio must be between 0 and 1")
    expected = set(EXPECTED if expected_event_types is None else expected_event_types)
    observed = {event["event_type"] for event in events}
    ratio = len(observed & expected) / len(expected) if expected else 1.0
    missing = sorted(expected - observed)
    return {
        "completeness": round(ratio, 6),
        "minimum_required_completeness": minimum_ratio,
        "observed_event_types": sorted(observed),
        "missing_event_types": missing,
        "telemetry_sufficient": ratio >= minimum_ratio,
    }
