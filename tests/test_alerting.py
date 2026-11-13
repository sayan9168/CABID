"""Tests for alert delivery, suppression, and credential hygiene.

Every test uses a fake transport; nothing here touches the network.
"""
from __future__ import annotations

import json

import pytest

from cabid.alerting import (
    ALERTABLE,
    AlertError,
    AlertState,
    build_message,
    fingerprint,
    load_state,
    redact,
    send,
    send_from_stream_report,
    severity_of,
    should_alert,
    write_state,
)


class FakeTransport:
    def __init__(self, status: int = 200, fail: bool = False) -> None:
        self.status = status
        self.fail = fail
        self.posts: list[tuple[str, dict]] = []
        self.mails: list[object] = []

    def post_json(self, url: str, payload: dict, timeout: float) -> int:
        if self.fail:
            raise AlertError("delivery failed: connection refused")
        self.posts.append((url, payload))
        return self.status

    def send_mail(self, message, host, port, username, password, use_tls) -> None:
        if self.fail:
            raise AlertError("email delivery failed")
        self.mails.append(message)


def _report(status: str = "HIGH_RISK", score: float = 0.91, codes=("temporal_rate_or_burst",)) -> dict:
    return {
        "status": status,
        "anomaly_score": score,
        "event_count": 1200,
        "reasons": [{"code": code, "detail": f"{code} detail"} for code in codes],
    }


# -------------------------------------------------------------- redaction ----

def test_redact_never_returns_the_secret():
    url = "https://hooks.slack.com/services/T00/B00/SUPERSECRETTOKEN"
    masked = redact(url)
    assert "SUPERSECRETTOKEN" not in masked
    assert "hooks.slack.com" in masked
    assert masked != redact("https://hooks.slack.com/services/T00/B00/OTHER")


def test_redact_handles_missing_and_odd_values():
    assert redact(None) == "(unset)"
    assert redact("") == "(unset)"
    assert "…" in redact("not a url")


def test_email_addresses_are_redacted():
    from cabid.alerting import _redact_address

    masked = _redact_address("analyst@example.com")
    assert masked == "a…@example.com"
    assert _redact_address(None) == "(unset)"
    assert _redact_address("no-at-sign") == "…"


# -------------------------------------------------------------- fingerprint ----

def test_fingerprint_ignores_score_and_uses_substance():
    first = fingerprint(_report(score=0.81), "web-01")
    second = fingerprint(_report(score=0.99), "web-01")
    assert first == second


def test_fingerprint_distinguishes_host_status_and_codes():
    base = fingerprint(_report(), "web-01")
    assert fingerprint(_report(), "web-02") != base
    assert fingerprint(_report(status="SUSPICIOUS"), "web-01") != base
    assert fingerprint(_report(codes=("telemetry_gap",)), "web-01") != base


def test_fingerprint_is_order_independent_for_codes():
    a = fingerprint(_report(codes=("b", "a")), "h")
    b = fingerprint(_report(codes=("a", "b")), "h")
    assert a == b


# ---------------------------------------------------------------- severity ----

def test_should_alert_respects_the_floor():
    assert should_alert(_report("SUSPICIOUS")) is True
    assert should_alert(_report("HIGH_RISK")) is True
    assert should_alert(_report("NO_ANOMALY_DETECTED")) is False
    assert should_alert(_report("SUSPICIOUS"), minimum="HIGH_RISK") is False
    assert should_alert(_report("HIGH_RISK"), minimum="HIGH_RISK") is True


def test_should_alert_rejects_an_unknown_floor():
    with pytest.raises(AlertError):
        should_alert(_report(), minimum="ANY")


def test_severity_of_handles_unknown_status():
    assert severity_of({"status": "WEIRD"}) == "UNKNOWN"
    assert severity_of({}) == "UNKNOWN"


def test_alertable_includes_insufficient_evidence_but_not_quiet():
    assert "INSUFFICIENT_EVIDENCE" in ALERTABLE
    assert "NO_ANOMALY_DETECTED" not in ALERTABLE


# ------------------------------------------------------------------ message ----

def test_message_carries_the_caveat_and_the_codes():
    message = build_message(_report(), host="web-01")
    assert message["status"] == "HIGH_RISK"
    assert "temporal_rate_or_burst" in message["text"]
    assert "not a probability" in message["text"]
    assert "not a verdict" in message["text"]
    assert message["host"] == "web-01"


def test_message_includes_a_dashboard_link_when_given():
    message = build_message(_report(), host="h", dashboard_url="http://dash/1")
    assert "http://dash/1" in message["text"]


def test_message_survives_a_minimal_report():
    message = build_message({"status": "SUSPICIOUS"})
    assert "SUSPICIOUS" in message["text"]
    assert message["reason_codes"] == []


# -------------------------------------------------------------------- send ----

def test_send_delivers_a_slack_payload(monkeypatch):
    monkeypatch.setenv("CABID_SLACK_WEBHOOK", "https://hooks.slack.com/services/x")
    transport = FakeTransport()
    receipt = send([_report()], channel="slack", transport=transport, host="web-01")
    assert receipt["sent"] == 1
    assert transport.posts
    url, payload = transport.posts[0]
    assert "blocks" in payload
    assert "SUPERSECRET" not in json.dumps(receipt)


def test_send_suppresses_duplicates_within_the_quiet_window(monkeypatch):
    monkeypatch.setenv("CABID_SLACK_WEBHOOK", "https://hooks.slack.com/services/x")
    transport = FakeTransport()
    state = AlertState()
    first = send([_report()], channel="slack", transport=transport, host="h",
                 state=state, now=1000.0)
    second = send([_report()], channel="slack", transport=transport, host="h",
                  state=state, now=1100.0)
    assert first["sent"] == 1
    assert second["sent"] == 0
    assert second["suppressed"]["duplicate_within_window"] == 1


def test_send_repeats_after_the_quiet_window(monkeypatch):
    monkeypatch.setenv("CABID_SLACK_WEBHOOK", "https://hooks.slack.com/services/x")
    transport = FakeTransport()
    state = AlertState()
    send([_report()], channel="slack", transport=transport, host="h", state=state, now=0.0)
    again = send([_report()], channel="slack", transport=transport, host="h",
                 state=state, now=5000.0)
    assert again["sent"] == 1


def test_send_counts_below_threshold_suppression(monkeypatch):
    monkeypatch.setenv("CABID_SLACK_WEBHOOK", "https://hooks.slack.com/services/x")
    receipt = send([_report("NO_ANOMALY_DETECTED", 0.01)], channel="slack",
                   transport=FakeTransport(), host="h")
    assert receipt["suppressed"]["below_threshold"] == 1
    assert receipt["sent"] == 0


def test_send_respects_the_run_budget(monkeypatch):
    monkeypatch.setenv("CABID_SLACK_WEBHOOK", "https://hooks.slack.com/services/x")
    reports = [_report(codes=(f"code-{index}",)) for index in range(5)]
    receipt = send(reports, channel="slack", transport=FakeTransport(), host="h",
                   max_per_run=2)
    assert receipt["sent"] == 2
    assert receipt["suppressed"]["run_budget_exhausted"] == 3


def test_send_records_delivery_errors_without_aborting(monkeypatch):
    monkeypatch.setenv("CABID_SLACK_WEBHOOK", "https://hooks.slack.com/services/x")
    receipt = send([_report()], channel="slack", transport=FakeTransport(fail=True),
                   host="h")
    assert receipt["errors"]
    assert receipt["sent"] == 0


def test_send_without_a_configured_destination_reports_it(monkeypatch):
    monkeypatch.delenv("CABID_SLACK_WEBHOOK", raising=False)
    receipt = send([_report()], channel="slack", transport=FakeTransport(), host="h")
    assert receipt["destination_configured"] is False
    assert any("CABID_SLACK_WEBHOOK" in error for error in receipt["errors"])


def test_send_rejects_non_2xx_responses(monkeypatch):
    monkeypatch.setenv("CABID_SLACK_WEBHOOK", "https://hooks.slack.com/services/x")
    receipt = send([_report()], channel="slack", transport=FakeTransport(status=500),
                   host="h")
    assert receipt["sent"] == 0
    assert any("500" in error for error in receipt["errors"])


def test_send_validates_its_parameters():
    with pytest.raises(AlertError):
        send([], channel="pigeon")
    with pytest.raises(AlertError):
        send([], channel="slack", quiet_seconds=-1)
    with pytest.raises(AlertError):
        send([], channel="slack", max_per_run=-1)


# --------------------------------------------------------------- dry run ----

def test_dry_run_previews_without_a_destination(monkeypatch):
    monkeypatch.delenv("CABID_SLACK_WEBHOOK", raising=False)
    receipt = send([_report()], channel="slack", host="h", dry_run=True)
    assert receipt["dry_run"] is True
    assert receipt["sent"] == 1
    assert receipt["preview"][0]["payload"]["blocks"]
    assert receipt["errors"] == []


def test_dry_run_still_applies_suppression(monkeypatch):
    monkeypatch.delenv("CABID_SLACK_WEBHOOK", raising=False)
    state = AlertState()
    send([_report()], channel="slack", host="h", dry_run=True, state=state, now=0.0)
    again = send([_report()], channel="slack", host="h", dry_run=True, state=state,
                 now=10.0)
    assert again["preview"] == []
    assert again["suppressed"]["duplicate_within_window"] == 1


def test_dry_run_previews_every_channel_shape():
    for channel in ("slack", "discord", "webhook", "email"):
        receipt = send([_report()], channel=channel, host="h", dry_run=True)
        assert receipt["preview"][0]["channel"] == channel


# ------------------------------------------------------------------ email ----

def test_email_delivery_builds_a_message():
    transport = FakeTransport()
    receipt = send([_report()], channel="email", transport=transport, host="web-01",
                   email_from="cabid@example.com", email_to="soc@example.com",
                   smtp_host="mail.example.com")
    assert receipt["sent"] == 1
    assert len(transport.mails) == 1
    message = transport.mails[0]
    assert "HIGH_RISK" in message["Subject"]
    assert "web-01" in message["Subject"]
    assert message["To"] == "soc@example.com"


def test_email_without_required_settings_fails_clearly():
    receipt = send([_report()], channel="email", transport=FakeTransport(), host="h")
    assert receipt["sent"] == 0
    assert any("--smtp-host" in error for error in receipt["errors"])


def test_email_receipt_redacts_the_recipient():
    receipt = send([_report()], channel="email", transport=FakeTransport(), host="h",
                   email_from="a@b.c", email_to="soc@example.com", smtp_host="mail")
    assert receipt["destination"] == "s…@example.com"


# ---------------------------------------------------------------- discord ----

def test_discord_payload_disables_mentions(monkeypatch):
    monkeypatch.setenv("CABID_DISCORD_WEBHOOK", "https://discord.com/api/webhooks/x")
    transport = FakeTransport()
    send([_report()], channel="discord", transport=transport, host="h")
    payload = transport.posts[0][1]
    assert payload["allowed_mentions"] == {"parse": []}
    assert payload["username"] == "CABID"


def test_webhook_payload_is_structured(monkeypatch):
    monkeypatch.setenv("CABID_WEBHOOK_URL", "https://example.com/hook")
    transport = FakeTransport()
    send([_report()], channel="webhook", transport=transport, host="web-01")
    payload = transport.posts[0][1]
    assert payload["host"] == "web-01"
    assert payload["status"] == "HIGH_RISK"
    assert payload["reason_codes"] == ["temporal_rate_or_burst"]


# ------------------------------------------------------------------ state ----

def test_state_round_trips_through_disk(tmp_path):
    state = AlertState(sent={"abc": 1.0}, counts={"abc": 2}, total_sent=1)
    path = write_state(state, tmp_path / "nested" / "state.json")
    assert load_state(path).to_dict() == state.to_dict()


def test_load_state_returns_empty_when_absent(tmp_path):
    assert load_state(tmp_path / "missing.json").to_dict()["total_sent"] == 0


def test_load_state_rejects_broken_json(tmp_path):
    broken = tmp_path / "broken.json"
    broken.write_text("{oops", encoding="utf-8")
    with pytest.raises(AlertError, match="invalid state JSON"):
        load_state(broken)


def test_state_from_dict_rejects_non_object():
    with pytest.raises(AlertError):
        AlertState.from_dict([])  # type: ignore[arg-type]


# --------------------------------------------------------------- stream ----

def test_stream_report_alert_uses_the_worst_window():
    report = {
        "windows_scored": [
            {"status": "NO_ANOMALY_DETECTED", "anomaly_score": 0.01, "event_count": 50,
             "reason_codes": []},
            {"status": "HIGH_RISK", "anomaly_score": 0.93, "event_count": 400,
             "reason_codes": ["temporal_rate_or_burst"]},
        ],
    }
    receipt = send_from_stream_report(report, channel="slack", host="h", dry_run=True)
    assert receipt["sent"] == 1
    assert "temporal_rate_or_burst" in receipt["preview"][0]["text"]


def test_stream_report_without_windows_sends_nothing():
    receipt = send_from_stream_report({"windows_scored": []}, channel="slack",
                                      host="h", dry_run=True)
    assert receipt["sent"] == 0
    assert receipt["considered"] == 0


def test_receipt_always_states_that_suppression_is_visible():
    receipt = send([_report()], channel="slack", host="h", dry_run=True)
    assert any("Suppressed counts are reported explicitly" in note
               for note in receipt["notes"])
    assert any("does not act" in note for note in receipt["notes"])
