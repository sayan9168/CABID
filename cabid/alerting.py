"""Alert delivery to Slack, Discord, email, and generic webhooks.

CABID refuses to attempt containment automatically, so notification is where a
finding actually reaches a human. That makes two things matter more than delivery
mechanics:

**Not every finding deserves a page.** A sensor at 10⁵ events/min with a 60-second
window can produce an alert every minute, and an operator who receives a hundred
nightly messages stops reading them. This module therefore applies, in order:

1. a **severity floor**, so trivial bands are never sent;
2. **deduplication** on a fingerprint of the finding's substance, so an unchanged
   situation is not re-sent;
3. a **per-fingerprint rate limit**, so a flapping signal cannot dominate a channel;
4. an optional **global budget** across fingerprints.

Suppression is always reported, never silent. The result of a send says exactly how
many were sent and how many were withheld, and why — a channel that looks quiet
because alerts were dropped is worse than a noisy one.

**Secrets never appear in output.** Webhook URLs and SMTP passwords are read from the
environment, redacted in every rendered message and receipt, and never written to a
report.

Delivery uses only the standard library (``urllib``, ``smtplib``), consistent with
CABID's zero-runtime-dependency rule. All network sends are behind a transport seam
so the whole module is unit-tested without network access.
"""
from __future__ import annotations

import hashlib
import json
import os
import smtplib
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage
from pathlib import Path
from typing import Callable, Protocol

ALERT_FORMAT = "cabid-alert-receipt/1"

SEVERITY_ORDER = ("NO_ANOMALY_DETECTED", "SUSPICIOUS", "HIGH_RISK", "INSUFFICIENT_EVIDENCE")

#: Statuses that may produce an alert. INSUFFICIENT_EVIDENCE is included because a
#: blind sensor is an operational problem an operator needs to know about, but it is
#: ranked above HIGH_RISK only for ordering, never as an attack signal.
ALERTABLE = ("SUSPICIOUS", "HIGH_RISK", "INSUFFICIENT_EVIDENCE")

CHANNELS = ("slack", "discord", "email", "webhook")

#: Default dedup/rate-limit window. Long enough to cover a typical shift handover.
DEFAULT_QUIET_SECONDS = 1800.0

#: Environment variables consulted for credentials. Kept out of every rendered
#: document; a receipt records only which variable was used.
CREDENTIAL_ENV = {
    "slack": "CABID_SLACK_WEBHOOK",
    "discord": "CABID_DISCORD_WEBHOOK",
    "webhook": "CABID_WEBHOOK_URL",
    "email": "CABID_SMTP_PASSWORD",
}


class AlertError(ValueError):
    """Raised when an alert cannot be built or delivered safely."""


class Transport(Protocol):
    """Minimal seam for delivery, so tests never touch the network."""

    def post_json(self, url: str, payload: dict, timeout: float) -> int:
        ...

    def send_mail(self, message: EmailMessage, host: str, port: int, username: str | None,
                  password: str | None, use_tls: bool) -> None:
        ...


class UrllibTransport:
    """Real delivery over the standard library."""

    def post_json(self, url: str, payload: dict, timeout: float) -> int:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json",
                                     "User-Agent": "cabid-alert/1"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return int(response.status)
        except urllib.error.HTTPError as exc:
            raise AlertError(f"delivery rejected with HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            raise AlertError(f"delivery failed: {exc.reason}") from exc

    def send_mail(self, message: EmailMessage, host: str, port: int,
                  username: str | None, password: str | None, use_tls: bool) -> None:
        try:
            with smtplib.SMTP(host, port, timeout=30) as client:
                if use_tls:
                    client.starttls()
                if username and password:
                    client.login(username, password)
                client.send_message(message)
        except (smtplib.SMTPException, OSError) as exc:
            raise AlertError(f"email delivery failed: {exc}") from exc


@dataclass
class AlertState:
    """Suppression state: fingerprint -> last sent timestamp and send count."""

    sent: dict[str, float] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    total_sent: int = 0

    def to_dict(self) -> dict:
        return {"sent": dict(self.sent), "counts": dict(self.counts),
                "total_sent": self.total_sent}

    @classmethod
    def from_dict(cls, data: dict) -> "AlertState":
        if not isinstance(data, dict):
            raise AlertError("alert state must be a JSON object")
        return cls(
            sent={str(key): float(value) for key, value in (data.get("sent") or {}).items()},
            counts={str(key): int(value) for key, value in (data.get("counts") or {}).items()},
            total_sent=int(data.get("total_sent") or 0),
        )


def redact(url: str | None) -> str:
    """Reduce a webhook URL to something safe to print.

    Slack, Discord, and Teams webhook URLs are bearer credentials: anyone holding the
    URL can post to the channel. Only the host and a short digest are kept, which is
    enough to tell two destinations apart in a receipt.
    """
    if not url:
        return "(unset)"
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:8]
    try:
        host = urllib.parse.urlparse(url).netloc or "(local)"
    except ValueError:
        host = "(unparseable)"
    return f"{host}/…#{digest}"


def fingerprint(report: dict, host: str | None = None) -> str:
    """A stable identity for a finding's *substance*.

    Built from the host, the status, and the sorted reason codes — deliberately not
    from the score or the timestamp. The same problem recurring with a slightly
    different score is the same problem, and re-alerting on it is what trains
    operators to ignore the channel.
    """
    codes = sorted(str(reason.get("code")) for reason in report.get("reasons") or []
                   if isinstance(reason, dict))
    status = str(report.get("status") or "UNKNOWN")
    material = "|".join([host or "-", status, ",".join(codes)])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def severity_of(report: dict) -> str:
    status = str(report.get("status") or "UNKNOWN")
    return status if status in SEVERITY_ORDER else "UNKNOWN"


def should_alert(report: dict, minimum: str = "SUSPICIOUS") -> bool:
    if minimum not in ALERTABLE:
        raise AlertError(f"minimum severity must be one of {', '.join(ALERTABLE)}")
    status = severity_of(report)
    if status not in ALERTABLE:
        return False
    return ALERTABLE.index(status) >= ALERTABLE.index(minimum)


def build_message(report: dict, *, host: str | None = None,
                  dashboard_url: str | None = None) -> dict:
    """Render the channel-neutral alert content.

    Everything downstream (Slack blocks, Discord embeds, email bodies, webhook JSON)
    is a projection of this dict, so what an operator reads is identical regardless
    of channel.
    """
    status = severity_of(report)
    codes = [str(reason.get("code")) for reason in report.get("reasons") or []
             if isinstance(reason, dict)]
    scores = report.get("anomaly_score")
    lines = [f"*{status}* on `{host or 'unknown host'}`"]
    if isinstance(scores, (int, float)):
        lines.append(f"Anomaly score: {float(scores):.3f} "
                     "(heuristic, not a probability)")
    if report.get("event_count") is not None:
        lines.append(f"Events: {report.get('event_count')}")
    if codes:
        lines.append("Reason codes: " + ", ".join(codes))
    details = [str(reason.get("detail")) for reason in report.get("reasons") or []
               if isinstance(reason, dict) and reason.get("detail")]
    if details:
        lines.append("")
        lines.extend(f"• {detail}" for detail in details[:5])
    lines.append("")
    lines.append("Triage hint from behavioural pattern matching, not a verdict.")
    if dashboard_url:
        lines.append(f"Dashboard: {dashboard_url}")
    return {
        "format": ALERT_FORMAT,
        "host": host,
        "status": status,
        "anomaly_score": scores,
        "event_count": report.get("event_count"),
        "reason_codes": codes,
        "fingerprint": fingerprint(report, host),
        "text": "\n".join(lines),
        "dashboard_url": dashboard_url,
    }


def _payload_for(channel: str, message: dict) -> dict:
    if channel == "slack":
        return _slack_payload(message)
    if channel == "discord":
        return _discord_payload(message)
    if channel == "webhook":
        return _webhook_payload(message)
    return {"subject": f"[CABID] {message['status']} on {message['host'] or 'unknown host'}",
            "body": message["text"]}


def _slack_payload(message: dict) -> dict:
    return {"text": message["text"],
            "unfurl_links": False,
            "blocks": [{"type": "section", "text": {"type": "mrkdwn",
                                                    "text": message["text"]}}]}


def _discord_payload(message: dict) -> dict:
    return {"content": message["text"][:2000],
            "username": "CABID",
            "allowed_mentions": {"parse": []}}


def _webhook_payload(message: dict) -> dict:
    return {"source": "cabid",
            "format": ALERT_FORMAT,
            "host": message["host"],
            "status": message["status"],
            "anomaly_score": message["anomaly_score"],
            "event_count": message["event_count"],
            "reason_codes": message["reason_codes"],
            "fingerprint": message["fingerprint"],
            "text": message["text"],
            "dashboard_url": message["dashboard_url"]}


def _email_message(message: dict, *, sender: str, recipient: str) -> EmailMessage:
    email = EmailMessage()
    subject_host = message["host"] or "unknown host"
    email["Subject"] = f"[CABID] {message['status']} on {subject_host}"
    email["From"] = sender
    email["To"] = recipient
    email.set_content(message["text"])
    return email


def send(reports: list[dict], *, channel: str, transport: Transport | None = None,
         host: str | None = None, minimum: str = "SUSPICIOUS",
         state: AlertState | None = None, quiet_seconds: float = DEFAULT_QUIET_SECONDS,
         now: float | None = None, max_per_run: int = 20,
         timeout: float = 10.0, dashboard_url: str | None = None,
         email_from: str | None = None, email_to: str | None = None,
         smtp_host: str | None = None, smtp_port: int = 587,
         smtp_user: str | None = None, smtp_tls: bool = True,
         dry_run: bool = False) -> dict:
    """Deliver alerts for reports at or above ``minimum`` severity.

    Returns a receipt describing what was sent, what was suppressed and why. Every
    suppressed finding is counted by reason; nothing is dropped silently.
    """
    if channel not in CHANNELS:
        raise AlertError(f"channel must be one of {', '.join(CHANNELS)}")
    if quiet_seconds < 0:
        raise AlertError("quiet_seconds must be non-negative")
    if max_per_run < 0:
        raise AlertError("max_per_run must be non-negative")
    state = state if state is not None else AlertState()
    clock = time.time() if now is None else float(now)
    transport = transport or UrllibTransport()

    receipt: dict = {
        "format": ALERT_FORMAT,
        "channel": channel,
        "destination": "(none configured)",
        "considered": len(reports),
        "sent": 0,
        "suppressed": {"below_threshold": 0, "duplicate_within_window": 0,
                       "run_budget_exhausted": 0},
        "delivered_fingerprints": [],
        "preview": [],
        "errors": [],
        "credential_source": None,
    }

    url = email = None
    if channel in ("slack", "discord", "webhook"):
        url = os.environ.get(CREDENTIAL_ENV[channel], "").strip() or None
        receipt["credential_source"] = CREDENTIAL_ENV[channel] if url else "argument"
        receipt["destination"] = redact(url)
        receipt["destination_configured"] = bool(url)
    else:
        receipt["credential_source"] = CREDENTIAL_ENV["email"]
        receipt["destination"] = _redact_address(email_to)

    for report in reports:
        if not should_alert(report, minimum):
            receipt["suppressed"]["below_threshold"] += 1
            continue
        message = build_message(report, host=host, dashboard_url=dashboard_url)
        key = message["fingerprint"]
        last = state.sent.get(key)
        if last is not None and clock - last < quiet_seconds:
            receipt["suppressed"]["duplicate_within_window"] += 1
            state.counts[key] = state.counts.get(key, 0) + 1
            continue
        if state.total_sent >= max_per_run:
            receipt["suppressed"]["run_budget_exhausted"] += 1
            continue
        if dry_run:
            # Preview the exact payload that would be delivered. A first integration
            # should never be able to page somebody by accident.
            receipt["preview"].append({
                "fingerprint": key,
                "status": message["status"],
                "channel": channel,
                "text": message["text"],
                "payload": _payload_for(channel, message),
            })
            state.sent[key] = clock
            receipt["sent"] += 1
            receipt["delivered_fingerprints"].append(key)
            continue
        try:
            if channel in ("slack", "discord", "webhook"):
                if not url:
                    raise AlertError(
                        f"no destination configured; set {CREDENTIAL_ENV[channel]}")
                payload_builder = {"slack": _slack_payload, "discord": _discord_payload,
                                   "webhook": _webhook_payload}[channel]
                status_code = transport.post_json(url, payload_builder(message), timeout)
                if status_code >= 300:
                    raise AlertError(f"delivery rejected with HTTP {status_code}")
            else:
                if not (email_from and email_to and smtp_host):
                    raise AlertError(
                        "email needs --email-from, --email-to and --smtp-host")
                email = _email_message(message, sender=email_from, recipient=email_to)
                transport.send_mail(
                    email, smtp_host, smtp_port, smtp_user,
                    os.environ.get(CREDENTIAL_ENV["email"]) or None, smtp_tls)
        except AlertError as exc:
            # One failed destination must not abort the whole batch; the receipt
            # records it so a silent channel is visible.
            receipt["errors"].append(str(exc))
            continue
        state.sent[key] = clock
        state.total_sent += 1
        receipt["sent"] += 1
        receipt["delivered_fingerprints"].append(key)

    if dry_run:
        receipt["dry_run"] = True
    receipt["state"] = state.to_dict()
    receipt["notes"] = [
        "Suppressed counts are reported explicitly: a quiet channel caused by "
        "suppression is different from a quiet channel caused by calm hosts.",
        "Duplicates are keyed on host, status and reason codes, not on score, so the "
        "same problem recurring is not re-sent within the quiet window.",
        "Alert content is a triage hint; CABID does not judge intent and does not act.",
    ]
    return receipt


def _redact_address(address: str | None) -> str:
    if not address:
        return "(unset)"
    local, separator, domain = str(address).partition("@")
    if not separator:
        return "…"
    return f"{local[:1]}…@{domain}"


def write_state(state: AlertState, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(state.to_dict(), indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    return destination


def load_state(path: str | Path) -> AlertState:
    source = Path(path)
    if not source.exists():
        return AlertState()
    try:
        return AlertState.from_dict(json.loads(source.read_text(encoding="utf-8")))
    except json.JSONDecodeError as exc:
        raise AlertError(f"{source}: invalid state JSON: {exc}") from exc


def send_from_stream_report(report: dict, *, channel: str, transport: Transport | None = None,
                            host: str | None = None, minimum: str = "SUSPICIOUS",
                            **kwargs) -> dict:
    """Convenience wrapper that turns a stream report's worst window into an alert.

    A stream report aggregates many windows, so alerting on it means alerting on the
    worst one. The synthetic session shape carries the window's reason codes through,
    which keeps the dedup fingerprint meaningful.
    """
    windows = report.get("windows_scored") or []
    if not windows:
        return send([], channel=channel, transport=transport, host=host,
                    minimum=minimum, **kwargs)
    worst = max(windows, key=lambda window: (SEVERITY_ORDER.index(window["status"])
                                             if window.get("status") in SEVERITY_ORDER
                                             else -1,
                                             float(window.get("anomaly_score") or 0.0)))
    synthetic = {
        "status": worst.get("status"),
        "anomaly_score": worst.get("anomaly_score"),
        "event_count": worst.get("event_count"),
        "reasons": [{"code": code} for code in worst.get("reason_codes") or []],
    }
    return send([synthetic], channel=channel, transport=transport, host=host,
                minimum=minimum, **kwargs)


TransportFactory = Callable[[], Transport]
