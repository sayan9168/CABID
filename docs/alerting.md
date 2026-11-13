# Alerting

CABID deliberately does not contain hosts automatically, so notification is where a
finding actually reaches a human. This document covers delivery to Slack, Discord,
email, and generic webhooks — and, more importantly, the suppression that keeps the
channel worth reading.

```bash
# Preview what would be sent. No delivery, no credentials needed.
cabid alert report.json --channel slack --host web-01

# Deliver, with suppression state persisted between runs.
CABID_SLACK_WEBHOOK=https://hooks.slack.com/services/... \
  cabid alert report.json --channel slack --host web-01 \
         --state alert-state.json --send
```

## Dry run is the default

`cabid alert` without `--send` renders the exact payload it would deliver, applies
the full suppression logic, and exits without contacting anything. A first
integration cannot page an on-call engineer by accident, and the preview shows the
real payload shape rather than a description of it.

## Alert fatigue is the primary design problem

A sensor processing 10⁵ events/min with 60-second windows can produce a finding every
minute. An operator who receives a hundred nightly messages stops reading them, and a
channel nobody reads is worse than no channel — it creates the impression of
monitoring.

Four suppression stages apply, in order:

| Stage | Rule | Counted in the receipt as |
| --- | --- | --- |
| Severity floor | Only `SUSPICIOUS`, `HIGH_RISK`, `INSUFFICIENT_EVIDENCE` are alertable | `suppressed.below_threshold` |
| Deduplication | Same fingerprint within the quiet window | `suppressed.duplicate_within_window` |
| Rate limiting | Per-fingerprint, via the same window | `suppressed.duplicate_within_window` |
| Run budget | At most `--max-per-run` deliveries per invocation (default 20) | `suppressed.run_budget_exhausted` |

**Every suppression is counted and reported.** A receipt with `sent: 0` and
`suppressed.duplicate_within_window: 1` tells the operator the channel is quiet
because the finding is unchanged. Silence caused by filtering looks different from
silence caused by calm hosts, and the report keeps that distinction.

### The fingerprint

Deduplication keys on **host + status + sorted reason codes** — deliberately not on
the score or the timestamp:

```python
fingerprint({"status": "HIGH_RISK", "anomaly_score": 0.81, ...}, "web-01")  # 3e4c9129…
fingerprint({"status": "HIGH_RISK", "anomaly_score": 0.99, ...}, "web-01")  # 3e4c9129…
```

The same problem recurring with a slightly different score is the same problem.
Re-alerting on it is exactly what trains people to ignore the channel. A *different*
problem — different reason codes — produces a different fingerprint and alerts
immediately.

`INSUFFICIENT_EVIDENCE` is alertable because a blind sensor is an operational problem
somebody needs to know about. It is never presented as an attack signal.

## Channels

| Channel | Credential | Transport |
| --- | --- | --- |
| `slack` | `CABID_SLACK_WEBHOOK` | Block Kit message |
| `discord` | `CABID_DISCORD_WEBHOOK` | Content message, `allowed_mentions` disabled |
| `email` | `CABID_SMTP_PASSWORD` | `smtplib` with STARTTLS |
| `webhook` | `CABID_WEBHOOK_URL` | Structured JSON |

All four are projections of one channel-neutral message, so an operator reads the
same content regardless of destination:

```
*HIGH_RISK* on `web-01`
Anomaly score: 0.910 (heuristic, not a probability)
Events: 1200
Reason codes: temporal_rate_or_burst

• event rate 900/min exceeds bounds

Triage hint from behavioural pattern matching, not a verdict.
```

Discord payloads set `allowed_mentions: {"parse": []}` so an alert containing an
`@`-prefixed process name cannot ping a channel role.

## Credential hygiene

Webhook URLs are bearer credentials: anyone with the URL can post to the channel. So:

- URLs and SMTP passwords are read from the environment, never from the report or a
  config file;
- **every** rendered field is redacted — `hooks.slack.com/…#8682d5be`. The digest is
  enough to tell two destinations apart and useless for posting;
- delivery receipts record *which environment variable* was consulted
  (`credential_source`) and never its value;
- email recipients are redacted to `a…@example.com`;
- `destination_configured: true|false` lets an operator confirm setup without
  revealing the secret.

A test asserts that a secret placed in the environment never appears in a receipt.

## Failure handling

One failing destination does not abort a batch. Errors accumulate in `receipt.errors`,
the command still exits 0, and the undelivered findings are visible. This is
deliberate: exiting non-zero on a transient Slack 500 would discard the rest of a
night's alerts.

## Limits

- **Duplicate suppression is per-process unless state is persisted.** Pass `--state`
  to carry fingerprints between invocations; without it, each run starts fresh and
  every invocation can re-send the same finding.
- **State is a plain JSON file.** No locking. Two concurrent `cabid alert` runs
  sharing one state file can race and both deliver. Schedule one notifier per channel.
- **No retry or backoff.** A failed delivery is recorded and dropped; the next run
  re-sends only if the finding changed or the quiet window expired.
- **No receiver-side acknowledgement.** The receipt says the HTTP call returned 2xx,
  not that a human saw it.
- **Email uses `smtplib` directly**, so it needs a reachable SMTP relay. There is no
  sendmail integration.
- **Alert content is a triage hint.** The message says so, because a notification in
  a chat channel reads like an alert and the distinction matters.

## Files

| Path | Purpose |
| --- | --- |
| `cabid/alerting.py` | Fingerprinting, message building, suppression, four transports, redaction. |
| `cabid alert` | CLI, dry-run by default, `--state` for persisted suppression. |
| `tests/test_alerting.py` | 37 tests over a fake transport; no network access. |
