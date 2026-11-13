# Security policy

CABID is a defensive analysis tool. It reads event logs and reports heuristics; it
does not install sensors, alter system policy, or block anything.

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private advisory form:
**<https://github.com/sayan9168/CABID/security/advisories/new>**

If that is unavailable, open a minimal public issue asking for a private contact
channel and include no exploit detail.

Helpful in a report:

- affected version (`cabid --version`) and Python version;
- the module and function involved;
- whether the input is an event file, a configuration, a policy, a rule pack, or
  an HTTP request to `cabid dashboard`;
- a minimal reproduction, with any sensitive paths or hostnames replaced.

## What counts as a vulnerability

CABID parses untrusted input by design, so these are in scope:

| Area | Example |
| --- | --- |
| Input handling | a malformed JSONL, audit raw, config, policy, or rule file that crashes, hangs, or exhausts memory instead of failing cleanly |
| Path safety | escaping the `datasets/synthetic/` directory via `GET /api/datasets/<name>` |
| Request handling | cross-origin writes, request-body limits, header injection |
| Report rendering | scripting or markup injection via event content into HTML, Markdown, SARIF, or CSV output |
| Integrity | making `cabid seal --verify` report `verified: true` for edited content |
| Data leakage | the history database retaining paths, command lines, or addresses; the dashboard serving files outside its directory |

## What is out of scope

These are documented limitations, not vulnerabilities:

- **Detection accuracy.** A heuristic that misses or over-flags activity is a
  research result, not a security bug. Report it as a detection issue with the
  fixture and configuration.
- **Uncalibrated scores.** Every report states that scores are heuristics, not
  probabilities.
- **Missing telemetry.** An `INSUFFICIENT_EVIDENCE` verdict on a partial sensor is
  the intended behaviour.
- **Seal forgery by the key holder.** HMAC proves shared-secret knowledge; anyone
  who can verify can re-seal. This is stated in `docs/report-integrity.md`. Use
  `openssl dgst -sign` when non-repudiation is required.
- **Exposed dashboards.** `cabid dashboard --host 0.0.0.0` is unauthenticated by
  design and documented as loopback-only. Exposing it to an untrusted network is a
  deployment error.
- **Tampered history database.** `cabid-history.sqlite3` is a local convenience
  store, not a tamper-evident audit log.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.6.x | yes |
| ≤ 0.5.x | no — upgrade, the plugins-free core is drop-in |

## Safe use

- Run CABID only on systems and logs you own or are authorized to analyze.
- Exported logs can contain usernames, paths, and process arguments. Treat them as
  sensitive; reports truncate targets but do not redact everything.
- `cabid dashboard` binds to loopback by default. Do not change `--host` without
  putting an authenticating proxy in front of it.
- Keep `--seal-key-env` values out of shell history: pass them through the
  environment, never as a command-line argument.
