# Detection policy

Heuristics answer *"does this stream look unusual?"*. A policy answers the
operational question *"does it touch anything we declared sensitive, and which
known-good activity should be acknowledged?"*. Policy output is additive
context: it never rewrites the heuristic score.

## Apply a policy

    cabid analyze events.jsonl --policy policy.json --format md

Without `--policy`, default patterns are still evaluated (so findings are never
silently absent), and the report marks `policy_applied: false`.

## Policy file (`cabid-policy/1`)

```json
{
  "sensitive_paths": ["/etc/shadow", "/etc/sudoers", "/srv/app/secrets*"],
  "sensitive_ports": [22, 6379],
  "allow_process_names": ["systemd", "sshd"],
  "allow_executables": ["/usr/lib/systemd/", "/usr/sbin/sshd"],
  "suppress_rule_codes": ["temporal_rate_or_burst"],
  "notes": "Reviewed 2026-11-13; file patterns scoped to this host group."
}
```

| Key | Behaviour |
| --- | --- |
| `sensitive_paths` | Glob or prefix patterns matched against the basename-stripped target of `file_write` events. |
| `sensitive_ports` | Integer ports matched against `network_connect` targets (`host:port`, `[v6]:port`, `host@port`). |
| `allow_process_names` / `allow_executables` | Known-good matching. Findings are still reported but marked `allow_listed_process: true` so reviewers can triage quickly. |
| `suppress_rule_codes` | Reason codes removed from the report's `reasons` list. Suppressed codes are listed in the output, never dropped silently. |

Unknown keys, non-string patterns, and out-of-range ports are rejected with exit
status `2`.

## What a finding means — and does not mean

- `sensitive_path_write` means a **write-capable** event targeted a declared
  pattern. For auditd input this is open intent, not proof that bytes changed.
- `sensitive_port_connect` means a successful connection event targeted a
  sensitive port. It does not assert data exfiltration.
- Findings include a bounded `target_ref` (basename, max 120 chars) rather than
  the full command line, to limit accidental secret capture in reports.

## Suppressions are governance, not detection

Suppressing `telemetry_gap` will make a partial sensor look conclusive. Record
every suppression with the policy file (the report lists the suppressed codes)
and review it when the sensor changes.
