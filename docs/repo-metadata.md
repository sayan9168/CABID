# Repository metadata

GitHub **topics** make the project discoverable in search and topic pages. They are
repository settings, not files, so they cannot be applied from a commit. This page
records the intended set so it can be applied reproducibly by whoever owns the
repository.

## Apply

With the GitHub CLI authenticated as a repository admin:

```bash
gh repo edit sayan9168/CABID \
  --add-topic linux \
  --add-topic cybersecurity \
  --add-topic security-tools \
  --add-topic intrusion-detection \
  --add-topic anomaly-detection \
  --add-topic behavioral-analysis \
  --add-topic threat-detection \
  --add-topic telemetry \
  --add-topic auditd \
  --add-topic procfs \
  --add-topic explainable-ai \
  --add-topic security-research \
  --add-topic dfir \
  --add-topic endpoint-security \
  --add-topic sarif \
  --add-topic python \
  --add-topic cli
```

Or via the REST API (replace the token):

```bash
curl -L -X PUT \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/sayan9168/CABID/topics \
  -d '{"names":["linux","cybersecurity","security-tools","intrusion-detection",
       "anomaly-detection","behavioral-analysis","threat-detection","telemetry",
       "auditd","procfs","explainable-ai","security-research","dfir",
       "endpoint-security","sarif","python","cli"]}'
```

Note: topics need the repository **administration** permission. Automations and
GitHub App tokens are commonly limited to `contents`/`metadata` and receive
`403 Resource not accessible by integration` even when other admin actions work.

## Suggested description

> A resource-efficient Linux cybersecurity research framework combining temporal
> behavior analysis, causal process relationships, and telemetry-aware confidence
> to detect and explain suspicious system activity.

## Why this set

- **Discovery:** `linux`, `python`, `cli` — language and interface.
- **Domain:** `cybersecurity`, `security-tools`, `security-research`, `dfir`,
  `endpoint-security`, `threat-detection`.
- **Technique:** `intrusion-detection`, `anomaly-detection`, `behavioral-analysis`,
  `explainable-ai` — matches the actual method (weighted heuristics with reasons,
  not a learned model).
- **Telemetry:** `telemetry`, `auditd`, `procfs` — the sources actually supported.
- **Interop:** `sarif` — reports export to SARIF 2.1.0.

Avoid `machine-learning`, `deep-learning`, `ebpf`, `sigma`, and `edr`: the project
uses hand-set heuristic weights, ships no kernel sensor, and is explicitly not an
EDR. Mislabelling there would mislead people who find the repo by topic.
