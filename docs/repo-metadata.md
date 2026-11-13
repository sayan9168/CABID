# Repository metadata

GitHub **topics** make the project discoverable in search and topic pages. They are
repository settings, not files, so they cannot be applied from a commit. This page
records the intended set so it can be applied reproducibly by whoever owns the
repository.

## The 20 topics

| # | Topic | Why |
| --- | --- | --- |
| 1 | `linux` | platform |
| 2 | `python` | language |
| 3 | `cybersecurity` | domain |
| 4 | `security-tools` | category |
| 5 | `security-research` | project framing |
| 6 | `intrusion-detection` | core problem |
| 7 | `hids` | host-based IDS category |
| 8 | `anomaly-detection` | method |
| 9 | `behavioral-analysis` | method |
| 10 | `threat-detection` | outcome |
| 11 | `blue-team` | practitioner audience |
| 12 | `incident-response` | workflow use |
| 13 | `dfir` | forensics/IR audience |
| 14 | `endpoint-security` | host telemetry domain |
| 15 | `telemetry` | completeness gate is central |
| 16 | `auditd` | supported source |
| 17 | `procfs` | supported source |
| 18 | `log-analysis` | input format |
| 19 | `explainable-ai` | every verdict carries ordered reasons |
| 20 | `sarif` | report export format |

Deliberately **excluded**: `machine-learning` and `deep-learning` (weights are
hand-set, not learned), `ebpf` (no kernel sensor is shipped), `edr` (the project
states it is not an EDR), `sigma` (no Sigma support). Tagging those would mislead
people arriving from topic pages.

## Apply — option 1: GitHub CLI

`--add-topic` takes a comma-separated list, so this is one command:

```bash
gh repo edit sayan9168/CABID \
  --add-topic linux,cybersecurity,security-tools,intrusion-detection,anomaly-detection,behavioral-analysis,threat-detection,hids,blue-team,incident-response,dfir,endpoint-security,security-research,telemetry,auditd,procfs,log-analysis,explainable-ai,sarif,python
```

## Apply — option 2: REST API

Topics are **replaced** by this call, which makes it fully idempotent — running it
twice gives the same 20 topics:

```bash
GITHUB_TOKEN=ghp_xxx   # needs a classic token with the `public_repo` scope (repo admin)
curl -sS -X PUT \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/sayan9168/CABID/topics \
  -d '{"names":["linux","cybersecurity","security-tools","intrusion-detection","anomaly-detection","behavioral-analysis","threat-detection","hids","blue-team","incident-response","dfir","endpoint-security","security-research","telemetry","auditd","procfs","log-analysis","explainable-ai","sarif","python"]}' \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(len(d["names"]), "topics:", ", ".join(sorted(d["names"])))'
```

## Apply — option 3: web UI

<https://github.com/sayan9168/CABID> → gear icon next to **About** → paste the
topics one at a time → **Save changes**.

## Verify

```bash
gh repo view sayan9168/CABID --json repositoryTopics --jq '[.repositoryTopics[].name] | (length|tostring) + " topics: " + join(", ")'
```

Expected: `20 topics: anomaly-detection, auditd, ...`

## Via an automation token

Tokens issued to GitHub Apps / integrations are commonly limited to
`contents`/`metadata` and receive `403 Resource not accessible by integration` on
this endpoint even when the repository shows `admin: true` in
`gh api repos/OWNER/REPO --jq .permissions`. Apply topics from an interactive
`gh auth login` session or the web UI instead.

## Suggested description

> A resource-efficient Linux cybersecurity research framework combining temporal
> behavior analysis, causal process relationships, and telemetry-aware confidence
> to detect and explain suspicious system activity.
