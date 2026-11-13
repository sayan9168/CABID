# Response: containment plans and what CABID will not do to your host

CABID can turn a report into a containment plan. It can also execute a narrow,
audited part of that plan. Both are deliberately harder to use than the rest of the
tool, and this page explains why.

## The short version

    cabid analyze events.jsonl -o report.json
    cabid respond report.json -o report.response.json   # review this
    cabid respond report.json --apply --dry-run         # see what would happen
    cabid respond report.json --apply --confirm <digest>

Nothing runs until a human passes the plan's digest. The default outcome of
`cabid respond` is a document, not an action.

## Why this is not an auto-blocker, and never will be

Automated response driven by a heuristic score fails in two directions, and both
are worse than doing nothing.

**It kills innocent things.** The anomaly score is a triage hint in `[0, 1]`, not a
probability. On a busy host a deploy, a restart loop, or a backup job will
eventually produce a score that crosses a threshold. An auto-blocker attached to
that threshold has a false-positive rate measured in outages.

**It is a weapon.** This is the direction people miss. An attacker who learns which
shapes trigger containment does not need to defeat the detector — only to *emit*
those shapes. Fork a few shells from a service, write a file to a cron path, and the
defender suspends a process of your choosing. Automated response built on a
detectable heuristic is a remote DoS with extra steps.

So the design here is not "detect and block". It is:

**evidence → kill chain → gates → plan → human → narrow execution → audit**

Every gate below exists because of one of those two failure modes.

## 1. Evidence becomes a kill chain

Each pid collects evidence from four sources, and every piece keeps the source that
produced it:

| Source | Example |
| --- | --- |
| Correlation rules | `rule shell-from-service (high)` |
| Process tree | `tree interpreter_spawn` |
| Entity rollup | `sensitive reference /etc/shadow` |
| Policy findings | `policy hit on /etc/cron.d/x` |

Each piece of evidence is mapped to a coarse kill-chain phase: `initial_access`,
`execution`, `persistence`, `privilege_escalation`, `defense_evasion`,
`credential_access`, `discovery`, `lateral_movement`, `exfiltration`, `impact`.

These are mappings of **observed shapes**, not statements about intent. A rule
named `shell-from-service` says a service spawned a shell; it does not say the shell
was hostile. CGI handlers and admin tooling do this all day.

Then the chain is graded:

| Phases | Strength | What it means |
| --- | --- | --- |
| 0 | none | nothing to contain |
| 1 | `single_signal` | routinely ordinary deploy or admin work |
| 2 | `corroborated` | worth review; still reachable by a routine unit-file deploy |
| 3+ | `strong` | much harder to reach by accident |

The asymmetry matters: two phases are much easier to produce accidentally than
three. Requiring more than one phase is what stops the "one noisy rule = one killed
process" failure.

## 2. Gates

A destructive action needs to clear **all** of these. The first failure caps the
ladder at observation for that pid.

| Gate | Rule |
| --- | --- |
| `protected_process` | never contain `systemd`, `init`, `sshd`, `auditd`, `cron`, `dbus-daemon`, `dockerd`, `containerd`, pid 1, or the root of the observed tree |
| `kill_chain_corroboration` | at least **2 distinct phases** |
| `telemetry_sufficiency` | no containment on a stream that is missing event classes |
| `plan_budget` | at most `--max-destructive` (default 3) actions that take a process down |
| `containment_loop` | if the same pid has already been contained 3+ times, escalate to a human instead of acting again |

Some notes on the less obvious ones.

**Protected processes.** A defender that can be made to kill `sshd` has handed over
the host. Killing pid 1 stops the machine. Containing the root of the observed tree
hides everything beneath it, which is the opposite of an investigation.

**Telemetry sufficiency.** Containment based on a partial event stream is not a
response, it is a guess with consequences. If the report says
`INSUFFICIENT_EVIDENCE`, the plan can observe and capture, and nothing else.

**Containment loop.** This gate exists specifically for the attack described above.
An attacker who repeatedly triggers the detector to contain the same pid is
generating repeated outages. After the third time, the plan refuses further action
and says so, because the pattern is no longer "we found something", it is "something
is steering us".

**The budget counts suspension.** Suspension is reversible, but the process is down
while it lasts. Ten suspended services is an outage with extra steps, so the budget
counts anything that takes a process down, not only the irreversible actions.

## 3. The escalation ladder

Selection always picks the **lowest** rung the gates permit:

| Severity | Action | Destructive | Blast radius |
| --- | --- | --- | --- |
| 0 | `monitor` | no | none |
| 1 | `snapshot` | no | disk space for the evidence copy |
| 2 | `suspend_process` | no | **the process stops until resumed** |
| 3 | `quarantine_file` | no | a copy is written; the original stays readable |
| 4 | `kill_process` | **yes** | in-memory state is lost |
| 5 | `block_address` | **yes** | shared NAT/CDN can make this block unrelated traffic |
| 6 | `isolate_host`, `disable_account` | **yes** | connectivity or access is gone |

Suspension sits above snapshot and below kill on purpose: `SIGSTOP` stops the
activity *and* leaves the memory image intact, which is exactly what an
investigation needs. Killing is only reached when suspension is not permitted by
`--allow`.

Suspension is reported as a **reversible outage**, not as "observe only". A tidy
number that hides an outage is worse than an honest one.

## 4. The plan is a document

```json
{
  "format": "cabid-response/1",
  "plan_digest": "1c43f7c6...",
  "based_on": {"status": "SUSPICIOUS", "telemetry_sufficient": true, "..." : "..."},
  "kill_chains": [{"process_id": 401, "phases": [...], "chain_strength": "corroborated"}],
  "decisions": [{"process_id": 401, "recommended_action": "suspend_process",
                 "destructive": false, "blast_radius": "...",
                 "blocked_by": [], "alternatives": [...]}],
  "refusals": [{"process_id": 501, "reasons": ["single_phase"]}],
  "safety_review": {"would_break": [...], "irreversible_count": 0,
                    "reversible_outage_count": 1, "refused_count": 1},
  "gates": [...],
  "execute": {"command": "cabid respond <report.json> --apply --confirm <plan_digest>"}
}
```

The `plan_digest` is a SHA-256 over the whole document. It binds the plan a human
reviewed to the plan that runs: edit one action in the file and the digest no
longer matches, and execution is refused before anything happens.

`safety_review.would_break` is mandatory reading. If a plan cannot state what it
would break, it is not ready to run.

## 5. Execution is narrow and audited

`cabid/executor.py` can do four things:

- write an evidence copy of a decision,
- send `SIGSTOP` or `SIGKILL`,
- copy a file into a quarantine directory,
- print a shell command for a human.

It cannot touch audit rules, kernel modules, firewall tables, accounts, or delete
anything. The things it will not do are listed at the bottom of that file.

**Every step is audited before it runs**, not after. If the process dies mid-run,
the trail still says what was attempted — which is the case where you need it most.

    {"format": "cabid-audit/1", "action": "suspend_process", "outcome": "attempted",
     "detail": "signal SIGSTOP", "uid": 1000, "timestamp": 1794576399.1}
    {"format": "cabid-audit/1", "action": "suspend_process", "outcome": "sent",
     "detail": "signal SIGSTOP delivered"}

Network and account actions are **emitted, never executed**. `isolate_host` prints
an `nft` recipe for a human, because a tool that can silently drop all connectivity
on a host will eventually drop all connectivity on the wrong host.

Skip is also audited. A step that could not run (pid gone, no quarantine directory)
still leaves a record, because "the plan said suspend and nothing happened" is
exactly the state an investigator needs to be able to see afterwards.

## The loop is closed: containment is remembered

Every executed suspension, kill, or capture is recorded in the history database
(pid, action, timestamp only — nothing about the process itself). That record feeds
the `containment_loop` gate on the next run, which is how the attack described at
the top is caught: not by detecting it, but by noticing that the defender is being
made to act repeatedly.

## Try it without risk

    cabid analyze datasets/synthetic/tree-example.jsonl -o /tmp/r.json
    cabid respond /tmp/r.json

That report has incomplete telemetry, so the plan will refuse containment and
recommend observation. That is the intended behaviour, not a failure — and it is the
single most useful thing to look at before trusting any of this.

## What is still wrong with this feature

- **The phase mapping is hand-written.** It is a table of shapes, not a taxonomy
  validated against real intrusions.
- **A patient attacker can stay under two phases.** Slow, single-phase activity
  never earns containment. That is intentional, and it means this does not replace
  a human.
- **`suspend_process` on a container pid** may suspend the wrong host process if
  the event stream carried a namespaced pid. Check `containers` in the report
  first; scoped events keep the original id, but a plan targets the pid as reported.
- **No rollback.** Suspension can be undone with `SIGCONT`; kill cannot. There is
  no automatic resume, because resuming on a timer is its own kind of guess.
- **The executor has only been exercised against test-sized inputs** and pids the
  test owns. It has never contained anything real, and this page will not pretend
  otherwise.

Read `docs/limitations.md` before pointing any of this at a machine you care about.
