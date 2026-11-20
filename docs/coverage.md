# What can this deployment actually see?

    cabid coverage
    cabid coverage --events events.jsonl -f md -o coverage.md
    cabid coverage -r rules.json -p policy.json -b baseline.json --fail-on-gap

`cabid coverage` is a static audit of the *configuration*, not of a detection
run. It answers three questions a green test suite tends to hide:

1. Which event classes does the completeness gate require, and which of them has
   no rule or component that would ever look at them?
2. Which rules in the loaded pack cannot fire at all against the classes this
   sensor emits?
3. Which ATT&CK techniques does the pack claim to hint at, and which rules have
   no technique label at all?

The output is a matrix, not a score. It never says "you are covered".

## What it derives

| Block | Source |
| --- | --- |
| `event_classes.core` / `.optional` | the schema in `cabid/normalize.py` |
| `event_classes.required_by_completeness_gate` | the configured completeness config |
| `classes_to_rules` | the `filter` block of every enabled rule in the pack |
| `techniques` | `mitre` strings on rules, parsed into T-ids |
| `rules[].reachable` | whether every class the rule needs is *observable* |
| `components[]` | the five scoring components with `depends_on` and `blind_spot` |
| `baseline` | whether a baseline profile was supplied, and what it covers |
| `policy` | how many sensitive paths/ports/allow-list entries are configured |

`reachable` is `null` when no `--events` file was supplied (nothing was observed,
so nothing can be called unreachable), and `false` when the events could not have
produced the class the rule needs. `heartbeat` is deliberately *not* treated as an
uncovered behavioural class: it is liveness telemetry that the gate requires, and
a rule for it would be noise.

## Gaps

    --fail-on-gap   # exit 1 when a class has no rule or a rule cannot fire

`gaps` reports `classes_without_rules`, `optional_classes_not_gated`,
`rules_unreachable_from_observed`, `rules_without_mitre_hint`, and — when events
were supplied — `observed_classes_missing_but_required`. That last one is the
interesting case: the gate requires a class your sensor never emitted, so every
report from that deployment will be `INSUFFICIENT_EVIDENCE` regardless of what
happens on the host.

## Limitations

- Coverage means *a rule or component references the class*. It is not evidence
  that the rule fires correctly, or that it fires at a useful rate. A covered
  class with a badly tuned rule is worse than an honest gap.
- The matrix is derived from the rule's declared `filter`, not from its code. A
  rule that inspects classes dynamically, or after Sigma import dropped
  unsupported clauses, can be marked reachable and still never fire. Check
  `provenance.unsupported` on imported rules.
- ATT&CK technique extraction reads `hint:` strings. It measures labelling
  effort, not detection of those techniques.
- `--events` only observes the sample you give it. A single 30-line fixture will
  make almost everything look unreachable; use a representative window.
- The component blind-spot lines are hand-written descriptions of the scoring
  code. They are correct only as long as this document and the code agree, and
  that is a maintenance obligation, not a proof.
- Coverage says nothing about precision. A deployment can cover every class and
  still be unable to tell an intrusion from a backup job.
