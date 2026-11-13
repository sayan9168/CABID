## What changed

<!-- One or two sentences. What behaviour is different after this PR? -->

## Why

<!-- The problem this solves. Link the issue if there is one: Closes #123 -->

## Checks

- [ ] `make check` passes (pyflakes, mypy, coverage floor)
- [ ] New behaviour has a test that fails without the change
- [ ] Docs updated if a command, flag, report field, or event type changed
- [ ] `CHANGELOG.md` updated under `Unreleased`

## Claims and caveats

CABID's value depends on not overstating what it does. Tick what applies.

- [ ] No new claim of probability, attribution, or real-world detection accuracy
- [ ] New detection surfaces are labelled as heuristics/pattern matches, not verdicts
- [ ] Missing telemetry still yields `INSUFFICIENT_EVIDENCE`, never a pass
- [ ] Rule/tree output still does not change the weighted anomaly score
- [ ] No runtime dependency added to the core package (extras are fine)

## Report shape

If this changes the JSON report, list the added/removed/renamed keys:

```
```

## Anything reviewers should be suspicious of

<!-- Where are you least sure? What did you not test? -->
