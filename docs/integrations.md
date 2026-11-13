# Integrations: Sigma import and STIX export

Two directions, one rule: never quietly change the meaning of someone else's data.

## Sigma import

Sigma rules are YAML. PyYAML is an **optional** extra, so the core package stays
dependency-free:

    python -m pip install 'cabid[sigma]'
    cabid import-sigma my-rule.yml -o imported-pack.json
    cabid analyze events.jsonl -r imported-pack.json

The output is a normal CABID rule pack plus a `provenance` block. The pack loads
through the same strict validator as a hand-written one.

### The mapping is partial, and says so

Sigma's detection language is much larger than CABID's rule format. Rather than
approximating and hoping, translation reports what it could not express:

```json
{
  "provenance": {
    "source": "my-rule.yml",
    "sigma_id": "4d1f7c10-...",
    "sigma_status": "experimental",
    "unsupported": ["my-rule.yml: selection: field not mapped: User"],
    "caveat": "Field mapping is partial. Anything listed in 'unsupported' was dropped, ..."
  }
}
```

Read `unsupported` before trusting an imported rule. A rule with entries there is
**weaker** than the original.

### Field mapping

| Sigma | CABID slot |
| --- | --- |
| `Image`, `Image\|endswith`, `ImageName`, `OriginalFileName` | `executable` |
| `ParentImage`, `ParentImageName` | `parent_executable` |
| `CommandLine`, `TargetFilename`, `DestinationPort` | `target` |
| `ProcessName` | `process_name` |

`parent_executable` exists because the obvious shortcut — mapping `ParentImage`
onto `executable` too — would collapse Sigma's AND into an OR. A rule saying
"image is /bin/sh **and** parent is /nginx" would have matched any shell anywhere.
The parent lookup reads the parent's own event; a parent that is not in the window
matches nothing, so a translated rule can never fire on an unobserved parent.

If two *different* Sigma fields still land on the same slot, translation keeps the
first and records the collision in `unsupported` rather than silently widening the
rule.

### Modifiers

`|startswith`, `|endswith`, `|contains` are rewritten into globs (`foo*`, `*foo`,
`*foo*`). `|all` and `|any` are accepted as list semantics, which CABID already
has. `|re` and anything unknown are refused into `unsupported` — implementing a
half-regex engine would be worse than declining.

### Conditions

A single selection, `all of them`, `any of them`, and `1 of them`. Anything else
(`selection and not filter`, `|count() > 5`) raises an error rather than producing
a rule that fires differently from the original.

### Severity

`level` maps through `informational` → `low`. An unrecognised level is an error:
coercing it to a default would silently change the alerting level.

### Rules about Windows

A rule that references Windows-only fields is not refused, because it still
translates — but the import is tagged as approximate in `unsupported`. Do not
deploy those without checking every field by hand.

## STIX 2.1 export

    cabid export-stix report.json -o bundle.json --host web-01

Produces a `bundle` (spec 2.1) containing one `identity`, one `report`, one
`indicator` per rule finding, and one `note` per process-tree finding. The report's
`object_refs` lists every child object, so a consumer that walks references sees
the whole result.

### What the indicators are not

```json
{
  "type": "indicator",
  "pattern_type": "cabid-heuristic",
  "pattern": "cabid-rule:'shell-from-service'",
  "confidence": 70,
  "x_cabid_semantics": "pattern match, not a verdict"
}
```

- `pattern_type` is deliberately **not** `stix`. This is not a comparison
  expression another tool can sweep a filesystem with; it names a CABID rule that
  matched.
- `confidence` is mapped from rule severity (low 30, medium 50, high 70, critical
  90). It is an ordinal translation, not a measured probability.
- The bundle caveat states plainly that this is a triage hint and **not an
  attribution**: it does not identify an actor, campaign, or tool.

The report object also carries `x_cabid_status`, `x_cabid_anomaly_score`,
`x_cabid_score_semantics`, `x_cabid_config_digest`, `x_cabid_coverage`, and
`x_cabid_missing_event_types`, so a downstream system can see whether the verdict
rested on complete telemetry.

## What neither direction fixes

Exported indicators inherit every limitation of the report they came from. If a
report says `INSUFFICIENT_EVIDENCE`, the bundle says so too, and no downstream
platform should treat a low indicator confidence as an all-clear.
