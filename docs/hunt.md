# Hunting with a query language

    cabid hunt 'event_type = file_write and process_name ~ "*sh"' events.jsonl
    cabid hunt 'process_name in [nginx, curl] and timestamp > 1760200000' events.jsonl --group-by target
    cabid hunt 'not event_type = heartbeat' events.jsonl -f jsonl -o trimmed.jsonl

`cabid hunt` answers "which events in this file match this condition?" without
piping JSONL through `jq`, and without silently returning nothing when the query
was malformed. Every query is parsed into a small tree first; a typo is an error,
never an empty result set.

## Grammar

    query    := or_expr
    or_expr  := and_expr ( "or" and_expr )*
    and_expr := unary ( "and" unary )*
    unary    := "not" unary | comparison | "(" or_expr ")"
    compare  := FIELD ( "=" | "!=" | ">" | ">=" | "<" | "<=" | "~" | "!~"
                       | "contains" ) VALUE
              | FIELD "in" "[" VALUE ( "," VALUE )* "]"
    VALUE    := bare-word | "double quoted" | 'single quoted' | number

Keywords (`and`, `or`, `not`, `in`, `contains`) and field names are
case-insensitive. `~` is a shell glob (`fnmatch` semantics), not a regular
expression: `*` and `?` only.

## Fields

Field names are resolved against the normalized schema, with a few aliases:

| Alias | Field |
| --- | --- |
| `pid` | `process_id` |
| `ppid` | `parent_process_id` |
| `name`, `process` | `process_name` |
| `path`, `exe` | `executable` |
| `kind`, `type` | `event_type` |
| `ts`, `time` | `timestamp` |

Numeric fields (`timestamp`, `process_id`, `parent_process_id`) are compared as
numbers, so `pid > 400` is numeric. Everything else is compared as text, so
`target = 443` looks for the literal string `443` rather than a port suffix —
use `target ~ "*:443"`. An unknown field is rejected with a "did you mean"
suggestion instead of matching nothing.

## Missing fields

A field absent from an event does not satisfy a positive comparison. It *does*
satisfy `!=` and `!~`, and that asymmetry is reported: the result carries
`field_presence` (`present`/`missing` counts per referenced field) and a note
when a field is absent from every event, because "no matches" from a typo'd
field and "no matches" from a quiet host look identical otherwise.

## Output and exit codes

    cabid hunt QUERY FILE                       # table (default), 50 rows
    cabid hunt QUERY FILE -f json               # full receipt: counts, notes, rollup
    cabid hunt QUERY FILE -f jsonl -o hits.jsonl
    cabid hunt QUERY FILE --group-by process_name --limit 0
    cabid hunt QUERY FILE --fields process_id,process_name,target
    cabid hunt QUERY FILE --fail-if-match       # exit 1 when anything matched

`--limit` bounds only the printed rows; every count in the receipt covers the
whole match set, and truncation is stated. A malformed query exits `2` with the
column and token that confused the parser; `--fail-if-match` exits `1` so a hunt
can gate CI or a cron job.

## Limitations

- The query engine scans the whole file in memory. It is a triage tool for
  fixtures and sampled windows, not an index over terabytes of logs.
- There is no `select`, no aggregation beyond counting, and no join. `--group-by`
  counts matches per value; it does not compute sums, percentiles, or time series.
- Matching is per event. A query cannot express "process A wrote X **and then**
  connected to Y" — that is what correlation rules and `cabid timeline` are for.
- `~` is a glob. There is no regex support, so character classes and anchors are
  not available.
- Text comparison is byte-for-byte after `str()`; no case folding, no Unicode
  normalisation, and no path canonicalisation. `target = /etc/shadow` will not
  match `/etc//shadow`.
- Query results are exactly the events the *sensor* emitted. A hunt that finds
  nothing tells you the events are not in the file, not that they did not happen.
