# Containers and pid namespaces

A pid is not a global identifier. Inside a container, `pid 42` is whatever that
container calls 42; on the host, `pid 42` is something else entirely. Two
containers can both report a pid 1, and neither has a visible relationship to the
host process tree.

Merging such streams naively produces three specific failures:

1. Parent links that point at unrelated processes, because two different processes
   both claim pid 42.
2. False cycles in tree reconstruction, because A claims to be B's parent and B
   claims to be A's.
3. Inflated or collapsed entity counts, because distinct processes get merged.

CABID cannot read `/proc/<pid>/cgroup` from a log file, so it works from fields the
event itself carries.

## What it reads

| Field | Example | Meaning |
| --- | --- | --- |
| `container_id` or `container` | `abc123def456` | Scopes the pid. Any `[A-Za-z0-9_.:-]`, up to 128 chars. |
| `pid_ns` or `namespace_pid` | `42` | The pid as seen inside that scope. |

Both are optional. With no metadata, every event is treated as one host scope and
CABID behaves exactly as it did before the feature existed — there is no
behaviour change for existing datasets.

## What the report says

```json
{
  "container_aware": true,
  "scope_count": 3,
  "namespaced_event_count": 3,
  "host_event_count": 1,
  "scopes": [
    {"scope": "abc123", "events": 2, "process_count": 2,
     "process_names": ["nginx", "php"],
     "first_timestamp": 1.0, "last_timestamp": 2.0}
  ],
  "pid_collisions": [{"pid": 42, "scopes": ["abc123", "def456"]}],
  "collision_count": 1
}
```

`pid_collisions` is the interesting field. It tells you that pid 42 exists in two
different scopes — which is **expected and normal**, not suspicious. It matters
because it is precisely the case where naive merging would have produced a bogus
parent link.

The report also lists, in `notes`, that scopes come from event metadata only and
that cross-scope parent links are meaningless. That note is there so a reader does
not have to remember this page.

## When metadata is absent

`container_aware: false` means the sensor did not record container information.
That is not "there were no containers" — it means CABID cannot tell. Treat a
containerised workload's report accordingly, and prefer an ingest pipeline that
records `container_id` if you have one.

## What is not done

- No cgroup, mount-namespace, or `clone`-flag inspection. CABID reads logs.
- No automatic re-writing of `process_id`. Events are kept as reported; the scope
  is used for grouping, and the original host pid is preserved when a scoped view
  is needed.
- No cross-scope correlation. A container pid and a host pid are not matched to
  each other, because the metadata to do so correctly is usually gone by the time
  a log is exported.

`max_scopes` in the report is capped at 50 summaries to keep reports readable; the
counts above them stay exact.
