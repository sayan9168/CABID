# Local analysis dashboard

CABID includes a read-only web console for interactive exploration. It is built
on the Python standard library: no Node, no build step, no external assets.

    cabid dashboard --port 8765

Then open <http://127.0.0.1:8765/>.

## What it does

- Loads a bundled synthetic fixture or any JSONL you paste in.
- Runs the same engine as `cabid analyze` (config, policy, windows).
- Shows the verdict, component weights, weighted contributions, ordered reasons,
  lifecycle transitions, policy findings, and per-window scores as a spark chart.
- Merges every bundled fixture in one analysis ("Merge all") and applies a time
  range (Since/Until), showing the kept/total event counts.
- Opens a **Processes** tab with the per-pid rollup: risk bar, contradictions,
  sensitive hits — the same numbers as the CLI `entities` block.
- **Rules** tab: which rules matched, severity, matched steps, affected pids.
- **Tree** tab: node/edge/depth/cycle counters, structural findings, common edges.
- **Process graph** tab: interactive process tree with filters, collapse, tooltips
  and a pinned detail panel.
- **Timeline** tab: event-density histogram over the analysed window.
- **Filter** tab: name-level rollup; click a name to filter the graph.
- Runs the synthetic benchmark with adjustable seed and sample count.

## Interactive graph, timeline, and filters

"Build graph & timeline" posts the current input to `/api/graph` and enables three
tabs. Nothing is derived in the browser: the server resolves the structure and the
UI renders it.

### Process graph

A collapsible tree with one resolved parent per pid.

| Interaction | Effect |
| --- | --- |
| Click a process | Pins it in the detail panel (parent, children, activity) |
| Click the caret, or Alt-click | Collapse or expand that subtree |
| Hover | Tooltip with pid, parent, and event count |
| Search box | Filters by process name or pid |
| "≥ 2 events" | Hides single-event noise processes |

Two decisions worth knowing:

- **The tree shows ancestors of matches.** Filtering to `payload` shows the chain
  that led to it. Hiding the parents of a matching child would remove exactly the
  context an investigator is looking for; matching nodes are outlined and
  non-matching ancestors are dimmed rather than dropped.
- **One parent per pid is enforced server-side.** The parent edge comes from the
  same resolution the scoring model uses, so a process cannot appear under two
  parents in the UI while the analysis used one. That would look like an analysis
  bug and be a display bug.

Node count is capped at 400. Truncation is reported in the UI — a partial tree
rendered as if whole is the failure mode worth avoiding.

### Timeline

Event density per bin across the analysed window, with the peak and median bin
reported. Bars are a histogram of activity, **not a score**: a tall bar means a
busy moment, and busy is not suspicious. Bins at or below half the median are
faded, which makes gaps and bursts visible at a glance.

### Filters

A name-level rollup (pids and event counts per process name). Clicking a row jumps
to the graph filtered to that name, which is the fastest path from "what is this
`sh` process" to "what did it start".

## Server-side derivation

`graph_payload` in `cabid/server.py` does the work, so the browser receives a
resolved structure rather than raw events plus instructions:

- `nodes` — pid, name, event count, resolved parent, root flag
- `edges` — parent → child with activity
- `bins` — timestamped counts with a normalised share
- `window` — start, end, duration
- `truncated`, `node_count`, `rendered_nodes`

A parent outside the observed window is kept as a dangling edge rather than
dropped, so an orphaned process renders as an orphan instead of a root.

## API

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | version and dataset count |
| `GET` | `/api/datasets` | list bundled fixtures |
| `GET` | `/api/datasets/<name>` | normalized events from one fixture |
| `GET` | `/api/defaults` | resolved default configuration and policy |
| `GET` | `/api/benchmark?seed=&per_class=` | synthetic benchmark report |
| `POST` | `/api/analyze` | `{events | datasets, since?, until?, window_seconds?, config?, policy?}` → report |
| `POST` | `/api/baseline` | `{datasets: [...]}` → baseline profile |
| `GET` | `/api/graph?dataset=<name>` | process graph and timeline for a fixture |
| `POST` | `/api/graph` | `{events, since?, until?}` → graph and timeline |

`/api/graph` returns 422 for malformed input, like every other route.

`events` accepts either a JSON array or a JSONL string. `datasets` accepts a list
of bundled fixture names and merges them exactly like the CLI multi-file mode.
`since`/`until` take ISO-8601 or Unix seconds. Event normalization, filtering, and
configuration validation are identical to the CLI, so an API error means the same
thing as a CLI error.

## Hosted previews

When the dashboard runs inside a hosting platform that proxies ports, the server
understands two proxy conventions: the Vercel-style prefix
(`/__proxy/<port>/api/...`) is stripped before routing, and absolute-form request
targets (`POST http://<host>/api/analyze`) are accepted when the authority matches
the `Host` header. A mismatched absolute-form authority is rejected with `400`, and
cross-origin POSTs stay blocked. Start with `--host 0.0.0.0` only when the platform
supplies its own access control.

## Security posture

- Binds to `127.0.0.1` by default. `--host 0.0.0.0` is an explicit opt-in and is
  **not** authenticated — never expose it to an untrusted network.
- Only files inside `datasets/synthetic/` are readable, and names are matched
  against a strict pattern, so requests cannot escape the directory.
- Request bodies are capped (8 MiB, 200 000 events).
- Cross-origin POSTs are rejected, responses are `no-store` with `nosniff`.
- No writes, no persistence, no telemetry, no outbound requests from the page.

The dashboard is a viewer for one trusted operator. It is not a multi-user
service and must not be used as a substitute for a secured application.

`/api/graph` follows the same caps as `/api/analyze` (8 MiB body, 200 000 events)
and additionally caps rendered nodes at 400 so a pathological input cannot hang
the browser.

## Limitations

- **The graph is a tree, not a DAG.** Each pid resolves to one parent, which is the
  model the scoring engine uses. Real process ancestry is a tree; the *observed*
  edges may form a graph when a pid is reused, and the graph view does not attempt
  to show both.
- **Truncation is real.** Past 400 processes the tree is partial. `truncated` is
  surfaced in the UI but the missing nodes are simply absent.
- **The timeline is unweighted.** Every event counts as one, so a chatty heartbeat
  looks as significant as a file write. Per-type filtering is not implemented.
- **No drill-down to events from the graph.** Selecting a process shows counts, not
  the underlying events; the Events tab shows the raw input instead.
- **Client state is per page load.** Collapsed subtrees, the selected process, and
  filters reset on reload; nothing is persisted.
- **The JS is tested by extraction, not in a browser.** The filtering and
  child-map helpers were exercised under Node against real `/api/graph` payloads,
  but no browser automation ran in this environment. Layout and rendering are
  unverified.
- **No virtualisation.** 400 nodes is fine; a much larger cap would need windowed
  rendering.
