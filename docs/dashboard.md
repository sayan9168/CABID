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
- Runs the synthetic benchmark with adjustable seed and sample count.

## API

| Method | Route | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | version and dataset count |
| `GET` | `/api/datasets` | list bundled fixtures |
| `GET` | `/api/datasets/<name>` | normalized events from one fixture |
| `GET` | `/api/defaults` | resolved default configuration and policy |
| `GET` | `/api/benchmark?seed=&per_class=` | synthetic benchmark report |
| `POST` | `/api/analyze` | `{events, window_seconds?, config?, policy?}` → report |
| `POST` | `/api/baseline` | `{datasets: [...]}` → baseline profile |

`events` accepts either a JSON array or a JSONL string. Event normalization and
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
