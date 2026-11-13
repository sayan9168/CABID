"""Local read-only dashboard server for CABID (standard library only).

Design notes:
* Binds to 127.0.0.1 by default; ``--host`` must be given explicitly to expose it.
* Honours the hosting platform's preview proxy: Vercel forwards ``/__proxy/<port>/...``
  and Alibaba/e2b hosts forward absolute-form request targets
  (``POST http://<host>/api/analyze``). Only same-origin authority is accepted,
  and path prefixes used by the proxy are stripped before routing.
* Serves exactly four JSON endpoints plus one static HTML page.
* Request bodies are size-capped, dataset names are whitelisted, and no
  arbitrary filesystem path from the client is ever opened.
* It is a research viewer, not a multi-user service: no authentication, no
  persistence, no background collection.
"""
from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .baseline import build_profile
from .filters import FilterError, filter_events
from .benchmark import evaluate, generate_cases
from .config import ConfigError, load_config
from .detector import analyze, analyze_windows
from .ingest import normalize_many, read_jsonl
from .normalize import EventError
from .aggregate import IngestError, ingest_sources
from .policy import PolicyError, evaluate_policy, load_policy

MAX_BODY_BYTES = 8 * 1024 * 1024
MAX_EVENTS = 200_000
DATASET_DIR = Path(__file__).resolve().parent.parent / "datasets" / "synthetic"
_ASSET = Path(__file__).resolve().parent / "dashboard.html"
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_PROXY_PREFIX = re.compile(r"^/(?:__proxy/\d+|_arena_proxy)(?=/|$)")


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


def list_datasets(directory: Path = DATASET_DIR) -> list[dict]:
    items: list[dict] = []
    if not directory.is_dir():
        return items
    for path in sorted(directory.glob("*.jsonl")):
        items.append({"name": path.name, "bytes": path.stat().st_size})
    return items


def _dataset_path(name: str, directory: Path = DATASET_DIR) -> Path:
    if not _SAFE_NAME.match(name or ""):
        raise ApiError(400, "invalid dataset name")
    path = (directory / name).resolve()
    if path.parent != directory.resolve() or not path.is_file():
        raise ApiError(404, f"dataset not found: {name}")
    return path


def load_dataset(name: str, directory: Path = DATASET_DIR) -> list[dict]:
    path = _dataset_path(name, directory)
    try:
        return read_jsonl(path)
    except EventError as exc:
        raise ApiError(422, str(exc)) from exc


def parse_events(payload: object) -> list[dict]:
    """Accept a list of objects or a JSONL string of at most MAX_EVENTS rows."""
    if isinstance(payload, str):
        rows = []
        for line in payload.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ApiError(422, f"invalid JSONL: {exc}") from exc
        payload = rows
    if not isinstance(payload, list):
        raise ApiError(422, "events must be a JSON array or JSONL string")
    if len(payload) > MAX_EVENTS:
        raise ApiError(413, f"too many events (limit {MAX_EVENTS})")
    try:
        return normalize_many(payload)
    except EventError as exc:
        raise ApiError(422, str(exc)) from exc


def analyze_payload(payload: dict) -> dict:
    if "datasets" in payload:
        names = payload.get("datasets")
        if not isinstance(names, list) or not names:
            raise ApiError(422, "datasets must be a non-empty list of dataset names")
        try:
            merged = ingest_sources([_dataset_path(name) for name in names[:16]])
        except (IngestError, ApiError) as exc:
            raise ApiError(422 if isinstance(exc, IngestError) else exc.status, str(exc))
        events = merged.pop("events")
        sources = merged
    else:
        events = parse_events(payload.get("events"))
        sources = None
    try:
        events, time_window = filter_events(events, payload.get("since"), payload.get("until"))
    except FilterError as exc:
        raise ApiError(422, str(exc)) from exc
    window = payload.get("window_seconds")
    if window is not None:
        try:
            window = float(window)
        except (TypeError, ValueError) as exc:
            raise ApiError(422, "window_seconds must be a number") from exc
        if window <= 0:
            raise ApiError(422, "window_seconds must be positive")
    config = payload.get("config") or {}
    try:
        report = analyze(events, config, policy=payload.get("policy") if isinstance(
            payload.get("policy"), dict) else None)
    except (ConfigError, ValueError) as exc:
        raise ApiError(422, str(exc)) from exc
    if sources is not None:
        report["sources"] = sources
    report["time_filter"] = time_window
    policy_payload = payload.get("policy")
    if isinstance(policy_payload, dict):
        report["policy"] = evaluate_policy(events, policy_payload, report.get("reasons"))
    elif payload.get("policy", "default") is not False:
        # The UI shows default-policy findings unless policy evaluation is disabled.
        report["policy"] = evaluate_policy(events, None, report.get("reasons"))
    if window is not None:
        report["windowed"] = analyze_windows(events, window, config, None,
                                             policy=payload.get("policy") if isinstance(
                                                 payload.get("policy"), dict) else None)
    return report


def benchmark_payload(query: dict) -> dict:
    def as_int(key: str, default: int, low: int, high: int) -> int:
        raw = query.get(key)
        if raw is None or raw == "":
            return default
        try:
            value = int(raw)
        except ValueError as exc:
            raise ApiError(422, f"{key} must be an integer") from exc
        if not low <= value <= high:
            raise ApiError(422, f"{key} must be between {low} and {high}")
        return value

    seed = as_int("seed", 20261113, -2**31, 2**31 - 1)
    per_class = as_int("per_class", 25, 1, 200)
    return evaluate(generate_cases(seed, per_class))


def build_baseline_payload(payload: dict) -> dict:
    datasets = payload.get("datasets") or []
    if not isinstance(datasets, list) or not datasets:
        raise ApiError(422, "datasets must be a non-empty list of dataset names")
    sessions = [(name, load_dataset(name)) for name in datasets[:32]]
    try:
        return build_profile([(name, events) for name, events in sessions if events], minimum_sessions=1)
    except ValueError as exc:
        raise ApiError(422, str(exc)) from exc


class CabidHandler(BaseHTTPRequestHandler):
    server_version = f"CABID/{__version__}"
    config_path: str | None = None
    policy_path: str | None = None

    def log_message(self, fmt: str, *args) -> None:  # keep the console quiet
        return

    # -- helpers ---------------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, payload: object, status: int = 200) -> None:
        self._send(status, json.dumps(payload, sort_keys=True).encode("utf-8"),
                   "application/json; charset=utf-8")

    def _read_body(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ApiError(400, "invalid Content-Length")
        if length < 0 or length > MAX_BODY_BYTES:
            raise ApiError(413, "request body too large")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(400, f"invalid JSON body: {exc}") from exc
        if not isinstance(payload, dict):
            raise ApiError(400, "request body must be a JSON object")
        return payload

    def _guard(self) -> bool:
        """Reject cross-origin writes; the dashboard is same-origin only."""
        origin = self.headers.get("Origin")
        if origin and self.command not in {"GET", "HEAD"}:
            host = self.headers.get("Host", "")
            if urlparse(origin).netloc != host:
                self._json({"error": "cross-origin requests are not allowed"}, 403)
                return False
        return True

    def _request_path(self) -> str:
        """Normalise proxied absolute-form targets and hosting prefixes."""
        parsed = urlparse(self.path)
        host_header = (self.headers.get("Host") or "").lower()
        if parsed.netloc and host_header and parsed.netloc.lower() != host_header:
            return ""  # absolute-form target pointing at a different authority
        return _PROXY_PREFIX.sub("", parsed.path) or "/"

    # -- routes ----------------------------------------------------------
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path, query = self._request_path(), parse_qs(parsed.query)
        if not path:
            self._json({"error": "unexpected absolute-form request target"}, 400)
            return
        try:
            if path in {"/", "/index.html", "/dashboard"}:
                self._page()
            elif path == "/api/health":
                self._json({"status": "ok", "version": __version__,
                            "datasets": len(list_datasets())})
            elif path == "/api/datasets":
                self._json({"datasets": list_datasets()})
            elif path.startswith("/api/datasets/"):
                name = path.rsplit("/", 1)[-1]
                self._json({"name": name, "events": load_dataset(name)})
            elif path == "/api/benchmark":
                self._json(benchmark_payload({key: values[0] for key, values in query.items()}))
            elif path == "/api/defaults":
                config = load_config(self.config_path)
                policy = load_policy(self.policy_path)
                self._json({"config": config, "policy": policy})
            else:
                self._json({"error": f"no route for {path}"}, 404)
        except ApiError as exc:
            self._json({"error": str(exc)}, exc.status)
        except (OSError, ValueError, PolicyError) as exc:
            self._json({"error": str(exc)}, 500)

    def do_POST(self) -> None:
        if not self._guard():
            return
        path = self._request_path()
        if not path:
            self._json({"error": "unexpected absolute-form request target"}, 400)
            return
        try:
            payload = self._read_body()
            if path == "/api/analyze":
                self._json(analyze_payload(payload))
            elif path == "/api/baseline":
                self._json(build_baseline_payload(payload))
            else:
                self._json({"error": f"no route for {path}"}, 404)
        except ApiError as exc:
            self._json({"error": str(exc)}, exc.status)
        except (OSError, ValueError, ConfigError, PolicyError, EventError) as exc:
            self._json({"error": str(exc)}, 500)

    def do_HEAD(self) -> None:
        self.do_GET()

    def _page(self) -> None:
        if not _ASSET.is_file():
            raise ApiError(500, "dashboard asset is missing from the package")
        body = _ASSET.read_bytes()
        self._send(200, body, "text/html; charset=utf-8")


def serve(host: str = "127.0.0.1", port: int = 8765, config: str | None = None,
          policy: str | None = None) -> ThreadingHTTPServer:
    handler = type("BoundCabidHandler", (CabidHandler,), {"config_path": config, "policy_path": policy})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd
