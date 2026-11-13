"""Local run history in SQLite, and baseline-vs-current trend comparison.

Runs are stored in a single local database so an analyst can ask "what did this
host look like yesterday?" without re-analyzing archived JSONL. Only summary
metrics, reason codes, and the ranked entity rollup are stored: raw event
content (paths, command lines, addresses) is never written to the database.
"""
from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

SCHEMA_VERSION = 1
DEFAULT_DB = "cabid-history.sqlite3"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    label TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL,
    anomaly_score REAL NOT NULL,
    event_count INTEGER NOT NULL,
    coverage REAL NOT NULL,
    config_digest TEXT,
    source TEXT,
    summary TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS runs_fingerprint ON runs(fingerprint, created_at);
CREATE INDEX IF NOT EXISTS runs_created ON runs(created_at);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS containments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    timestamp REAL NOT NULL,
    process_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    config_digest TEXT
);
CREATE INDEX IF NOT EXISTS containments_pid ON containments(process_id, timestamp);
"""


class HistoryError(ValueError):
    """Raised when the history database cannot be opened or used safely."""


def _connect(path: str | Path) -> sqlite3.Connection:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        connection = sqlite3.connect(str(destination))
        connection.executescript(_SCHEMA)
        connection.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', ?)", (str(SCHEMA_VERSION),))
        connection.commit()
    except sqlite3.DatabaseError as exc:
        raise HistoryError(f"{destination}: cannot use as a history database: {exc}") from exc
    return connection


def _summary(report: dict) -> dict:
    """Compact, content-free record of one analysis."""
    return {
        "components": report.get("components", {}),
        "contribution": report.get("contribution", {}),
        "reason_codes": [reason.get("code") for reason in report.get("reasons", [])],
        "missing_event_types": (report.get("completeness") or {}).get("missing_event_types", []),
        "top_entities": [
            {"process_id": item["process_id"], "names": item["process_names"],
             "risk": item["entity_risk"], "hits": item["sensitive_hits"]}
            for item in (report.get("entities") or {}).get("top_entities", [])[:5]
        ],
        "policy_findings": (report.get("policy") or {}).get("finding_count", 0),
        "windowed_worst": ((report.get("windowed") or {}).get("summary") or {}).get("worst_status"),
    }


def record_run(report: dict, path: str | Path = DEFAULT_DB, label: str = "run",
               source: str | None = None, fingerprint: str = "local") -> int:
    """Persist one report summary; returns the new row id."""
    summary = _summary(report)
    created = datetime.now(timezone.utc).isoformat(timespec="seconds")
    connection = _connect(path)
    try:
        cursor = connection.execute(
            "INSERT INTO runs(fingerprint, label, created_at, status, anomaly_score, event_count, "
            "coverage, config_digest, source, summary) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (str(fingerprint)[:200], str(label)[:200], created,
             str(report.get("status", "UNKNOWN")), float(report.get("anomaly_score", 0.0)),
             int(report.get("event_count", 0)),
             float((report.get("completeness") or {}).get("completeness", 0.0)),
             str(report.get("config_digest") or ""), str(source or "")[:400],
             json.dumps(summary, sort_keys=True)),
        )
        connection.commit()
        if cursor.lastrowid is None:
            raise HistoryError("database did not return a row id for the recorded run")
        return int(cursor.lastrowid)
    except sqlite3.DatabaseError as exc:
        raise HistoryError(f"cannot record run: {exc}") from exc
    finally:
        connection.close()


def list_runs(path: str | Path = DEFAULT_DB, limit: int = 20) -> list[dict]:
    if limit < 1:
        raise HistoryError("limit must be at least 1")
    connection = _connect(path)
    try:
        rows = connection.execute(
            "SELECT id, label, created_at, status, anomaly_score, event_count, coverage, source "
            "FROM runs ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
    finally:
        connection.close()
    keys = ("id", "label", "created_at", "status", "anomaly_score", "event_count", "coverage", "source")
    return [dict(zip(keys, row)) for row in rows]


def _load_row(connection: sqlite3.Connection, run_id: int) -> dict:
    row = connection.execute(
        "SELECT id, label, created_at, status, anomaly_score, event_count, coverage, summary, config_digest "
        "FROM runs WHERE id = ?", (int(run_id),)).fetchone()
    if row is None:
        raise HistoryError(f"run {run_id} not found in history")
    return {
        "id": row[0], "label": row[1], "created_at": row[2], "status": row[3],
        "anomaly_score": row[4], "event_count": row[5], "coverage": row[6],
        "summary": json.loads(row[7]), "config_digest": row[8],
    }


def compare_runs(current: dict, baseline_id: int, path: str | Path = DEFAULT_DB) -> dict:
    """Differ the current report against a stored run."""
    connection = _connect(path)
    try:
        previous = _load_row(connection, baseline_id)
    finally:
        connection.close()
    current_summary = _summary(current)
    previous_summary = previous["summary"]
    component_delta = {}
    for name in sorted(set(current.get("components", {})) | set(previous_summary.get("components", {}))):
        now = float(current.get("components", {}).get(name, 0.0))
        before = float(previous_summary.get("components", {}).get(name, 0.0))
        component_delta[name] = round(now - before, 6)
    current_codes = [code for code in current_summary["reason_codes"] if code]
    previous_codes = [code for code in previous_summary.get("reason_codes", []) if code]
    current_entities = {item["process_id"]: item for item in current_summary["top_entities"]}
    previous_entities = {item["process_id"]: item for item in previous_summary.get("top_entities", [])}
    return {
        "baseline_run": {
            "id": previous["id"], "label": previous["label"], "created_at": previous["created_at"],
            "status": previous["status"], "anomaly_score": previous["anomaly_score"],
        },
        "current": {
            "status": current.get("status"), "anomaly_score": current.get("anomaly_score"),
            "coverage": (current.get("completeness") or {}).get("completeness"),
        },
        "score_delta": round(float(current.get("anomaly_score", 0.0)) - float(previous["anomaly_score"]), 6),
        "status_changed": current.get("status") != previous["status"],
        "component_delta": component_delta,
        "new_reason_codes": sorted(set(current_codes) - set(previous_codes)),
        "cleared_reason_codes": sorted(set(previous_codes) - set(current_codes)),
        "new_processes": sorted(set(current_entities) - set(previous_entities)),
        "disappeared_processes": sorted(set(previous_entities) - set(current_entities)),
        "config_changed": (current.get("config_digest") or "") not in {"", previous["config_digest"]},
        "note": "Comparison is metric-level; raw event content is never stored in history.",
    }


def record_containment(path: str | Path, process_id: int, action: str,
                       config_digest: str | None = None) -> int:
    """Note that a response action was taken, for loop detection.

    Only the pid, the action name, and the time are stored. That is enough to spot
    "this pid keeps getting contained", which is the shape of an attacker using the
    defender as a weapon, and it stores nothing about the process itself.
    """
    if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
        raise ValueError("process_id must be a positive integer")
    if not str(action).strip():
        raise ValueError("action must not be empty")
    connection = _connect(path)
    try:
        cursor = connection.execute(
            "INSERT INTO containments(created_at, timestamp, process_id, action, config_digest) "
            "VALUES(?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"),
             time.time(), process_id, str(action)[:64], config_digest),
        )
        connection.commit()
        return int(cursor.lastrowid or 0)
    finally:
        connection.close()


def list_containments(path: str | Path, limit: int = 200) -> list[dict]:
    """Recent containment records, newest first."""
    connection = _connect(path)
    try:
        rows = connection.execute(
            "SELECT timestamp, process_id, action, config_digest FROM containments "
            "ORDER BY timestamp DESC LIMIT ?", (max(1, int(limit)),)).fetchall()
    finally:
        connection.close()
    return [{"timestamp": row[0], "process_id": row[1], "action": row[2],
             "config_digest": row[3]} for row in rows]
