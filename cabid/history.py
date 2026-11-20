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
from datetime import datetime, timedelta, timezone
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
        "rule_ids": sorted({str(item.get("rule_id"))
                            for item in (report.get("rules") or {}).get("findings", [])
                            if item.get("rule_id")}),
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


def _parse_created(value: str) -> datetime:
    """Parse a stored ``created_at``; naive values are treated as UTC."""
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise HistoryError(f"unreadable created_at value: {value!r}") from exc
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _summary_rule_codes(summary: object) -> list[str]:
    """Rule ids recorded in a stored summary, tolerating older/unknown shapes."""
    try:
        payload = json.loads(summary) if isinstance(summary, str) else summary
    except (TypeError, ValueError):
        return []
    if not isinstance(payload, dict):
        return []
    codes = []
    for entry in payload.get("rule_ids") or []:
        text = str(entry).strip()
        if text:
            codes.append(text)
    return codes


def history_stats(path: str | Path = DEFAULT_DB) -> dict:
    """Counts and time span for one history database.

    This is a convenience store, not an audit log: the numbers describe what the
    file currently says, and anyone with write access could have changed it.
    """
    existed = Path(path).exists()
    connection = _connect(path)
    try:
        rows = connection.execute(
            "SELECT status, created_at, anomaly_score, summary FROM runs").fetchall()
        containments = connection.execute(
            "SELECT COUNT(*) FROM containments").fetchone()[0]
        schema = connection.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    finally:
        connection.close()
    status_counts: dict[str, int] = {}
    timestamps = []
    scores = []
    rule_codes: dict[str, int] = {}
    for status, created_at, score, summary in rows:
        status_counts[str(status)] = status_counts.get(str(status), 0) + 1
        timestamps.append(_parse_created(created_at))
        scores.append(float(score))
        for code in _summary_rule_codes(summary):
            rule_codes[code] = rule_codes.get(code, 0) + 1
    destination = Path(path)
    return {
        "format": "cabid-history-stats/1",
        "db": str(destination),
        "exists": existed,
        "schema_version": int(schema[0]) if schema else SCHEMA_VERSION,
        "run_count": len(rows),
        "containment_count": int(containments),
        "status_counts": dict(sorted(status_counts.items())),
        "first_run_at": min(timestamps).isoformat(timespec="seconds") if timestamps else None,
        "last_run_at": max(timestamps).isoformat(timespec="seconds") if timestamps else None,
        "max_anomaly_score": round(max(scores), 6) if scores else None,
        "rule_matches_by_code": dict(sorted(rule_codes.items())),
        "db_bytes": destination.stat().st_size if destination.exists() else 0,
        "note": "summary metrics only; no event content, command lines, or addresses are stored",
    }


def prune_history(path: str | Path = DEFAULT_DB, *, keep_last: int | None = None,
                  older_than_days: float | None = None, dry_run: bool = True,
                  vacuum: bool = False, now: datetime | None = None) -> dict:
    """Delete stored runs matching a retention rule.

    At least one rule is required, and nothing is deleted unless ``dry_run`` is
    False — a pruning command that can be run by accident is a data-loss bug
    waiting for a typo. The newest ``keep_last`` runs are always retained, even
    when they are older-wise eligible, so "keep 10 and drop anything over 30 days"
    cannot empty the table.
    """
    if keep_last is None and older_than_days is None:
        raise HistoryError("pruning needs --keep and/or --older-than-days; refusing to guess")
    if keep_last is not None:
        if isinstance(keep_last, bool) or not isinstance(keep_last, int) or keep_last < 1:
            raise HistoryError("keep_last must be a positive integer")
    if older_than_days is not None:
        if isinstance(older_than_days, bool) or not isinstance(older_than_days, (int, float)) \
                or older_than_days <= 0:
            raise HistoryError("older_than_days must be a positive number of days")
    cutoff = None
    if older_than_days is not None:
        reference = now or datetime.now(timezone.utc)
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)
        cutoff = reference - timedelta(days=float(older_than_days))

    connection = _connect(path)
    try:
        rows = connection.execute(
            "SELECT id, label, created_at, status FROM runs ORDER BY id DESC").fetchall()
        retained = {row[0] for row in rows[:keep_last]} if keep_last is not None else set()
        selected = []
        for row_id, label, created_at, status in rows:
            if row_id in retained:
                continue
            if cutoff is not None and _parse_created(created_at) >= cutoff:
                continue
            selected.append({"id": row_id, "label": label, "created_at": created_at,
                             "status": status})
        if not dry_run and selected:
            connection.executemany("DELETE FROM runs WHERE id = ?",
                                   [(row["id"],) for row in selected])
            connection.commit()
    except sqlite3.DatabaseError as exc:
        raise HistoryError(f"cannot prune history: {exc}") from exc
    finally:
        connection.close()

    if vacuum and not dry_run:
        # VACUUM cannot run inside a transaction; a fresh connection is the simple
        # way to be sure the file is actually compacted.
        connection = _connect(path)
        try:
            connection.executescript("VACUUM;")
            connection.close()
        except sqlite3.DatabaseError as exc:
            raise HistoryError(f"cannot vacuum history: {exc}") from exc

    return {
        "format": "cabid-history-prune/1",
        "db": str(path),
        "dry_run": bool(dry_run),
        "keep_last": keep_last,
        "older_than_days": older_than_days,
        "cutoff": cutoff.isoformat(timespec="seconds") if cutoff else None,
        "run_count_before": len(rows),
        "selected": len(selected),
        "deleted": 0 if dry_run else len(selected),
        "runs": selected[:50],
        "truncated": len(selected) > 50,
        "vacuumed": bool(vacuum and not dry_run),
        "note": _prune_note(dry_run, len(selected)),
    }


def _prune_note(dry_run: bool, selected: int) -> str:
    if selected == 0:
        return "nothing matched the retention rule; the database is unchanged"
    if dry_run:
        return "dry run: nothing was deleted; re-run with --apply"
    return "deleted rows cannot be recovered from this file"


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
