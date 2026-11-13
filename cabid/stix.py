"""Export findings as a STIX 2.1 bundle for threat-intel platforms.

CABID output is a heuristic triage artefact, so what maps to STIX cleanly is the
*observation*: which host, when, what pattern was seen. It is **not** an indicator
of compromise, and it is not an attribution. The bundle therefore:

* marks indicators with ``pattern_type: cabid-heuristic`` rather than pretending
  to be a standard STIX comparison pattern;
* embeds ``x_cabid_`` custom properties carrying the score, semantics, and config
  digest, so a consumer cannot mistake the object for a vetted IOC;
* sets ``confidence`` from the rule severity, documenting that it is a mapping of
  a heuristic, not a calibrated probability.

No network calls and no TAXII client: this writes a file a consumer can import.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

STIX_VERSION = "2.1"
# Fixed namespace so identifiers are stable for identical inputs.
_NAMESPACE = uuid.UUID("6f1c7a54-2d3e-4a7b-9c8d-1e2f3a4b5c6d")
_SEVERITY_CONFIDENCE = {"low": 30, "medium": 50, "high": 70, "critical": 90}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _stix_id(kind: str, seed: str) -> str:
    return f"{kind}--{uuid.uuid5(_NAMESPACE, seed)}"


def _iso(stamp: float) -> str:
    try:
        return datetime.fromtimestamp(float(stamp), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z")
    except (OverflowError, OSError, ValueError):
        return _now()


def build_bundle(report: dict, host: str = "unknown-host", source: str = "events.jsonl") -> dict:
    """Build a STIX 2.1 bundle from one CABID report."""
    if not isinstance(report, dict):
        raise ValueError("report must be a JSON object")
    created = _now()
    status = str(report.get("status") or "UNKNOWN")
    digest = str(report.get("config_digest") or "")[:64]
    seed = hashlib.sha256(json.dumps(
        {"status": status, "score": report.get("anomaly_score"), "host": host,
         "digest": digest}, sort_keys=True).encode()).hexdigest()[:16]

    identity = {
        "type": "identity",
        "spec_version": STIX_VERSION,
        "id": _stix_id("identity", "cabid-tool"),
        "created": created,
        "modified": created,
        "name": "CABID",
        "identity_class": "system",
        "description": "Heuristic behavioral analysis (research prototype)",
    }
    report_object = {
        "type": "report",
        "spec_version": STIX_VERSION,
        "id": _stix_id("report", seed),
        "created": created,
        "modified": created,
        "name": f"CABID analysis of {host}",
        "description": (
            "Heuristic triage output. Scores are not probabilities and findings are not "
            "attributions. Missing telemetry is reported as insufficient evidence, never as safe."
        ),
        "report_types": ["observed-data"],
        "published": created,
        "object_refs": [],
        "created_by_ref": identity["id"],
        "x_cabid_status": status,
        "x_cabid_anomaly_score": report.get("anomaly_score"),
        "x_cabid_score_semantics": report.get("score_semantics"),
        "x_cabid_config_digest": digest or None,
        "x_cabid_source": source,
        "x_cabid_event_count": report.get("event_count"),
        "x_cabid_coverage": (report.get("completeness") or {}).get("completeness"),
        "x_cabid_missing_event_types": (report.get("completeness") or {}).get(
            "missing_event_types", []),
    }

    objects = [identity, report_object]

    for finding in (report.get("rules") or {}).get("findings") or []:
        severity = str(finding.get("severity") or "medium")
        indicator = {
            "type": "indicator",
            "spec_version": STIX_VERSION,
            "id": _stix_id("indicator", f"{seed}:{finding.get('rule_id')}:{finding.get('start_timestamp')}"),
            "created": created,
            "modified": created,
            "created_by_ref": identity["id"],
            "name": str(finding.get("title") or finding.get("rule_id")),
            "description": (str(finding.get("description") or "")[:900]
                            + " [CABID pattern match, not a verdict]").strip(),
            "indicator_types": ["anomalous-activity"],
            # Not a standard STIX comparison expression on purpose: this describes a
            # CABID rule match, not a byte pattern another tool can apply.
            "pattern_type": "cabid-heuristic",
            "pattern": f"cabid-rule:'{finding.get('rule_id')}'",
            "valid_from": _iso(finding.get("start_timestamp") or 0.0),
            "confidence": _SEVERITY_CONFIDENCE.get(severity, 50),
            "x_cabid_rule_id": finding.get("rule_id"),
            "x_cabid_severity": severity,
            "x_cabid_matched_steps": finding.get("matched_steps"),
            "x_cabid_process_ids": finding.get("process_ids", []),
            "x_cabid_mitre_hint": finding.get("mitre"),
            "x_cabid_semantics": "pattern match, not a verdict",
            "x_cabid_host": host,
        }
        objects.append(indicator)
        report_object["object_refs"].append(indicator["id"])

    for finding in (report.get("tree") or {}).get("findings") or []:
        note = {
            "type": "note",
            "spec_version": STIX_VERSION,
            "id": _stix_id("note", f"{seed}:tree:{finding.get('kind')}:{finding.get('detail')}"),
            "created": created,
            "modified": created,
            "created_by_ref": identity["id"],
            "content": (str(finding.get("detail") or finding.get("kind") or "")[:900]
                        + " [CABID tree pattern match, context only, not a verdict]").strip(),
            "object_refs": [report_object["id"]],
            "x_cabid_kind": finding.get("kind"),
            "x_cabid_severity": finding.get("severity"),
        }
        objects.append(note)
        report_object["object_refs"].append(note["id"])

    if not report_object["object_refs"]:
        report_object["object_refs"].append(report_object["id"])

    return {
        "type": "bundle",
        "id": _stix_id("bundle", seed),
        "spec_version": STIX_VERSION,
        "objects": objects,
        "x_cabid_generated_by": "CABID",
        "x_cabid_caveat": (
            "Indicators use pattern_type 'cabid-heuristic' and must not be treated as "
            "validated indicators of compromise. Confidence values are mapped from "
            "CABID rule severity, not measured. This bundle is a triage hint and not "
            "an attribution: it does not identify an actor, campaign, or tool."
        ),
    }


def write_bundle(report: dict, path: str | Path, host: str = "unknown-host",
                 source: str = "events.jsonl") -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    bundle = build_bundle(report, host, source)
    destination.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination
