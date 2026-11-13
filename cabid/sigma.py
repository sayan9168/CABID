"""Best-effort import of a Sigma rule subset into CABID correlation rules.

Sigma is a large, YAML-based, vendor-neutral format. This module is a *translator
for a deliberately small subset*, not a Sigma engine: it reads a narrow YAML
dialect (no anchors, no multi-document streams, no tags) and maps only the fields
CABID actually has (``event_type``, ``process_name``, ``executable``, ``target``).

Anything it cannot map is reported in ``unsupported`` rather than silently dropped,
because a Sigma rule that looks imported but lost its conditions is worse than one
that was refused. ``condition`` support is limited to a single selection, ``all of
them``, or ``1 of them``; anything with ``|count()|``, ``|near|``, or nested boolean
logic is refused.

Requires PyYAML when importing from a file. Generating CABID JSON needs no
dependency; only the YAML read does.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from .rules import RULES_FORMAT

SIGMA_FORMAT_HINT = "sigma"
_SUPPORTED_LOGSOURCE = {"process_creation", "process_creation_linux", "file_event",
                        "file_event_linux", "network_connection", "process_access"}
_FIELD_MAP = {
    "imagename": "executable",
    "image": "executable",
    "originalfilename": "executable",
    "commandline": "target",
    "targetfilename": "target",
    "targetobject": "target",
    "parentimagename": "parent_executable",
    "parentimage": "parent_executable",
    "processname": "process_name",
    "destinationport": "target",
}
_EVENT_HINT = {
    "process_creation": "process_exec",
    "process_creation_linux": "process_exec",
    "file_event": "file_write",
    "file_event_linux": "file_write",
    "network_connection": "network_connect",
    "process_access": "kernel_state_change",
}
_WINDOWS_ONLY_HINT = re.compile(r"(?i)\b(windows|win_|sysmon|eventid|winlog)\b")


class SigmaError(ValueError):
    """Raised when a Sigma rule cannot be read or translated."""


def _load_yaml(path: Path) -> dict:
    try:
        import yaml  # type: ignore[import-untyped]  # optional extra, not a core dep
    except ImportError as exc:  # pragma: no cover - depends on environment
        raise SigmaError(
            "importing Sigma rules needs PyYAML: pip install 'cabid[sigma]'"
        ) from exc
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SigmaError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(document, dict):
        raise SigmaError(f"{path}: a Sigma rule must be a YAML mapping")
    return document


# Modifiers become glob operators. Sigma's default (no modifier) is exact match,
# which is also a valid glob, so it needs no rewriting.
_MODIFIERS = {
    "endswith": lambda value: f"*{value}",
    "startswith": lambda value: f"{value}*",
    "contains": lambda value: f"*{value}*",
}


def _apply_modifiers(raw_key: str, values: list, where: str,
                     unsupported: list[str]) -> tuple[list[str] | None, str | None]:
    """Split ``Field|mod1|mod2`` and rewrite values into glob patterns."""
    parts = str(raw_key).split("|")
    field_name, modifiers = parts[0], [part.lower() for part in parts[1:]]
    field = _FIELD_MAP.get(field_name.lower().replace("_", ""))
    if field is None:
        unsupported.append(f"{where}: field not mapped: {field_name}")
        return None, None
    transforms = []
    for modifier in modifiers:
        if modifier in {"all", "any"}:
            continue  # list semantics; CABID already ORs list values
        if modifier == "re":
            unsupported.append(f"{where}: regex modifier not supported for {raw_key}")
            return None, None
        if modifier not in _MODIFIERS:
            unsupported.append(f"{where}: modifier not supported: {modifier}")
            return None, None
        transforms.append(_MODIFIERS[modifier])

    rewritten: list[str] = []
    for item in values:
        if not isinstance(item, (str, int)):
            unsupported.append(f"{where}: non-scalar value for {raw_key}")
            continue
        text = str(item)
        for transform in transforms:
            text = transform(text)
        rewritten.append(text)
    return rewritten, field


def _selection_items(selection: dict, where: str) -> tuple[list[dict], list[str]]:
    """Turn a Sigma selection mapping into CABID filter keys."""
    mapped: dict[str, list[str]] = {}
    origins: dict[str, str] = {}
    unsupported: list[str] = []
    for raw_key, value in selection.items():
        values = value if isinstance(value, list) else [value]
        rewritten, field = _apply_modifiers(str(raw_key), values, where, unsupported)
        if field is None or not rewritten:
            continue
        if field in origins and origins[field] != str(raw_key):
            # Sigma ANDs distinct fields. CABID has one slot per field here, so a
            # second distinct key would turn an AND into an OR. Say so instead.
            unsupported.append(
                f"{where}: cannot express AND of {origins[field]!r} and {raw_key!r} "
                f"(both map to {field!r}); using {origins[field]!r} only, rule is weaker")
            continue
        origins[field] = str(raw_key)
        mapped.setdefault(field, []).extend(rewritten)
    return ([mapped] if mapped else []), unsupported


def translate_rule(rule: dict, source: str = "sigma") -> dict:
    """Translate one parsed Sigma rule into a CABID rule dict."""
    if not isinstance(rule, dict):
        raise SigmaError(f"{source}: rule must be a mapping")
    title = str(rule.get("title") or "").strip()
    if not title:
        raise SigmaError(f"{source}: rule has no title")
    rule_id = re.sub(r"[^a-z0-9_-]+", "-",
                     str(rule.get("id") or title).lower()).strip("-")[:60] or "sigma-rule"
    logsource = rule.get("logsource") or {}
    category = str(logsource.get("category") or "").lower()
    if category and category not in _SUPPORTED_LOGSOURCE:
        raise SigmaError(f"{source}: unsupported logsource category: {category}")
    severity = str((rule.get("level") or "medium")).lower()
    severity = {"informational": "low", "critical": "critical"}.get(severity, severity)
    if severity not in {"low", "medium", "high", "critical"}:
        # Coercing to a default would quietly change the alerting level.
        raise SigmaError(
            f"{source}: unsupported severity {severity!r} "
            "(expected low, medium, high, critical, or informational)")

    detection = rule.get("detection") or {}
    if not isinstance(detection, dict):
        raise SigmaError(f"{source}: detection must be a mapping")
    condition = str(detection.get("condition") or "").strip()
    selections = {key: value for key, value in detection.items() if key != "condition"}
    if not selections:
        raise SigmaError(f"{source}: detection has no selections")

    if condition and condition not in {"all of them", "1 of them", "any of them"}:
        if condition not in selections:
            raise SigmaError(
                f"{source}: condition not supported (only a single selection, "
                f"'all of them', or '1 of them'): {condition!r}")
        chosen = [condition]
    elif condition in {"all of them", "any of them", "1 of them"}:
        chosen = list(selections)
    else:
        chosen = list(selections)[:1]

    steps: list[dict] = []
    unsupported: list[str] = []
    filters: list[dict] = []
    for name in chosen:
        value = selections[name]
        if not isinstance(value, dict):
            unsupported.append(f"{source}: selection {name!r} is not a simple mapping")
            continue
        items, problems = _selection_items(value, f"{source}: {name}")
        unsupported.extend(problems)
        filters.extend(items)

    if not filters:
        reasons = "; ".join(unsupported) if unsupported else "no selections were usable"
        raise SigmaError(f"{source}: nothing translatable after mapping fields ({reasons})")

    event_type = _EVENT_HINT.get(category)
    for item in filters:
        step: dict = {}
        if event_type:
            step["event_type"] = event_type
        if "process_name" in item:
            step["process_name"] = item.pop("process_name")
        if "executable" in item:
            step["executable"] = item.pop("executable")
        if "parent_executable" in item:
            step["parent_executable"] = item.pop("parent_executable")
        if "target" in item:
            step["target"] = item.pop("target")
        for leftover in item:
            unsupported.append(f"{source}: dropped key {leftover}")
        steps.append(step)

    if len(steps) == 1:
        # Single-selection Sigma rules become a count rule over one shape.
        translated = {
            "id": rule_id,
            "title": title,
            "description": str(rule.get("description") or "").strip()[:2000],
            "severity": severity,
            "kind": "count",
            "filter": steps[0],
            "window": 60,
            "min_count": 1,
            "mitre": ", ".join(str(tag) for tag in (rule.get("tags") or [])
                               if str(tag).startswith("attack."))[:200],
        }
    else:
        for index, step in enumerate(steps):
            if index:
                step["within"] = 60
        translated = {
            "id": rule_id,
            "title": title,
            "description": str(rule.get("description") or "").strip()[:2000],
            "severity": severity,
            "kind": "sequence",
            "steps": steps,
            "mitre": ", ".join(str(tag) for tag in (rule.get("tags") or [])
                               if str(tag).startswith("attack."))[:200],
        }
    return {"rule": translated, "unsupported": unsupported}


def import_sigma(path: str | Path) -> dict:
    """Translate one Sigma YAML file into a CABID rules document."""
    source = Path(path)
    if not source.is_file():
        raise SigmaError(f"{source}: not a file")
    raw = _load_yaml(source)
    translated = translate_rule(raw, source.name)
    unsupported = list(translated["unsupported"])
    if _WINDOWS_ONLY_HINT.search(json.dumps(raw)):
        unsupported.append(
            "rule references Windows-specific fields or paths; the Linux mapping is approximate")
    return {
        "format": RULES_FORMAT,
        "name": f"imported from {source.name}",
        "description": "Translated from Sigma by CABID. Review before use.",
        "rules": [translated["rule"]],
        "provenance": {
            "source": source.name,
            "sigma_id": raw.get("id"),
            "sigma_status": raw.get("status"),
            "unsupported": unsupported,
            "caveat": "Field mapping is partial. Anything listed in 'unsupported' was dropped, "
                      "so this rule is weaker than the original Sigma rule.",
        },
    }
