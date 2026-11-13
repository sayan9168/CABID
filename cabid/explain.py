"""Stable JSON rendering for analysis reports."""
import json

def render_report(report: dict, pretty: bool = True) -> str:
    return json.dumps(report, indent=2 if pretty else None, sort_keys=True)
