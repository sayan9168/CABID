import pytest

from cabid.baseline import build_profile
from cabid.coverage import (CoverageError, analyse_coverage, has_gaps,
                            observed_classes_from_events, render_markdown)
from cabid.ingest import read_jsonl
from cabid.rules import load_rules


def test_default_pack_is_derived_from_the_real_rules():
    report = analyse_coverage()
    assert report["format"] == "cabid-coverage/1"
    assert report["rule_count"] == len(load_rules(None))
    assert report["classes_to_rules"]["privilege_change"] == ["privilege-escalation-to-exec"]
    assert "T1059" in report["techniques"]
    assert report["techniques"]["T1059"] == ["shell-from-service"]


def test_heartbeat_without_a_rule_is_not_a_gap():
    report = analyse_coverage()
    assert "heartbeat" in report["event_classes"]["core"]
    assert "heartbeat" not in report["gaps"]["classes_without_rules"]
    assert has_gaps(report) is False


def test_observed_classes_make_unreachable_rules_visible():
    events = read_jsonl("datasets/synthetic/tree-example.jsonl")
    observed = observed_classes_from_events(events)
    report = analyse_coverage(observed_classes=observed)
    row = {item["rule_id"]: item for item in report["rules"]}
    assert row["shell-from-service"]["reachable"] is True
    assert row["privilege-escalation-to-exec"]["reachable"] is False
    assert "privilege-escalation-to-exec" in report["gaps"]["rules_unreachable_from_observed"]
    assert "process_exit" in report["gaps"]["observed_classes_missing_but_required"]
    assert has_gaps(report) is True


def test_all_classes_observed_makes_every_rule_reachable():
    from cabid.normalize import ALLOWED

    report = analyse_coverage(observed_classes=set(ALLOWED))
    assert report["gaps"]["rules_unreachable_from_observed"] == []
    assert report["gaps"]["observed_classes_missing_but_required"] == []
    assert has_gaps(report) is False


def test_unknown_observed_class_is_rejected():
    with pytest.raises(CoverageError, match="not in the schema"):
        analyse_coverage(observed_classes={"teleportation"})


def test_custom_rule_pack_changes_the_matrix():
    rules = [{"id": "only-writes", "title": "writes", "description": "",
              "severity": "low", "kind": "count", "filter": {"event_type": ["file_write"]},
              "window": 5, "min_count": 1, "max_matches": 10, "mitre": "", "enabled": True}]
    report = analyse_coverage(rules=rules)
    assert report["rule_count"] == 1
    assert report["classes_to_rules"]["file_write"] == ["only-writes"]
    assert "network_connect" in report["gaps"]["classes_without_rules"]
    assert report["gaps"]["rules_without_mitre_hint"] == ["only-writes"]
    assert report["techniques"] == {}


def test_policy_and_baseline_blocks_describe_their_inputs():
    sessions = [("a", read_jsonl("datasets/synthetic/example.jsonl")),
                ("b", read_jsonl("datasets/synthetic/tree-example.jsonl")),
                ("c", read_jsonl("datasets/synthetic/suspicious-example.jsonl"))]
    profile = build_profile(sessions, minimum_sessions=3)
    report = analyse_coverage(profile=profile)
    assert report["baseline"]["present"] is True
    assert report["baseline"]["session_count"] == 3
    assert report["policy"]["sensitive_ports"] == [22, 23, 445, 3389, 2375, 6379]
    assert report["policy"]["sensitive_path_patterns"] > 0


def test_no_baseline_is_stated_not_hidden():
    report = analyse_coverage()
    assert report["baseline"]["present"] is False
    assert "novelty component is inactive" in report["baseline"]["note"]


def test_components_expose_their_blind_spots():
    report = analyse_coverage()
    names = [item["component"] for item in report["components"]]
    assert names == ["temporal", "causal", "sequence", "telemetry_gap", "novelty"]
    for component in report["components"]:
        assert component["depends_on"]
        assert component["blind_spot"]


def test_optional_classes_are_listed_as_ungated():
    report = analyse_coverage()
    assert "privilege_change" in report["gaps"]["optional_classes_not_gated"]


def test_markdown_contains_every_section():
    markdown = render_markdown(analyse_coverage())
    for heading in ("# CABID coverage", "## Event classes", "## Rules",
                    "## Techniques the pack hints at", "## Components", "## Gaps",
                    "## Baseline", "## Caveats"):
        assert heading in markdown
    assert report_semantics() in markdown


def report_semantics() -> str:
    return analyse_coverage()["semantics"]


def test_rules_must_be_a_list():
    with pytest.raises(CoverageError, match="list of loaded rule dicts"):
        analyse_coverage(rules={"id": "not-a-list"})


def test_observed_classes_from_events_ignores_missing_types():
    assert observed_classes_from_events([{"event_type": "file_write"}, {}]) == {"file_write"}
