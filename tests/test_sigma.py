import json

import pytest

from cabid.rules import RULES_FORMAT, RuleError, load_rules, load_rules_from_dict
from cabid.sigma import SigmaError, import_sigma, translate_rule

SIGMA_RULE = """\
title: Shell spawned by service
id: 8f0e1c22-1111-4a2b-9c3d-1234567890ab
description: A service process spawned a shell.
level: high
logsource:
  product: linux
  service: auditd
detection:
  selection:
    Image|endswith:
      - '/sh'
      - '/bash'
    ParentImage|endswith: '/nginx'
  condition: selection
"""


def _write(tmp_path, text, name="rule.yml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_translate_produces_a_valid_cabid_rule():
    result = translate_rule(_yaml(SIGMA_RULE), "rule.yml")
    rule = result["rule"]
    assert rule["id"]
    assert rule["severity"] == "high"
    assert rule["kind"] in {"count", "sequence"}


def _yaml(text):
    try:
        import yaml
    except ImportError:  # pragma: no cover - pyyaml is a test dependency
        pytest.skip("PyYAML not installed")
    return yaml.safe_load(text)


def test_import_sigma_round_trips_through_the_rules_loader(tmp_path):
    path = _write(tmp_path, SIGMA_RULE)
    document = import_sigma(path)
    assert document["format"] == RULES_FORMAT
    assert document["provenance"]["sigma_id"].startswith("8f0e1c22")
    assert document["provenance"]["caveat"]
    # The strict loader must accept what the importer writes, provenance included.
    rules = load_rules_from_dict(document, origin=str(path))
    assert len(rules) == 1
    assert rules[0]["id"] == document["rules"][0]["id"]


def test_import_sigma_writes_a_loadable_pack(tmp_path):
    source = _write(tmp_path, SIGMA_RULE)
    document = import_sigma(source)
    pack = tmp_path / "pack.json"
    pack.write_text(json.dumps(document), encoding="utf-8")
    rules = load_rules(pack)
    assert [rule["id"] for rule in rules] == [document["rules"][0]["id"]]


def test_field_modifiers_become_globs():
    rule = translate_rule(_yaml(SIGMA_RULE), "rule.yml")["rule"]
    rendered = json.dumps(rule)
    assert "*/sh" in rendered or "*/bash" in rendered


def test_unmapped_field_is_reported_not_dropped():
    text = SIGMA_RULE.replace("ParentImage|endswith: '/nginx'",
                              "ParentImage|endswith: '/nginx'\n    TotallyUnknownField: value")
    result = translate_rule(_yaml(text), "rule.yml")
    assert any("TotallyUnknownField" in item for item in result["unsupported"])


REGEX_RULE = """\
title: Regex rule
level: medium
detection:
  selection:
    CommandLine|endswith: '/bin/sh'
    Image|re: '.*/(sh|bash)$'
  condition: selection
"""


def test_unsupported_modifier_is_reported():
    # CommandLine still maps, so the pack translates and the rejected regex
    # modifier must be reported rather than silently ignored.
    result = translate_rule(_yaml(REGEX_RULE), "rule.yml")
    assert any("re" in item for item in result["unsupported"])
    assert result["rule"]["filter"]["target"] == ["*/bin/sh"]


def test_unsupported_condition_is_rejected_loudly():
    text = SIGMA_RULE.replace("condition: selection", "condition: selection and not filter")
    with pytest.raises(SigmaError):
        translate_rule(_yaml(text), "rule.yml")


def test_informational_level_maps_to_low():
    text = SIGMA_RULE.replace("level: high", "level: informational")
    assert translate_rule(_yaml(text), "rule.yml")["rule"]["severity"] == "low"


def test_translated_rule_matches_only_when_the_parent_matches():
    """The AND must survive: this is the whole point of parent_executable."""
    from cabid.ingest import normalize_many
    from cabid.rules import evaluate_rules

    rule = translate_rule(_yaml(SIGMA_RULE), "rule.yml")["rule"]
    events = normalize_many([
        {"timestamp": 1, "event_type": "process_start", "process_id": 10,
         "parent_process_id": 1, "process_name": "nginx", "executable": "/usr/sbin/nginx"},
        {"timestamp": 2, "event_type": "process_start", "process_id": 11,
         "parent_process_id": 10, "process_name": "bash", "executable": "/bin/bash"},
        {"timestamp": 3, "event_type": "process_start", "process_id": 20,
         "parent_process_id": 1, "process_name": "cron", "executable": "/usr/sbin/cron"},
        {"timestamp": 4, "event_type": "process_start", "process_id": 21,
         "parent_process_id": 20, "process_name": "bash", "executable": "/bin/bash"},
        {"timestamp": 5, "event_type": "process_start", "process_id": 30,
         "parent_process_id": 999, "process_name": "bash", "executable": "/bin/bash"},
    ])
    report = evaluate_rules(events, [rule])
    assert report["finding_count"] == 1
    assert report["findings"][0]["process_ids"] == [11]


def test_parent_step_never_matches_an_unobserved_parent():
    from cabid.ingest import normalize_many
    from cabid.rules import evaluate_rules

    rule = translate_rule(_yaml(SIGMA_RULE), "rule.yml")["rule"]
    orphan = normalize_many([
        {"timestamp": 1, "event_type": "process_start", "process_id": 30,
         "parent_process_id": 999, "process_name": "bash", "executable": "/bin/bash"},
    ])
    assert evaluate_rules(orphan, [rule])["finding_count"] == 0


def test_nothing_translatable_explains_why():
    text = SIGMA_RULE.replace("Image|endswith", "UnknownA|endswith").replace(
        "ParentImage|endswith", "UnknownB|endswith")
    with pytest.raises(SigmaError, match="unknowna|UnknownA"):
        translate_rule(_yaml(text), "rule.yml")


def test_invalid_severity_is_rejected():
    text = SIGMA_RULE.replace("level: high", "level: urgent")
    with pytest.raises(SigmaError):
        translate_rule(_yaml(text), "rule.yml")


def test_rule_without_detection_is_rejected():
    with pytest.raises(SigmaError):
        translate_rule({"title": "nothing"}, "rule.yml")


def test_missing_file_is_reported(tmp_path):
    with pytest.raises(SigmaError):
        import_sigma(tmp_path / "absent.yml")


def test_provenance_must_be_an_object():
    document = {"format": RULES_FORMAT, "rules": [], "provenance": "not-an-object"}
    with pytest.raises(RuleError):
        load_rules_from_dict(document, origin="memory")


def test_bundled_example_rule_imports_cleanly():
    """docs/cabid-sigma.example.yml is referenced by the Makefile and the docs."""
    from pathlib import Path

    document = import_sigma(Path("docs/cabid-sigma.example.yml"))
    assert document["provenance"]["unsupported"] == []
    assert document["rules"][0]["severity"] == "high"
    load_rules_from_dict(document, origin="example")


def test_all_and_any_modifiers_are_accepted_as_list_semantics():
    text = SIGMA_RULE.replace("Image|endswith:", "Image|endswith|all:")
    result = translate_rule(_yaml(text), "rule.yml")
    assert result["rule"]["filter"]["executable"] == ["*/sh", "*/bash"]


def test_non_scalar_values_are_reported():
    rule = {"title": "T", "detection": {"selection": {"Image": [{"nested": 1}, "/bin/sh"]},
                                        "condition": "selection"}}
    result = translate_rule(rule, "rule.yml")
    assert any("non-scalar" in item for item in result["unsupported"])
    assert result["rule"]["filter"]["executable"] == ["/bin/sh"]


def test_selection_that_is_not_a_mapping_is_reported():
    rule = {"title": "T", "detection": {"selection": "a string", "condition": "selection"}}
    with pytest.raises(SigmaError, match="nothing translatable"):
        translate_rule(rule, "rule.yml")


def test_rule_without_a_title_is_rejected():
    with pytest.raises(SigmaError, match="no title"):
        translate_rule({"detection": {"selection": {"Image": "/bin/sh"}}}, "rule.yml")


def test_detection_that_is_not_a_mapping_is_rejected():
    with pytest.raises(SigmaError, match="detection must be a mapping"):
        translate_rule({"title": "T", "detection": ["nope"]}, "rule.yml")


def test_logsource_category_is_checked():
    rule = {"title": "T", "logsource": {"category": "registry_event"},
            "detection": {"selection": {"Image": "/bin/sh"}, "condition": "selection"}}
    with pytest.raises(SigmaError, match="unsupported logsource category"):
        translate_rule(rule, "rule.yml")


def test_missing_yaml_dependency_is_explained(monkeypatch, tmp_path):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("no yaml here")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    path = tmp_path / "rule.yml"
    path.write_text("title: T\n", encoding="utf-8")
    with pytest.raises(SigmaError, match="cabid\\[sigma\\]"):
        import_sigma(path)


def test_invalid_yaml_is_reported(tmp_path):
    path = tmp_path / "broken.yml"
    path.write_text("title: [unclosed\n", encoding="utf-8")
    with pytest.raises(SigmaError, match="invalid YAML"):
        import_sigma(path)


def test_non_mapping_document_is_reported(tmp_path):
    path = tmp_path / "list.yml"
    path.write_text("- one\n- two\n", encoding="utf-8")
    with pytest.raises(SigmaError, match="YAML mapping"):
        import_sigma(path)


def test_windows_only_rule_is_flagged_as_approximate(tmp_path):
    path = tmp_path / "win.yml"
    path.write_text(
        "title: Windows rule\nlevel: medium\nlogsource:\n  product: windows\n"
        "detection:\n  selection:\n    Image|endswith: '/cmd.exe'\n"
        "  condition: selection\n", encoding="utf-8")
    document = import_sigma(path)
    assert any("Windows" in item for item in document["provenance"]["unsupported"])
