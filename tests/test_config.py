import json

import pytest

from cabid.config import ConfigError, config_digest, config_template, default_config, load_config, validate_config


def test_defaults_are_valid_and_stable():
    config = validate_config({})
    assert config["thresholds"]["suspicious"] == 0.55
    assert config["completeness"]["expected_event_types"] == sorted(config["completeness"]["expected_event_types"])
    assert config == default_config()


def test_merge_keeps_untouched_defaults():
    config = validate_config({"thresholds": {"suspicious": 0.4}})
    assert config["thresholds"]["suspicious"] == 0.4
    assert config["thresholds"]["high"] == 0.80
    assert config["weights"]["temporal"] == default_config()["weights"]["temporal"]


@pytest.mark.parametrize("bad", [
    {"nonexistent": 1},
    {"thresholds": {"suspicious": 0.9, "high": 0.5}},
    {"weights": {"temporal": -0.1}},
    {"thresholds": {"rate_per_minute": 0}},
    {"completeness": {"minimum_ratio": 1.5}},
    {"completeness": {"expected_event_types": ["not_an_event"]}},
    {"completeness": {"expected_event_types": []}},
    {"sequence": {"amplification": 0}},
    {"window_seconds": -3},
    {"thresholds": {"suspicious": True}},
    {"baseline": 42},
])
def test_invalid_configurations_are_rejected(bad):
    with pytest.raises(ConfigError):
        validate_config(bad)


def test_all_zero_weights_rejected():
    with pytest.raises(ConfigError):
        validate_config({"weights": {"temporal": 0, "causal": 0, "sequence": 0, "telemetry_gap": 0}})


def test_load_config_file_and_digest(tmp_path):
    path = tmp_path / "cfg.json"
    path.write_text(json.dumps({"$schema": "x", "format": "cabid-config/1",
                                "weights": {"temporal": 0.9}}), encoding="utf-8")
    config = load_config(path)
    assert config["weights"]["temporal"] == 0.9
    assert config_digest(config) == config_digest(dict(config))
    assert len(config_digest(config)) == 64


def test_load_config_reports_bad_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid JSON"):
        load_config(path)


def test_template_is_loadable():
    template = config_template()
    stripped = {k: v for k, v in template.items() if not k.startswith("$") and k != "format"}
    assert validate_config(stripped) == default_config()
