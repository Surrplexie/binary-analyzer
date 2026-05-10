import json

import pytest

from binary_analyzer.rules import (
    RULES_ENV_VAR,
    load_default_rules,
    load_effective_rules,
    load_rules_from_path,
)
from binary_analyzer.risk import classify_risk_level


def test_load_default_rules_legacy_thresholds():
    r = load_default_rules()
    assert r.source == "package-default"
    assert r.risk_high_min_score == 40
    assert r.risk_high_min_strings == 5
    assert r.risk_medium_min_score == 20
    assert r.risk_medium_min_strings == 2
    assert "WriteProcessMemory" in r.suspicious_imports
    assert "powershell" in r.suspicious_string_keywords


def test_merge_extra_import_weight(tmp_path):
    path = tmp_path / "custom.json"
    path.write_text(json.dumps({"suspicious_imports": {"CustomMalApi": 99}}), encoding="utf-8")
    r = load_rules_from_path(path)
    assert r.suspicious_imports["CustomMalApi"] == 99
    assert r.suspicious_imports["fork"] == 8
    assert classify_risk_level(99, 0, r) == "HIGH"


def test_merge_risk_high_override_changes_classification(tmp_path):
    path = tmp_path / "high_only.json"
    path.write_text(
        json.dumps({"risk": {"high": {"min_suspicion_score": 100, "min_suspicious_string_count": 5}}}),
        encoding="utf-8",
    )
    r = load_rules_from_path(path)
    assert classify_risk_level(40, 0, r) == "MEDIUM"
    assert classify_risk_level(100, 0, r) == "HIGH"


def test_load_effective_rules_cli_over_env(monkeypatch, tmp_path):
    env_file = tmp_path / "env.json"
    env_file.write_text(json.dumps({"suspicious_imports": {"EnvOnly": 1}}), encoding="utf-8")
    cli_file = tmp_path / "cli.json"
    cli_file.write_text(json.dumps({"suspicious_imports": {"CliOnly": 2}}), encoding="utf-8")
    monkeypatch.setenv(RULES_ENV_VAR, str(env_file))
    r = load_effective_rules(cli_path=str(cli_file))
    assert "CliOnly" in r.suspicious_imports
    assert "EnvOnly" not in r.suspicious_imports


def test_load_effective_rules_env_when_no_cli(monkeypatch, tmp_path):
    env_file = tmp_path / "env.json"
    env_file.write_text(json.dumps({"suspicious_imports": {"EnvOnly": 3}}), encoding="utf-8")
    monkeypatch.setenv(RULES_ENV_VAR, str(env_file))
    r = load_effective_rules(cli_path=None)
    assert r.suspicious_imports.get("EnvOnly") == 3


def test_rules_file_missing():
    with pytest.raises(FileNotFoundError):
        load_rules_from_path("/nonexistent/rules.json")


def test_invalid_rules_import_weight(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"suspicious_imports": {"x": "not_int"}}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_rules_from_path(path)


def test_custom_keywords_replace_when_provided(tmp_path):
    path = tmp_path / "kw.json"
    path.write_text(json.dumps({"suspicious_string_keywords": ["CUSTOM_MARKER"]}), encoding="utf-8")
    r = load_rules_from_path(path)
    assert r.suspicious_string_keywords == ["CUSTOM_MARKER"]
