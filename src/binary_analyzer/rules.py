"""Load and validate analysis rules from packaged defaults and optional JSON overrides."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any


RULES_ENV_VAR = "BINARY_ANALYZER_RULES"


@dataclass(frozen=True)
class AnalysisRules:
    suspicious_imports: dict[str, int]
    suspicious_string_keywords: list[str]
    risk_high_min_score: int
    risk_high_min_strings: int
    risk_medium_min_score: int
    risk_medium_min_strings: int
    source: str


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = json.loads(json.dumps(base))
    for key, val in override.items():
        if key == "suspicious_imports" and isinstance(val, dict):
            merged = dict(out.get("suspicious_imports", {}))
            merged.update(val)
            out["suspicious_imports"] = merged
        elif key == "risk" and isinstance(val, dict):
            rb = dict(out.get("risk", {}))
            for band in ("high", "medium"):
                if band in val and isinstance(val[band], dict):
                    rb[band] = {**(rb.get(band) or {}), **val[band]}
                elif band in val:
                    rb[band] = val[band]
            out["risk"] = rb
        else:
            out[key] = val
    return out


def _validate_rules(data: dict[str, Any]) -> None:
    if "suspicious_imports" in data:
        imp = data["suspicious_imports"]
        if not isinstance(imp, dict):
            raise ValueError("suspicious_imports must be an object")
        for k, v in imp.items():
            if not isinstance(k, str) or not isinstance(v, int) or v < 0:
                raise ValueError(f"invalid suspicious_imports entry: {k!r}")

    if "suspicious_string_keywords" in data:
        kw = data["suspicious_string_keywords"]
        if not isinstance(kw, list) or not all(isinstance(x, str) for x in kw):
            raise ValueError("suspicious_string_keywords must be a list of strings")

    risk = data.get("risk")
    if risk is not None:
        if not isinstance(risk, dict):
            raise ValueError("risk must be an object")
        for band in ("high", "medium"):
            if band not in risk:
                continue
            b = risk[band]
            if not isinstance(b, dict):
                raise ValueError(f"risk.{band} must be an object")
            ms = b.get("min_suspicion_score")
            mc = b.get("min_suspicious_string_count")
            if ms is not None and (not isinstance(ms, int) or ms < 0):
                raise ValueError(f"risk.{band}.min_suspicion_score invalid")
            if mc is not None and (not isinstance(mc, int) or mc < 0):
                raise ValueError(f"risk.{band}.min_suspicious_string_count invalid")


def _dict_to_rules(data: dict[str, Any], source: str) -> AnalysisRules:
    _validate_rules(data)
    risk = data.get("risk") or {}
    high = risk.get("high") or {}
    medium = risk.get("medium") or {}
    return AnalysisRules(
        suspicious_imports=dict(data["suspicious_imports"]),
        suspicious_string_keywords=list(data["suspicious_string_keywords"]),
        risk_high_min_score=int(high["min_suspicion_score"]),
        risk_high_min_strings=int(high["min_suspicious_string_count"]),
        risk_medium_min_score=int(medium["min_suspicion_score"]),
        risk_medium_min_strings=int(medium["min_suspicious_string_count"]),
        source=source,
    )


def load_rules_dict_from_package() -> dict[str, Any]:
    raw = resources.files("binary_analyzer").joinpath("default_rules.json").read_text(encoding="utf-8")
    return json.loads(raw)


def load_rules_from_path(path: str | Path, base: dict[str, Any] | None = None) -> AnalysisRules:
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"rules file not found: {p}")
    with open(p, encoding="utf-8") as f:
        override = json.load(f)
    if not isinstance(override, dict):
        raise ValueError("rules file must contain a JSON object")
    merged = _deep_merge(base if base is not None else load_rules_dict_from_package(), override)
    _validate_rules(merged)
    return _dict_to_rules(merged, str(p.resolve()))


def load_default_rules() -> AnalysisRules:
    data = load_rules_dict_from_package()
    return _dict_to_rules(data, "package-default")


def load_effective_rules(cli_path: str | None = None) -> AnalysisRules:
    """
    Resolve rules: explicit --rules path, then BINARY_ANALYZER_RULES, then packaged default.
    """
    if cli_path:
        return load_rules_from_path(cli_path)
    env_path = os.environ.get(RULES_ENV_VAR, "").strip()
    if env_path:
        return load_rules_from_path(env_path)
    return load_default_rules()
