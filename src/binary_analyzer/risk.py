from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .rules import AnalysisRules

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def classify_risk_level(
    suspicion_score: int,
    suspicious_count: int,
    rules: Optional["AnalysisRules"] = None,
) -> str:
    from .rules import load_default_rules

    r = rules or load_default_rules()
    if suspicion_score >= r.risk_high_min_score or suspicious_count >= r.risk_high_min_strings:
        return "HIGH"
    if suspicion_score >= r.risk_medium_min_score or suspicious_count >= r.risk_medium_min_strings:
        return "MEDIUM"
    return "LOW"


def risk_rank(level: str) -> int:
    return RISK_ORDER.get(level, 0)


def risk_meets_minimum(level: str, minimum: Optional[str]) -> bool:
    if not minimum:
        return False
    return risk_rank(level) >= risk_rank(minimum)
