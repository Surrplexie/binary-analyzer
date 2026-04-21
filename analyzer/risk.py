from typing import Optional

RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def classify_risk_level(suspicion_score: int, suspicious_count: int) -> str:
    if suspicion_score >= 40 or suspicious_count >= 5:
        return "HIGH"
    if suspicion_score >= 20 or suspicious_count >= 2:
        return "MEDIUM"
    return "LOW"


def risk_rank(level: str) -> int:
    return RISK_ORDER.get(level, 0)


def risk_meets_minimum(level: str, minimum: Optional[str]) -> bool:
    if not minimum:
        return False
    return risk_rank(level) >= risk_rank(minimum)
