import pytest

from risk import classify_risk_level, risk_meets_minimum, risk_rank


@pytest.mark.parametrize(
    "score,count,expected",
    [
        (0, 0, "LOW"),
        (0, 1, "LOW"),
        (0, 2, "MEDIUM"),
        (0, 5, "HIGH"),
        (19, 0, "LOW"),
        (20, 0, "MEDIUM"),
        (40, 0, "HIGH"),
    ],
)
def test_classify_risk_level(score, count, expected):
    assert classify_risk_level(score, count) == expected


def test_risk_meets_minimum():
    assert risk_meets_minimum("HIGH", "MEDIUM") is True
    assert risk_meets_minimum("MEDIUM", "MEDIUM") is True
    assert risk_meets_minimum("LOW", "MEDIUM") is False
    assert risk_meets_minimum("MEDIUM", None) is False


def test_risk_rank_ordering():
    assert risk_rank("LOW") < risk_rank("MEDIUM") < risk_rank("HIGH")
