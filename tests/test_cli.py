import types

from cli import isolation_triggers


def _results(score=0, level="LOW", kw_total=0):
    return {
        "imports": {"suspicion_score": score},
        "risk": {"level": level},
        "suspicious_indicators_total": kw_total,
    }


def test_isolation_triggers_score_only():
    args = types.SimpleNamespace(
        isolate_threshold=10,
        isolate_on_risk=None,
        keyword_isolate_threshold=0,
    )
    ok, reason = isolation_triggers(args, _results(score=15, level="LOW", kw_total=0))
    assert ok is True
    assert "suspicion_score" in reason


def test_isolation_triggers_risk():
    args = types.SimpleNamespace(
        isolate_threshold=999,
        isolate_on_risk="MEDIUM",
        keyword_isolate_threshold=0,
    )
    ok, _ = isolation_triggers(args, _results(score=0, level="HIGH", kw_total=0))
    assert ok is True


def test_isolation_triggers_keyword():
    args = types.SimpleNamespace(
        isolate_threshold=999,
        isolate_on_risk=None,
        keyword_isolate_threshold=3,
    )
    ok, reason = isolation_triggers(args, _results(score=0, level="LOW", kw_total=3))
    assert ok is True
    assert "suspicious_strings_count" in reason


def test_isolation_triggers_none():
    args = types.SimpleNamespace(
        isolate_threshold=50,
        isolate_on_risk=None,
        keyword_isolate_threshold=0,
    )
    ok, reason = isolation_triggers(args, _results(score=10, level="LOW", kw_total=1))
    assert ok is False
    assert reason is None
