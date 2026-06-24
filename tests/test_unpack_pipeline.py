import os
import tempfile

import pytest

from binary_analyzer.analysis import build_comparison, build_results_with_unpack


def test_build_comparison_deltas():
    before = {
        "file_info": {"sha256": "aaa", "size_bytes": 1000},
        "entropy": {"score": 7.5},
        "imports": {"count": 2, "matched_suspicious": ["kernel32.dll!Sleep"]},
        "risk": {"level": "MEDIUM"},
        "suspicious_indicators_total": 3,
    }
    after = {
        "file_info": {"sha256": "bbb", "size_bytes": 2500},
        "entropy": {"score": 5.1},
        "imports": {"count": 40, "matched_suspicious": ["kernel32.dll!Sleep", "user32.dll!MessageBoxA"]},
        "risk": {"level": "HIGH"},
        "suspicious_indicators_total": 5,
    }

    comparison = build_comparison(before, after)
    assert comparison["sha256_changed"] is True
    assert comparison["size_delta_bytes"] == 1500
    assert comparison["entropy_delta"] == pytest.approx(-2.4)
    assert comparison["risk_before"] == "MEDIUM"
    assert comparison["risk_after"] == "HIGH"
    assert "user32.dll!MessageBoxA" in comparison["imports_added"]


def test_build_results_with_unpack_detect_only(monkeypatch):
    def fake_build_results(path, max_strings, rules=None):
        return {
            "file_path": path,
            "file_info": {"size_bytes": 10, "sha256": "deadbeef"},
            "file_type": "PE (Windows Executable)",
            "strings": {"total_found": 0, "preview": []},
            "imports": {"count": 0, "matched_suspicious": [], "suspicion_score": 0, "analysis_error": None},
            "entropy": {"score": 7.0, "status": "HIGH"},
            "pe_info": {"arch": "x64", "sections": [{"name": "UPX0", "size": 1, "offset": 0}]},
            "suspicious_indicators_total": 0,
            "risk": {"level": "LOW"},
        }

    monkeypatch.setattr("binary_analyzer.analysis.build_results", fake_build_results)
    monkeypatch.setattr("binary_analyzer.analysis.extract_strings", lambda _p: [])

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"MZ")
        path = f.name
    try:
        results = build_results_with_unpack(path, max_strings=5, unpack=False)
        assert results["analysis"]["after"] is None
        assert results["comparison"] is None
        assert len(results["packer"]["detected"]) == 1
        assert results["packer"]["detected"][0]["name"] == "UPX"
        assert results["packer"]["unpack"]["attempted"] is False
    finally:
        os.unlink(path)


def test_build_results_with_unpack_attempts_recipe(monkeypatch):
    from binary_analyzer.unpackers.base import UnpackResult

    calls = {"unpack": 0, "build": 0}

    def fake_build_results(path, max_strings, rules=None):
        calls["build"] += 1
        label = "after" if "unpacked" in path else "before"
        return {
            "file_path": path,
            "file_info": {"size_bytes": 10, "sha256": label},
            "file_type": "PE (Windows Executable)",
            "strings": {"total_found": 0, "preview": []},
            "imports": {"count": 1 if label == "after" else 0, "matched_suspicious": [], "suspicion_score": 0, "analysis_error": None},
            "entropy": {"score": 7.0 if label == "before" else 5.0, "status": "HIGH"},
            "pe_info": {"arch": "x64", "sections": [{"name": "UPX0", "size": 1, "offset": 0}]},
            "suspicious_indicators_total": 0,
            "risk": {"level": "LOW"},
        }

    def fake_unpack(_packer, _path, output_dir):
        calls["unpack"] += 1
        out_path = os.path.join(output_dir, "unpacked_sample.exe")
        with open(out_path, "wb") as f:
            f.write(b"unpacked")
        return UnpackResult(
            attempted=True,
            performed=True,
            method="test",
            packer="UPX",
            output_path=out_path,
            sha256="unpackedhash",
            error=None,
        )

    monkeypatch.setattr("binary_analyzer.analysis.build_results", fake_build_results)
    monkeypatch.setattr("binary_analyzer.analysis.extract_strings", lambda _p: [])
    monkeypatch.setattr("binary_analyzer.analysis.attempt_unpack", fake_unpack)

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"MZ")
        path = f.name
    try:
        with tempfile.TemporaryDirectory() as tmp:
            results = build_results_with_unpack(
                path,
                max_strings=5,
                unpack=True,
                unpack_output_dir=tmp,
            )
        assert calls["unpack"] == 1
        assert calls["build"] == 2
        assert results["packer"]["unpack"]["performed"] is True
        assert results["analysis"]["after"] is not None
        assert results["comparison"]["sha256_changed"] is True
    finally:
        os.unlink(path)
