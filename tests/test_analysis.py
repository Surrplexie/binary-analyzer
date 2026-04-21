import os
import tempfile

import pytest

from analysis import build_results, detect_file_type


def test_detect_file_type_pe():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"MZ\x90\x00" + b"\x00" * 64)
        path = f.name
    try:
        assert detect_file_type(path).startswith("PE")
    finally:
        os.unlink(path)


def test_detect_file_type_elf():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"\x7fELF" + b"\x00" * 60)
        path = f.name
    try:
        assert "ELF" in detect_file_type(path)
    finally:
        os.unlink(path)


def test_detect_file_type_unknown():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"XXXX")
        path = f.name
    try:
        assert detect_file_type(path) == "Unknown"
    finally:
        os.unlink(path)


def test_build_results_includes_risk_and_totals(monkeypatch):
    def fake_get_imports(_path):
        return []

    def fake_strings(_path):
        return ["safe", "powershell -nop"]

    def fake_find_suspicious(strings):
        return [s for s in strings if "powershell" in s.lower()]

    monkeypatch.setattr("analysis.get_imports", fake_get_imports)
    monkeypatch.setattr("analysis.extract_strings", fake_strings)
    monkeypatch.setattr("analysis.find_suspicious_strings", fake_find_suspicious)

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"hello world test")
        path = f.name
    try:
        r = build_results(path, max_strings=1)
        assert r["suspicious_indicators_total"] == 1
        assert len(r["suspicious_indicators"]) == 1
        assert len(r["suspicious_indicators_all"]) == 1
        assert "risk" in r and r["risk"]["level"] in ("LOW", "MEDIUM", "HIGH")
        assert "sha256" in r["file_info"]
    finally:
        os.unlink(path)
