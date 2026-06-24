import struct
import tempfile
import os

import pytest

from binary_analyzer.packer import detect_packers, pick_unpack_target


def _minimal_pe_with_sections(section_names):
    """Build a tiny PE with named sections for packer signature tests."""
    dos_stub = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x8664, len(section_names), 0, 0, 0, 224, 0x103)
    optional = b"\x00" * 224
    sections = b""
    for name in section_names:
        raw = name.encode("ascii", errors="ignore")[:8]
        raw = raw.ljust(8, b"\x00")
        sections += raw + struct.pack("<IIIIIIII", 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0)
    return dos_stub + b"\x00" * (0x80 - len(dos_stub)) + pe_sig + coff + optional + sections


def test_detect_upx_from_sections():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(_minimal_pe_with_sections(["UPX0", "UPX1", ".rsrc"]))
        path = f.name
    try:
        from binary_analyzer.pe_parser import parse_pe

        pe_info = parse_pe(path)
        matches = detect_packers(path, pe_info=pe_info, strings=[], entropy=7.5)
        assert len(matches) == 1
        assert matches[0].name == "UPX"
        assert matches[0].confidence == "high"
        assert any(s.startswith("section:UPX") for s in matches[0].signals)
    finally:
        os.unlink(path)


def test_detect_upx_from_binary_marker():
    with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as f:
        f.write(b"MZ" + b"\x00" * 100 + b"UPX!" + b"\x00" * 20)
        path = f.name
    try:
        matches = detect_packers(path, pe_info=None, strings=[], entropy=6.5)
        assert len(matches) == 1
        assert matches[0].name == "UPX"
        assert "binary:UPX!" in matches[0].signals
    finally:
        os.unlink(path)


def test_detect_upx_from_strings():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"plain data")
        path = f.name
    try:
        matches = detect_packers(
            path,
            pe_info=None,
            strings=["packed with UPX!"],
            entropy=7.3,
        )
        assert len(matches) == 1
        assert matches[0].confidence in ("medium", "high", "low")
    finally:
        os.unlink(path)


def test_no_packer_detected():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"hello world")
        path = f.name
    try:
        matches = detect_packers(path, pe_info=None, strings=["hello"], entropy=4.0)
        assert matches == []
    finally:
        os.unlink(path)


def test_pick_unpack_target_prefers_upx():
    from binary_analyzer.packer import PackerMatch

    matches = [
        PackerMatch(name="UPX", confidence="medium", signals=["section:UPX0"]),
    ]
    target = pick_unpack_target(matches)
    assert target is not None
    assert target.name == "UPX"


def test_pick_unpack_target_empty():
    assert pick_unpack_target([]) is None
