import os
from dataclasses import asdict, dataclass
from typing import Optional


UPX_SECTION_NAMES = frozenset({"UPX0", "UPX1", "UPX2", "UPX!"})
UPX_STRING_MARKERS = ("UPX!", "UPX0", "UPX1", "upx")


@dataclass
class PackerMatch:
    name: str
    confidence: str
    signals: list[str]

    def to_dict(self):
        return asdict(self)


def _scan_binary_for_upx(file_path: str) -> list[str]:
    signals = []
    try:
        with open(file_path, "rb") as f:
            data = f.read(1024 * 1024)
    except OSError:
        return signals

    if b"UPX!" in data:
        signals.append("binary:UPX!")
    if b"$Info: This file is packed with the UPX executable packer" in data:
        signals.append("binary:upx-info-string")
    return signals


def _upx_section_signals(pe_info: Optional[dict]) -> list[str]:
    if not pe_info:
        return []
    signals = []
    for section in pe_info.get("sections", []):
        name = section.get("name", "")
        if name in UPX_SECTION_NAMES:
            signals.append(f"section:{name}")
    return signals


def _upx_string_signals(strings: list[str]) -> list[str]:
    signals = []
    for s in strings:
        upper = s.upper()
        for marker in UPX_STRING_MARKERS:
            if marker.upper() in upper:
                signals.append(f"string:{marker}")
                break
    return signals


def _score_upx(signals: list[str], entropy: Optional[float]) -> str:
    strong = sum(
        1
        for s in signals
        if s.startswith("section:") or s.startswith("binary:")
    )
    if strong >= 2 or (strong >= 1 and any(s.startswith("string:") for s in signals)):
        return "high"
    if strong >= 1:
        return "medium"
    if signals and entropy is not None and entropy > 6.0:
        return "low"
    if signals:
        return "medium"
    return "low"


def detect_packers(
    file_path: str,
    *,
    pe_info: Optional[dict] = None,
    strings: Optional[list[str]] = None,
    entropy: Optional[float] = None,
) -> list[PackerMatch]:
    """Detect common executable packers. UPX is implemented first."""
    matches = []

    section_signals = _upx_section_signals(pe_info)
    string_signals = _upx_string_signals(strings or [])
    binary_signals = _scan_binary_for_upx(file_path)
    upx_signals = sorted(set(section_signals + string_signals + binary_signals))

    if upx_signals:
        matches.append(
            PackerMatch(
                name="UPX",
                confidence=_score_upx(upx_signals, entropy),
                signals=upx_signals,
            )
        )

    return matches


def pick_unpack_target(matches: list[PackerMatch]) -> Optional[PackerMatch]:
    """Choose the best packer match to attempt unpacking."""
    if not matches:
        return None

    priority = {"high": 0, "medium": 1, "low": 2}
    ranked = sorted(matches, key=lambda m: (priority.get(m.confidence, 9), m.name))
    for match in ranked:
        if match.name == "UPX":
            return match
    return ranked[0]
