import os
import tempfile
from typing import TYPE_CHECKING, Optional

from .string_extractor import extract_strings
from .entropy import calculate_entropy, entropy_verdict
from .pe_parser import parse_pe
from .indicators import find_suspicious_strings, get_imports, calculate_suspicion_score
from .packer import detect_packers, pick_unpack_target
from .quarantine import sha256_file
from .risk import classify_risk_level
from .unpackers import attempt_unpack

if TYPE_CHECKING:
    from .rules import AnalysisRules


def detect_file_type(file_path):
    with open(file_path, "rb") as f:
        magic = f.read(4)

    if magic.startswith(b"MZ"):
        return "PE (Windows Executable)"
    if magic.startswith(b"\x7fELF"):
        return "ELF (Linux Binary)"
    return "Unknown"


def build_results(file_path, max_strings, rules: Optional["AnalysisRules"] = None):
    from .rules import load_default_rules

    eff = rules or load_default_rules()

    size = os.path.getsize(file_path)
    file_hash = sha256_file(file_path)
    file_type = detect_file_type(file_path)
    strings = extract_strings(file_path)

    imports = []
    suspicion_score = 0
    import_analysis_error = None
    try:
        imports = get_imports(file_path)
        if imports:
            suspicion_score = calculate_suspicion_score(imports, eff.suspicious_imports)
    except Exception as e:
        import_analysis_error = str(e)

    entropy = calculate_entropy(file_path)
    verdict = entropy_verdict(entropy)

    pe_info = None
    if file_type.startswith("PE"):
        pe_info = parse_pe(file_path)
    suspicious = find_suspicious_strings(strings, eff.suspicious_string_keywords)
    weights = eff.suspicious_imports
    matched_suspicious_imports = sorted(set(i for i in imports if i in weights))
    suspicious_total = len(suspicious)

    return {
        "file_path": file_path,
        "rules": {"source": eff.source},
        "file_info": {
            "size_bytes": size,
            "sha256": file_hash,
        },
        "file_type": file_type,
        "strings": {
            "total_found": len(strings),
            "preview": strings[:max_strings],
        },
        "imports": {
            "count": len(imports),
            "suspicion_score": suspicion_score,
            "matched_suspicious": matched_suspicious_imports,
            "analysis_error": import_analysis_error,
        },
        "entropy": {
            "score": entropy,
            "status": verdict,
        },
        "pe_info": pe_info,
        "suspicious_indicators": suspicious[:max_strings],
        "suspicious_indicators_all": suspicious,
        "suspicious_indicators_total": suspicious_total,
        "risk": {
            "level": classify_risk_level(suspicion_score, suspicious_total, eff),
        },
        "isolation": {
            "attempted": False,
            "performed": False,
            "path": None,
            "reason": None,
            "error": None,
        },
    }


def build_comparison(before: dict, after: dict) -> dict:
    before_imports = set(before["imports"]["matched_suspicious"])
    after_imports = set(after["imports"]["matched_suspicious"])

    return {
        "sha256_changed": before["file_info"]["sha256"] != after["file_info"]["sha256"],
        "size_delta_bytes": after["file_info"]["size_bytes"] - before["file_info"]["size_bytes"],
        "entropy_delta": round(after["entropy"]["score"] - before["entropy"]["score"], 4),
        "imports_count_before": before["imports"]["count"],
        "imports_count_after": after["imports"]["count"],
        "imports_added": sorted(after_imports - before_imports),
        "imports_removed": sorted(before_imports - after_imports),
        "risk_before": before["risk"]["level"],
        "risk_after": after["risk"]["level"],
        "risk_changed": before["risk"]["level"] != after["risk"]["level"],
        "suspicious_indicators_before": before["suspicious_indicators_total"],
        "suspicious_indicators_after": after["suspicious_indicators_total"],
        "suspicious_indicators_delta": (
            after["suspicious_indicators_total"] - before["suspicious_indicators_total"]
        ),
    }


def build_results_with_unpack(
    file_path,
    max_strings,
    rules: Optional["AnalysisRules"] = None,
    *,
    detect_packers_flag: bool = True,
    unpack: bool = False,
    unpack_output_dir: Optional[str] = None,
):
    """Analyze a binary, optionally detect packers and unpack for before/after comparison."""
    before = build_results(file_path, max_strings, rules)

    matches = []
    if detect_packers_flag:
        all_strings = extract_strings(file_path)
        matches = detect_packers(
            file_path,
            pe_info=before.get("pe_info"),
            strings=all_strings,
            entropy=before["entropy"]["score"],
        )

    unpack_info = {
        "attempted": False,
        "performed": False,
        "method": None,
        "packer": None,
        "output_path": None,
        "sha256": None,
        "error": None,
    }

    after = None
    comparison = None
    output_dir = unpack_output_dir
    owns_temp_dir = False

    if unpack:
        target = pick_unpack_target(matches)
        if target is None:
            unpack_info["error"] = "no supported packer detected to unpack"
        else:
            if output_dir is None:
                output_dir = tempfile.mkdtemp(prefix="binary-analyzer-unpack-")
                owns_temp_dir = True

            unpack_info["attempted"] = True
            result = attempt_unpack(target.name, file_path, output_dir)
            unpack_info.update(result.to_dict())

            if result.performed and result.output_path:
                after = build_results(result.output_path, max_strings, rules)
                comparison = build_comparison(before, after)

    packer_block = {
        "detected": [m.to_dict() for m in matches],
        "unpack": unpack_info,
        "temp_output_dir": output_dir if owns_temp_dir else None,
    }

    return {
        "file_path": file_path,
        "packer": packer_block,
        "analysis": {
            "before": before,
            "after": after,
        },
        "comparison": comparison,
    }
