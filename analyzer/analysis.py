import os

from string_extractor import extract_strings
from entropy import calculate_entropy, entropy_verdict
from pe_parser import parse_pe
from indicators import find_suspicious_strings, get_imports, calculate_suspicion_score, SUSPICIOUS_IMPORTS
from quarantine import sha256_file
from risk import classify_risk_level


def detect_file_type(file_path):
    with open(file_path, "rb") as f:
        magic = f.read(4)

    if magic.startswith(b"MZ"):
        return "PE (Windows Executable)"
    if magic.startswith(b"\x7fELF"):
        return "ELF (Linux Binary)"
    return "Unknown"


def build_results(file_path, max_strings):
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
            suspicion_score = calculate_suspicion_score(imports)
    except Exception as e:
        import_analysis_error = str(e)

    entropy = calculate_entropy(file_path)
    verdict = entropy_verdict(entropy)

    pe_info = None
    if file_type.startswith("PE"):
        pe_info = parse_pe(file_path)
    suspicious = find_suspicious_strings(strings)
    matched_suspicious_imports = sorted(set(i for i in imports if i in SUSPICIOUS_IMPORTS))
    suspicious_total = len(suspicious)

    return {
        "file_path": file_path,
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
            "level": classify_risk_level(suspicion_score, suspicious_total),
        },
        "isolation": {
            "attempted": False,
            "performed": False,
            "path": None,
            "reason": None,
            "error": None,
        },
    }
