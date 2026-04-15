import os
import sys
import json
import argparse
import hashlib
import shutil
from datetime import datetime, timezone

from string_extractor import extract_strings
from entropy import calculate_entropy, entropy_verdict
from pe_parser import parse_pe
from indicators import find_suspicious_strings, get_imports, calculate_suspicion_score, SUSPICIOUS_IMPORTS

def print_banner():
    print("Binary Analyzer v0.2")
    print("---------------------")

def section(title):
    print(f"\n{title}")
    print("-" * len(title))

def file_info(file_path):
    size = os.path.getsize(file_path)
    section("File Info")
    print(f"Size: {size} bytes")

def detect_file_type(file_path):
    with open(file_path, "rb") as f:
        magic = f.read(4)

    if magic.startswith(b"MZ"):
        return "PE (Windows Executable)"
    if magic.startswith(b"\x7fELF"):
        return "ELF (Linux Binary)"
    return "Unknown"

def sha256_file(file_path):
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

def isolate_file(file_path, quarantine_dir, suspicion_score, threshold):
    result = {
        "attempted": False,
        "performed": False,
        "path": None,
        "reason": None,
        "error": None,
    }

    result["attempted"] = True
    result["reason"] = f"suspicion_score>={threshold} (actual={suspicion_score})"

    try:
        os.makedirs(quarantine_dir, exist_ok=True)

        source_hash = sha256_file(file_path)
        original_name = os.path.basename(file_path)
        quarantine_name = f"{source_hash}_{original_name}.quarantine"
        quarantine_path = os.path.join(quarantine_dir, quarantine_name)

        if os.path.exists(quarantine_path):
            result["error"] = f"Quarantine target already exists: {quarantine_path}"
            return result

        shutil.move(file_path, quarantine_path)
        destination_hash = sha256_file(quarantine_path)
        if source_hash != destination_hash:
            result["error"] = "Hash verification failed after isolation move"
            return result

        os.chmod(quarantine_path, 0o444)

        result["performed"] = True
        result["path"] = quarantine_path
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

def append_manifest(manifest_path, results, isolation_result, threshold):
    event = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "original_path": results["file_path"],
        "quarantine_path": isolation_result["path"],
        "sha256": results["file_info"]["sha256"],
        "file_size": results["file_info"]["size_bytes"],
        "suspicion_score": results["imports"]["suspicion_score"],
        "matched_imports": results["imports"]["matched_suspicious"],
        "matched_keywords": results["suspicious_indicators"],
        "trigger_reason": f"suspicion_score>={threshold}",
        "status": "isolated" if isolation_result["performed"] else "failed",
        "error": isolation_result["error"],
    }

    with open(manifest_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")

def parse_args():
    parser = argparse.ArgumentParser(description="Analyze executable binaries for RE indicators.")
    parser.add_argument("binary_file", help="Path to the binary file to analyze")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Output machine-readable JSON instead of human-readable text",
    )
    parser.add_argument(
        "--max-strings",
        type=int,
        default=10,
        help="Number of extracted strings to preview (default: 10)",
    )
    parser.add_argument(
        "--auto-isolate",
        action="store_true",
        help="Move suspicious files to a quarantine directory for manual review",
    )
    parser.add_argument(
        "--isolate-threshold",
        type=int,
        default=25,
        help="Suspicion score threshold to trigger isolation (default: 25)",
    )
    parser.add_argument(
        "--quarantine-dir",
        default="quarantine",
        help="Directory where isolated files and manifest are stored (default: quarantine)",
    )
    return parser.parse_args()

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
        "isolation": {
            "attempted": False,
            "performed": False,
            "path": None,
            "reason": None,
            "error": None,
        },
    }

def print_human_results(results, max_strings):
    print_banner()
    print(f"Analyzing file: {results['file_path']}")

    section("File Info")
    print(f"Size: {results['file_info']['size_bytes']} bytes")
    print(f"SHA256: {results['file_info']['sha256']}")

    section("File Type")
    print(results["file_type"])

    section(f"Strings Found (first {max_strings})")
    for s in results["strings"]["preview"]:
        print(s)

    section("Import Analysis")
    if results["imports"]["analysis_error"]:
        print(f"Could not analyze imports: {results['imports']['analysis_error']}")
    elif results["imports"]["count"] == 0:
        print("No imports found or not a dynamic binary.")
    else:
        score = results["imports"]["suspicion_score"]
        print(f"Total Suspicion Score: {score}")
        if score > 20:
            print("[!] Warning: High number of sensitive API imports detected.")

    section("Entropy Analysis")
    print(f"Entropy Score: {results['entropy']['score']:.2f}")
    print(f"Status: {results['entropy']['status']}")

    if results["pe_info"]:
        section("PE Info")
        print(f"Architecture: {results['pe_info']['arch']}")

    section("Suspicious Indicators")
    if results["suspicious_indicators"]:
        for s in results["suspicious_indicators"]:
            print(f"[!] {s}")
    else:
        print("None found")

    if results["isolation"]["attempted"]:
        section("Isolation")
        if results["isolation"]["performed"]:
            print(f"[!] File isolated for manual review: {results['isolation']['path']}")
            print(f"Trigger: {results['isolation']['reason']}")
        else:
            print(f"Isolation failed: {results['isolation']['error']}")

def main():
    args = parse_args()
    file_path = args.binary_file
    max_strings = max(args.max_strings, 0)

    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist")
        sys.exit(1)

    results = build_results(file_path, max_strings)
    if args.auto_isolate and results["imports"]["suspicion_score"] >= args.isolate_threshold:
        isolation_result = isolate_file(
            file_path=file_path,
            quarantine_dir=args.quarantine_dir,
            suspicion_score=results["imports"]["suspicion_score"],
            threshold=args.isolate_threshold,
        )
        results["isolation"] = isolation_result
        manifest_path = os.path.join(args.quarantine_dir, "manifest.jsonl")
        append_manifest(manifest_path, results, isolation_result, args.isolate_threshold)

    if args.as_json:
        print(json.dumps(results, indent=2))
        return

    print_human_results(results, max_strings)

if __name__ == "__main__":
    main()