import os
import sys
import json
import argparse

from string_extractor import extract_strings
from entropy import calculate_entropy, entropy_verdict
from pe_parser import parse_pe
from indicators import find_suspicious_strings, get_imports, calculate_suspicion_score

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
    return parser.parse_args()

def build_results(file_path, max_strings):
    size = os.path.getsize(file_path)
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

    return {
        "file_path": file_path,
        "file_info": {
            "size_bytes": size,
        },
        "file_type": file_type,
        "strings": {
            "total_found": len(strings),
            "preview": strings[:max_strings],
        },
        "imports": {
            "count": len(imports),
            "suspicion_score": suspicion_score,
            "analysis_error": import_analysis_error,
        },
        "entropy": {
            "score": entropy,
            "status": verdict,
        },
        "pe_info": pe_info,
        "suspicious_indicators": suspicious[:max_strings],
    }

def print_human_results(results, max_strings):
    print_banner()
    print(f"Analyzing file: {results['file_path']}")

    section("File Info")
    print(f"Size: {results['file_info']['size_bytes']} bytes")

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

def main():
    args = parse_args()
    file_path = args.binary_file
    max_strings = max(args.max_strings, 0)

    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist")
        sys.exit(1)

    results = build_results(file_path, max_strings)

    if args.as_json:
        print(json.dumps(results, indent=2))
        return

    print_human_results(results, max_strings)

if __name__ == "__main__":
    main()