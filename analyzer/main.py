import sys
import os

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

def main():
    print_banner()

    if len(sys.argv) < 2:
        print("Usage: python main.py <binary_file>")
        sys.exit(1)

    file_path = sys.argv[1]

    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist")
        sys.exit(1)

    print(f"Analyzing file: {file_path}")

    # 1. Basic File Info
    file_info(file_path)

    # 2. File Type Detection
    file_type = detect_file_type(file_path)
    section("File Type")
    print(file_type)

    # 3. String Extraction
    strings = extract_strings(file_path)
    section("Strings Found (first 10)")
    for s in strings[:10]:
        print(s)

    # 4. Import & Behavioral Analysis
    section("Import Analysis")
    try:
        imports = get_imports(file_path)
        if imports:
            score = calculate_suspicion_score(imports)
            print(f"Total Suspicion Score: {score}")
            if score > 20:
                print("[!] Warning: High number of sensitive API imports detected.")
        else:
            print("No imports found or not a dynamic binary.")
    except Exception as e:
        print(f"Could not analyze imports: {e}")
        
    # 5. Entropy Analysis
    section("Entropy Analysis")
    entropy = calculate_entropy(file_path)
    verdict = entropy_verdict(entropy)
    print(f"Entropy Score: {entropy:.2f}")
    print(f"Status: {verdict}")

    # 6. PE Specific Info
    if file_type.startswith("PE"):
        pe_info = parse_pe(file_path)
        if pe_info:
            section("PE Info")
            print(f"Architecture: {pe_info['arch']}")

    # 7. Suspicious Keywords in Strings
    suspicious = find_suspicious_strings(strings)
    section("Suspicious Indicators")
    if suspicious:
        for s in suspicious[:10]:
            print(f"[!] {s}")
    else:
        print("None found")

if __name__ == "__main__":
    main()