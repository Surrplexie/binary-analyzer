import sys
import os


from string_extractor import extract_strings
from pe_parser import parse_pe
from indicators import find_suspicious_strings


def print_banner():
    print("Binary Analyzer v0.1")
    print("---------------------")


def file_info(file_path):
    size = os.path.getsize(file_path)
    print("\nFile Info")
    print("---------")
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

    file_info(file_path)
    file_type = detect_file_type(file_path)
    print(f"File Type: {file_type}")

    # -------------------------------
    # Extract strings from binary
    strings = extract_strings(file_path)

    print("\nStrings Found (first 10)")
    print("------------------------")

    for s in strings[:10]:
        print(s)
    # -------------------------------


    def section(title):
        print(f"\n{title}")
        print("-" * len(title))


    pe_info = parse_pe(file_path)
    if pe_info:
        print("\nPE Info")
        print("--------")
        print(f"Architecture: {pe_info['arch']}")


    suspicious = find_suspicious_strings(strings)
    print("\nSuspicious Indicators")
    print("---------------------")
    for s in suspicious[:10]:
        print(s)


if __name__ == "__main__":
    main()