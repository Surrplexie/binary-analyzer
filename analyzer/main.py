import sys
import os


from string_extractor import extract_strings 


def print_banner():
    print("binary-analyzer - A tool for analyzing binary files")
    print("--------------------------------------------------")


def main():
    print_banner()
    if len(sys.argv) < 2:
        print("Usage: python main.py <binary_file>")
        sys.exit(1)
        file_path = sys.argv[1]
    if not os.path.exists(file_path):
        print("Error: File does not exist.")
        sys.exit(1)
        print(f"Analyzing file: {file_path}")
        print("\nStrings Found (first 20):")
    strings = extract_strings(file_path)
    for s in strings[:20]:
        print(s)
    # further analysis functions will go here


if __name__ == "__main__":
    main()