import sys
import os


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


if __name__ == "__main__":
    main()