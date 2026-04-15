# binary-analyzer
Build a tool that can analyze executable files and extract for RE info such as file type, architecture, imported function, strings, entropy, and patterns.

## Usage

Run standard human-readable analysis:

`python analyzer/main.py samples/example.exe`

Run machine-readable JSON output:

`python analyzer/main.py samples/example.exe --json`

Control how many strings are previewed:

`python analyzer/main.py samples/example.exe --max-strings 25`
