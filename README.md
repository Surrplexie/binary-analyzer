# binary-analyzer
Build a tool that can analyze executable files and extract for RE info such as file type, architecture, imported function, strings, entropy, and patterns.

## Usage

Run standard human-readable analysis:

`python analyzer/main.py samples/test.exe`

Run machine-readable JSON output:

`python analyzer/main.py samples/test.exe --json`

Control how many strings are previewed:

`python analyzer/main.py samples/test.exe --max-strings 25`

## Build Windows EXE

From `analyzer/`, create and activate a virtual environment:

`python -m venv .venv`

`.\.venv\Scripts\activate`

Install dependencies and build:

`build.bat`

EXE output path:

`analyzer/dist/binary-analyzer.exe`

Run the EXE from `analyzer/`:

`.\dist\binary-analyzer.exe "..\samples\test.exe"`

`.\dist\binary-analyzer.exe "..\samples\test.exe" --json`
