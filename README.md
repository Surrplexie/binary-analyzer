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

Two samples to test for immediately are in the `test-sample` folder

## Phase 1 Isolation (Quarantine)

Enable auto-isolation for suspicious files:

`python analyzer/main.py samples/test.exe --auto-isolate`

Set a custom threshold and quarantine directory:

`python analyzer/main.py samples/test.exe --auto-isolate --isolate-threshold 25 --quarantine-dir quarantine`

When a file is isolated, it is moved to the quarantine folder with a `.quarantine` extension and an event is logged to `manifest.jsonl` for manual review.

## Phase 2 Manual Review Workflow

List files currently in quarantine:

`python analyzer/main.py --list-quarantine --quarantine-dir quarantine`

Restore a quarantined file by SHA256 prefix:

`python analyzer/main.py --restore 7830b26b --quarantine-dir quarantine`

JSON output works for review and restore commands too:

`python analyzer/main.py --list-quarantine --quarantine-dir quarantine --json`

## Phase 3 Quarantine Operations

Delete a quarantined file by SHA256 prefix:

`python analyzer/main.py --delete-from-quarantine 7830b26b --quarantine-dir quarantine`

Export quarantine manifest to CSV:

`python analyzer/main.py --export-manifest-csv --quarantine-dir quarantine`

Export to a custom CSV path:

`python analyzer/main.py --export-manifest-csv logs/quarantine.csv --quarantine-dir quarantine`

Risk levels are now included in analysis output as `LOW`, `MEDIUM`, or `HIGH` based on suspicious imports and keyword hits.
