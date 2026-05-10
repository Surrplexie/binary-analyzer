# binary-analyzer
Build a tool that can analyze executable files and extract for RE info such as file type, architecture, imported function, strings, entropy, and patterns.

## Install

From the repository root, using a virtual environment is recommended:

`python -m venv .venv`

`.\.venv\Scripts\activate` (Windows) or `source .venv/bin/activate` (Unix)

`python -m pip install -e .`

This installs the `binary-analyzer` package and the `binary-analyzer` CLI command.

For development (tests + PyInstaller): `python -m pip install -e ".[dev]"`

### Programmatic API

```python
from binary_analyzer import build_results, detect_file_type

results = build_results(r"path\to\file.exe", max_strings=20)
print(results["risk"]["level"])
```

Or import submodules explicitly, for example `from binary_analyzer.analysis import build_results`.

## Usage

Run standard human-readable analysis:

`binary-analyzer samples/test.exe`

Or: `python -m binary_analyzer samples/test.exe`

Run machine-readable JSON output:

`binary-analyzer samples/test.exe --json`

Control how many strings are previewed:

`binary-analyzer samples/test.exe --max-strings 25`

## Build Windows EXE

From the repository root, create and activate a virtual environment:

`python -m venv .venv`

`.\.venv\Scripts\activate`

Install and build:

`build.bat`

EXE output path:

`dist/binary-analyzer.exe`

Run the EXE from the repository root (adjust paths as needed):

`.\dist\binary-analyzer.exe samples\test.exe`

`.\dist\binary-analyzer.exe samples\test.exe --json`

Two samples to test for immediately are in the `test-sample` folder

## Phase 1 Isolation (Quarantine)

Enable auto-isolation for suspicious files:

`binary-analyzer samples/test.exe --auto-isolate`

Set a custom threshold and quarantine directory:

`binary-analyzer samples/test.exe --auto-isolate --isolate-threshold 25 --quarantine-dir quarantine`

When a file is isolated, it is moved to the quarantine folder with a `.quarantine` extension and an event is logged to `manifest.jsonl` for manual review.

## Phase 2 Manual Review Workflow

List files currently in quarantine:

`binary-analyzer --list-quarantine --quarantine-dir quarantine`

Restore a quarantined file by SHA256 prefix:

`binary-analyzer --restore 7830b26b --quarantine-dir quarantine`

JSON output works for review and restore commands too:

`binary-analyzer --list-quarantine --quarantine-dir quarantine --json`

## Phase 3 Quarantine Operations

Delete a quarantined file by SHA256 prefix:

`binary-analyzer --delete-from-quarantine 7830b26b --quarantine-dir quarantine`

Export quarantine manifest to CSV:

`binary-analyzer --export-manifest-csv --quarantine-dir quarantine`

Export to a custom CSV path:

`binary-analyzer --export-manifest-csv logs/quarantine.csv --quarantine-dir quarantine`

Risk levels are now included in analysis output as `LOW`, `MEDIUM`, or `HIGH` based on suspicious imports and keyword hits.

## Tests

Install with dev extras and run tests from the repo root:

`python -m pip install -e ".[dev]"`

`python -m pytest tests/ -q`

## Isolation triggers (combined)

Auto-isolation runs when **any** enabled condition matches:

- Import score: `suspicion_score >= --isolate-threshold` (default 25)
- Risk band: `--isolate-on-risk MEDIUM` isolates **MEDIUM and HIGH**; `HIGH` isolates **HIGH only**
- Keyword volume: `--keyword-isolate-threshold N` isolates when suspicious string hit count is **>= N** (use `0` to disable)

Example (isolate high-risk string samples even with low import score):

`binary-analyzer test-sample/bad_sample.bin --auto-isolate --isolate-on-risk MEDIUM --quarantine-dir quarantine`
