# Binary analyzer development log

## Day 1 0.0.1
- Create project
- Initialize Git repo (Will use GitHub to reflect)
- Define project goals
- Support PE fiiles

## Day 2 0.0.12
- Detect executable type
- Extract strings

## Day 3 0.0.13
- Fixed 'main.py'
- Added automatic logging to 'logs/strings.txt'
- Attempts to output the first 20 strings for reading
- 'extract_strings(file_path)'
- Tested on Windows

## Day 4 0.0.14
- Fixed 'main.py' with adding string function, removed a repeated 'def' 
- Made the output for the first 10 strings to print successfully

## Day 5 0.0.15
- Updated entropy.py
- Fixed and reorganized main.py
- Updated indicators.py for returning

## Day 6 0.0.16
- Ability to use AI to improve workflow, productivity, knowledge, and skills.
Core Logic & Feature Additions
- Integrated LIEF Library: Added lief to indicators.py to enable deep inspection of binary import tables for both ELF and PE formats.
Implemented Behavioral Scoring:
- Added SUSPICIOUS_IMPORTS dictionary to indicators.py to assign weight to sensitive API calls (e.g., WriteProcessMemory, CreateRemoteThread).
- Added calculate_suspicion_score function to quantify the potential risk of a binary based on its imported functions.
Enhanced Entropy Reporting:
- Updated entropy.py with entropy_verdict(e) to provide human-readable risk assessments (NORMAL vs. HIGH) based on Shannon entropy values.
- Improved calculate_entropy to handle file paths directly, reducing memory overhead in main.py.
Bug Fixes & Maintenance
- Resolved NameError in pe_parser.py: Removed the undefined imports reference in the return dictionary that previously caused crashes during PE analysis.
- Fixed Memory Handling: Streamlined how main.py passes file references to sub-modules to prevent redundant loading of large binary data into memory.
- Standardized Imports: Synchronized function naming across main.py and indicators.py (e.g., transitioning to calculate_suspicion_score).
UI & UX Improvements
- Cleaned main.py Output:
- Reorganized the analysis flow into distinct sections: File Info, Import Analysis, Entropy Analysis, and Suspicious Indicators.
- Added warning flags [!] for high-entropy results and suspicious string matches.
- Implemented a "Total Suspicion Score" display to provide a quick behavioral snapshot.
Next goals:
- Implement a logging system to export these findings to a JSON or Text report for automated batch processing.
- Create a new module hasher.py that calculates the MD5, SHA-1, and SHA-256 of the target binary.
- Add a flag to main.py (e.g., --export) that saves the entire analysis output into a structured format like a .json file or a formatted .txt report in a reports/ folder.

## Day 6 0.0.17
- Added a new CLI interface with --json and --max-strings options so analysis can be used in scripts/automation and tuned for different verbosity needs.
- Refactored output generation to build one structured results object, then render either human-readable text or JSON, making behavior more consistent and easier to extend.
- Improved resilience when lief is not installed: the tool now starts normally and reports a clear import-analysis dependency message instead of crashing at startup.
-Added executable packaging support with PyInstaller and validated the generated binary-analyzer.exe end-to-end in both human-readable and --json modes on real Windows binaries.
- Improved dependency handling for LIEF so the tool no longer hard-crashes when the library is unavailable, and now reports a clear import-analysis status in output.
- Fixed import extraction compatibility across LIEF API variants, enabling successful PE import parsing (verified with real sample output showing non-zero import counts).
