Dev logs, simple terms; REM-1, REM-2 = major logs entered here, REM-1.2, REM-1.4 etc. GitHub pushing only, not named here.

## REM-1
- Create project
- Initialize Git repo (Will use GitHub to reflect)
- Define project goals
- Support PE fiiles
## REM-2
- Detect executable type
- Extract strings
## REM-3
- Fixed 'main.py'
- Added automatic logging to 'logs/strings.txt'
- Attempts to output the first 20 strings for reading
- 'extract_strings(file_path)'
- Tested on Windows
## REM-4
- Fixed 'main.py' with adding string function, removed a repeated 'def' 
- Made the output for the first 10 strings to print successfully
## REM-2
- Updated entropy.py
- Fixed and reorganized main.py
- Updated indicators.py for returning
## REM-3
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
## REM-4
- Added a new CLI interface with --json and --max-strings options so analysis can be used in scripts/automation and tuned for different verbosity needs.
- Refactored output generation to build one structured results object, then render either human-readable text or JSON, making behavior more consistent and easier to extend.
- Improved resilience when lief is not installed: the tool now starts normally and reports a clear import-analysis dependency message instead of crashing at startup.
-Added executable packaging support with PyInstaller and validated the generated binary-analyzer.exe end-to-end in both human-readable and --json modes on real Windows binaries.
- Improved dependency handling for LIEF so the tool no longer hard-crashes when the library is unavailable, and now reports a clear import-analysis status in output.
- Fixed import extraction compatibility across LIEF API variants, enabling successful PE import parsing (verified with real sample output showing non-zero import counts).
- Added build reproducibility and packaging workflow artifacts by pinning dependencies in analyzer/requirements.txt, introducing a one-command Windows build script (analyzer/build.bat), and documenting EXE build/run steps in README.md.
- Improved release hygiene and repository cleanliness by adding .gitignore rules for virtual environment files, Python cache files, and PyInstaller build outputs (analyzer/build/, analyzer/dist/, analyzer/*.spec).
## REM-5
- Implemented Phase 1 quarantine isolation flow with new CLI flags (`--auto-isolate`, `--isolate-threshold`, `--quarantine-dir`) to move suspicious files into controlled manual-review storage.
- Added SHA-256 hashing and isolation manifest logging (`manifest.jsonl`) so each isolation event records when/why a file was quarantined, file hash, score, and original path for auditability.
- Implemented Phase 2 manual-review operations with `--list-quarantine` and `--restore <sha256_prefix>` to inspect isolated artifacts and safely restore them to their original locations.
- Implemented Phase 3 operations with `--delete-from-quarantine` and `--export-manifest-csv` to support cleanup and reporting workflows for analysts.
- Added risk-level tagging (`LOW`, `MEDIUM`, `HIGH`) to analysis results to provide faster triage decisions in both human-readable and JSON output modes.
- Added synthetic binary test samples in `test-sample/` (benign + suspicious) to quickly validate detection behavior and quarantine workflows during development.
## REM-3
- Refactored the CLI entry path: `main.py` now delegates to `cli.py`, with analysis logic in `analysis.py`, quarantine/manifest/CSV helpers in `quarantine.py`, and risk helpers in `risk.py` for easier maintenance and testing.
- Extended auto-isolation with combined triggers: `--isolate-on-risk {LOW,MEDIUM,HIGH}` (isolate when computed risk meets or exceeds the chosen band) and `--keyword-isolate-threshold N` (isolate when suspicious string hit count is at least N; `0` disables). Any matching rule together with `--auto-isolate` can quarantine a file; the manifest records the full trigger reason string.
- Enriched analysis results with `suspicious_indicators_total` and `suspicious_indicators_all` so triage and manifests use full keyword coverage, not only the preview slice.
- Added a `tests/` suite (pytest) covering risk classification, file-type detection, mocked `build_results`, manifest parsing/CSV export, and isolation trigger composition; added `requirements-dev.txt` and documented `python -m pytest tests/` in README.md.
- Added GitHub Actions workflow `.github/workflows/tests.yml` (Windows, Python 3.12) to install dependencies and run the test suite on push/PR to `main`.
- Updated quarantine CSV export to include a `risk_level` column for manifest rows; ignored `.pytest_cache/` in `.gitignore`.
## REM-4

## REM-5

## REM-6

## REM-4

## REM-5

## REM-6

## REM-7

## REM-5

## REM-6

## REM-7

## REM-8

## REM-6

## REM-7

## REM-8

## REM-9

## REM-7

## REM-8

## REM-9

## REM-10

## REM-8

## REM-9

## REM-10

## REM-11

## REM-9

## REM-10

## REM-11

## REM-12

## REM-10

## REM-11

## REM-12

## REM-13

## REM-11

## REM-12

## REM-13

## REM-14

## REM-12

## REM-13

## REM-14

## REM-15

## REM-13

## REM-14

## REM-15

## REM-16

## REM-14

## REM-15

## REM-16

## REM-17

## REM-15

## REM-16

## REM-17

## REM-18

## REM-16

## REM-17

## REM-18

## REM-19

## REM-17

## REM-18

## REM-19

## REM-20

## REM-18

## REM-19

## REM-20

## REM-21

## REM-19

## REM-20

## REM-21

## REM-22

## REM-20

## REM-21

## REM-22

## REM-23

## REM-21

## REM-22

## REM-23

## REM-24

## REM-22

## REM-23

## REM-24

## REM-25

## REM-23

## REM-24

## REM-25

## REM-26

## REM-24

## REM-25

## REM-26

## REM-27

## REM-25

## REM-26

## REM-27

## REM-28

## REM-26

## REM-27

## REM-28

## REM-29

## REM-27

## REM-28

## REM-29

## REM-30

## REM-28

## REM-29

## REM-30

## REM-31

## REM-29

## REM-30

## REM-31

## REM-32

## REM-30

## REM-31

## REM-32

## REM-33

## REM-31

## REM-32

## REM-33

## REM-34

## REM-32

## REM-33

## REM-34

## REM-35

## REM-33

## REM-34

## REM-35

## REM-36

## REM-34

## REM-35

## REM-36

## REM-37

## REM-35

## REM-36

## REM-37

## REM-38

## REM-36

## REM-37

## REM-38

## REM-39

## REM-37

## REM-38

## REM-39

## REM-40

## REM-38

## REM-39

## REM-40

## REM-41

## REM-39

## REM-40

## REM-41

## REM-42

## REM-40

## REM-41

## REM-42

## REM-43

## REM-41

## REM-42

## REM-43

## REM-44

## REM-42

## REM-43

## REM-44

## REM-45

## REM-43

## REM-44

## REM-45

## REM-46

## REM-44

## REM-45

## REM-46

## REM-47

## REM-45

## REM-46

## REM-47

## REM-48

## REM-46

## REM-47

## REM-48

## REM-49

## REM-47

## REM-48

## REM-49

## REM-50

## REM-48

## REM-49

## REM-50

## REM-51

## REM-49

## REM-50

## REM-51

## REM-52

## REM-50

## REM-51

## REM-52

## REM-53

## REM-51

## REM-52

## REM-53

## REM-54

## REM-52

## REM-53

## REM-54

## REM-55

## REM-53

## REM-54

## REM-55

## REM-56

## REM-54

## REM-55

## REM-56

## REM-57

## REM-55

## REM-56

## REM-57

## REM-58

## REM-56

## REM-57

## REM-58

## REM-59

## REM-57

## REM-58

## REM-59

## REM-60

## REM-58

## REM-59

## REM-60

## REM-61

## REM-59

## REM-60

## REM-61

## REM-62

## REM-60

## REM-61

## REM-62

## REM-63

## REM-61

## REM-62

## REM-63

## REM-64

## REM-62

## REM-63

## REM-64

## REM-65

## REM-63

## REM-64

## REM-65

## REM-66

## REM-64

## REM-65

## REM-66

## REM-67

## REM-65

## REM-66

## REM-67

## REM-68

## REM-66

## REM-67

## REM-68

## REM-69

## REM-67

## REM-68

## REM-69

## REM-70

## REM-68

## REM-69

## REM-70

## REM-71

## REM-69

## REM-70

## REM-71

## REM-72

## REM-70

## REM-71

## REM-72

## REM-73

## REM-71

## REM-72

## REM-73

## REM-74

## REM-72

## REM-73

## REM-74

## REM-75

## REM-73

## REM-74

## REM-75

## REM-76

## REM-74

## REM-75

## REM-76

## REM-77

## REM-75

## REM-76

## REM-77

## REM-78

## REM-76

## REM-77

## REM-78

## REM-79

## REM-77

## REM-78

## REM-79

## REM-80

## REM-78

## REM-79

## REM-80

## REM-81

## REM-79

## REM-80

## REM-81

## REM-82

## REM-80

## REM-81

## REM-82

## REM-83

## REM-81

## REM-82

## REM-83

## REM-84

## REM-82

## REM-83

## REM-84

## REM-85

## REM-83

## REM-84

## REM-85

## REM-86

## REM-84

## REM-85

## REM-86

## REM-87

## REM-85

## REM-86

## REM-87

## REM-88

## REM-86

## REM-87

## REM-88

## REM-89

## REM-87

## REM-88

## REM-89

## REM-90

## REM-88

## REM-89

## REM-90

## REM-91

## REM-89

## REM-90

## REM-91

## REM-92

## REM-90

## REM-91

## REM-92

## REM-93

## REM-91

## REM-92

## REM-93

## REM-94

## REM-92

## REM-93

## REM-94

## REM-95

## REM-93

## REM-94

## REM-95

## REM-96

## REM-94

## REM-95

## REM-96

## REM-97

## REM-95

## REM-96

## REM-97

## REM-98

## REM-96

## REM-97

## REM-98

## REM-99

## REM-97

## REM-98

## REM-99

## REM-100

## REM-98

## REM-99

## REM-100

## REM-101

## REM-99

## REM-100

## REM-101

## REM-102

## REM-100

## REM-101

## REM-102

## REM-103

## REM-101

## REM-102

## REM-103

## REM-104

## REM-102

## REM-103

## REM-104

## REM-105

## REM-103

## REM-104

## REM-105

## REM-106

## REM-104

## REM-105

## REM-106

## REM-107

## REM-105

## REM-106

## REM-107

## REM-108

## REM-106

## REM-107

## REM-108

## REM-109

## REM-107

## REM-108

## REM-109

## REM-110

## REM-108

## REM-109

## REM-110

## REM-111

## REM-109

## REM-110

## REM-111

## REM-112

## REM-110

## REM-111

## REM-112

## REM-113

## REM-111

## REM-112

## REM-113

## REM-114

## REM-112

## REM-113

## REM-114

## REM-115

## REM-113

## REM-114

## REM-115

## REM-116

## REM-114

## REM-115

## REM-116

## REM-117

## REM-115

## REM-116

## REM-117

## REM-118

## REM-116

## REM-117

## REM-118

## REM-119

## REM-117

## REM-118

## REM-119

## REM-120

## REM-118

## REM-119

## REM-120

## REM-121

## REM-119

## REM-120

## REM-121

## REM-122

## REM-120

## REM-121

## REM-122

## REM-123

## REM-121

## REM-122

## REM-123

## REM-124

## REM-122

## REM-123

## REM-124

## REM-125

## REM-123

## REM-124

## REM-125

## REM-126

## REM-124

## REM-125

## REM-126

## REM-127

## REM-125

## REM-126

## REM-127

## REM-128

## REM-126