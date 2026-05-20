# Remediations log

Development milestones for **binary-analyzer**. Use `REM-N` for major updates in this file. Sub-versions such as `REM-1.2` are for Git commit messages only — not listed here.

---

## REM-1 — Project bootstrap

- Created project and initialized Git (GitHub remote)
- Defined goals: static analysis for executable files
- Initial PE support

## REM-2 — Core extraction

- Executable type detection (PE / ELF magic bytes)
- Printable string extraction
- Entropy module and indicators scaffolding

## REM-3 — CLI refactor and scoring

- Split monolithic `main.py` into `cli.py`, `analysis.py`, `quarantine.py`, `risk.py`
- Integrated LIEF for PE/ELF import tables
- Suspicious import weights and `calculate_suspicion_score`
- Entropy verdicts (NORMAL / MEDIUM / HIGH)
- Structured `build_results()` dict; human and JSON output modes
- `--json`, `--max-strings`; resilient behavior when LIEF is missing
- Risk levels: LOW / MEDIUM / HIGH
- `suspicious_indicators_total` and `suspicious_indicators_all` for full keyword coverage
- PyInstaller packaging (`build.py`, `build.bat`, `build.sh`) and release docs

## REM-4 — Rules, tests, and CI

- Configurable rules: `default_rules.json`, merge semantics, `--rules`, `BINARY_ANALYZER_RULES`
- `tests/` suite (pytest) and `.github/workflows/tests.yml`
- Extended isolation triggers: `--isolate-on-risk`, `--keyword-isolate-threshold`
- Quarantine CSV export includes `risk_level`

## REM-5 — Quarantine workflow

- Phase 1: `--auto-isolate`, `--isolate-threshold`, `--quarantine-dir`, SHA-256 manifest (`manifest.jsonl`)
- Phase 2: `--list-quarantine`, `--restore <sha256_prefix>`
- Phase 3: `--delete-from-quarantine`, `--export-manifest-csv`
- Synthetic samples in `test-sample/` (benign + suspicious)

## REM-6 — GUI and dual-binary releases

- CustomTkinter HUD (`gui.py`): analyze, isolate, copy JSON, save report, load rules
- `python -m binary_analyzer --gui` and `binary-analyzer-gui` entry point
- CI builds CLI + GUI on Windows and Linux; tag-based GitHub Releases
- Drag-and-drop via optional `tkinterdnd2`

## REM-7 — Documentation hygiene (Tier 1)

- Stop tracking `*.egg-info/` in git; document architecture in `docs/architecture.md`
- README fixes: TOC numbering, real clone URL, project structure, `--gui` in CLI reference
- Reorganized this remediations log and backlog section below

---

## Backlog

Open items not yet implemented. Pick up in future REM entries.

| Item | Notes |
|------|--------|
| CLI `--output` / `--export` | Write analysis JSON (and optional text report) to a file path for batch/SOAR pipelines |
| Extra hashes (MD5, SHA-1) | Optional `file_info` fields; SHA-256 already present |
| ELF section metadata | Symmetric `elf_info` in results (PE has `pe_info` today) |
| Integration tests | Exercise `test-sample/bad_sample.bin` and `good_sample.bin` in pytest |
| Linux CI for tests | Extend `tests.yml` beyond `windows-latest` |
| Streaming entropy/strings | Reduce memory use on large binaries |
| Import score deduplication | Score unique matched imports, not repeated symbol occurrences |

### Historical notes (superseded)

- `logs/strings.txt` auto-logging — removed with CLI refactor; use `--json` or GUI Save Report
- `analyzer/requirements.txt` — replaced by `pyproject.toml` optional extras (`[dev]`, `[gui]`)
- `requirements-dev.txt` — dev deps live in `pyproject.toml` `[project.optional-dependencies]`
