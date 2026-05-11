#!/usr/bin/env python3
"""
Cross-platform build script for binary-analyzer.

Targets:
  python build.py           build CLI binary only (default)
  python build.py --gui     build GUI binary only
  python build.py --both    build both

Flags:
  --clean        wipe build/ and dist/ first
  --no-install   skip pip install step
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT    = Path(__file__).parent.resolve()
DIST    = ROOT / "dist"
BUILD   = ROOT / "build"
IS_WIN  = sys.platform == "win32"

# Entry-point shims (plain scripts — relative imports break when frozen)
CLI_ENTRY = ROOT / "_entry.py"
GUI_ENTRY = ROOT / "_entry_gui.py"


def _ensure_entry_shims():
    """Write entry shims if they don't already exist (they're .gitignored)."""
    if not CLI_ENTRY.exists():
        CLI_ENTRY.write_text(
            "from binary_analyzer.cli import main\n\n"
            "if __name__ == '__main__':\n    main()\n",
            encoding="utf-8",
        )
    if not GUI_ENTRY.exists():
        GUI_ENTRY.write_text(
            "from binary_analyzer.gui import run_gui\n\n"
            "if __name__ == '__main__':\n    run_gui()\n",
            encoding="utf-8",
        )


def run(cmd: list, **kwargs) -> None:
    print(f"\n>>> {' '.join(str(c) for c in cmd)}")
    r = subprocess.run([str(c) for c in cmd], **kwargs)
    if r.returncode != 0:
        sys.exit(r.returncode)


def clean() -> None:
    for d in (DIST, BUILD):
        if d.exists():
            print(f"Removing {d}")
            shutil.rmtree(d)
    for spec in ROOT.glob("*.spec"):
        print(f"Removing {spec}")
        spec.unlink()


def install_deps() -> None:
    run([sys.executable, "-m", "pip", "install", "-e", ".[dev]", "-q"])


def _check_dnd() -> bool:
    """Return True if tkinterdnd2 is importable (for --collect-all in GUI build)."""
    try:
        import tkinterdnd2  # noqa
        return True
    except ImportError:
        return False


def build_cli() -> Path:
    _ensure_entry_shims()
    if not CLI_ENTRY.exists():
        print(f"ERROR: CLI entry not found: {CLI_ENTRY}", file=sys.stderr)
        sys.exit(1)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "binary-analyzer",
        "--paths", str(ROOT / "src"),
        "--collect-data", "binary_analyzer",
        "--collect-all", "lief",
        "--hidden-import", "binary_analyzer",
        "--hidden-import", "binary_analyzer.rules",
        "--hidden-import", "binary_analyzer.analysis",
        "--hidden-import", "binary_analyzer.cli",
        "--hidden-import", "binary_analyzer.entropy",
        "--hidden-import", "binary_analyzer.indicators",
        "--hidden-import", "binary_analyzer.pe_parser",
        "--hidden-import", "binary_analyzer.quarantine",
        "--hidden-import", "binary_analyzer.risk",
        "--hidden-import", "binary_analyzer.string_extractor",
        "--noconfirm",
        str(CLI_ENTRY),
    ]
    run(cmd, cwd=str(ROOT))
    return _check_output("binary-analyzer")


def build_gui() -> Path:
    _ensure_entry_shims()
    if not GUI_ENTRY.exists():
        print(f"ERROR: GUI entry not found: {GUI_ENTRY}", file=sys.stderr)
        sys.exit(1)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", "binary-analyzer-gui",
        "--paths", str(ROOT / "src"),
        "--collect-data", "binary_analyzer",
        "--collect-all", "lief",
        "--collect-all", "customtkinter",
        "--hidden-import", "binary_analyzer",
        "--hidden-import", "binary_analyzer.gui",
        "--hidden-import", "binary_analyzer.rules",
        "--hidden-import", "binary_analyzer.analysis",
        "--hidden-import", "binary_analyzer.cli",
        "--hidden-import", "binary_analyzer.entropy",
        "--hidden-import", "binary_analyzer.indicators",
        "--hidden-import", "binary_analyzer.pe_parser",
        "--hidden-import", "binary_analyzer.quarantine",
        "--hidden-import", "binary_analyzer.risk",
        "--hidden-import", "binary_analyzer.string_extractor",
        "--hidden-import", "tkinter",
        "--hidden-import", "tkinter.ttk",
        "--hidden-import", "tkinter.filedialog",
        "--hidden-import", "tkinter.messagebox",
        "--hidden-import", "tkinter.simpledialog",
        "--noconfirm",
    ]

    if IS_WIN:
        cmd.append("--windowed")   # suppress console window on Windows

    if _check_dnd():
        cmd += ["--collect-all", "tkinterdnd2"]

    cmd.append(str(GUI_ENTRY))
    run(cmd, cwd=str(ROOT))
    return _check_output("binary-analyzer-gui")


def _check_output(name: str) -> Path:
    suffix = ".exe" if IS_WIN else ""
    out = DIST / f"{name}{suffix}"
    if not out.exists():
        print(f"ERROR: expected output not found: {out}", file=sys.stderr)
        sys.exit(1)
    return out


def _report(out: Path):
    mb = out.stat().st_size / (1024 * 1024)
    print(f"\n  OK  {out}  ({mb:.1f} MB)")


def main():
    parser = argparse.ArgumentParser(description="Build binary-analyzer standalone binaries.")
    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--gui",  action="store_true", help="Build GUI binary only")
    grp.add_argument("--both", action="store_true", help="Build CLI + GUI binaries")
    parser.add_argument("--no-install", action="store_true", help="Skip pip install step")
    parser.add_argument("--clean",      action="store_true", help="Wipe build/ and dist/ first")
    args = parser.parse_args()

    print(f"Platform : {sys.platform}")
    print(f"Python   : {sys.version.split()[0]}")
    print(f"Root     : {ROOT}")

    if args.clean:
        clean()

    if not args.no_install:
        print("\n[install] Installing package + dev dependencies…")
        install_deps()

    outputs = []

    if args.gui:
        print("\n[build] Building GUI binary…")
        outputs.append(build_gui())
    elif args.both:
        print("\n[build] Building CLI binary…")
        outputs.append(build_cli())
        print("\n[build] Building GUI binary…")
        outputs.append(build_gui())
    else:
        print("\n[build] Building CLI binary…")
        outputs.append(build_cli())

    print("\nBuild complete:")
    for o in outputs:
        _report(o)

    print("\nRun examples:")
    for o in outputs:
        if "gui" in o.name:
            print(f"  {o} samples/test.exe")
        else:
            print(f"  {o} samples/test.exe --json")


if __name__ == "__main__":
    main()
