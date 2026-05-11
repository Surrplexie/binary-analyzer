#!/usr/bin/env python3
"""
Cross-platform build script for binary-analyzer.

Usage:
  python build.py                # build for this platform
  python build.py --no-install   # skip pip install step
  python build.py --clean        # wipe build/ and dist/ first
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
# _entry.py is a plain (non-package) shim that avoids the relative-import
# issue that occurs when PyInstaller uses __main__.py as the frozen entry.
ENTRY = ROOT / "_entry.py"
DIST = ROOT / "dist"
BUILD = ROOT / "build"

IS_WIN = sys.platform == "win32"
EXE_NAME = "binary-analyzer"


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


def build_binary() -> Path:
    if not ENTRY.exists():
        print(f"ERROR: entry point not found: {ENTRY}", file=sys.stderr)
        sys.exit(1)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--name", EXE_NAME,
        # let PyInstaller find the installed package AND the editable src layout
        "--paths", str(ROOT / "src"),
        # bundle the JSON data files packed inside the package
        "--collect-data", "binary_analyzer",
        # lief is a C-extension; collect its binaries as well
        "--collect-all", "lief",
        # explicit hidden imports so nothing is missed by static analysis
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
        str(ENTRY),
    ]

    run(cmd, cwd=str(ROOT))

    suffix = ".exe" if IS_WIN else ""
    out = DIST / f"{EXE_NAME}{suffix}"
    if not out.exists():
        print(f"ERROR: expected output not found: {out}", file=sys.stderr)
        sys.exit(1)
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Build binary-analyzer standalone binary.")
    parser.add_argument("--no-install", action="store_true", help="Skip pip install step")
    parser.add_argument("--clean", action="store_true", help="Remove build/ and dist/ before building")
    args = parser.parse_args()

    print(f"Platform : {sys.platform}")
    print(f"Python   : {sys.version}")
    print(f"Root     : {ROOT}")
    print(f"Entry    : {ENTRY}")

    if args.clean:
        clean()

    if not args.no_install:
        print("\n[1/2] Installing package + dev dependencies...")
        install_deps()
    else:
        print("\n[1/2] Skipping install (--no-install)")

    print("\n[2/2] Building standalone binary via PyInstaller...")
    out = build_binary()

    size_mb = out.stat().st_size / (1024 * 1024)
    print(f"\nBuild complete: {out}  ({size_mb:.1f} MB)")
    print(f"Run it with  : {out} samples/test.exe --json")


if __name__ == "__main__":
    main()
