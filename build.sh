#!/usr/bin/env bash
# Build binary-analyzer for Linux.
# Usage:
#   ./build.sh               # normal build
#   ./build.sh --clean       # wipe build/ and dist/ first
#   ./build.sh --no-install  # skip pip install step
set -euo pipefail
cd "$(dirname "$0")"
python3 build.py "$@"
