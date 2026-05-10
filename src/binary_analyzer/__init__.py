"""Static analysis helpers for PE/ELF binaries (strings, entropy, imports, risk scoring)."""

from .analysis import build_results, detect_file_type

__all__ = ["build_results", "detect_file_type"]
__version__ = "0.2.0"
