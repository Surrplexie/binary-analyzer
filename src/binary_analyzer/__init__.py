"""Static analysis helpers for PE/ELF binaries (strings, entropy, imports, risk scoring)."""

from .analysis import build_results, detect_file_type
from .rules import (
    AnalysisRules,
    load_default_rules,
    load_effective_rules,
    load_rules_from_path,
    RULES_ENV_VAR,
)

__all__ = [
    "build_results",
    "detect_file_type",
    "AnalysisRules",
    "load_default_rules",
    "load_effective_rules",
    "load_rules_from_path",
    "RULES_ENV_VAR",
]
__version__ = "0.2.0"
