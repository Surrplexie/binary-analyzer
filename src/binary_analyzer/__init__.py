"""Static analysis helpers for PE/ELF binaries (strings, entropy, imports, risk scoring)."""

from .analysis import build_results, build_results_with_unpack, detect_file_type
from .packer import PackerMatch, detect_packers, pick_unpack_target
from .rules import (
    AnalysisRules,
    load_default_rules,
    load_effective_rules,
    load_rules_from_path,
    RULES_ENV_VAR,
)

__all__ = [
    "build_results",
    "build_results_with_unpack",
    "detect_file_type",
    "detect_packers",
    "pick_unpack_target",
    "PackerMatch",
    "AnalysisRules",
    "load_default_rules",
    "load_effective_rules",
    "load_rules_from_path",
    "RULES_ENV_VAR",
]
__version__ = "0.2.0"
