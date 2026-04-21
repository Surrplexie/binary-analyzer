import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_ANALYZER = _ROOT / "analyzer"
if str(_ANALYZER) not in sys.path:
    sys.path.insert(0, str(_ANALYZER))
