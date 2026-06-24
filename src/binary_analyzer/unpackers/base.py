from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class UnpackResult:
    attempted: bool = False
    performed: bool = False
    method: Optional[str] = None
    packer: Optional[str] = None
    output_path: Optional[str] = None
    sha256: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self):
        return asdict(self)
