import os
import shutil
import subprocess

from ..quarantine import sha256_file
from .base import UnpackResult


def unpack_upx(file_path: str, output_dir: str) -> UnpackResult:
    """Unpack a UPX-compressed PE via the external ``upx -d`` recipe."""
    upx_cmd = shutil.which("upx")
    if not upx_cmd:
        return UnpackResult(
            attempted=True,
            performed=False,
            method="upx-cli",
            packer="UPX",
            error="upx not found on PATH",
        )

    os.makedirs(output_dir, exist_ok=True)
    base = os.path.basename(file_path)
    out_path = os.path.join(output_dir, f"unpacked_{base}")

    try:
        proc = subprocess.run(
            [upx_cmd, "-d", "-o", out_path, file_path],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return UnpackResult(
            attempted=True,
            performed=False,
            method="upx-cli",
            packer="UPX",
            error="upx timed out after 120s",
        )
    except OSError as exc:
        return UnpackResult(
            attempted=True,
            performed=False,
            method="upx-cli",
            packer="UPX",
            error=str(exc),
        )

    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        return UnpackResult(
            attempted=True,
            performed=False,
            method="upx-cli",
            packer="UPX",
            error=detail or f"upx exited with code {proc.returncode}",
        )

    if not os.path.isfile(out_path):
        return UnpackResult(
            attempted=True,
            performed=False,
            method="upx-cli",
            packer="UPX",
            error="upx reported success but output file is missing",
        )

    return UnpackResult(
        attempted=True,
        performed=True,
        method="upx-cli",
        packer="UPX",
        output_path=out_path,
        sha256=sha256_file(out_path),
        error=None,
    )
