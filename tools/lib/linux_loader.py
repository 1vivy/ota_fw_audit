"""Extract LinuxLoader.efi from ABL images using gbl_root_canoe extractfv."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


EFISP_PATTERN_UTF16LE = b"e\x00f\x00i\x00s\x00p\x00"

_DEFAULT_BINARIES = [
    str(
        Path(__file__).resolve().parent.parent.parent.parent
        / "tools"
        / "gbl_root_canoe"
        / "tools"
        / "extractfv_host"
    ),
    str(
        Path(__file__).resolve().parent.parent.parent.parent
        / "tools"
        / "gbl_root_canoe"
        / "tools"
        / "extractfv"
    ),
]


def _find_binary() -> str | None:
    which = shutil.which("extractfv")
    if which:
        return which
    for candidate in _DEFAULT_BINARIES:
        if os.path.isfile(candidate):
            return candidate
    return None


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _prepare_output_dir(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    linux_loader = output_dir / "LinuxLoader.efi"
    if linux_loader.exists():
        linux_loader.unlink()


def inspect_abl(
    image_path: str,
    binary: str | None = None,
    output_dir: str | None = None,
) -> dict | None:
    """Extract LinuxLoader.efi from ABL and return basic metadata."""
    binary = binary or _find_binary()
    if not binary:
        return None

    if output_dir is not None:
        output_path = Path(output_dir)
        _prepare_output_dir(output_path)
        cleanup_dir = False
    else:
        output_path = Path(tempfile.mkdtemp(prefix="fw_audit_abl_")) / "out"
        _prepare_output_dir(output_path)
        cleanup_dir = True

    try:
        try:
            result = subprocess.run(
                [binary, "-o", str(output_path), image_path],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return {
                "tool": "extractfv",
                "success": False,
                "error": str(exc),
            }

        linux_loader = output_path / "LinuxLoader.efi"
        combined = ((result.stdout or "") + (result.stderr or "")).strip()
        if not linux_loader.is_file():
            return {
                "tool": "extractfv",
                "success": False,
                "error": combined or f"exit {result.returncode}",
            }

        data = linux_loader.read_bytes()
        return {
            "tool": "extractfv",
            "success": True,
            "size": linux_loader.stat().st_size,
            "sha256": _sha256_file(linux_loader),
            "has_efisp_string": EFISP_PATTERN_UTF16LE in data,
            "efisp_count": data.count(EFISP_PATTERN_UTF16LE),
            "mz_header": data[:2] == b"MZ",
        }
    finally:
        if cleanup_dir:
            shutil.rmtree(output_path.parent, ignore_errors=True)
