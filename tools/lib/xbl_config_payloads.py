"""Wrapper around XBLConfigReader for xbl_config payload extraction."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


_DEFAULT_BINARY = str(
    Path(__file__).resolve().parent.parent.parent.parent
    / "tools"
    / "XBLConfigReader"
    / "build"
    / "xcreader"
)


def _find_binary() -> str | None:
    which = shutil.which("xcreader")
    if which:
        return which
    if os.path.isfile(_DEFAULT_BINARY):
        return _DEFAULT_BINARY
    return None


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _prepare_output_dir(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for child in output_dir.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()


def _parse_output(raw: str, output_dir: Path) -> dict:
    result: dict = {
        "tool": "xcreader",
        "success": True,
        "cfgl_offset": None,
        "file_count": None,
        "files": [],
    }

    m = re.search(r"CFGL Offset:\s+0x([0-9a-fA-F]+)", raw)
    if m:
        result["cfgl_offset"] = int(m.group(1), 16)

    m = re.search(r"File Counts:\s+(\d+)", raw)
    if m:
        result["file_count"] = int(m.group(1))

    current: dict | None = None
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("File "):
            if current:
                result["files"].append(current)
            current = {}
            continue
        if current is None:
            continue
        if stripped.startswith("Name:"):
            original_name = stripped.split(":", 1)[1].strip()
            current["name"] = original_name
            current["extracted_name"] = Path(original_name).name
        elif stripped.startswith("Size:"):
            current["size"] = int(stripped.split(":", 1)[1].strip(), 16)
        elif stripped.startswith("Offset:"):
            current["offset"] = int(stripped.split(":", 1)[1].strip(), 16)
        elif stripped.startswith("File Offset:"):
            current["file_offset"] = int(stripped.split(":", 1)[1].strip(), 16)

    if current:
        result["files"].append(current)

    for entry in result["files"]:
        extracted_name = entry.get("extracted_name")
        if not extracted_name:
            continue
        file_path = output_dir / extracted_name
        if file_path.is_file():
            entry["sha256"] = _sha256_file(file_path)
            entry["extracted_size"] = file_path.stat().st_size

    return result


def inspect_xbl_config(
    image_path: str,
    binary: str | None = None,
    output_dir: str | None = None,
) -> dict | None:
    """Extract xbl_config payloads using XBLConfigReader.

    Returns None when the binary is unavailable, otherwise a dict describing
    success/failure and any extracted payload metadata.
    """
    binary = binary or _find_binary()
    if not binary:
        return None

    if output_dir is not None:
        output_path = Path(output_dir)
        _prepare_output_dir(output_path)
        cleanup_dir = False
    else:
        output_path = Path(tempfile.mkdtemp(prefix="fw_audit_xcreader_"))
        cleanup_dir = True

    try:
        try:
            result = subprocess.run(
                [binary, image_path, str(output_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return {
                "tool": "xcreader",
                "success": False,
                "error": str(exc),
            }

        combined = (result.stdout or "") + (result.stderr or "")
        if result.returncode != 0:
            return {
                "tool": "xcreader",
                "success": False,
                "error": combined.strip() or f"exit {result.returncode}",
            }

        return _parse_output(combined, output_path)
    finally:
        if cleanup_dir:
            shutil.rmtree(output_path, ignore_errors=True)
