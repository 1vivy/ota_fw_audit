"""Wrapper around xbltools/unpackxbl for extracting XBL components."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


_DEFAULT_BINARY = str(
    Path(__file__).resolve().parent.parent.parent.parent
    / "tools"
    / "xbltools"
    / "build"
    / "unpackxbl"
)


def _find_binary() -> str | None:
    which = shutil.which("unpackxbl")
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
    for name in ["sbl1.elf", "xbl_core.elf", "xbl_sec.mbn"]:
        path = output_dir / name
        if path.exists():
            path.unlink()


def inspect_xbl(
    image_path: str,
    binary: str | None = None,
    output_dir: str | None = None,
) -> dict | None:
    """Attempt to split xbl into sbl1/xbl_core/xbl_sec components."""
    binary = binary or _find_binary()
    if not binary:
        return None

    if output_dir is not None:
        tmpdir = Path(output_dir)
        _prepare_output_dir(tmpdir)
        cleanup_dir = False
    else:
        tmpdir = Path(tempfile.mkdtemp(prefix="fw_audit_xbl_"))
        cleanup_dir = True

    try:
        try:
            result = subprocess.run(
                [binary, image_path],
                cwd=tmpdir,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return {
                "tool": "unpackxbl",
                "success": False,
                "error": str(exc),
                "components": {},
            }

        components = {}
        for name in ["sbl1.elf", "xbl_core.elf", "xbl_sec.mbn"]:
            path = tmpdir / name
            if path.is_file():
                components[name] = {
                    "size": path.stat().st_size,
                    "sha256": _sha256_file(path),
                }

        combined = ((result.stderr or "") + "\n" + (result.stdout or "")).strip()
        success = result.returncode == 0 and bool(components)

        output = {
            "tool": "unpackxbl",
            "success": success,
            "components": components,
        }
        if combined:
            output["log"] = combined
        if not success and result.returncode != 0:
            output["error"] = combined or f"exit {result.returncode}"
        return output
    finally:
        if cleanup_dir:
            shutil.rmtree(tmpdir, ignore_errors=True)
