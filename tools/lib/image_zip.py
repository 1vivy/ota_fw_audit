"""Raw firmware image zip support.

Some firmware drops are not OTA packages at all: they are a flat zip of
`<partition>.img` members with no `payload.bin` and no OTA metadata.  Those
cannot be read by `payload_dumper`, so partitions are taken straight out of
the zip instead.

`detect_kind` distinguishes the two shapes so the caller only requires
`payload_dumper` for packages that actually carry an update payload.
"""

from __future__ import annotations

import shutil
import zipfile
from pathlib import Path
from typing import Final

PAYLOAD_MEMBER: Final[str] = "payload.bin"
_IMAGE_SUFFIX: Final[str] = ".img"
_COPY_CHUNK: Final[int] = 1024 * 1024


def _member_images(names: list[str]) -> dict[str, str]:
    """Map partition name -> zip member for top-level `<name>.img` members."""
    images: dict[str, str] = {}
    for name in names:
        if "/" in name or not name.endswith(_IMAGE_SUFFIX):
            continue
        images[name[: -len(_IMAGE_SUFFIX)]] = name
    return images


def detect_kind(zip_path: str) -> str:
    """Return "payload" for an OTA payload zip, "raw_images" for an image zip.

    Returns "unknown" when the zip is unreadable or carries neither shape.
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as archive:
            names = archive.namelist()
    except (zipfile.BadZipFile, OSError):
        return "unknown"
    if any(name.endswith(PAYLOAD_MEMBER) for name in names):
        return "payload"
    if _member_images(names):
        return "raw_images"
    return "unknown"


def list_images(zip_path: str) -> list[str]:
    """List partition names available as raw images in the zip."""
    with zipfile.ZipFile(zip_path, "r") as archive:
        return sorted(_member_images(archive.namelist()))


def extract_images(zip_path: str, partitions: list[str], out_dir: str) -> dict[str, str]:
    """Extract the requested partitions from a raw image zip.

    Returns a mapping of partition name -> extracted file path, containing
    only the partitions the zip actually provides.
    """
    destination = Path(out_dir)
    destination.mkdir(parents=True, exist_ok=True)
    extracted: dict[str, str] = {}
    with zipfile.ZipFile(zip_path, "r") as archive:
        available = _member_images(archive.namelist())
        for partition in partitions:
            member = available.get(partition)
            if member is None:
                continue
            target = destination / f"{partition}{_IMAGE_SUFFIX}"
            with archive.open(member) as source, target.open("wb") as sink:
                shutil.copyfileobj(source, sink, _COPY_CHUNK)
            extracted[partition] = str(target)
    return extracted
