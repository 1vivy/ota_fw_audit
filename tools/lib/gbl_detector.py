"""
GBL (Generic Boot Loader) exploit detector for ABL images.

Detects whether an ABL image contains the GBL vulnerability that allows
loading unsigned EFIs from the EFISP partition.

The detection works by:
1. Scanning the raw ABL image for the UTF-16LE string "efisp"
2. If not found in raw data, attempting LZMA decompression of embedded
   UEFI firmware volume sections and scanning the decompressed data

ABL images typically contain LZMA-compressed UEFI firmware volumes.
The LinuxLoader.efi PE binary lives inside these compressed sections.
The "efisp" string (UTF-16LE) is the partition name ABL uses to locate
and load unsigned EFI applications.

Reference: https://github.com/superturtlee/gbl_root_canoe

This is useful for firmware audit because:
- The GBL vulnerability is a developer-facing exploit worth retaining
- OEMs can patch it out by removing the "efisp" reference from ABL
- Knowing whether it's present helps decide if a firmware downgrade
  is worth pursuing to keep the exploit path open
"""

import lzma
import struct

# The target pattern: UTF-16LE encoding of "efisp"
EFISP_PATTERN_UTF16LE = b"e\x00f\x00i\x00s\x00p\x00"

# LZMA alone header magic byte (properties byte)
LZMA_PROPS_BYTE = 0x5D

# Minimum size for a plausible LZMA section
MIN_LZMA_SIZE = 64


def _find_pattern(data: bytes, pattern: bytes) -> list[int]:
    """Find all occurrences of pattern in data."""
    offsets = []
    start = 0
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + len(pattern)
    return offsets


def _try_lzma_decompress(data: bytes) -> bytes:
    """Try various LZMA decompression strategies on a data blob."""
    # Strategy 1: lzma.decompress with FORMAT_AUTO
    try:
        return lzma.decompress(data)
    except Exception:
        pass

    # Strategy 2: lzma.decompress with FORMAT_ALONE
    try:
        return lzma.decompress(data, format=lzma.FORMAT_ALONE)
    except Exception:
        pass

    # Strategy 3: construct LZMA alone header like extractfv does
    # extractfv takes 5 props bytes, adds 8 bytes of 0xFF for unknown size,
    # then the rest of the compressed data
    if len(data) >= 5 and data[0] == LZMA_PROPS_BYTE:
        try:
            header = data[:5] + b"\xFF" * 8
            compressed = header + data[5:]
            return lzma.decompress(compressed, format=lzma.FORMAT_ALONE)
        except Exception:
            pass

    return b""


def _find_and_decompress_lzma_sections(data: bytes) -> list[bytes]:
    """Scan raw data for LZMA-compressed sections and decompress them.

    This mimics how extractfv scans UEFI Firmware Volume sections for
    LZMA-compressed payloads.
    """
    results = []

    # Scan for LZMA props byte (0x5D) with plausible following bytes
    for i in range(len(data) - MIN_LZMA_SIZE):
        if data[i] != LZMA_PROPS_BYTE:
            continue

        # Try multiple chunk sizes (LZMA sections can vary in size)
        for chunk_end in [
            min(i + 4 * 1024 * 1024, len(data)),
            min(i + 8 * 1024 * 1024, len(data)),
            min(i + 16 * 1024 * 1024, len(data)),
        ]:
            chunk = data[i:chunk_end]
            decompressed = _try_lzma_decompress(chunk)
            if len(decompressed) > 1024:
                results.append(decompressed)
                break  # Got a good decompress, move on

        # Limit to first 5 successful decompressions to avoid timeouts
        if len(results) >= 5:
            break

    return results


def detect_gbl_vulnerability(abl_data: bytes) -> dict:
    """Scan ABL image data for GBL vulnerability indicators.

    First checks the raw image, then decompresses LZMA sections
    if no matches found in raw data.

    Args:
        abl_data: raw bytes of abl.img

    Returns dict with keys:
        gbl_vulnerable: bool - True if EFISP string found
        efisp_count: int - number of occurrences found
        found_in: str - "raw", "decompressed", or "not_found"
    """
    # Step 1: Check raw data
    raw_offsets = _find_pattern(abl_data, EFISP_PATTERN_UTF16LE)
    if raw_offsets:
        return {
            "gbl_vulnerable": True,
            "efisp_count": len(raw_offsets),
            "found_in": "raw",
        }

    # Step 2: Decompress LZMA sections and search
    try:
        sections = _find_and_decompress_lzma_sections(abl_data)
        for section in sections:
            offsets = _find_pattern(section, EFISP_PATTERN_UTF16LE)
            if offsets:
                return {
                    "gbl_vulnerable": True,
                    "efisp_count": len(offsets),
                    "found_in": "decompressed",
                }
    except Exception:
        pass

    return {
        "gbl_vulnerable": False,
        "efisp_count": 0,
        "found_in": "not_found",
    }
