"""
Version and security-relevant string extractor for firmware images.

Scans binary images for:
  - QC_IMAGE_VERSION_STRING
  - OEM_IMAGE_VERSION_STRING
  - Other version-like strings
  - Security-relevant strings (rollback, fuse, RPMB, cert, key, etc.)
"""

import re
from typing import Optional


# Minimum length for extracted strings
MIN_STRING_LEN = 6


def _extract_printable_strings(data: bytes, min_len: int = MIN_STRING_LEN) -> list[str]:
    """Extract ASCII printable strings from binary data."""
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    return [m.group().decode("ascii") for m in pattern.finditer(data)]


# Patterns for Qualcomm version strings
QC_VERSION_RE = re.compile(r"QC_IMAGE_VERSION_STRING=(.+)")
OEM_VERSION_RE = re.compile(r"OEM_IMAGE_VERSION_STRING=(.+)")

# Patterns for security-relevant content
SECURITY_PATTERNS = [
    re.compile(r".*(?:anti.?rollback|anti.?roll.?back).*", re.IGNORECASE),
    re.compile(r".*(?:qsee_blow_sw_fuse|qsee_is_sw_fuse_blown|IsFuseBlown).*"),
    re.compile(r".*(?:qsee_sfs_is_anti_rollback_enabled).*"),
    re.compile(r".*Secure Boot.*", re.IGNORECASE),
    re.compile(r".*(?:OEM_PK_HASH|OEM_rot_pk_hash|root.of.trust).*", re.IGNORECASE),
    re.compile(r".*(?:RPMB|rpmb).*(?:provision|version|rollback|counter|key).*", re.IGNORECASE),
    re.compile(r".*(?:KM_TAG_ROLLBACK_RESISTANT|ROLLBACK_RESISTANT).*"),
    re.compile(r".*(?:Boot state|boot.state|verified boot).*", re.IGNORECASE),
    re.compile(r".*(?:qfprom|QFPROM).*"),
    re.compile(r".*(?:SecFuse|sec_config).*"),
    re.compile(r".*(?:cert.*chain|certificate.*store).*", re.IGNORECASE),
]

# Additional version-like patterns
GENERIC_VERSION_RE = re.compile(
    r"(?:version|VERSION|Version)[\s=:]+[\w.\-]+", re.IGNORECASE
)


def extract_version_info(data: bytes) -> dict:
    """Extract version and security strings from firmware image bytes.

    Returns dict with keys:
        qc_image_version: str or None
        oem_image_version: str or None
        version_strings: list[str]  (other version-like strings, deduplicated)
        security_strings: list[str] (security-relevant strings, deduplicated)
    """
    strings = _extract_printable_strings(data)

    qc_version: Optional[str] = None
    oem_version: Optional[str] = None
    version_strs: list[str] = []
    security_strs: set[str] = set()

    for s in strings:
        # QC version
        m = QC_VERSION_RE.search(s)
        if m:
            qc_version = m.group(1).strip()
            continue

        # OEM version
        m = OEM_VERSION_RE.search(s)
        if m:
            oem_version = m.group(1).strip()
            continue

        # Security strings
        for pat in SECURITY_PATTERNS:
            if pat.match(s):
                # Truncate very long strings
                security_strs.add(s[:200])
                break

    return {
        "qc_image_version": qc_version,
        "oem_image_version": oem_version,
        "version_strings": sorted(set(version_strs)),
        "security_strings": sorted(security_strs),
    }
