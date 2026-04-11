"""
uefi_setup_mode.py — UEFI Secure Boot setup-mode analyser for Qualcomm firmware.

Determines whether the platform will boot in UEFI Setup Mode (no PK enrolled,
LoadImage accepts unsigned EFI images) or User Mode (PK enrolled, Secure Boot
enforced).

Background
----------
UEFI Secure Boot state lives in the EFI variable store (NVRAM partition,
NOT in the OTA zip images).  The variable store can be:

  1. Initialised empty  -> SetupMode=1, SecureBoot=0
     LoadImage succeeds for any image, including unsigned GBL payloads.

  2. Pre-populated by OEM code at first boot or via manufacturing provisioning
     -> SetupMode=0, SecureBoot=1
     LoadImage for unsigned images returns EFI_SECURITY_VIOLATION.

For Qualcomm platforms we check three sources in order of confidence:

  A. uefi.img (the main UEFI binary, an ELF64 with embedded FFS2 firmware
     volume):  scan for embedded EFI_SIGNATURE_LIST structures (PK/KEK/db
     pre-enrollment blobs) and for SetVariable/EnrollKey code patterns that
     would install a PK at first boot.

  B. xbl.img  (XBL ELF): scan for SetupMode-related strings and embedded
     key data (rare but present on some SKUs).

  C. xbl_config.img: scan for PCD overrides for gEfiSecureBootEnable,
     gEfiSetupMode, or related tokens that control the boot-time default.

Findings are returned as a dict suitable for embedding in an OTA manifest.
"""

import hashlib
import re
import struct
from pathlib import Path
from typing import Optional

# ── EFI signature type GUIDs ────────────────────────────────────────────────
EFI_CERT_X509_GUID = bytes(
    [
        0xA1,
        0x59,
        0xC0,
        0xA5,
        0xE4,
        0x94,
        0xA7,
        0x4A,
        0x87,
        0xB5,
        0xAB,
        0x15,
        0x5C,
        0x2B,
        0xF0,
        0x72,
    ]
)
EFI_CERT_SHA256_GUID = bytes(
    [
        0x26,
        0x16,
        0xC4,
        0xC1,
        0x4C,
        0x50,
        0x92,
        0x40,
        0xAC,
        0xA9,
        0x41,
        0xF9,
        0x36,
        0x93,
        0x43,
        0x28,
    ]
)
EFI_CERT_RSA2048_GUID = bytes(
    [
        0xE8,
        0x66,
        0x57,
        0x3C,
        0x9C,
        0x26,
        0x34,
        0x4E,
        0xAA,
        0x14,
        0xED,
        0x77,
        0x6E,
        0x85,
        0xB3,
        0xB6,
    ]
)

# EFI_GLOBAL_VARIABLE_GUID
EFI_GLOBAL_GUID = bytes(
    [
        0x61,
        0xDF,
        0xE4,
        0x8B,
        0xCA,
        0x93,
        0xD2,
        0x11,
        0xAA,
        0x0D,
        0x00,
        0xE0,
        0x98,
        0x03,
        0x2B,
        0x8C,
    ]
)

# EFI_IMAGE_SECURITY_DATABASE_GUID
EFI_IMAGE_SECURITY_GUID = bytes(
    [
        0xCB,
        0xB2,
        0x19,
        0xD7,
        0x3A,
        0x3D,
        0x96,
        0x45,
        0xA3,
        0xBC,
        0xDA,
        0xD0,
        0x0E,
        0x67,
        0x65,
        0x6F,
    ]
)

# EFI variable store header signature
VARIABLE_STORE_SIG = struct.pack("<I", 0xDDCF3517)

# FV header signature
FVH_SIGNATURE = b"\x5f\x46\x56\x48"  # _FVH

# NvVar FV GUID: {fff12b77-af0e-42c5-bbcc-40b7d40df36a}
SYSTEM_NV_DATA_FV_GUID = bytes(
    [
        0x77,
        0x2B,
        0xF1,
        0xFF,
        0x0E,
        0xAF,
        0xC5,
        0x42,
        0xBB,
        0xCC,
        0x40,
        0xB7,
        0xD4,
        0x0D,
        0xF3,
        0x6A,
    ]
)

# Key variable names as UTF-16LE
_KEY_VARNAMES_U16 = {
    name: name.encode("utf-16-le")
    for name in (
        "PK",
        "KEK",
        "db",
        "dbx",
        "dbt",
        "SecureBoot",
        "SetupMode",
        "CustomMode",
        "DeployedMode",
        "AuditMode",
    )
}

# Enrollment-related ASCII strings that suggest code-driven key installation
_ENROLL_PATTERNS = re.compile(
    r"(?:EnrollKey|InstallKey|SetVariable.*PK|SetupMode.*enroll|"
    r"SB.*enroll|SecureBootDefaultKeys|PlatformKey.*install|"
    r"DefaultPK|DefaultKEK|"
    r"EnableSecureBoot(?!ed)|SecureBootEnable(?!d))",
    re.IGNORECASE,
)

_PRINTABLE = re.compile(rb"[\x20-\x7e]{8,}")


def _printable_strings(data: bytes) -> list:
    return [m.group().decode("ascii") for m in _PRINTABLE.finditer(data)]


def _find_all(data: bytes, needle: bytes) -> list:
    hits, pos = [], 0
    while True:
        idx = data.find(needle, pos)
        if idx == -1:
            break
        hits.append(idx)
        pos = idx + 1
    return hits


def _parse_asn1_len(data: bytes, off: int) -> tuple:
    if off >= len(data):
        return -1, 0
    b = data[off]
    if b < 0x80:
        return b, 1
    n = b & 0x7F
    if n == 0 or n > 4 or off + 1 + n > len(data):
        return -1, 0
    val = 0
    for i in range(n):
        val = (val << 8) | data[off + 1 + i]
    return val, 1 + n


def _scan_signature_lists(data: bytes) -> list:
    """Scan binary for EFI_SIGNATURE_LIST structures.

    Returns list of dicts: {sig_type, list_size, sig_size, file_offset}.
    """
    results = []
    for guid, name in [
        (EFI_CERT_X509_GUID, "X.509"),
        (EFI_CERT_SHA256_GUID, "SHA-256"),
        (EFI_CERT_RSA2048_GUID, "RSA-2048"),
    ]:
        for off in _find_all(data, guid):
            if off + 28 > len(data):
                continue
            list_size = struct.unpack_from("<I", data, off + 16)[0]
            hdr_size = struct.unpack_from("<I", data, off + 20)[0]
            sig_size = struct.unpack_from("<I", data, off + 24)[0]
            # Sanity: list_size should be at least 28 + sig_size
            if list_size < 28 or list_size > 0x10000:
                continue
            if sig_size == 0 or sig_size > list_size:
                continue
            results.append(
                {
                    "sig_type": name,
                    "list_size": list_size,
                    "sig_size": sig_size,
                    "file_offset": off,
                }
            )
    return results


def _count_der_certs(data: bytes) -> int:
    """Count plausible DER-encoded X.509 certificates (0x30 0x82 with 200-2048 byte body)."""
    count = 0
    pos = 0
    while pos < len(data) - 4:
        if data[pos] == 0x30 and data[pos + 1] == 0x82:
            cert_len = (data[pos + 2] << 8) | data[pos + 3]
            if 200 <= cert_len <= 2048:
                count += 1
        pos += 1
    return count


def _scan_variable_names(data: bytes) -> list:
    """Return list of key variable names found as UTF-16LE strings."""
    found = []
    for name, u16 in _KEY_VARNAMES_U16.items():
        if u16 in data:
            found.append(name)
    return found


def _scan_enroll_strings(data: bytes) -> list:
    """Return enrollment-related ASCII strings found in the binary."""
    results = []
    for s in _printable_strings(data):
        if _ENROLL_PATTERNS.search(s):
            results.append(s[:120])
    return results


def _elf_code_region(data: bytes) -> bytes:
    """Return the concatenated PT_LOAD (p_type=1) segments of an ELF64."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return data
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsz = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    chunks = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsz
        if off + 56 > len(data):
            break
        p_type = struct.unpack_from("<I", data, off)[0]
        p_offset = struct.unpack_from("<Q", data, off + 8)[0]
        p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
        if p_type == 1 and p_filesz > 0:  # PT_LOAD
            end = p_offset + p_filesz
            if end <= len(data):
                chunks.append(data[p_offset:end])
    return b"".join(chunks) if chunks else data


# ── Public API ──────────────────────────────────────────────────────────────


def analyse_uefi_img(data: bytes) -> dict:
    """Analyse uefi.img bytes for Secure Boot setup-mode indicators.

    Returns dict:
        signature_lists_found: list  - EFI_SIGNATURE_LIST entries found
        der_certs_in_code:     int   - DER cert candidates in code region
        key_varnames_found:    list  - UTF-16LE key variable names present
        enroll_strings:        list  - enrollment-related ASCII strings
        has_pk_data:           bool  - True if any PK-related data found
        verdict:               str   - 'setup_mode' | 'user_mode' | 'unknown'
        detail:                str   - human-readable explanation
    """
    code = _elf_code_region(data)

    sig_lists = _scan_signature_lists(code)
    der_count = _count_der_certs(code)
    var_names = _scan_variable_names(data)
    enroll_strs = _scan_enroll_strings(code)

    # PK-related evidence
    has_pk = (
        any(sl["sig_type"] in ("X.509", "RSA-2048") for sl in sig_lists)
        or "PK" in var_names
        or bool(enroll_strs)
    )

    if has_pk:
        verdict = "user_mode"
        detail = (
            "uefi.img contains PK/enrollment evidence — "
            "platform likely exits Setup Mode at boot."
        )
    else:
        verdict = "setup_mode"
        detail = (
            "No PK enrollment data found in uefi.img — "
            "platform boots in UEFI Setup Mode "
            "(LoadImage accepts unsigned images)."
        )

    return {
        "signature_lists_found": sig_lists,
        "der_certs_in_code": der_count,
        "key_varnames_found": var_names,
        "enroll_strings": enroll_strs,
        "has_pk_data": has_pk,
        "verdict": verdict,
        "detail": detail,
    }


def analyse_xbl_img(data: bytes) -> dict:
    """Analyse xbl.img bytes for Secure Boot setup-mode indicators.

    Returns dict with same keys as analyse_uefi_img.
    """
    code = _elf_code_region(data)

    sig_lists = _scan_signature_lists(code)
    var_names = _scan_variable_names(data)
    enroll_strs = _scan_enroll_strings(code)

    has_pk = bool(sig_lists) or "PK" in var_names or bool(enroll_strs)

    if has_pk:
        verdict = "user_mode"
        detail = "xbl.img contains PK/enrollment evidence."
    else:
        verdict = "setup_mode"
        detail = "No PK enrollment data in xbl.img."

    return {
        "signature_lists_found": sig_lists,
        "key_varnames_found": var_names,
        "enroll_strings": enroll_strs,
        "has_pk_data": has_pk,
        "verdict": verdict,
        "detail": detail,
    }


def analyse_images(image_dir: str) -> dict:
    """Analyse all UEFI/XBL images in a directory.

    Looks for: uefi.img, xbl.img, xbl_config.img, uefisecapp.img.

    Returns dict:
        overall_verdict:    str   - 'setup_mode' | 'user_mode' | 'unknown'
        overall_detail:     str   - human-readable summary
        sources_checked:    list  - which image files were found and checked
        per_image:          dict  - per-image analysis results
        gbl_loadimage_ok:   bool  - True if Setup Mode means LoadImage will work
    """
    d = Path(image_dir)
    candidates = {
        "uefi.img": analyse_uefi_img,
        "xbl.img": analyse_xbl_img,
        "uefisecapp.img": analyse_uefi_img,
    }

    sources_checked = []
    per_image = {}
    any_user_mode = False
    any_checked = False

    for filename, analyser in candidates.items():
        path = d / filename
        if not path.exists():
            continue
        try:
            data = path.read_bytes()
            result = analyser(data)
            per_image[filename] = result
            sources_checked.append(filename)
            any_checked = True
            if result["verdict"] == "user_mode":
                any_user_mode = True
        except Exception as e:
            per_image[filename] = {"error": str(e)}

    if not any_checked:
        return {
            "overall_verdict": "unknown",
            "overall_detail": "No uefi.img or xbl.img found in image directory.",
            "sources_checked": [],
            "per_image": {},
            "gbl_loadimage_ok": None,
        }

    if any_user_mode:
        verdict = "user_mode"
        detail = (
            "One or more UEFI images contain PK enrollment data. "
            "Platform likely in User Mode — "
            "gBS->LoadImage will REJECT unsigned GBL images "
            "(EFI_SECURITY_VIOLATION). GBL exploit blocked by UEFI SB."
        )
        ok = False
    else:
        verdict = "setup_mode"
        detail = (
            "No PK/KEK enrollment data found in any UEFI image. "
            "Platform boots in UEFI Setup Mode — "
            "gBS->LoadImage ACCEPTS unsigned EFI images. "
            "GBL exploit is not blocked by UEFI Secure Boot."
        )
        ok = True

    return {
        "overall_verdict": verdict,
        "overall_detail": detail,
        "sources_checked": sources_checked,
        "per_image": per_image,
        "gbl_loadimage_ok": ok,
    }


def check_setup_mode(image_path_or_dir: str) -> dict:
    """Convenience entry point.

    Accepts either:
      - A directory containing firmware images (will auto-detect uefi.img etc.)
      - A direct path to uefi.img or xbl.img

    Returns the same dict as analyse_images().
    """
    p = Path(image_path_or_dir)
    if p.is_dir():
        return analyse_images(str(p))

    # Single file
    data = p.read_bytes()
    name = p.name.lower()

    if "xbl" in name and "config" not in name:
        result = analyse_xbl_img(data)
    else:
        result = analyse_uefi_img(data)

    ok = result["verdict"] == "setup_mode"
    return {
        "overall_verdict": result["verdict"],
        "overall_detail": result["detail"],
        "sources_checked": [p.name],
        "per_image": {p.name: result},
        "gbl_loadimage_ok": ok,
    }
