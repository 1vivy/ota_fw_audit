"""
Parser for Android_Tool_RUST (androidtool) inspect output.

Calls the androidtool binary and parses its pipe-delimited table output
into structured dicts for integration into fw_audit manifests.

Only captures interoperability-relevant fields, not ELF headers or
program header tables.
"""

import os
import re
import subprocess
from pathlib import Path
from typing import Optional


# Default location relative to this file
_DEFAULT_BINARY = str(
    Path(__file__).resolve().parent.parent.parent.parent
    / "tools" / "Android_Tool_RUST" / "target" / "release" / "androidtool"
)


def _find_binary() -> str:
    """Locate the androidtool binary."""
    import shutil
    which = shutil.which("androidtool")
    if which:
        return which
    if os.path.isfile(_DEFAULT_BINARY):
        return _DEFAULT_BINARY
    raise FileNotFoundError(
        "androidtool binary not found. Build Android_Tool_RUST or place it on PATH.")


def _parse_table_line(line: str) -> Optional[tuple[str, str]]:
    """Parse a '| Key  | Value  |' line into (key, value) or None."""
    line = line.strip()
    if not line.startswith("|"):
        return None
    parts = [p.strip() for p in line.split("|")]
    # parts[0] is empty (before first |), parts[-1] is empty (after last |)
    parts = [p for p in parts if p]
    if len(parts) < 2:
        return None
    key = parts[0].rstrip(":")
    value = parts[1]
    return key, value


def _parse_hex_or_int(value: str) -> Optional[int]:
    """Parse a hex (0x...) or decimal string to int, or None."""
    value = value.strip()
    try:
        if value.startswith("0x") or value.startswith("0X"):
            return int(value, 16)
        return int(value)
    except ValueError:
        return None


def _parse_bool(value: str) -> Optional[bool]:
    """Parse True/False string."""
    v = value.strip().lower()
    if v == "true":
        return True
    if v == "false":
        return False
    return None


def run_inspect(image_path: str, binary: Optional[str] = None) -> Optional[str]:
    """Run androidtool inspect on an image and return raw stdout."""
    binary = binary or _find_binary()
    try:
        result = subprocess.run(
            [binary, "inspect", image_path],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return None
        return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def parse_inspect_output(raw: str) -> dict:
    """Parse raw androidtool inspect output into a structured dict.

    Returns a dict with keys:
        common_metadata: dict or None
        oem_metadata: dict or None
        oem_signature: dict or None
        oem_cert_chain: dict or None
        oem_root_cert: dict or None
        hash_table_header: dict or None
    """
    result = {
        "common_metadata": None,
        "oem_metadata": None,
        "oem_signature": None,
        "oem_cert_chain": None,
        "oem_attest_cert": None,
        "oem_ca_cert": None,
        "oem_root_cert": None,
        "hash_table_header": None,
    }

    # Split into sections by header lines (lines ending with ":" and not starting with "|")
    current_section = None
    section_lines: dict[str, list[str]] = {}

    for line in raw.splitlines():
        stripped = line.strip()
        # Detect section headers: "Something Something:" without leading "|"
        if stripped and not stripped.startswith("|") and stripped.endswith(":"):
            current_section = stripped[:-1].strip()
            section_lines[current_section] = []
        elif current_section is not None:
            section_lines[current_section].append(line)

    # Parse Hash Table Segment Header
    if "Hash Table Segment Header" in section_lines:
        hdr = {}
        for line in section_lines["Hash Table Segment Header"]:
            parsed = _parse_table_line(line)
            if not parsed:
                continue
            key, value = parsed
            if "Version" in key and "version" not in hdr:
                hdr["version"] = _parse_hex_or_int(value)
            elif "Common Metadata Size" in key:
                hdr["common_metadata_size"] = _parse_hex_or_int(value.split()[0])
            elif "QTI Metadata Size" in key:
                hdr["qti_metadata_size"] = _parse_hex_or_int(value.split()[0])
            elif "OEM Metadata Size" in key:
                hdr["oem_metadata_size"] = _parse_hex_or_int(value.split()[0])
            elif "Hash Table Size" in key:
                hdr["hash_table_size"] = _parse_hex_or_int(value.split()[0])
            elif "QTI Signature Size" in key:
                hdr["qti_signature_size"] = _parse_hex_or_int(value.split()[0])
            elif "QTI Certificate Chain Size" in key:
                hdr["qti_cert_chain_size"] = _parse_hex_or_int(value.split()[0])
            elif "OEM Signature Size" in key:
                hdr["oem_signature_size"] = _parse_hex_or_int(value.split()[0])
            elif "OEM Certificate Chain Size" in key:
                hdr["oem_cert_chain_size"] = _parse_hex_or_int(value.split()[0])
        if hdr:
            result["hash_table_header"] = hdr

    # Parse Common Metadata
    if "Common Metadata" in section_lines:
        cm = {}
        for line in section_lines["Common Metadata"]:
            parsed = _parse_table_line(line)
            if not parsed:
                continue
            key, value = parsed
            if key == "Major Version":
                cm["major_version"] = _parse_hex_or_int(value)
            elif key == "Minor Version":
                cm["minor_version"] = _parse_hex_or_int(value)
            elif key == "Software ID":
                cm["software_id"] = value
            elif key == "Secondary Software ID":
                cm["secondary_software_id"] = value
            elif "Hash Table Algorithm" in key:
                cm["hash_algorithm"] = value
            elif "Measurement Register Target" in key:
                cm["measurement_register_target"] = value
        if cm:
            result["common_metadata"] = cm

    # Parse OEM Metadata
    if "OEM Metadata" in section_lines:
        oem = {}
        for line in section_lines["OEM Metadata"]:
            parsed = _parse_table_line(line)
            if not parsed:
                continue
            key, value = parsed
            if key == "Major Version":
                oem["major_version"] = _parse_hex_or_int(value)
            elif key == "Minor Version":
                oem["minor_version"] = _parse_hex_or_int(value)
            elif key == "Anti-Rollback Version":
                oem["anti_rollback_version"] = _parse_hex_or_int(value)
            elif key == "Root Certificate Index":
                oem["root_certificate_index"] = _parse_hex_or_int(value)
            elif key == "SoC Hardware Version":
                oem["soc_hw_version"] = value
            elif key == "Product Segment ID":
                oem["product_segment_id"] = value
            elif key == "JTAG ID":
                oem["jtag_id"] = value
            elif key == "OEM ID":
                oem["oem_id"] = value
            elif key == "OEM Product ID":
                oem["oem_product_id"] = value
            elif key == "OEM Lifecycle State":
                oem["oem_lifecycle_state"] = value
            elif "OEM Root Certificate Hash Algorithm" in key:
                oem["oem_root_cert_hash_algo"] = value
            elif key.startswith("Bound to"):
                field = key.replace("Bound to ", "bound_to_").lower().replace(" ", "_")
                oem[field] = _parse_bool(value)
            elif key == "JTAG Debug":
                oem["jtag_debug"] = value
            elif key == "Transfer Root":
                oem["transfer_root"] = _parse_bool(value)
        if oem:
            result["oem_metadata"] = oem

    # Parse OEM Signature Properties
    if "OEM Signature Properties" in section_lines:
        sig = {}
        for line in section_lines["OEM Signature Properties"]:
            parsed = _parse_table_line(line)
            if not parsed:
                continue
            key, value = parsed
            if key == "Algorithm":
                sig["algorithm"] = value
            elif key == "Hash Algorithm":
                sig["hash_algorithm"] = value
            elif key == "Curve":
                sig["curve"] = value
            elif key == "Key Size":
                sig["key_size"] = _parse_hex_or_int(value)
        if sig:
            result["oem_signature"] = sig

    # Parse OEM Certificate Chain Properties
    if "OEM Certificate Chain Properties" in section_lines:
        cc = {}
        for line in section_lines["OEM Certificate Chain Properties"]:
            parsed = _parse_table_line(line)
            if not parsed:
                continue
            key, value = parsed
            if "Total" in key:
                cc["total_certs"] = _parse_hex_or_int(value)
            elif "Attest" in key:
                cc["attest_certs"] = _parse_hex_or_int(value)
            elif "CA" in key:
                cc["ca_certs"] = _parse_hex_or_int(value)
            elif "Root" in key:
                cc["root_certs"] = _parse_hex_or_int(value)
        if cc:
            result["oem_cert_chain"] = cc

    # Parse cert detail sections
    for section_name, result_key in [
        ("OEM Attest Certificate Properties", "oem_attest_cert"),
        ("OEM CA Certificate Properties", "oem_ca_cert"),
        ("OEM Root Certificate Properties", "oem_root_cert"),
    ]:
        if section_name in section_lines:
            cert = {}
            for line in section_lines[section_name]:
                parsed = _parse_table_line(line)
                if not parsed:
                    continue
                key, value = parsed
                if key == "Root Certificate Hash (SHA256)":
                    cert["root_cert_hash_sha256"] = value
                elif key == "Root Certificate Hash (SHA384)":
                    cert["root_cert_hash_sha384"] = value
                elif key == "Signature Algorithm":
                    cert["signature_algorithm"] = value
                elif key == "Hash Algorithm":
                    cert["hash_algorithm"] = value
                elif key == "Curve":
                    cert["curve"] = value
                elif key == "Key Size":
                    cert["key_size"] = _parse_hex_or_int(value)
                elif key == "Extended Key Usage":
                    cert["extended_key_usage"] = value
            if cert:
                result[result_key] = cert

    return result


def inspect_image(image_path: str, binary: Optional[str] = None) -> Optional[dict]:
    """High-level: run inspect and return parsed dict, or None on failure."""
    raw = run_inspect(image_path, binary)
    if raw is None:
        return None
    parsed = parse_inspect_output(raw)
    # If no useful sections were found, return None
    if not any(v is not None for v in parsed.values()):
        return None
    return parsed
