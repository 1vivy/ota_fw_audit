#!/usr/bin/env python3
"""
analyze_ota.py - Extract firmware metadata from an OTA zip.

Usage:
    python3 analyze_ota.py --profile <profile.yaml> --ota <ota.zip> --out <manifest.json>

If the OTA metadata does not contain a usable version_name, the user
is prompted for a label.

The script:
  1. Reads OTA metadata from the zip
  2. Extracts firmware partition images listed in the device profile
  3. For each image, records: sha256, size, format, version strings,
     security strings, cert fingerprints, ARB metadata (xbl_config),
     AVB data (vbmeta*)
  4. Writes a single JSON manifest
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

# Add lib/ to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__))))

from lib import elf_parser, xbl_config, cert_extractor, version_strings, avb_parser, ota_metadata


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_format(data: bytes) -> str:
    """Detect firmware image format from magic bytes."""
    if elf_parser.is_elf64_le(data):
        return "elf64"
    if data[:4] == b"AVB0":
        return "avb_vbmeta"
    if data[:8] == b"ANDROID!":
        return "android_bootimg"
    if data[:8] == b"VNDRBOOT":
        return "vendor_bootimg"
    if len(data) > 0x1FE and data[0x1FE:0x200] == b"\x55\xAA":
        return "fat_mbr"
    if data[:2] == b"\xEB\x3C" or data[:2] == b"\xEB\x58":
        return "fat"
    if data[:4] == b"\xd1\xdc\x4b\x84":
        return "mbn_legacy"
    return "opaque_blob"


def find_payload_dumper() -> str:
    """Locate payload_dumper binary."""
    # Check PATH
    which = shutil.which("payload_dumper")
    if which:
        return which
    # Check our local tools dir
    local = Path(__file__).resolve().parent.parent.parent / "tools" / "payload_dumper" / "payload_dumper"
    if local.is_file():
        return str(local)
    raise FileNotFoundError(
        "payload_dumper not found. Install it or place it in tools/payload_dumper/")


def extract_partitions(ota_zip: str, partitions: list[str], out_dir: str,
                       dumper: str) -> dict[str, str]:
    """Extract listed partitions from OTA zip into out_dir.

    Returns dict mapping partition_name -> extracted file path.
    """
    # Build comma-separated include list
    include = ",".join(partitions)
    cmd = [dumper, ota_zip, "-i", include, "--out", out_dir]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        print(f"WARNING: payload_dumper returned {result.returncode}",
              file=sys.stderr)
        if result.stderr:
            print(result.stderr[:500], file=sys.stderr)

    # Map what was actually extracted
    extracted = {}
    for name in partitions:
        p = os.path.join(out_dir, f"{name}.img")
        if os.path.isfile(p):
            extracted[name] = p
    return extracted


def analyze_image(name: str, path: str) -> dict:
    """Analyze a single firmware image and return its metadata dict."""
    data = open(path, "rb").read()
    fmt = detect_format(data)
    h = hashlib.sha256(data).hexdigest()
    size = len(data)

    result = {
        "sha256": h,
        "size": size,
        "format": fmt,
    }

    # Version strings (only fields that change per-OTA)
    vinfo = version_strings.extract_version_info(data)
    result["qc_image_version"] = vinfo["qc_image_version"]
    result["oem_image_version"] = vinfo["oem_image_version"]

    # ELF-specific: hash segment metadata + cert extraction
    if fmt == "elf64":
        phdrs = elf_parser.parse_elf64_phdrs(data)
        hash_phdr = elf_parser.find_hash_segment(phdrs) if phdrs else None
        if hash_phdr is not None:
            segment = elf_parser.read_hash_segment(data, hash_phdr)
            hdr = elf_parser.locate_hash_table_header(segment)
            if hdr is not None:
                result["hash_segment"] = {
                    "phdr_index": hash_phdr["index"],
                    "file_offset": hash_phdr["p_offset"],
                    "size": hash_phdr["p_filesz"],
                    "header_version": hdr["hash_header_version"],
                    "oem_metadata_size": hdr["oem_metadata_size"],
                    "oem_signature_size": hdr.get("oem_signature_size", 0),
                    "oem_cert_chain_size": hdr.get("oem_cert_chain_size", 0),
                    "qti_metadata_size": hdr["qti_metadata_size"],
                    "qti_signature_size": hdr.get("qti_signature_size", 0),
                    "qti_cert_chain_size": hdr.get("qti_cert_chain_size", 0),
                }

        certs = cert_extractor.extract_certs_from_image(data)
        result["cert_chain"] = certs

        # xbl_config-specific: ARB
        if name == "xbl_config":
            arb = xbl_config.extract_arb(data)
            if arb:
                result["arb"] = arb

    # AVB vbmeta
    if fmt == "avb_vbmeta" or name.startswith("vbmeta"):
        avb = avb_parser.parse_vbmeta(data)
        if avb:
            result["avb"] = avb

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Analyze firmware images in an OTA and produce a JSON manifest.")
    parser.add_argument("--profile", required=True,
                        help="Path to device profile YAML")
    parser.add_argument("--ota", required=True,
                        help="Path to OTA zip file")
    parser.add_argument("--out", required=True,
                        help="Path for output JSON manifest")
    parser.add_argument("--name", default=None,
                        help="Human label for this OTA (prompted if not supplied and "
                             "not found in metadata)")
    parser.add_argument("--keep-extracted", default=None,
                        help="If set, keep extracted images in this directory")
    args = parser.parse_args()

    # Load profile
    with open(args.profile) as f:
        profile = yaml.safe_load(f)

    # Collect all partitions to extract
    all_partitions = []
    for group in ["boot_chain", "subsystem_firmware", "low_priority", "boundary"]:
        all_partitions.extend(profile.get("partitions", {}).get(group, []))

    # Read OTA metadata
    print(f"Reading OTA metadata from {args.ota}...")
    meta = ota_metadata.extract_ota_metadata(args.ota)
    if meta is None:
        meta = {}
        print("WARNING: Could not read OTA metadata from zip", file=sys.stderr)

    # Determine OTA label
    ota_label = (args.name
                 or meta.get("version_name")
                 or meta.get("version_name_show")
                 or meta.get("ota-id"))
    if not ota_label:
        ota_label = input("Could not determine OTA version. Enter a label: ").strip()
        if not ota_label:
            print("ERROR: No OTA label provided.", file=sys.stderr)
            sys.exit(1)

    print(f"OTA label: {ota_label}")

    # Find dumper
    dumper = find_payload_dumper()

    # Extract partitions
    if args.keep_extracted:
        extract_dir = args.keep_extracted
        os.makedirs(extract_dir, exist_ok=True)
        cleanup = False
    else:
        extract_dir = tempfile.mkdtemp(prefix="fw_audit_")
        cleanup = True

    try:
        print(f"Extracting {len(all_partitions)} partitions...")
        extracted = extract_partitions(args.ota, all_partitions, extract_dir, dumper)
        print(f"Extracted {len(extracted)} images.")

        # Analyze each image
        partitions_data = {}
        for name in all_partitions:
            if name not in extracted:
                continue
            print(f"  Analyzing {name}...")
            partitions_data[name] = analyze_image(name, extracted[name])

        # Build manifest
        manifest = {
            "ota_label": ota_label,
            "ota_metadata": meta,
            "device_profile": profile.get("device_family", "unknown"),
            "partitions_analyzed": len(partitions_data),
            "partitions": partitions_data,
        }

        # Write output
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as f:
            json.dump(manifest, f, indent=2, sort_keys=False)

        print(f"Manifest written to {args.out}")

    finally:
        if cleanup:
            shutil.rmtree(extract_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
