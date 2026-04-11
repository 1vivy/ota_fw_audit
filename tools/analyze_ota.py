#!/usr/bin/env python3
"""
analyze_ota.py - Extract firmware metadata from a full or incremental OTA zip.

Usage:
    python3 analyze_ota.py --profile <profile.yaml> --ota <ota.zip> --out <manifest.json>
    python3 analyze_ota.py --profile <profile.yaml> --ota <incremental.zip> \
        --base-ota <full-source.zip> --out <manifest.json>

If the OTA metadata does not contain a usable label, the script falls back to
`post-build-incremental` or the OTA filename.

The script:
  1. Reads OTA metadata from the target zip
  2. Extracts tracked firmware partition images from the OTA payload
  3. Reconstructs incremental/partial OTAs when `--base-ota` is provided
  4. Records per-image metadata: hashes, format, Qualcomm signing metadata,
     AVB data, GBL status, and fallback version information
  5. Records platform-level UEFI Setup Mode status from the extracted images
  6. Writes a single JSON manifest
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

from lib import (
    androidtool_parser,
    avb_parser,
    cert_extractor,
    elf_parser,
    gbl_detector,
    ota_metadata,
    uefi_setup_mode,
    version_strings,
    xbl_config,
)


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
    if len(data) > 0x1FE and data[0x1FE:0x200] == b"\x55\xaa":
        return "fat_mbr"
    if data[:2] == b"\xeb\x3c" or data[:2] == b"\xeb\x58":
        return "fat"
    if data[:4] == b"\xd1\xdc\x4b\x84":
        return "mbn_legacy"
    return "opaque_blob"


def clear_tracked_images(directory: Path, partitions: list[str]) -> None:
    """Delete tracked image files from a reused work dir."""
    directory.mkdir(parents=True, exist_ok=True)
    for name in partitions:
        image_path = directory / f"{name}.img"
        if image_path.is_file():
            image_path.unlink()


def prepare_extract_layout(
    work_dir: str | None, has_base_ota: bool
) -> tuple[Path, Path, Path | None, bool]:
    """Return work_root, target_dir, base_dir, cleanup_work_root.

    `--work-dir` is only a convenience override for payload extraction.
    - Full OTA: extract directly into `work_dir`.
    - Incremental OTA: use `<work_dir>/base` and `<work_dir>/target`.
    - No `--work-dir`: use a temp dir and clean it up afterward.
    """
    if work_dir:
        work_root = Path(work_dir)
        cleanup_work_root = False
    else:
        work_root = Path(tempfile.mkdtemp(prefix="fw_audit_"))
        cleanup_work_root = True

    work_root.mkdir(parents=True, exist_ok=True)

    if has_base_ota:
        base_dir = work_root / "base"
        target_dir = work_root / "target"
        base_dir.mkdir(parents=True, exist_ok=True)
        target_dir.mkdir(parents=True, exist_ok=True)
    else:
        base_dir = None
        target_dir = work_root

    return work_root, target_dir, base_dir, cleanup_work_root


def find_payload_dumper() -> str:
    """Locate payload_dumper binary."""
    # Check PATH
    which = shutil.which("payload_dumper")
    if which:
        return which
    # Check our local tools dir
    local = (
        Path(__file__).resolve().parent.parent.parent
        / "tools"
        / "payload_dumper"
        / "payload_dumper"
    )
    if local.is_file():
        return str(local)
    raise FileNotFoundError(
        "payload_dumper not found. Install it or place it in tools/payload_dumper/"
    )


def extract_partitions(
    ota_zip: str,
    partitions: list[str],
    out_dir: str,
    dumper: str,
    source_dir: str | None = None,
) -> dict[str, str]:
    """Extract listed partitions from OTA zip into out_dir.

    Returns dict mapping partition_name -> extracted file path.
    """
    # Build comma-separated include list
    include = ",".join(partitions)
    cmd = [dumper, ota_zip, "-i", include, "--out", out_dir]
    if source_dir:
        cmd.extend(["--source-dir", source_dir])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        print(f"WARNING: payload_dumper returned {result.returncode}", file=sys.stderr)
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
    data = Path(path).read_bytes()
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

    # Qualcomm metadata via androidtool (primary source for ELF images)
    # This gives us structured OEM metadata, binding flags, root cert hashes,
    # signature properties, and cert chain breakdown.
    qc_meta = androidtool_parser.inspect_image(path)
    if qc_meta is not None:
        result["qualcomm_metadata"] = qc_meta

    # ELF-specific fallback: our own cert extraction + xbl_config ARB
    if fmt == "elf64":
        # Only add our cert_chain if androidtool didn't provide cert data
        if qc_meta is None or qc_meta.get("oem_root_cert") is None:
            certs = cert_extractor.extract_certs_from_image(data)
            if certs:
                result["cert_chain"] = certs

        # xbl_config ARB fallback (in case androidtool fails)
        if name == "xbl_config" and (
            qc_meta is None or qc_meta.get("oem_metadata") is None
        ):
            arb = xbl_config.extract_arb(data)
            if arb:
                result["arb"] = arb

    # AVB vbmeta
    if fmt == "avb_vbmeta" or name.startswith("vbmeta"):
        avb = avb_parser.parse_vbmeta(data)
        if avb:
            result["avb"] = avb

    # GBL vulnerability check for ABL images
    if name == "abl":
        gbl = gbl_detector.detect_gbl_vulnerability(data)
        result["gbl"] = gbl

    return result


def build_profile_metadata(profile: dict, profile_path: str) -> dict:
    """Normalize profile metadata for embedding in manifests."""
    profile_id = (
        profile.get("profile_id")
        or profile.get("device_family")
        or Path(profile_path).stem
    )

    return {
        "profile_id": profile_id,
        "profile_file": Path(profile_path).name,
        "manufacturer": profile.get("manufacturer"),
        "device_name": profile.get("device_name"),
        "device_codename": profile.get("codename"),
        "device_aliases": profile.get("aliases", []),
        "soc": profile.get("soc"),
        "model_numbers": profile.get("model_numbers", []),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Analyze firmware images in an OTA and produce a JSON manifest."
    )
    parser.add_argument("--profile", required=True, help="Path to device profile YAML")
    parser.add_argument("--ota", required=True, help="Path to OTA zip file")
    parser.add_argument(
        "--base-ota",
        default=None,
        help="Path to the source full OTA zip for reconstructing an incremental/partial OTA",
    )
    parser.add_argument("--out", required=True, help="Path for output JSON manifest")
    parser.add_argument(
        "--name",
        default=None,
        help="Human label for this OTA (prompted if not supplied and "
        "not found in metadata)",
    )
    parser.add_argument(
        "--work-dir",
        default=None,
        help="Working directory root for extracted OTA images (defaults to fw_audit/workdir)",
    )
    args = parser.parse_args()

    # Load profile
    with open(args.profile) as f:
        profile = yaml.safe_load(f)
    profile_meta = build_profile_metadata(profile, args.profile)

    # Collect all partitions to extract
    all_partitions = []
    for group in ["boot_chain", "subsystem_firmware", "low_priority", "boundary"]:
        all_partitions.extend(profile.get("partitions", {}).get(group, []))

    # Read OTA metadata
    meta = {}
    print(f"Reading OTA metadata from {args.ota}...")
    meta = ota_metadata.extract_ota_metadata(args.ota) or {}
    if not meta:
        print("WARNING: Could not read OTA metadata from zip", file=sys.stderr)

    # Determine OTA label
    ota_label = (
        args.name
        or meta.get("version_name")
        or meta.get("version_name_show")
        or meta.get("post-build-incremental")
        or meta.get("ota-id")
        or os.path.basename(args.ota)
    )
    if not ota_label:
        ota_label = input("Could not determine OTA version. Enter a label: ").strip()
        if not ota_label:
            print("ERROR: No OTA label provided.", file=sys.stderr)
            sys.exit(1)

    print(f"OTA label: {ota_label}")

    dumper = find_payload_dumper()

    work_root, extract_dir, base_extract_dir, cleanup_work_root = prepare_extract_layout(
        args.work_dir, bool(args.base_ota)
    )

    try:
        if args.base_ota and base_extract_dir is not None:
            clear_tracked_images(base_extract_dir, all_partitions)
            print(f"Extracting source partitions from base OTA: {args.base_ota}...")
            base_extracted = extract_partitions(
                args.base_ota,
                all_partitions,
                str(base_extract_dir),
                dumper,
            )
            print(f"Extracted {len(base_extracted)} source images.")

        clear_tracked_images(extract_dir, all_partitions)
        print(f"Extracting {len(all_partitions)} partitions from target OTA...")
        extracted = extract_partitions(
            args.ota,
            all_partitions,
            str(extract_dir),
            dumper,
            source_dir=str(base_extract_dir) if base_extract_dir else None,
        )
        print(f"Extracted {len(extracted)} images.")

        setup_mode = uefi_setup_mode.check_setup_mode(str(extract_dir))

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
            "profile_id": profile_meta["profile_id"],
            "profile_file": profile_meta["profile_file"],
            "manufacturer": profile_meta["manufacturer"],
            "device_name": profile_meta["device_name"],
            "device_codename": profile_meta["device_codename"],
            "device_aliases": profile_meta["device_aliases"],
            "soc": profile_meta["soc"],
            "model_numbers": profile_meta["model_numbers"],
            "source_ota": args.ota,
            "base_ota": args.base_ota,
            "ota_kind": "incremental" if args.base_ota else "full",
            "uefi_setup_mode": setup_mode,
            "partitions_analyzed": len(partitions_data),
            "partitions": partitions_data,
        }

        # Write output
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w") as f:
            json.dump(manifest, f, indent=2, sort_keys=False)

        print(f"Manifest written to {args.out}")
    finally:
        if cleanup_work_root:
            shutil.rmtree(work_root, ignore_errors=True)


if __name__ == "__main__":
    main()
