#!/usr/bin/env python3
"""
compare_otas.py - Compare two OTA manifests and produce a diff report.

Usage:
    python3 compare_otas.py [--risk-dict risk_dictionary.yaml] \
        manifest_a.json manifest_b.json --out report.json

The report contains:
  - Which partitions changed (sha256 diff)
  - Which Qualcomm metadata fields changed
  - Which AVB public keys or rollback indexes changed
  - Whether UEFI Setup Mode / unsigned EFI loading changed
  - Per-partition risk assessment from the risk dictionary
  - Summary flags for ARB, root keys, Setup Mode, GBL, and EDL risk
"""

import argparse
import json
import os
import sys

import yaml


def load_risk_dict(path: str) -> dict:
    """Load the risk dictionary YAML."""
    if path and os.path.isfile(path):
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


def compare_certs(certs_a: list, certs_b: list) -> dict:
    """Compare two cert chain lists and report differences."""
    fps_a = {c["sha256"] for c in certs_a}
    fps_b = {c["sha256"] for c in certs_b}

    added = fps_b - fps_a
    removed = fps_a - fps_b
    common = fps_a & fps_b

    return {
        "added": sorted(added),
        "removed": sorted(removed),
        "unchanged_count": len(common),
        "changed": bool(added or removed),
    }


def compare_avb(avb_a: dict, avb_b: dict) -> dict:
    """Compare two AVB metadata dicts."""
    result = {"changed_fields": []}

    for key in ["rollback_index", "rollback_index_location", "algorithm",
                "public_key_sha256", "flags"]:
        va = avb_a.get(key)
        vb = avb_b.get(key)
        if va != vb:
            result["changed_fields"].append({
                "field": key,
                "old": va,
                "new": vb,
            })

    # Compare descriptors by type+partition_name
    def desc_key(d):
        return (d.get("type", ""), d.get("partition_name", ""))

    descs_a = {desc_key(d): d for d in avb_a.get("descriptors", [])}
    descs_b = {desc_key(d): d for d in avb_b.get("descriptors", [])}

    desc_changes = []
    for k in sorted(set(list(descs_a.keys()) + list(descs_b.keys()))):
        da = descs_a.get(k)
        db = descs_b.get(k)
        if da != db:
            desc_changes.append({
                "key": list(k),
                "old": da,
                "new": db,
            })

    result["descriptor_changes"] = desc_changes
    result["changed"] = bool(result["changed_fields"] or desc_changes)
    return result


def compare_qualcomm_metadata(qm_a: dict, qm_b: dict) -> dict:
    """Compare qualcomm_metadata blocks from androidtool.

    Returns dict with changed_fields list and boolean flags for
    interoperability-critical changes.
    """
    result = {
        "changed_fields": [],
        "arb_changed": False,
        "arb_incremented": False,
        "root_cert_hash_changed": False,
        "oem_id_changed": False,
        "soc_hw_version_changed": False,
        "binding_changed": False,
        "signing_changed": False,
        "lifecycle_changed": False,
        "changed": False,
    }

    # Compare OEM metadata fields
    oem_a = qm_a.get("oem_metadata", {}) or {}
    oem_b = qm_b.get("oem_metadata", {}) or {}

    # Interoperability-critical OEM metadata keys
    for key in [
        "anti_rollback_version", "root_certificate_index",
        "soc_hw_version", "product_segment_id", "jtag_id",
        "oem_id", "oem_product_id", "oem_lifecycle_state",
        "oem_root_cert_hash_algo",
        "bound_to_soc_hardware_versions", "bound_to_product_segment_id",
        "bound_to_jtag_id", "bound_to_serial_numbers",
        "bound_to_oem_id", "bound_to_oem_product_id",
        "bound_to_soc_lifecycle_state", "bound_to_oem_lifecycle_state",
        "bound_to_oem_root_certificate_hash",
        "jtag_debug", "transfer_root",
        "major_version", "minor_version",
    ]:
        va = oem_a.get(key)
        vb = oem_b.get(key)
        if va != vb:
            result["changed_fields"].append({
                "section": "oem_metadata",
                "field": key,
                "old": va,
                "new": vb,
            })
            if key == "anti_rollback_version":
                result["arb_changed"] = True
                if va is not None and vb is not None and vb > va:
                    result["arb_incremented"] = True
            if key == "oem_id":
                result["oem_id_changed"] = True
            if key == "soc_hw_version":
                result["soc_hw_version_changed"] = True
            if key == "oem_lifecycle_state":
                result["lifecycle_changed"] = True
            if key.startswith("bound_to_"):
                result["binding_changed"] = True

    # Compare root cert hashes
    root_a = qm_a.get("oem_root_cert", {}) or {}
    root_b = qm_b.get("oem_root_cert", {}) or {}
    for key in ["root_cert_hash_sha256", "root_cert_hash_sha384"]:
        va = root_a.get(key)
        vb = root_b.get(key)
        if va != vb and va is not None and vb is not None:
            result["changed_fields"].append({
                "section": "oem_root_cert",
                "field": key,
                "old": va,
                "new": vb,
            })
            result["root_cert_hash_changed"] = True

    # Compare signature properties
    sig_a = qm_a.get("oem_signature", {}) or {}
    sig_b = qm_b.get("oem_signature", {}) or {}
    for key in ["algorithm", "hash_algorithm", "curve", "key_size"]:
        va = sig_a.get(key)
        vb = sig_b.get(key)
        if va != vb and va is not None and vb is not None:
            result["changed_fields"].append({
                "section": "oem_signature",
                "field": key,
                "old": va,
                "new": vb,
            })
            result["signing_changed"] = True

    # Compare common metadata
    cm_a = qm_a.get("common_metadata", {}) or {}
    cm_b = qm_b.get("common_metadata", {}) or {}
    for key in ["software_id", "secondary_software_id", "hash_algorithm"]:
        va = cm_a.get(key)
        vb = cm_b.get(key)
        if va != vb and va is not None and vb is not None:
            result["changed_fields"].append({
                "section": "common_metadata",
                "field": key,
                "old": va,
                "new": vb,
            })

    result["changed"] = bool(result["changed_fields"])
    return result


def compare_setup_mode(sm_a: dict, sm_b: dict) -> dict:
    """Compare platform-level UEFI Setup Mode analysis."""
    result = {
        "changed_fields": [],
        "setup_mode_changed": False,
        "unsigned_efi_load_changed": False,
        "changed": False,
    }

    for key in ["overall_verdict", "gbl_loadimage_ok"]:
        va = sm_a.get(key)
        vb = sm_b.get(key)
        if va != vb:
            result["changed_fields"].append({
                "field": key,
                "old": va,
                "new": vb,
            })
            if key == "overall_verdict":
                result["setup_mode_changed"] = True
            if key == "gbl_loadimage_ok":
                result["unsigned_efi_load_changed"] = True

    result["changed"] = bool(result["changed_fields"])
    return result


def compare_partition(name: str, pa: dict, pb: dict) -> dict:
    """Compare metadata for a single partition across two manifests."""
    diff = {
        "sha256_changed": pa.get("sha256") != pb.get("sha256"),
        "size_change": pb.get("size", 0) - pa.get("size", 0),
        "format_a": pa.get("format"),
        "format_b": pb.get("format"),
    }

    # Version strings
    qc_a = pa.get("qc_image_version")
    qc_b = pb.get("qc_image_version")
    if qc_a != qc_b:
        diff["qc_version_change"] = {"old": qc_a, "new": qc_b}

    oem_a = pa.get("oem_image_version")
    oem_b = pb.get("oem_image_version")
    if oem_a != oem_b:
        diff["oem_version_change"] = {"old": oem_a, "new": oem_b}

    # Qualcomm metadata (primary interoperability comparison)
    qm_a = pa.get("qualcomm_metadata")
    qm_b = pb.get("qualcomm_metadata")
    if qm_a and qm_b:
        qm_diff = compare_qualcomm_metadata(qm_a, qm_b)
        if qm_diff["changed"]:
            diff["qualcomm_metadata_change"] = qm_diff

    # Legacy ARB fallback (if qualcomm_metadata not available)
    if not (qm_a and qm_b):
        arb_a = pa.get("arb", {})
        arb_b = pb.get("arb", {})
        if arb_a or arb_b:
            arb_diff = {}
            for key in ["oem_major", "oem_minor", "anti_rollback"]:
                va = arb_a.get(key)
                vb = arb_b.get(key)
                if va != vb:
                    arb_diff[key] = {"old": va, "new": vb}
            if arb_diff:
                diff["arb_change"] = arb_diff

    # Legacy cert chain fallback
    certs_a = pa.get("cert_chain", [])
    certs_b = pb.get("cert_chain", [])
    if certs_a or certs_b:
        cert_diff = compare_certs(certs_a, certs_b)
        if cert_diff["changed"]:
            diff["cert_change"] = cert_diff

    # AVB
    avb_a = pa.get("avb")
    avb_b = pb.get("avb")
    if avb_a and avb_b:
        avb_diff = compare_avb(avb_a, avb_b)
        if avb_diff["changed"]:
            diff["avb_change"] = avb_diff

    # GBL vulnerability (ABL only)
    gbl_a = pa.get("gbl")
    gbl_b = pb.get("gbl")
    if gbl_a is not None and gbl_b is not None:
        va = gbl_a.get("gbl_vulnerable")
        vb = gbl_b.get("gbl_vulnerable")
        if va != vb:
            diff["gbl_change"] = {
                "old_vulnerable": va,
                "new_vulnerable": vb,
                "lost": va and not vb,
                "gained": not va and vb,
            }

    return diff


def main():
    parser = argparse.ArgumentParser(
        description="Compare two OTA manifests and produce a diff report.")
    parser.add_argument("manifest_a", help="Path to first (older) manifest JSON")
    parser.add_argument("manifest_b", help="Path to second (newer) manifest JSON")
    parser.add_argument("--risk-dict", default=None,
                        help="Path to risk_dictionary.yaml")
    parser.add_argument("--out", required=True,
                        help="Path for output report JSON")
    args = parser.parse_args()

    with open(args.manifest_a) as f:
        ma = json.load(f)
    with open(args.manifest_b) as f:
        mb = json.load(f)

    risk_dict = load_risk_dict(args.risk_dict)

    report = {
        "ota_a": ma.get("ota_label", "unknown"),
        "ota_b": mb.get("ota_label", "unknown"),
        "profile_id_a": ma.get("profile_id"),
        "profile_id_b": mb.get("profile_id"),
        "device_codename_a": ma.get("device_codename"),
        "device_codename_b": mb.get("device_codename"),
        "partitions_compared": 0,
        "changed_partitions": [],
        "unchanged_partitions": [],
        "missing_in_a": [],
        "missing_in_b": [],
        "platform_diffs": {},
        "summary": {
            "boot_chain_changed": False,
            "arb_changed": False,
            "arb_incremented": False,
            "root_cert_hash_changed": False,
            "oem_id_changed": False,
            "soc_hw_version_changed": False,
            "binding_changed": False,
            "signing_changed": False,
            "lifecycle_changed": False,
            "cert_chain_changed": False,
            "avb_key_changed": False,
            "avb_rollback_changed": False,
            "setup_mode_changed": False,
            "unsigned_efi_load_changed": False,
            "gbl_exploit_lost": False,
            "gbl_exploit_gained": False,
            "edl_risk_partitions": [],
        },
        "partition_diffs": {},
    }

    setup_a = ma.get("uefi_setup_mode")
    setup_b = mb.get("uefi_setup_mode")
    if setup_a and setup_b:
        setup_diff = compare_setup_mode(setup_a, setup_b)
        if setup_diff["changed"]:
            report["platform_diffs"]["uefi_setup_mode_change"] = setup_diff
            if setup_diff.get("setup_mode_changed"):
                report["summary"]["setup_mode_changed"] = True
            if setup_diff.get("unsigned_efi_load_changed"):
                report["summary"]["unsigned_efi_load_changed"] = True

    all_names = sorted(set(
        list(ma.get("partitions", {}).keys()) +
        list(mb.get("partitions", {}).keys())
    ))

    for name in all_names:
        pa = ma.get("partitions", {}).get(name)
        pb = mb.get("partitions", {}).get(name)

        if pa is None:
            report["missing_in_a"].append(name)
            continue
        if pb is None:
            report["missing_in_b"].append(name)
            continue

        report["partitions_compared"] += 1
        diff = compare_partition(name, pa, pb)

        if not diff["sha256_changed"]:
            report["unchanged_partitions"].append(name)
            continue

        report["changed_partitions"].append(name)

        # Enrich with risk info
        risk = risk_dict.get(name, {})
        diff["risk"] = {
            "role": risk.get("role", "unknown"),
            "arb_risk": risk.get("arb_risk", "unknown"),
            "key_rotation_risk": risk.get("key_rotation_risk", "unknown"),
            "edl_risk_if_mismatched": risk.get("edl_risk_if_mismatched", False),
            "must_move_with": risk.get("must_move_with", []),
            "implications": risk.get("implications", []),
        }

        report["partition_diffs"][name] = diff

        # Update summary flags
        if risk.get("role") == "boot_chain":
            report["summary"]["boot_chain_changed"] = True

        # Qualcomm metadata interoperability flags (primary)
        qm_diff = diff.get("qualcomm_metadata_change", {})
        if qm_diff:
            if qm_diff.get("arb_changed"):
                report["summary"]["arb_changed"] = True
            if qm_diff.get("arb_incremented"):
                report["summary"]["arb_incremented"] = True
            if qm_diff.get("root_cert_hash_changed"):
                report["summary"]["root_cert_hash_changed"] = True
            if qm_diff.get("oem_id_changed"):
                report["summary"]["oem_id_changed"] = True
            if qm_diff.get("soc_hw_version_changed"):
                report["summary"]["soc_hw_version_changed"] = True
            if qm_diff.get("binding_changed"):
                report["summary"]["binding_changed"] = True
            if qm_diff.get("signing_changed"):
                report["summary"]["signing_changed"] = True
            if qm_diff.get("lifecycle_changed"):
                report["summary"]["lifecycle_changed"] = True

        # Legacy ARB fallback
        if "arb_change" in diff:
            report["summary"]["arb_changed"] = True
            arb_old = diff["arb_change"].get("anti_rollback", {}).get("old")
            arb_new = diff["arb_change"].get("anti_rollback", {}).get("new")
            if arb_old is not None and arb_new is not None and arb_new > arb_old:
                report["summary"]["arb_incremented"] = True

        if "cert_change" in diff:
            report["summary"]["cert_chain_changed"] = True
        if "avb_change" in diff:
            avb_diff = diff["avb_change"]
            for fc in avb_diff.get("changed_fields", []):
                if fc["field"] == "public_key_sha256":
                    report["summary"]["avb_key_changed"] = True
                if fc["field"] == "rollback_index":
                    report["summary"]["avb_rollback_changed"] = True
        # GBL exploit status change
        gbl_change = diff.get("gbl_change")
        if gbl_change:
            if gbl_change.get("lost"):
                report["summary"]["gbl_exploit_lost"] = True
            if gbl_change.get("gained"):
                report["summary"]["gbl_exploit_gained"] = True

        if risk.get("edl_risk_if_mismatched"):
            report["summary"]["edl_risk_partitions"].append(name)

    # Write report
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2, sort_keys=False)

    # Print summary to stderr
    s = report["summary"]
    print(f"Compared: {report['ota_a']} -> {report['ota_b']}", file=sys.stderr)
    print(f"Changed: {len(report['changed_partitions'])} / {report['partitions_compared']}",
          file=sys.stderr)
    if s["arb_incremented"]:
        print("*** ARB INCREMENTED ***", file=sys.stderr)
    if s["root_cert_hash_changed"]:
        print("*** ROOT CERT HASH CHANGED (key rotation) ***", file=sys.stderr)
    if s["oem_id_changed"]:
        print("*** OEM ID CHANGED ***", file=sys.stderr)
    if s["soc_hw_version_changed"]:
        print("*** SoC HW VERSION CHANGED ***", file=sys.stderr)
    if s["binding_changed"]:
        print("*** BINDING FLAGS CHANGED ***", file=sys.stderr)
    if s["signing_changed"]:
        print("*** SIGNING METHOD CHANGED ***", file=sys.stderr)
    if s["lifecycle_changed"]:
        print("*** LIFECYCLE STATE CHANGED ***", file=sys.stderr)
    if s["setup_mode_changed"]:
        print("*** UEFI SETUP MODE CHANGED ***", file=sys.stderr)
    if s["unsigned_efi_load_changed"]:
        print("*** UNSIGNED EFI LOAD BEHAVIOR CHANGED ***", file=sys.stderr)
    if s["cert_chain_changed"]:
        print("*** CERT CHAIN CHANGED ***", file=sys.stderr)
    if s["gbl_exploit_lost"]:
        print("*** GBL EXPLOIT LOST (efisp removed from new ABL) ***", file=sys.stderr)
    if s["gbl_exploit_gained"]:
        print("*** GBL EXPLOIT GAINED (efisp present in new ABL) ***", file=sys.stderr)
    if s["avb_key_changed"]:
        print("*** AVB PUBLIC KEY CHANGED ***", file=sys.stderr)
    if s["edl_risk_partitions"]:
        print(f"*** EDL RISK partitions changed: {', '.join(s['edl_risk_partitions'])} ***",
              file=sys.stderr)
    print(f"Report written to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
