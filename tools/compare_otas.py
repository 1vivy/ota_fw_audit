#!/usr/bin/env python3
"""
compare_otas.py - Compare two OTA manifests and produce a diff report.

Usage:
    python3 compare_otas.py [--risk-dict risk_dictionary.yaml] \
        manifest_a.json manifest_b.json --out report.json

The report contains:
  - Which partitions changed (sha256 diff)
  - Which version strings changed
  - Which ARB values changed
  - Which cert fingerprints changed
  - Which AVB public keys or rollback indexes changed
  - Per-partition risk assessment from the risk dictionary
  - Summary flags: boot_chain_changed, arb_changed, key_changed, edl_risk
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

    # ARB
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

    # Cert chain
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
        "partitions_compared": 0,
        "changed_partitions": [],
        "unchanged_partitions": [],
        "missing_in_a": [],
        "missing_in_b": [],
        "summary": {
            "boot_chain_changed": False,
            "arb_changed": False,
            "arb_incremented": False,
            "cert_chain_changed": False,
            "avb_key_changed": False,
            "avb_rollback_changed": False,
            "edl_risk_partitions": [],
        },
        "partition_diffs": {},
    }

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
    if s["cert_chain_changed"]:
        print("*** CERT CHAIN CHANGED ***", file=sys.stderr)
    if s["avb_key_changed"]:
        print("*** AVB PUBLIC KEY CHANGED ***", file=sys.stderr)
    if s["edl_risk_partitions"]:
        print(f"*** EDL RISK partitions changed: {', '.join(s['edl_risk_partitions'])} ***",
              file=sys.stderr)
    print(f"Report written to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
