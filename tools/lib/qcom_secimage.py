"""Qualcomm sec-image signing metadata parser.

Decodes the metadata, signature, and certificate-chain structures carried in
the hash segment of a signed Qualcomm ELF firmware image (MBN header v7) into
the `qualcomm_metadata` block the audit records per partition.

An image may be signed by QTI, by the OEM, or by both; each party has its own
metadata block, signature, and certificate chain, and each is reported
separately.  Field names follow the on-disk struct, so `oem_id` inside
`qti_metadata` is the struct's OEM ID field as seen by QTI signing.

Layout reference: the 224-byte v7 metadata struct and its flag encoding are
documented by the MBN format parser at https://github.com/NichtsHsu/mbn-rs.
Anti-rollback, SoC/OEM binding, and root certificate hashes decoded here were
verified field-for-field against previously recorded SM8850 manifests.
"""

from __future__ import annotations

import struct
from typing import Final

from . import elf_parser, qcom_certs

METADATA_V7_SIZE: Final[int] = 224

_HASH_ALGORITHMS: Final[dict[int, str]] = {0: "NA", 2: "SHA256", 3: "SHA384"}

_MEASUREMENT_TARGETS: Final[dict[int, str]] = {
    0: "Measurement not to be recorded",
    1: "Hardware Measurement Register #1",
    2: "Hardware Measurement Register #2",
    3: "Firmware Measurement Register #1",
    4: "Firmware Measurement Register #2",
    5: "Firmware Measurement Register #3",
    6: "Firmware Measurement Register #4",
}

# Bit-pair position in the v7 flags word -> reported binding field name.
# Each pair encodes 0b01 as false and 0b10 as true.
_BINDING_FLAGS: Final[tuple[tuple[int, str], ...]] = (
    (0, "bound_to_soc_hardware_versions"),
    (1, "bound_to_product_segment_id"),
    (2, "bound_to_jtag_id"),
    (3, "bound_to_serial_numbers"),
    (4, "bound_to_oem_id"),
    (5, "bound_to_oem_product_id"),
    (6, "bound_to_soc_lifecycle_state"),
    (7, "bound_to_oem_lifecycle_state"),
    (8, "bound_to_oem_root_certificate_hash"),
)

_JTAG_DEBUG_PAIR: Final[int] = 9
_TRANSFER_ROOT_PAIR: Final[int] = 10


def _flag_pair(flags: int, pair: int) -> bool | None:
    """Decode one tri-state flag pair; None when the encoding is invalid."""
    match (flags >> (pair * 2)) & 0b11:
        case 0b01:
            return False
        case 0b10:
            return True
        case _:
            return None


def _hex(value: int) -> str:
    """Render an identifier field the way the audit records it."""
    return f"0x{value:x}"


def parse_common_metadata(block: bytes) -> dict | None:
    """Decode the 24-byte common metadata block."""
    if len(block) < 24:
        return None
    major, minor, software_id, app_id, hash_algorithm, measurement = struct.unpack_from(
        "<6I", block, 0
    )
    return {
        "major_version": major,
        "minor_version": minor,
        "software_id": _hex(software_id),
        "secondary_software_id": _hex(app_id),
        "hash_algorithm": _HASH_ALGORITHMS.get(hash_algorithm, _hex(hash_algorithm)),
        "measurement_register_target": _MEASUREMENT_TARGETS.get(
            measurement, _hex(measurement)
        ),
    }


def parse_metadata_v7(block: bytes) -> dict | None:
    """Decode a 224-byte v7 signing metadata block."""
    if len(block) < METADATA_V7_SIZE:
        return None
    major, minor, anti_rollback, root_index = struct.unpack_from("<4I", block, 0)
    soc_versions = struct.unpack_from("<12I", block, 16)
    feature_id, jtag_id = struct.unpack_from("<2I", block, 64)
    oem_id, model_id = struct.unpack_from("<2I", block, 136)
    (lifecycle,) = struct.unpack_from("<Q", block, 144)
    (root_hash_algorithm,) = struct.unpack_from("<I", block, 152)
    (flags,) = struct.unpack_from("<I", block, 220)

    active_soc = [_hex(v) for v in soc_versions if v]
    metadata: dict = {
        "major_version": major,
        "minor_version": minor,
        "anti_rollback_version": anti_rollback,
        "root_certificate_index": root_index,
        "soc_hw_version": ",".join(active_soc) if active_soc else _hex(0),
        "product_segment_id": _hex(feature_id),
        "jtag_id": _hex(jtag_id),
        "oem_id": _hex(oem_id),
        "oem_product_id": _hex(model_id),
        "oem_lifecycle_state": _hex(lifecycle),
        "oem_root_cert_hash_algo": _HASH_ALGORITHMS.get(
            root_hash_algorithm, _hex(root_hash_algorithm)
        ),
    }
    for pair, field in _BINDING_FLAGS:
        metadata[field] = _flag_pair(flags, pair)
    debug = _flag_pair(flags, _JTAG_DEBUG_PAIR)
    metadata["jtag_debug"] = "Nop" if debug is False else "Disabled" if debug else None
    metadata["transfer_root"] = _flag_pair(flags, _TRANSFER_ROOT_PAIR)
    return metadata


def _describe_party(segment: bytes, regions: dict, party: str, digest: str | None) -> dict:
    """Describe one signing party's metadata, signature, and certificates."""
    described: dict = {}
    md_off = regions[f"{party}_metadata_offset"]
    md_size = regions[f"{party}_metadata_size"]
    if md_size >= METADATA_V7_SIZE:
        described[f"{party}_metadata"] = parse_metadata_v7(
            segment[md_off : md_off + md_size]
        )

    chain_off = regions[f"{party}_cert_chain_offset"]
    chain_size = regions[f"{party}_cert_chain_size"]
    if chain_size <= 0:
        return described

    chain = qcom_certs.split_der_certs(segment[chain_off : chain_off + chain_size])
    if not chain:
        return described

    groups = qcom_certs.classify_chain(chain)
    described[f"{party}_signature"] = qcom_certs.signature_properties(chain, digest)
    described[f"{party}_cert_chain"] = {
        "total_certs": len(chain),
        "attest_certs": len(groups["attest"]),
        "ca_certs": len(groups["ca"]),
        "root_certs": len(groups["root"]),
    }
    for role in ("attest", "ca", "root"):
        if groups[role]:
            described[f"{party}_{role}_cert"] = qcom_certs.describe_cert(
                groups[role][0], with_hashes=role == "root"
            )
    return described


def inspect_image(data: bytes) -> dict | None:
    """Extract the Qualcomm signing metadata block from image bytes.

    Returns None when the image is not a signed Qualcomm ELF, i.e. it has no
    ELF64 header, no hash segment, or no recognisable hash table header.
    """
    if not elf_parser.is_elf64_le(data):
        return None
    phdrs = elf_parser.parse_elf64_phdrs(data)
    if not phdrs:
        return None
    hash_phdr = elf_parser.find_hash_segment(phdrs)
    if hash_phdr is None:
        return None
    segment = elf_parser.read_hash_segment(data, hash_phdr)
    header = elf_parser.locate_hash_table_header(segment)
    if header is None:
        return None

    regions = elf_parser.get_hash_segment_regions(segment, header)
    common_off = regions["common_metadata_offset"]
    common = parse_common_metadata(
        segment[common_off : common_off + regions["common_metadata_size"]]
    )
    digest = common["hash_algorithm"] if common else None

    result: dict = {"common_metadata": common}
    for party in ("qti", "oem"):
        result.update(_describe_party(segment, regions, party, digest))
    result["hash_table_header"] = {
        "version": header["hash_header_version"],
        "common_metadata_size": header["common_metadata_size"],
        "qti_metadata_size": header["qti_metadata_size"],
        "oem_metadata_size": header["oem_metadata_size"],
        "hash_table_size": header["hash_table_size"],
        "qti_signature_size": header["qti_signature_size"],
        "qti_cert_chain_size": header["qti_cert_chain_size"],
        "oem_signature_size": header["oem_signature_size"],
        "oem_cert_chain_size": header["oem_cert_chain_size"],
    }
    if not any(value is not None for value in result.values()):
        return None
    return result
