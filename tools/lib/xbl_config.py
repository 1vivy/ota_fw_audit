"""
xbl_config.img ARB metadata extractor.

Parses the OEM metadata block inside the Qualcomm hash segment of
xbl_config ELF images and extracts:
  - OEM major version
  - OEM minor version
  - Anti-rollback value
"""

import struct
from typing import Optional

from . import elf_parser


def extract_arb(data: bytes) -> Optional[dict]:
    """Extract ARB metadata from xbl_config image bytes.

    Returns dict with keys:
        oem_major, oem_minor, anti_rollback,
        oem_metadata_offset (absolute file offset)
    or None if parsing fails.
    """
    phdrs = elf_parser.parse_elf64_phdrs(data)
    if not phdrs:
        return None

    hash_phdr = elf_parser.find_hash_segment(phdrs)
    if hash_phdr is None:
        return None

    segment = elf_parser.read_hash_segment(data, hash_phdr)
    hdr = elf_parser.locate_hash_table_header(segment)
    if hdr is None:
        return None

    hdr_size = hdr.get("header_size", elf_parser.HASH_HDR_SIZE)
    oem_off = (hdr["header_offset"] + hdr_size
               + hdr["common_metadata_size"]
               + hdr["qti_metadata_size"])

    if oem_off + 12 > len(segment):
        return None

    major, minor, arb = struct.unpack_from("<III", segment, oem_off)

    return {
        "oem_major": major,
        "oem_minor": minor,
        "anti_rollback": arb,
        "oem_metadata_offset_in_segment": oem_off,
        "hash_segment_file_offset": hash_phdr["p_offset"],
    }
