"""
Qualcomm ELF64 firmware image parser.

Parses ELF program headers and locates the hash segment used by
Qualcomm secure-boot images (xbl, tz, hyp, abl, aop, keymaster, etc.).

The hash segment is typically the last PT_NULL program header with
nonzero p_filesz. Inside it lives the hash table header, per-segment
hashes, an optional signature blob, and an optional certificate chain.
"""

import struct
from typing import Optional

ELF_MAGIC = b"\x7fELF"
PT_NULL = 0
ELFCLASS64 = 2
ELFDATA2LSB = 1

# ELF64 header fields we care about
ELF64_EHDR_SIZE = 64
ELF64_PHDR_SIZE = 56


def is_elf64_le(data: bytes) -> bool:
    """Check if data starts with a little-endian ELF64 header."""
    if len(data) < 16:
        return False
    return (data[:4] == ELF_MAGIC
            and data[4] == ELFCLASS64
            and data[5] == ELFDATA2LSB)


def parse_elf64_phdrs(data: bytes) -> list[dict]:
    """Parse all ELF64 program headers from image bytes.

    Returns a list of dicts with keys:
        index, p_type, p_flags, p_offset, p_vaddr, p_paddr,
        p_filesz, p_memsz, p_align
    """
    if len(data) < ELF64_EHDR_SIZE:
        return []
    if not is_elf64_le(data):
        return []

    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsz = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]

    phdrs = []
    for idx in range(e_phnum):
        off = e_phoff + idx * e_phentsz
        if off + 56 > len(data):
            break
        (p_type, p_flags, p_offset, p_vaddr, p_paddr,
         p_filesz, p_memsz, p_align) = struct.unpack_from(
            "<IIQQQQQQ", data, off)
        phdrs.append({
            "index": idx,
            "p_type": p_type,
            "p_flags": p_flags,
            "p_offset": p_offset,
            "p_vaddr": p_vaddr,
            "p_paddr": p_paddr,
            "p_filesz": p_filesz,
            "p_memsz": p_memsz,
            "p_align": p_align,
        })
    return phdrs


def find_hash_segment(phdrs: list[dict]) -> Optional[dict]:
    """Return the last PT_NULL phdr with nonzero p_filesz (the hash segment)."""
    for phdr in reversed(phdrs):
        if phdr["p_type"] == PT_NULL and phdr["p_filesz"] > 0:
            return phdr
    return None


def read_hash_segment(data: bytes, phdr: dict) -> bytes:
    """Read the hash segment bytes from the image data."""
    off = phdr["p_offset"]
    sz = phdr["p_filesz"]
    return data[off:off + sz]


# --- Hash table header parsing ---
# Qualcomm hash segment starts with a header (found at a small offset
# from the start, often 0x4).  The header layout (all little-endian uint32):
#
#   [0]  version
#   [1]  common_metadata_size
#   [2]  qti_metadata_size
#   [3]  oem_metadata_size
#   [4]  hash_table_size
#   [5]  qti_signature_size
#   [6]  oem_signature_size
#   [7]  qti_cert_chain_size
#   [8]  oem_cert_chain_size
#
# Total header size: 9 x 4 = 36 bytes.
# The metadata regions follow immediately after the 36-byte header.

HASH_HDR_SIZE = 36  # 9 x uint32
HASH_HDR_SCAN_LIMIT = 0x1000


def locate_hash_table_header(segment: bytes) -> Optional[dict]:
    """Scan for the Qualcomm hash table header inside the hash segment.

    Returns dict with keys:
        header_offset, header_size,
        hash_header_version, common_metadata_size,
        qti_metadata_size, oem_metadata_size, hash_table_size,
        qti_signature_size, oem_signature_size,
        qti_cert_chain_size, oem_cert_chain_size
    or None if not found.
    """
    limit = min(len(segment), HASH_HDR_SCAN_LIMIT)
    for off in range(0, limit - HASH_HDR_SIZE + 1, 4):
        vals = struct.unpack_from("<9I", segment, off)
        (version, common_sz, qti_sz, oem_sz, hash_tbl_sz,
         qti_sig_sz, oem_sig_sz, qti_cert_sz, oem_cert_sz) = vals

        if version < 1 or version > 10:
            continue
        if common_sz > 0x1000 or qti_sz > 0x4000:
            continue
        if oem_sz > 0x4000 or hash_tbl_sz > 0x4000:
            continue
        # hash_tbl_sz must be nonzero (real images have hashes)
        if hash_tbl_sz == 0:
            continue
        # common_sz should be > 0 for real headers
        if common_sz == 0:
            continue
        # The region must fit inside the segment
        end = (off + HASH_HDR_SIZE + common_sz + qti_sz + oem_sz
               + hash_tbl_sz + qti_sig_sz + oem_sig_sz
               + qti_cert_sz + oem_cert_sz)
        if end > len(segment):
            continue

        return {
            "header_offset": off,
            "header_size": HASH_HDR_SIZE,
            "hash_header_version": version,
            "common_metadata_size": common_sz,
            "qti_metadata_size": qti_sz,
            "oem_metadata_size": oem_sz,
            "hash_table_size": hash_tbl_sz,
            "qti_signature_size": qti_sig_sz,
            "oem_signature_size": oem_sig_sz,
            "qti_cert_chain_size": qti_cert_sz,
            "oem_cert_chain_size": oem_cert_sz,
        }
    return None


def get_hash_segment_regions(segment: bytes, hdr: dict) -> dict:
    """Compute byte offsets for metadata, hash table, signatures, and certs
    inside the hash segment.

    Returns dict with keys for each region: offset and size.
    """
    hdr_size = hdr.get("header_size", HASH_HDR_SIZE)
    base = hdr["header_offset"] + hdr_size

    common_off = base
    qti_off = common_off + hdr["common_metadata_size"]
    oem_off = qti_off + hdr["qti_metadata_size"]
    hash_off = oem_off + hdr["oem_metadata_size"]
    qti_sig_off = hash_off + hdr["hash_table_size"]
    oem_sig_off = qti_sig_off + hdr.get("qti_signature_size", 0)
    qti_cert_off = oem_sig_off + hdr.get("oem_signature_size", 0)
    oem_cert_off = qti_cert_off + hdr.get("qti_cert_chain_size", 0)
    post_all_off = oem_cert_off + hdr.get("oem_cert_chain_size", 0)
    post_all_sz = max(0, len(segment) - post_all_off)

    return {
        "common_metadata_offset": common_off,
        "common_metadata_size": hdr["common_metadata_size"],
        "qti_metadata_offset": qti_off,
        "qti_metadata_size": hdr["qti_metadata_size"],
        "oem_metadata_offset": oem_off,
        "oem_metadata_size": hdr["oem_metadata_size"],
        "hash_table_offset": hash_off,
        "hash_table_size": hdr["hash_table_size"],
        "qti_signature_offset": qti_sig_off,
        "qti_signature_size": hdr.get("qti_signature_size", 0),
        "oem_signature_offset": oem_sig_off,
        "oem_signature_size": hdr.get("oem_signature_size", 0),
        "qti_cert_chain_offset": qti_cert_off,
        "qti_cert_chain_size": hdr.get("qti_cert_chain_size", 0),
        "oem_cert_chain_offset": oem_cert_off,
        "oem_cert_chain_size": hdr.get("oem_cert_chain_size", 0),
        "post_all_offset": post_all_off,
        "post_all_size": post_all_sz,
    }
