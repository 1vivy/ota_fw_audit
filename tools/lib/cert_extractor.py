"""
Certificate chain extractor for Qualcomm signed ELF firmware images.

After the hash table inside the hash segment, Qualcomm images typically
store a signature blob followed by a DER-encoded X.509 certificate chain.

The certificates are written sequentially in DER (BER) format.  We detect
them by looking for the ASN.1 SEQUENCE tag (0x30) with a valid length
encoding, then attempt to walk the chain.

For each certificate found we record:
  - SHA-256 fingerprint of the raw DER bytes
  - byte offset within the hash segment
  - length
  - subject and issuer common names (best effort)

We explicitly skip trivial top-level certs that appear identical across
all images (same fingerprint) -- the caller can filter those out by
comparing across OTAs.  But we record everything here so the comparison
layer has full data.
"""

import hashlib
import struct
from typing import Optional

from . import elf_parser


def _parse_asn1_length(data: bytes, offset: int) -> tuple[int, int]:
    """Parse an ASN.1 DER length field at offset.

    Returns (length, bytes_consumed) or (-1, 0) on failure.
    """
    if offset >= len(data):
        return -1, 0
    first = data[offset]
    if first < 0x80:
        return first, 1
    num_bytes = first & 0x7F
    if num_bytes == 0 or num_bytes > 4:
        return -1, 0
    if offset + 1 + num_bytes > len(data):
        return -1, 0
    length = 0
    for i in range(num_bytes):
        length = (length << 8) | data[offset + 1 + i]
    return length, 1 + num_bytes


def _try_extract_der_cert(data: bytes, offset: int) -> Optional[tuple[bytes, int]]:
    """Try to extract a single DER-encoded certificate starting at offset.

    A certificate is an ASN.1 SEQUENCE (tag 0x30) with a valid length.

    Returns (der_bytes, total_length) or None.
    """
    if offset >= len(data):
        return None
    if data[offset] != 0x30:
        return None
    length, consumed = _parse_asn1_length(data, offset + 1)
    if length < 0:
        return None
    total = 1 + consumed + length
    if offset + total > len(data):
        return None
    # Sanity: real certs are at least ~200 bytes
    if total < 128:
        return None
    return data[offset:offset + total], total


def _extract_cn_from_name(data: bytes) -> str:
    """Best-effort extraction of the CN (OID 2.5.4.3) from a DER Name.

    This is a simplified parser that scans for the CN OID and grabs the
    following UTF8String/PrintableString value.  It is not a full ASN.1
    parser; it is good enough for fingerprinting purposes.
    """
    cn_oid = b"\x55\x04\x03"  # 2.5.4.3
    idx = data.find(cn_oid)
    if idx < 0:
        return ""
    # Skip the OID (3 bytes) and the tag+length of the following string
    pos = idx + 3
    if pos >= len(data):
        return ""
    tag = data[pos]
    # PrintableString=0x13, UTF8String=0x0C, IA5String=0x16
    if tag not in (0x0C, 0x13, 0x16):
        return ""
    length, consumed = _parse_asn1_length(data, pos + 1)
    if length < 0:
        return ""
    start = pos + 1 + consumed
    try:
        return data[start:start + length].decode("utf-8", errors="replace")
    except Exception:
        return ""


def extract_certs_from_segment(segment: bytes, hdr: dict) -> list[dict]:
    """Extract certificate chain from the cert chain regions in the segment.

    The hash table header declares qti_cert_chain_size and oem_cert_chain_size.
    We scan both regions for DER-encoded X.509 certificates.

    Args:
        segment: raw hash segment bytes
        hdr: hash table header dict from elf_parser.locate_hash_table_header()

    Returns list of dicts, each with:
        offset, length, sha256, subject_cn, issuer_cn, chain
    """
    regions = elf_parser.get_hash_segment_regions(segment, hdr)

    certs = []

    # Scan QTI cert chain region
    for chain_name, off_key, sz_key in [
        ("qti", "qti_cert_chain_offset", "qti_cert_chain_size"),
        ("oem", "oem_cert_chain_offset", "oem_cert_chain_size"),
    ]:
        region_off = regions.get(off_key, 0)
        region_sz = regions.get(sz_key, 0)
        if region_sz <= 0:
            continue
        region_data = segment[region_off:region_off + region_sz]
        certs.extend(_scan_region_for_certs(region_data, region_off, chain_name))

    # Also scan any remaining data after all declared regions
    post_off = regions.get("post_all_offset", 0)
    post_sz = regions.get("post_all_size", 0)
    if post_sz > 128:
        post_data = segment[post_off:post_off + post_sz]
        certs.extend(_scan_region_for_certs(post_data, post_off, "trailing"))

    return certs


def _scan_region_for_certs(data: bytes, base_offset: int, chain_name: str) -> list[dict]:
    """Scan a byte region for DER-encoded X.509 certificates."""
    certs = []
    pos = 0
    while pos < len(data) - 128:
        result = _try_extract_der_cert(data, pos)
        if result is not None:
            der_bytes, total = result
            fp = hashlib.sha256(der_bytes).hexdigest()

            subject_cn = ""
            issuer_cn = ""
            try:
                cn_oid = b"\x55\x04\x03"
                idx1 = der_bytes.find(cn_oid)
                if idx1 >= 0:
                    issuer_cn = _extract_cn_from_name(der_bytes[idx1:])
                    idx2 = der_bytes.find(cn_oid, idx1 + len(cn_oid) + 4)
                    if idx2 >= 0:
                        subject_cn = _extract_cn_from_name(der_bytes[idx2:])
                    else:
                        subject_cn = issuer_cn
                        issuer_cn = ""
            except Exception:
                pass

            certs.append({
                "offset_in_region": pos,
                "offset_in_segment": base_offset + pos,
                "length": total,
                "sha256": fp,
                "subject_cn": subject_cn,
                "issuer_cn": issuer_cn,
                "chain": chain_name,
            })
            pos += total
        else:
            pos += 1

    return certs


def extract_certs_from_image(data: bytes) -> list[dict]:
    """High-level: extract certs from a Qualcomm ELF firmware image.

    Returns list of cert dicts, or empty list if not applicable.
    """
    phdrs = elf_parser.parse_elf64_phdrs(data)
    if not phdrs:
        return []

    hash_phdr = elf_parser.find_hash_segment(phdrs)
    if hash_phdr is None:
        return []

    segment = elf_parser.read_hash_segment(data, hash_phdr)
    hdr = elf_parser.locate_hash_table_header(segment)
    if hdr is None:
        return []

    return extract_certs_from_segment(segment, hdr)
