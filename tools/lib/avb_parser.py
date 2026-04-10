"""
Minimal AVB (Android Verified Boot) vbmeta image parser.

Parses the AVB vbmeta header and extracts:
  - AVB version
  - Rollback index
  - Rollback index location
  - Algorithm type
  - Public key digest (SHA-256 of the embedded public key)
  - Chained partition descriptors (partition name, rollback_index_location,
    public key digest)
  - Hash descriptors (partition name, digest)
  - Hashtree descriptors (partition name)

Reference: external/avb/libavb/avb_vbmeta_image.h
"""

import hashlib
import struct
from typing import Optional


AVB_MAGIC = b"AVB0"

# Descriptor tags
AVB_DESCRIPTOR_TAG_PROPERTY = 0
AVB_DESCRIPTOR_TAG_HASHTREE = 1
AVB_DESCRIPTOR_TAG_HASH = 2
AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE = 3
AVB_DESCRIPTOR_TAG_CHAIN_PARTITION = 4

# Algorithm types
AVB_ALGORITHMS = {
    0: "NONE",
    1: "SHA256_RSA2048",
    2: "SHA256_RSA4096",
    3: "SHA256_RSA8192",
    4: "SHA512_RSA2048",
    5: "SHA512_RSA4096",
    6: "SHA512_RSA8192",
}


def parse_vbmeta(data: bytes) -> Optional[dict]:
    """Parse a vbmeta image.

    Returns dict with keys:
        avb_version_major, avb_version_minor,
        rollback_index, rollback_index_location,
        algorithm, public_key_sha256,
        descriptors: list of descriptor dicts
    or None if not a valid vbmeta image.
    """
    if len(data) < 256 or data[:4] != AVB_MAGIC:
        return None

    # AVB vbmeta header is 256 bytes
    # Parse field by field at known offsets (big-endian)
    req_lib_ver_major = struct.unpack_from(">I", data, 4)[0]
    req_lib_ver_minor = struct.unpack_from(">I", data, 8)[0]
    auth_block_size = struct.unpack_from(">Q", data, 12)[0]
    aux_block_size = struct.unpack_from(">Q", data, 20)[0]
    algorithm_type = struct.unpack_from(">I", data, 28)[0]
    hash_offset = struct.unpack_from(">Q", data, 32)[0]
    hash_size = struct.unpack_from(">Q", data, 40)[0]
    sig_offset = struct.unpack_from(">Q", data, 48)[0]
    sig_size = struct.unpack_from(">Q", data, 56)[0]
    pub_key_offset = struct.unpack_from(">Q", data, 64)[0]
    pub_key_size = struct.unpack_from(">Q", data, 72)[0]
    pub_key_meta_offset = struct.unpack_from(">Q", data, 80)[0]
    pub_key_meta_size = struct.unpack_from(">Q", data, 88)[0]
    desc_offset = struct.unpack_from(">Q", data, 96)[0]
    desc_size = struct.unpack_from(">Q", data, 104)[0]
    rollback_index = struct.unpack_from(">Q", data, 112)[0]
    flags = struct.unpack_from(">I", data, 120)[0]
    rollback_index_location = struct.unpack_from(">I", data, 124)[0]

    # Release string at offset 128, 48 bytes
    release_string = data[128:176].split(b"\x00")[0].decode("ascii", errors="replace")

    # Public key digest
    auth_base = 256  # auth block starts right after the 256-byte header
    aux_base = auth_base + auth_block_size

    pub_key_sha256 = ""
    if pub_key_size > 0:
        pk_start = aux_base + pub_key_offset
        pk_data = data[pk_start:pk_start + pub_key_size]
        if pk_data:
            pub_key_sha256 = hashlib.sha256(pk_data).hexdigest()

    # Parse descriptors
    descriptors = []
    desc_start = aux_base + desc_offset
    pos = 0
    while pos + 16 <= desc_size:
        abs_pos = desc_start + pos
        if abs_pos + 16 > len(data):
            break
        tag = struct.unpack_from(">Q", data, abs_pos)[0]
        num_bytes = struct.unpack_from(">Q", data, abs_pos + 8)[0]
        desc_data = data[abs_pos + 16:abs_pos + 16 + num_bytes]

        desc = _parse_descriptor(tag, desc_data)
        if desc is not None:
            descriptors.append(desc)

        # Advance: 16 byte header + num_bytes, padded to 8-byte alignment
        total = 16 + num_bytes
        total = (total + 7) & ~7
        pos += total

    algo_name = AVB_ALGORITHMS.get(algorithm_type, f"UNKNOWN({algorithm_type})")

    return {
        "avb_version_major": req_lib_ver_major,
        "avb_version_minor": req_lib_ver_minor,
        "rollback_index": rollback_index,
        "rollback_index_location": rollback_index_location,
        "algorithm": algo_name,
        "flags": flags,
        "release_string": release_string,
        "public_key_sha256": pub_key_sha256,
        "descriptors": descriptors,
    }


def _parse_descriptor(tag: int, data: bytes) -> Optional[dict]:
    """Parse a single AVB descriptor."""
    if tag == AVB_DESCRIPTOR_TAG_HASH:
        return _parse_hash_descriptor(data)
    elif tag == AVB_DESCRIPTOR_TAG_HASHTREE:
        return _parse_hashtree_descriptor(data)
    elif tag == AVB_DESCRIPTOR_TAG_CHAIN_PARTITION:
        return _parse_chain_descriptor(data)
    elif tag == AVB_DESCRIPTOR_TAG_PROPERTY:
        return _parse_property_descriptor(data)
    elif tag == AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE:
        return {"type": "kernel_cmdline"}
    return None


def _parse_hash_descriptor(data: bytes) -> Optional[dict]:
    """Parse an AVB hash descriptor."""
    if len(data) < 72:
        return None
    image_size = struct.unpack_from(">Q", data, 0)[0]
    hash_offset = struct.unpack_from(">Q", data, 8)[0]
    digest_size = struct.unpack_from(">I", data, 16)[0]
    salt_size = struct.unpack_from(">I", data, 20)[0]
    partition_name_len = struct.unpack_from(">I", data, 24)[0]
    # salt_len at 28
    # digest at 32
    flags = struct.unpack_from(">I", data, 32)[0]
    # partition name starts at offset 68
    name_off = 68
    name = data[name_off:name_off + partition_name_len].decode("ascii", errors="replace")
    salt_off = name_off + partition_name_len
    salt = data[salt_off:salt_off + salt_size].hex() if salt_size > 0 else ""
    digest_off = salt_off + salt_size
    digest = data[digest_off:digest_off + digest_size].hex() if digest_size > 0 else ""

    return {
        "type": "hash",
        "partition_name": name,
        "image_size": image_size,
        "digest": digest,
        "salt": salt,
    }


def _parse_hashtree_descriptor(data: bytes) -> Optional[dict]:
    """Parse an AVB hashtree descriptor."""
    if len(data) < 132:
        return None
    partition_name_len = struct.unpack_from(">I", data, 60)[0]
    salt_len = struct.unpack_from(">I", data, 64)[0]
    root_digest_len = struct.unpack_from(">I", data, 68)[0]
    flags = struct.unpack_from(">I", data, 72)[0]
    name_off = 132
    name = data[name_off:name_off + partition_name_len].decode("ascii", errors="replace")
    salt_off = name_off + partition_name_len
    salt = data[salt_off:salt_off + salt_len].hex() if salt_len > 0 else ""
    digest_off = salt_off + salt_len
    root_digest = data[digest_off:digest_off + root_digest_len].hex() if root_digest_len > 0 else ""

    return {
        "type": "hashtree",
        "partition_name": name,
        "root_digest": root_digest,
        "salt": salt,
    }


def _parse_chain_descriptor(data: bytes) -> Optional[dict]:
    """Parse an AVB chain partition descriptor."""
    if len(data) < 28:
        return None
    rollback_index_location = struct.unpack_from(">I", data, 0)[0]
    partition_name_len = struct.unpack_from(">I", data, 4)[0]
    public_key_len = struct.unpack_from(">I", data, 8)[0]
    # Flags at 12
    name_off = 16
    name = data[name_off:name_off + partition_name_len].decode("ascii", errors="replace")
    pk_off = name_off + partition_name_len
    pk_data = data[pk_off:pk_off + public_key_len]
    pk_sha256 = hashlib.sha256(pk_data).hexdigest() if pk_data else ""

    return {
        "type": "chain_partition",
        "partition_name": name,
        "rollback_index_location": rollback_index_location,
        "public_key_sha256": pk_sha256,
    }


def _parse_property_descriptor(data: bytes) -> Optional[dict]:
    """Parse an AVB property descriptor."""
    if len(data) < 8:
        return None
    key_len = struct.unpack_from(">Q", data, 0)[0]
    val_len = struct.unpack_from(">Q", data, 8)[0]
    key = data[16:16 + key_len].decode("ascii", errors="replace")
    val = data[16 + key_len + 1:16 + key_len + 1 + val_len].decode("ascii", errors="replace")
    return {
        "type": "property",
        "key": key,
        "value": val,
    }
