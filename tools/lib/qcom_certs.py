"""Certificate-chain properties for Qualcomm signed firmware images.

The hash segment of a signed Qualcomm image carries a DER certificate chain
per signing party (QTI and/or OEM).  This module turns that chain into the
breakdown the audit compares across OTAs: how many attest/CA/root certs are
present, the key and signature properties of each, and the root certificate
hashes that identify the root of trust.

`cryptography` cannot parse the extension set of these OPLUS certificates --
they carry a BasicConstraints with `ca=False` plus a pathLen, which the
library rejects outright.  Extended Key Usage is therefore read with a small
DER scan instead of through `Certificate.extensions`.
"""

from __future__ import annotations

import hashlib
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa

# DER encoding of the id-ce-extKeyUsage OID (2.5.29.37).
_EKU_EXTN_OID_DER: Final[bytes] = b"\x06\x03\x55\x1d\x25"

_EKU_NAMES: Final[dict[str, str]] = {
    "1.3.6.1.5.5.7.3.1": "TLS Web Server Authentication",
    "1.3.6.1.5.5.7.3.2": "TLS Web Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "E-mail Protection",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "2.5.29.37.0": "Any Extended Key Usage",
}

_ECDSA_OID_PREFIX: Final[str] = "1.2.840.10045.4"
_RSA_OID_PREFIX: Final[str] = "1.2.840.113549.1.1"


def _read_der_length(data: bytes, offset: int) -> tuple[int, int]:
    """Return (length, offset_after_length) for a DER length at `offset`."""
    first = data[offset]
    if not first & 0x80:
        return first, offset + 1
    count = first & 0x7F
    return int.from_bytes(data[offset + 1 : offset + 1 + count], "big"), offset + 1 + count


def _decode_oid(raw: bytes) -> str:
    """Decode DER OID contents into dotted-decimal form."""
    if not raw:
        return ""
    parts = [str(raw[0] // 40), str(raw[0] % 40)]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def split_der_certs(blob: bytes) -> list[bytes]:
    """Split a concatenated DER certificate chain into individual certs."""
    certs: list[bytes] = []
    pos = 0
    while pos < len(blob) and blob[pos] == 0x30:
        length, after = _read_der_length(blob, pos + 1)
        total = (after - pos) + length
        if total <= 0 or pos + total > len(blob):
            break
        certs.append(blob[pos : pos + total])
        pos += total
    return certs


def extract_eku(der: bytes) -> list[str] | None:
    """Return the Extended Key Usage purposes of a DER certificate."""
    idx = der.find(_EKU_EXTN_OID_DER)
    if idx < 0:
        return None
    pos = idx + len(_EKU_EXTN_OID_DER)
    if pos < len(der) and der[pos] == 0x01:  # optional critical BOOLEAN
        length, after = _read_der_length(der, pos + 1)
        pos = after + length
    if pos >= len(der) or der[pos] != 0x04:  # extnValue OCTET STRING
        return None
    length, pos = _read_der_length(der, pos + 1)
    inner = der[pos : pos + length]
    if not inner or inner[0] != 0x30:
        return None
    length, pos = _read_der_length(inner, 1)
    body = inner[pos : pos + length]
    purposes: list[str] = []
    pos = 0
    while pos < len(body) and body[pos] == 0x06:
        length, after = _read_der_length(body, pos + 1)
        oid = _decode_oid(body[after : after + length])
        purposes.append(_EKU_NAMES.get(oid, oid))
        pos = after + length
    return purposes or None


def _signature_algorithm(cert: x509.Certificate) -> str | None:
    """Return the signature algorithm family that signed this certificate."""
    oid = cert.signature_algorithm_oid.dotted_string
    if oid.startswith(_ECDSA_OID_PREFIX):
        return "ECDSA"
    if oid.startswith(_RSA_OID_PREFIX):
        return "RSA"
    return None


def _key_properties(cert: x509.Certificate) -> tuple[str | None, int | None]:
    """Return (curve_name, key_size_bits) of the certificate public key."""
    match cert.public_key():
        case ec.EllipticCurvePublicKey() as key:
            return key.curve.name, key.curve.key_size
        case rsa.RSAPublicKey() as key:
            return None, key.key_size
        case _:
            return None, None


def _hash_algorithm(cert: x509.Certificate) -> str | None:
    """Return the digest used in this certificate's signature."""
    algorithm = cert.signature_hash_algorithm
    return algorithm.name.upper() if algorithm is not None else None


def describe_cert(der: bytes, *, with_hashes: bool) -> dict:
    """Describe one certificate's signing and key properties."""
    cert = x509.load_der_x509_certificate(der)
    curve, key_size = _key_properties(cert)
    described: dict = {}
    if with_hashes:
        described["root_cert_hash_sha256"] = "0x" + hashlib.sha256(der).hexdigest()
        described["root_cert_hash_sha384"] = "0x" + hashlib.sha384(der).hexdigest()
    described["signature_algorithm"] = _signature_algorithm(cert)
    described["hash_algorithm"] = _hash_algorithm(cert)
    described["curve"] = curve
    described["key_size"] = key_size
    eku = extract_eku(der)
    if eku:
        described["extended_key_usage"] = ", ".join(eku)
    return described


def classify_chain(chain: list[bytes]) -> dict[str, list[bytes]]:
    """Split a chain into attest (leaf), CA, and root certificates."""
    parsed = [x509.load_der_x509_certificate(der) for der in chain]
    issuers = {cert.issuer.public_bytes() for cert in parsed}
    groups: dict[str, list[bytes]] = {"attest": [], "ca": [], "root": []}
    for der, cert in zip(chain, parsed, strict=True):
        if cert.subject == cert.issuer:
            groups["root"].append(der)
        elif cert.subject.public_bytes() not in issuers:
            groups["attest"].append(der)
        else:
            groups["ca"].append(der)
    return groups


def signature_properties(chain: list[bytes], hash_algorithm: str | None) -> dict | None:
    """Describe the image signature produced by the chain's leaf key.

    The image is signed with the attest certificate's private key, so the
    algorithm, curve, and key size come from that certificate.  The digest is
    the hash table algorithm declared in the image's common metadata.
    """
    groups = classify_chain(chain)
    leaf = (groups["attest"] or groups["ca"] or groups["root"] or [None])[0]
    if leaf is None:
        return None
    cert = x509.load_der_x509_certificate(leaf)
    curve, key_size = _key_properties(cert)
    match cert.public_key():
        case ec.EllipticCurvePublicKey():
            algorithm = "ECDSA"
        case rsa.RSAPublicKey():
            algorithm = "RSA"
        case _:
            algorithm = None
    return {
        "algorithm": algorithm,
        "hash_algorithm": hash_algorithm,
        "curve": curve,
        "key_size": key_size,
    }
