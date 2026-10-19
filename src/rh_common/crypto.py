"""P-256 keys and signatures in the formats both sides use (SPEC §4).

Public keys travel as X9.63 uncompressed points (65 bytes, 0x04 || X || Y), which
is what SecKeyCopyExternalRepresentation returns on iOS. Signatures are ECDSA
P-256 / SHA-256 in DER, as Security.framework produces them.
"""

from __future__ import annotations

import base64
import binascii
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

__all__ = [
    "CURVE_ORDER",
    "b64d",
    "b64e",
    "b64url_d",
    "b64url_e",
    "generate_private_key",
    "load_private_scalar",
    "load_public_x963",
    "public_x963",
    "sha256_hex",
    "sign_der",
    "verify_der",
]

CURVE_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_ECDSA = ec.ECDSA(hashes.SHA256())


def b64e(data: bytes) -> str:
    """Standard base64 with padding (RFC 4648 §4)."""
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """Strict standard base64: rejects url-safe alphabet, missing padding, junk."""
    try:
        raw = base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError) as e:
        raise ValueError(f"not standard base64: {e}") from e
    if base64.b64encode(raw).decode("ascii") != text:
        raise ValueError("not canonical base64")
    return raw


def b64url_e(data: bytes) -> str:
    """base64url without padding (RFC 4648 §5), used only in the pairing string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_d(text: str) -> bytes:
    if "=" in text:
        raise ValueError("base64url must not be padded")
    try:
        raw = base64.urlsafe_b64decode((text + "=" * (-len(text) % 4)).encode("ascii"))
    except (binascii.Error, UnicodeEncodeError, ValueError) as e:
        raise ValueError(f"not base64url: {e}") from e
    if b64url_e(raw) != text:
        raise ValueError("not canonical base64url")
    return raw


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_public_x963(data: bytes) -> ec.EllipticCurvePublicKey:
    if len(data) != 65 or data[0] != 0x04:
        raise ValueError("public key must be 65-byte uncompressed X9.63")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), data)


def public_x963(key: ec.EllipticCurvePrivateKey | ec.EllipticCurvePublicKey) -> bytes:
    pub = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    return pub.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def generate_private_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def load_private_scalar(data: bytes) -> ec.EllipticCurvePrivateKey:
    """Raw 32-byte big-endian scalar, the form used for test keys in vectors."""
    if len(data) != 32:
        raise ValueError("private scalar must be 32 bytes")
    return ec.derive_private_key(int.from_bytes(data, "big"), ec.SECP256R1())


def sign_der(
    key: ec.EllipticCurvePrivateKey, message: bytes, *, deterministic: bool = False
) -> bytes:
    """Deterministic (RFC 6979) signing is used only to keep generated vectors stable."""
    algo = ec.ECDSA(hashes.SHA256(), deterministic_signing=True) if deterministic else _ECDSA
    return key.sign(message, algo)


def verify_der(public: bytes | ec.EllipticCurvePublicKey, message: bytes, signature: bytes) -> bool:
    """True iff signature is a valid DER ECDSA P-256/SHA-256 signature over message.

    High-S signatures are accepted: Security.framework may produce either form.
    """
    try:
        key = load_public_x963(public) if isinstance(public, bytes) else public
        key.verify(signature, message, _ECDSA)
    except (InvalidSignature, ValueError):
        return False
    return True
