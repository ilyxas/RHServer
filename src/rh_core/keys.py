"""The core's own P-256 key: signs every response and WebSocket frame."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from rh_common.crypto import generate_private_key


def load_or_create(path: Path) -> ec.EllipticCurvePrivateKey:
    """Load the key, creating it (mode 600) on first start."""
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
            raise ValueError(f"{path} is not a P-256 private key")
        return key
    key = generate_private_key()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)
    return key
