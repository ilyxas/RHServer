"""A minimal reference client for tests: what the iPhone does, in Python.

Software P-256 keys stand in for Secure Enclave keys (dev mode, SPEC §9.1).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from rh_common.crypto import b64d, b64e, generate_private_key, public_x963, sign_der, verify_der
from rh_common.protocol import (
    HEADER_AUTH,
    HEADER_SERVER_SIG,
    HEADER_SIG,
    HEADER_SIG_CRITICAL,
    build_signed_object,
    device_id,
    fingerprint,
    frame_sig_message,
    server_sig_message,
)


@dataclass
class Phone:
    name: str = "Мой iPhone"
    keys: dict[str, ec.EllipticCurvePrivateKey] = field(
        default_factory=lambda: {
            level: generate_private_key() for level in ("normal", "critical", "ssh")
        }
    )
    core_key: bytes | None = None

    @property
    def pub(self) -> dict[str, str]:
        return {level: b64e(public_x963(k)) for level, k in self.keys.items()}

    @property
    def id(self) -> str:
        return device_id(public_x963(self.keys["normal"]))

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.pub)

    def headers(
        self,
        *,
        op: str,
        key: str,
        nonce: str,
        body: bytes,
        now: datetime | None = None,
        lifetime: timedelta = timedelta(seconds=60),
    ) -> dict[str, str]:
        now = now or datetime.now(UTC).replace(microsecond=0)
        level = "normal" if key == "normal+critical" else key
        obj = build_signed_object(
            device=self.id,
            key=level,
            nonce=nonce,
            op=op,
            body=body,
            now=now,
            lifetime=lifetime,
        )
        msg = obj.canonical()
        out = {HEADER_AUTH: b64e(msg), HEADER_SIG: b64e(sign_der(self.keys[level], msg))}
        if key == "normal+critical":
            out[HEADER_SIG_CRITICAL] = b64e(sign_der(self.keys["critical"], msg))
        return out

    def pair_body(self, replaces: str | None = None) -> bytes:
        doc: dict[str, Any] = {"name": self.name, "keys": self.pub}
        if replaces:
            doc["replaces"] = replaces
        return json.dumps(doc, ensure_ascii=False).encode()

    def pair_headers(self, code: str, body: bytes) -> dict[str, str]:
        return self.headers(op="pair", key="normal+critical", nonce=code, body=body)

    def check_response(self, nonce: str, status: int, headers: Any, body: bytes) -> None:
        assert self.core_key is not None
        sig = b64d(headers[HEADER_SERVER_SIG])
        message = server_sig_message(nonce=nonce, status=status, body=body)
        assert verify_der(self.core_key, message, sig), "bad X-RH-Server-Sig"

    def check_frame(self, ws_nonce: str, frame: dict[str, Any]) -> dict[str, Any]:
        assert self.core_key is not None
        message = frame_sig_message(
            ws_nonce=ws_nonce, seq=frame["seq"], payload=frame["payload"].encode()
        )
        assert verify_der(self.core_key, message, b64d(frame["sig"])), "bad frame signature"
        payload: dict[str, Any] = json.loads(frame["payload"])
        assert payload["seq"] == frame["seq"]
        return payload
