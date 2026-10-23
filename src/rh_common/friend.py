"""Signed messages from the phone to the Friend session (`friend.send`).

Pure functions shared by rh-core, the Friend verifier and the vector generator:
the message body, the envelope the core spools for the bridge, the pointer line
typed into tmux, and the device list the core exports for the verifier.

The verifier trusts none of the transport. It re-checks the phone's signature
over the original request bytes against a device list signed by the core key.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from rh_common.crypto import b64d, b64e, load_public_x963, sha256_hex, sign_der, verify_der
from rh_common.jcs import JCSError, canonicalize, canonicalize_text
from rh_common.protocol import HEADER_AUTH, HEADER_SIG, format_ts

OP_SEND = "friend.send"
RECIPIENT = "Friend"

_MSG_ID_RE = re.compile(r"\A[A-Za-z0-9-]{1,64}\Z")
_SPOOL_ID_RE = re.compile(r"\A[0-9a-f]{32}\Z")
POINTER_RE = re.compile(r"\A⟦rh:([0-9a-f]{32})⟧\Z")


# --- message body -----------------------------------------------------------------


@dataclass(frozen=True)
class FriendMessage:
    to: str
    id: str
    text: str


def parse_body(body: bytes) -> FriendMessage:
    """{"to": "Friend", "id": "<1–64 of A-Za-z0-9->", "text": "<non-empty>"}; nothing else."""
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError("body is not JSON") from e
    if not isinstance(doc, dict) or set(doc) != {"to", "id", "text"}:
        raise ValueError("body must have exactly to, id, text")
    to, msg_id, text = doc["to"], doc["id"], doc["text"]
    if to != RECIPIENT:
        raise ValueError(f'to must be "{RECIPIENT}"')
    if not isinstance(msg_id, str) or not _MSG_ID_RE.match(msg_id):
        raise ValueError("id must be 1–64 characters A-Z, a-z, 0-9 or -")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("text must be a non-empty string")
    return FriendMessage(to=to, id=msg_id, text=text)


# --- envelope and pointer ---------------------------------------------------------------


def spool_id(nonce: str) -> str:
    """Name of the envelope: one per accepted request, since a nonce is used once."""
    return sha256_hex(nonce.encode("utf-8"))[:32]


def pointer(sid: str) -> str:
    """The only text the bridge types into tmux."""
    if not _SPOOL_ID_RE.match(sid):
        raise ValueError("spool id must be 32 lowercase hex")
    return f"⟦rh:{sid}⟧"


@dataclass(frozen=True)
class Envelope:
    """The request exactly as the core received it."""

    auth: str  # X-RH-Auth header value (base64 of the canonical signed object)
    sig: str  # X-RH-Sig header value (base64 DER)
    body: bytes

    def to_json(self) -> bytes:
        doc = {"v": 1, "auth": self.auth, "sig": self.sig, "body": b64e(self.body)}
        return canonicalize(doc)


def envelope_from_headers(headers: Mapping[str, str], body: bytes) -> Envelope:
    return Envelope(auth=headers[HEADER_AUTH], sig=headers[HEADER_SIG], body=body)


def parse_envelope(data: bytes) -> Envelope:
    try:
        doc = json.loads(data)
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError("envelope is not JSON") from e
    if not isinstance(doc, dict) or set(doc) != {"v", "auth", "sig", "body"} or doc["v"] != 1:
        raise ValueError("envelope must be {v: 1, auth, sig, body}")
    if not all(isinstance(doc[k], str) for k in ("auth", "sig", "body")):
        raise ValueError("envelope fields must be strings")
    return Envelope(auth=doc["auth"], sig=doc["sig"], body=b64d(doc["body"]))


# --- device list exported by the core ------------------------------------------------------


@dataclass(frozen=True)
class DeviceEntry:
    id: str
    name: str
    status: str  # active | revoked
    keys: Mapping[str, bytes]  # normal, critical (X9.63)


def build_devices_doc(
    devices: list[DeviceEntry], *, core_key: Any, core_pub: bytes, now: datetime
) -> bytes:
    """{"payload": "<JCS text>", "sig": "<core key over payload bytes>"}.

    The payload names the core key so a verifier can tell which core wrote it, but
    trusts only the core key pinned in its own configuration.
    """
    payload = canonicalize(
        {
            "v": 1,
            "core_key": b64e(core_pub),
            "generated": format_ts(now),
            "devices": [
                {
                    "id": d.id,
                    "name": d.name,
                    "status": d.status,
                    "keys": {level: b64e(d.keys[level]) for level in ("normal", "critical")},
                }
                for d in sorted(devices, key=lambda d: d.id)
            ],
        }
    )
    sig = sign_der(core_key, payload)
    return canonicalize({"payload": payload.decode("utf-8"), "sig": b64e(sig)})


def read_devices_doc(data: bytes, *, core_pub: bytes) -> dict[str, DeviceEntry]:
    """Verify the core signature first, then parse. Raises ValueError with a reason."""
    try:
        outer = json.loads(data)
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError("devices file is not JSON") from e
    if not isinstance(outer, dict) or set(outer) != {"payload", "sig"}:
        raise ValueError("devices file must be {payload, sig}")
    if not isinstance(outer["payload"], str) or not isinstance(outer["sig"], str):
        raise ValueError("devices file fields must be strings")
    payload = outer["payload"].encode("utf-8")
    if not verify_der(core_pub, payload, b64d(outer["sig"])):
        raise ValueError("devices file is not signed by the pinned core key")
    try:
        if canonicalize_text(payload) != payload:
            raise ValueError("devices payload is not canonical JSON")
    except JCSError as e:
        raise ValueError(f"devices payload is not JSON: {e}") from e
    doc = json.loads(payload)
    if doc.get("v") != 1 or doc.get("core_key") != b64e(core_pub):
        raise ValueError("devices payload is for another core or version")
    out: dict[str, DeviceEntry] = {}
    for d in doc.get("devices", []):
        keys = {level: b64d(d["keys"][level]) for level in ("normal", "critical")}
        for k in keys.values():
            load_public_x963(k)
        out[d["id"]] = DeviceEntry(id=d["id"], name=d["name"], status=d["status"], keys=keys)
    return out


__all__ = [
    "OP_SEND",
    "POINTER_RE",
    "RECIPIENT",
    "DeviceEntry",
    "Envelope",
    "FriendMessage",
    "build_devices_doc",
    "envelope_from_headers",
    "parse_body",
    "parse_envelope",
    "pointer",
    "read_devices_doc",
    "spool_id",
]
