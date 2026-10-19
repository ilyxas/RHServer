"""Signed request protocol (SPEC §4.2–4.4).

Pure functions shared by rh-core and the vector generator: building and parsing
the signed object, verifying a request against registry and nonce state, the
core's response and WebSocket frame signatures, the pairing string and the
device fingerprint. Storage and HTTP live in rh_core; this module only decides.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from rh_common.crypto import (
    b64d,
    b64e,
    b64url_d,
    b64url_e,
    load_public_x963,
    sha256_hex,
    verify_der,
)
from rh_common.jcs import JCSError, canonicalize, canonicalize_text

KeyLevel = Literal["normal", "critical"]
KEY_LEVELS: tuple[KeyLevel, ...] = ("normal", "critical")

PROTOCOL_VERSION = 1
MAX_LIFETIME = timedelta(seconds=60)  # exp - ts
MAX_CLOCK_SKEW = timedelta(seconds=120)
NONCE_TTL = timedelta(seconds=60)
PAIR_CODE_TTL = timedelta(minutes=5)
PAIRING_PREFIX = "rhpair:"

HEADER_AUTH = "X-RH-Auth"
HEADER_SIG = "X-RH-Sig"
HEADER_SIG_CRITICAL = "X-RH-Sig-Critical"
HEADER_SERVER_SIG = "X-RH-Server-Sig"

# HTTP status for each rejection code. 400: the request is not well formed;
# 401: well formed but not authentic or not fresh; 403: the device or pairing
# itself is refused.
ERROR_STATUS: dict[str, int] = {
    "malformed_auth": 400,
    "op_mismatch": 401,
    "wrong_key_level": 401,
    "bad_signature": 401,
    "nonce_unknown": 401,
    "nonce_used": 401,
    "nonce_expired": 401,
    "expired": 401,
    "clock_skew": 401,
    "body_mismatch": 401,
    "unknown_device": 403,
    "revoked_device": 403,
    "peer_mismatch": 403,
    "bad_pair_code": 403,
    "pair_rejected": 403,
}

_TS_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
_AUTH_FIELDS = {"v", "device", "key", "nonce", "ts", "exp", "op", "body"}
_HEX64_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_DEVICE_RE = re.compile(r"\A[0-9a-f]{32}\Z")


class ProtocolError(ValueError):
    """A rejection with a machine readable code (contracts ErrorCode)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message

    @property
    def status(self) -> int:
        return ERROR_STATUS[self.code]


# --- time -------------------------------------------------------------------


def format_ts(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(text: str) -> datetime:
    if not _TS_RE.match(text):
        raise ValueError(f"timestamp must be YYYY-MM-DDTHH:MM:SSZ: {text!r}")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


# --- identities ---------------------------------------------------------------


def device_id(normal_pub_x963: bytes) -> str:
    """First 32 hex characters of sha256 of the `normal` public key."""
    return sha256_hex(normal_pub_x963)[:32]


def fingerprint(keys: Mapping[str, str]) -> str:
    """Device fingerprint shown in the terminal and on the phone during pairing.

    keys: base64 X9.63 public keys `normal`, `critical`, `ssh`.
    Result: first 16 hex of sha256(JCS of the three keys), groups of 4 by spaces.
    """
    doc = {name: keys[name] for name in ("normal", "critical", "ssh")}
    digest = sha256_hex(canonicalize(doc))[:16]
    return " ".join(digest[i : i + 4] for i in range(0, 16, 4))


def body_hash(body: bytes) -> str:
    return sha256_hex(body)


# --- signed object ------------------------------------------------------------


@dataclass(frozen=True)
class SignedObject:
    device: str
    key: KeyLevel
    nonce: str
    ts: str
    exp: str
    op: str
    body: str
    v: int = PROTOCOL_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "v": self.v,
            "device": self.device,
            "key": self.key,
            "nonce": self.nonce,
            "ts": self.ts,
            "exp": self.exp,
            "op": self.op,
            "body": self.body,
        }

    def canonical(self) -> bytes:
        return canonicalize(self.to_dict())


def build_signed_object(
    *,
    device: str,
    key: KeyLevel,
    nonce: str,
    op: str,
    body: bytes,
    now: datetime,
    lifetime: timedelta = MAX_LIFETIME,
) -> SignedObject:
    return SignedObject(
        device=device,
        key=key,
        nonce=nonce,
        ts=format_ts(now),
        exp=format_ts(now + lifetime),
        op=op,
        body=body_hash(body),
    )


def parse_auth(header: str | None) -> tuple[SignedObject, bytes]:
    """Decode X-RH-Auth; return the object and the exact bytes that were signed.

    Only the canonical encoding is accepted, so two different byte strings can
    never carry the same signed meaning.
    """
    if not header:
        raise ProtocolError("malformed_auth", f"missing {HEADER_AUTH}")
    try:
        raw = b64d(header)
    except ValueError as e:
        raise ProtocolError("malformed_auth", f"{HEADER_AUTH} is not base64") from e
    try:
        canonical = canonicalize_text(raw)
    except (JCSError, UnicodeDecodeError) as e:
        raise ProtocolError("malformed_auth", f"{HEADER_AUTH} is not JSON: {e}") from e
    if canonical != raw:
        raise ProtocolError("malformed_auth", f"{HEADER_AUTH} is not canonical JSON (RFC 8785)")
    doc = json.loads(raw)
    if not isinstance(doc, dict) or set(doc) != _AUTH_FIELDS:
        raise ProtocolError(
            "malformed_auth", f"signed object must have fields {sorted(_AUTH_FIELDS)}"
        )
    if type(doc["v"]) is not int or doc["v"] != PROTOCOL_VERSION:
        raise ProtocolError("malformed_auth", "unsupported protocol version")
    for name in _AUTH_FIELDS - {"v"}:
        if not isinstance(doc[name], str):
            raise ProtocolError("malformed_auth", f"field {name} must be a string")
    if doc["key"] not in KEY_LEVELS:
        raise ProtocolError("malformed_auth", f"unknown key level {doc['key']!r}")
    if not _HEX64_RE.match(doc["body"]):
        raise ProtocolError("malformed_auth", "body must be lowercase hex sha256")
    try:
        ts, exp = parse_ts(doc["ts"]), parse_ts(doc["exp"])
    except ValueError as e:
        raise ProtocolError("malformed_auth", str(e)) from e
    if not timedelta(0) < exp - ts <= MAX_LIFETIME:
        raise ProtocolError("malformed_auth", "exp must be after ts and at most 60 s later")
    obj = SignedObject(
        device=doc["device"],
        key=doc["key"],
        nonce=doc["nonce"],
        ts=doc["ts"],
        exp=doc["exp"],
        op=doc["op"],
        body=doc["body"],
    )
    return obj, raw


def _decode_sig(header: str | None, name: str) -> bytes:
    if not header:
        raise ProtocolError("malformed_auth", f"missing {name}")
    try:
        return b64d(header)
    except ValueError as e:
        raise ProtocolError("malformed_auth", f"{name} is not base64") from e


# --- verification ---------------------------------------------------------------


@dataclass(frozen=True)
class Device:
    id: str
    name: str
    keys: Mapping[str, bytes]  # level -> X9.63 public key; also "ssh"
    status: Literal["active", "revoked"] = "active"


@dataclass(frozen=True)
class NonceRecord:
    device: str
    expires: datetime
    used: bool = False


@dataclass(frozen=True)
class Verdict:
    """Outcome of verify_request.

    consume_nonce is True once the signature is valid and the nonce is a known,
    unused one for this device: the caller marks it used even if a later check
    (expiry, clock, body) fails, so a valid signature can never be replayed.
    """

    obj: SignedObject | None
    device: Device | None
    error: ProtocolError | None
    consume_nonce: bool

    @property
    def ok(self) -> bool:
        return self.error is None


def verify_request(
    *,
    headers: Mapping[str, str],
    body: bytes,
    op: str,
    key_level: KeyLevel,
    now: datetime,
    find_device: Callable[[str], Device | None],
    find_nonce: Callable[[str], NonceRecord | None],
) -> Verdict:
    """Check one signed request. Order of checks is part of the contract:

    malformed_auth → unknown_device → revoked_device → op_mismatch →
    wrong_key_level → bad_signature → nonce_unknown → nonce_used →
    nonce_expired → expired → clock_skew → body_mismatch
    """
    device: Device | None = None
    obj: SignedObject | None = None
    consume = False
    try:
        obj, raw = parse_auth(headers.get(HEADER_AUTH))
        sig = _decode_sig(headers.get(HEADER_SIG), HEADER_SIG)
        device = find_device(obj.device)
        if device is None:
            raise ProtocolError("unknown_device", f"device {obj.device} is not paired")
        if device.status != "active":
            raise ProtocolError("revoked_device", f"device {obj.device} is revoked")
        if obj.op != op:
            raise ProtocolError("op_mismatch", f"signed op {obj.op!r}, endpoint expects {op!r}")
        if obj.key != key_level:
            raise ProtocolError("wrong_key_level", f"{op} requires the {key_level} key")
        if not verify_der(device.keys[key_level], raw, sig):
            raise ProtocolError("bad_signature", f"signature does not match the {key_level} key")
        record = find_nonce(obj.nonce)
        if record is None or record.device != device.id:
            raise ProtocolError("nonce_unknown", "nonce was not issued to this device")
        if record.used:
            raise ProtocolError("nonce_used", "nonce was already used")
        consume = True
        if now > record.expires:
            raise ProtocolError("nonce_expired", "nonce expired")
        _check_freshness(obj, now)
        if body_hash(body) != obj.body:
            raise ProtocolError("body_mismatch", "body hash does not match the signed object")
    except ProtocolError as e:
        return Verdict(obj=obj, device=device, error=e, consume_nonce=consume)
    return Verdict(obj=obj, device=device, error=None, consume_nonce=True)


def _check_freshness(obj: SignedObject, now: datetime) -> None:
    if now > parse_ts(obj.exp):
        raise ProtocolError("expired", "exp is in the past")
    if abs(now - parse_ts(obj.ts)) > MAX_CLOCK_SKEW:
        raise ProtocolError("clock_skew", "clock differs from the core by more than 120 s")


# --- pairing --------------------------------------------------------------------


@dataclass(frozen=True)
class PairCode:
    code: str  # base64, carried as the nonce of the pair request
    expires: datetime
    used: bool = False


@dataclass(frozen=True)
class PairRequest:
    obj: SignedObject
    name: str
    keys: dict[str, bytes]  # normal, critical, ssh
    keys_b64: dict[str, str]
    replaces: str | None


def verify_pair(
    *,
    headers: Mapping[str, str],
    body: bytes,
    now: datetime,
    find_code: Callable[[str], PairCode | None],
) -> PairRequest:
    """Check a pair request. It is signed by both new keys over one object.

    Order: malformed_auth → op_mismatch → bad_pair_code → bad_signature →
    expired → clock_skew → body_mismatch. The device id must equal
    device_id(normal key) from the body.
    """
    obj, raw = parse_auth(headers.get(HEADER_AUTH))
    sig_normal = _decode_sig(headers.get(HEADER_SIG), HEADER_SIG)
    sig_critical = _decode_sig(headers.get(HEADER_SIG_CRITICAL), HEADER_SIG_CRITICAL)
    if obj.op != "pair":
        raise ProtocolError("op_mismatch", f"signed op {obj.op!r}, endpoint expects 'pair'")
    if obj.key != "normal":
        raise ProtocolError("malformed_auth", "pair object must name the normal key")
    req = _parse_pair_body(body, obj)
    code = find_code(obj.nonce)
    if code is None or code.used or now > code.expires:
        raise ProtocolError("bad_pair_code", "pairing code is unknown, used or expired")
    if not verify_der(req.keys["normal"], raw, sig_normal):
        raise ProtocolError("bad_signature", "normal signature does not match")
    if not verify_der(req.keys["critical"], raw, sig_critical):
        raise ProtocolError("bad_signature", "critical signature does not match")
    _check_freshness(obj, now)
    if body_hash(body) != obj.body:
        raise ProtocolError("body_mismatch", "body hash does not match the signed object")
    return req


def _parse_pair_body(body: bytes, obj: SignedObject) -> PairRequest:
    try:
        doc = json.loads(body)
    except ValueError as e:
        raise ProtocolError("malformed_auth", "pair body is not JSON") from e
    allowed = {"name", "keys", "replaces"}
    if not isinstance(doc, dict) or not {"name", "keys"} <= set(doc) <= allowed:
        raise ProtocolError(
            "malformed_auth", "pair body must have name, keys and optional replaces"
        )
    name, keys, replaces = doc["name"], doc["keys"], doc.get("replaces")
    if not isinstance(name, str) or not 0 < len(name) <= 64:
        raise ProtocolError("malformed_auth", "name must be a string of 1–64 characters")
    if not isinstance(keys, dict) or set(keys) != {"normal", "critical", "ssh"}:
        raise ProtocolError("malformed_auth", "keys must be exactly normal, critical, ssh")
    if replaces is not None and not (isinstance(replaces, str) and _DEVICE_RE.match(replaces)):
        raise ProtocolError("malformed_auth", "replaces must be a device id")
    decoded: dict[str, bytes] = {}
    for level, value in keys.items():
        try:
            decoded[level] = b64d(value)
            load_public_x963(decoded[level])
        except (ValueError, TypeError) as e:
            raise ProtocolError("malformed_auth", f"keys.{level} is not a P-256 X9.63 key") from e
    if obj.device != device_id(decoded["normal"]):
        raise ProtocolError("malformed_auth", "device must be device_id(keys.normal)")
    return PairRequest(obj=obj, name=name, keys=decoded, keys_b64=dict(keys), replaces=replaces)


@dataclass(frozen=True)
class PairingString:
    url: str
    core_key: str  # base64 X9.63
    code: str  # base64
    exp: str

    def encode(self) -> str:
        doc = {
            "v": 1,
            "url": self.url,
            "core_key": self.core_key,
            "code": self.code,
            "exp": self.exp,
        }
        return PAIRING_PREFIX + b64url_e(canonicalize(doc))


def decode_pairing_string(text: str) -> PairingString:
    """Parse the QR / clipboard pairing string. Raises ValueError with a reason."""
    if not text.startswith(PAIRING_PREFIX):
        raise ValueError(f"must start with {PAIRING_PREFIX}")
    raw = b64url_d(text[len(PAIRING_PREFIX) :])
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise ValueError("payload is not JSON") from e
    if not isinstance(doc, dict) or set(doc) != {"v", "url", "core_key", "code", "exp"}:
        raise ValueError("payload must have exactly v, url, core_key, code, exp")
    if type(doc["v"]) is not int or doc["v"] != 1:
        raise ValueError("unsupported version")
    url = doc["url"]
    if not isinstance(url, str) or not re.match(
        r"\A(https://[^/?#\s]+|http://127\.0\.0\.1:\d+)\Z", url
    ):
        raise ValueError("url must be https://host[:port] or http://127.0.0.1:port")
    for name in ("core_key", "code", "exp"):
        if not isinstance(doc[name], str):
            raise ValueError(f"{name} must be a string")
    load_public_x963(b64d(doc["core_key"]))
    if len(b64d(doc["code"])) < 16:
        raise ValueError("code must be at least 16 random bytes")
    parse_ts(doc["exp"])
    return PairingString(url=url, core_key=doc["core_key"], code=doc["code"], exp=doc["exp"])


# --- core signatures ----------------------------------------------------------------


def server_sig_message(*, nonce: str, status: int, body: bytes) -> bytes:
    """Bytes the core signs for X-RH-Server-Sig.

    nonce: the request's nonce; for /v1/challenge the issued nonce (or "" when
    the challenge is refused); for /v1/pair the pairing code.
    """
    return canonicalize({"v": 1, "nonce": nonce, "status": status, "body": body_hash(body)})


def frame_sig_message(*, ws_nonce: str, seq: int, payload: bytes) -> bytes:
    """Bytes the core signs for one WebSocket frame.

    A frame is {"seq": n, "payload": "<JSON text>", "sig": "<base64 DER>"}; payload
    is hashed as raw UTF-8 bytes, so the client never re-canonicalizes event data.
    """
    return canonicalize({"v": 1, "nonce": ws_nonce, "seq": seq, "body": body_hash(payload)})


__all__ = [
    "ERROR_STATUS",
    "HEADER_AUTH",
    "HEADER_SERVER_SIG",
    "HEADER_SIG",
    "HEADER_SIG_CRITICAL",
    "KEY_LEVELS",
    "MAX_CLOCK_SKEW",
    "MAX_LIFETIME",
    "NONCE_TTL",
    "PAIR_CODE_TTL",
    "Device",
    "KeyLevel",
    "NonceRecord",
    "PairCode",
    "PairRequest",
    "PairingString",
    "ProtocolError",
    "SignedObject",
    "Verdict",
    "b64e",
    "body_hash",
    "build_signed_object",
    "decode_pairing_string",
    "device_id",
    "fingerprint",
    "format_ts",
    "frame_sig_message",
    "parse_auth",
    "parse_ts",
    "server_sig_message",
    "verify_pair",
    "verify_request",
]
