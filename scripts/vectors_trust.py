"""Stage 1 vectors: signatures, request building, request verification, core
signatures, pairing string, WebSocket frames.

Imported by gen_vectors.py. All keys are fixed test keys derived from labels;
ECDSA signatures use RFC 6979 so the output is reproducible.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from rh_common.crypto import (
    CURVE_ORDER,
    b64d,
    b64e,
    b64url_e,
    load_private_scalar,
    public_x963,
    sign_der,
    verify_der,
)
from rh_common.jcs import canonicalize
from rh_common.protocol import (
    ERROR_STATUS,
    HEADER_AUTH,
    HEADER_SIG,
    HEADER_SIG_CRITICAL,
    Device,
    NonceRecord,
    PairCode,
    PairingString,
    ProtocolError,
    build_signed_object,
    decode_pairing_string,
    device_id,
    fingerprint,
    format_ts,
    frame_sig_message,
    server_sig_message,
    verify_pair,
    verify_request,
)

NOW = datetime(2026, 10, 19, 12, 0, 0, tzinfo=UTC)


# --- test keys -----------------------------------------------------------------


def scalar(label: str) -> bytes:
    n = int.from_bytes(hashlib.sha256(f"rh-test-key:{label}".encode()).digest(), "big")
    return ((n % (CURVE_ORDER - 1)) + 1).to_bytes(32, "big")


def key(label: str) -> ec.EllipticCurvePrivateKey:
    return load_private_scalar(scalar(label))


def pub(label: str) -> bytes:
    return public_x963(key(label))


def sign(label: str, message: bytes) -> bytes:
    return sign_der(key(label), message, deterministic=True)


def nonce(label: str) -> str:
    return b64e(hashlib.sha256(f"rh-test-nonce:{label}".encode()).digest())


def keyset(prefix: str) -> dict[str, bytes]:
    return {level: pub(f"{prefix}.{level}") for level in ("normal", "critical", "ssh")}


def keyset_b64(prefix: str) -> dict[str, str]:
    return {level: b64e(value) for level, value in keyset(prefix).items()}


DEVICES = {
    "A": ("Мой iPhone", "active"),
    "B": ("iPad", "active"),
    "R": ("Old iPhone", "revoked"),
}


def dev_id(prefix: str) -> str:
    return device_id(pub(f"{prefix}.normal"))


def registry() -> dict[str, Device]:
    return {
        dev_id(p): Device(id=dev_id(p), name=name, keys=keyset(p), status=status)  # type: ignore[arg-type]
        for p, (name, status) in DEVICES.items()
    }


NONCES: dict[str, tuple[str, timedelta, bool]] = {
    # label: (device prefix, expires relative to NOW, used)
    "fresh": ("A", timedelta(seconds=30), False),
    "used": ("A", timedelta(seconds=30), True),
    "stale": ("A", timedelta(seconds=-1), False),
    "for-B": ("B", timedelta(seconds=30), False),
    "for-R": ("R", timedelta(seconds=30), False),
}


def nonce_table() -> dict[str, NonceRecord]:
    return {
        nonce(label): NonceRecord(device=dev_id(p), expires=NOW + delta, used=used)
        for label, (p, delta, used) in NONCES.items()
    }


PAIR_CODES: dict[str, tuple[timedelta, bool]] = {
    "pair-fresh": (timedelta(minutes=4), False),
    "pair-used": (timedelta(minutes=4), True),
    "pair-stale": (timedelta(seconds=-1), False),
}


def pair_code_table() -> dict[str, PairCode]:
    return {
        nonce(label): PairCode(code=nonce(label), expires=NOW + delta, used=used)
        for label, (delta, used) in PAIR_CODES.items()
    }


def fixture() -> dict[str, Any]:
    return {
        "now": format_ts(NOW),
        "core_pub_x963_b64": b64e(pub("core")),
        "devices": [
            {
                "id": dev_id(p),
                "name": name,
                "status": status,
                "keys": keyset_b64(p),
                "priv_scalars_b64": {
                    level: b64e(scalar(f"{p}.{level}")) for level in ("normal", "critical", "ssh")
                },
            }
            for p, (name, status) in DEVICES.items()
        ],
        "nonces": [
            {
                "nonce": nonce(label),
                "device": dev_id(p),
                "expires": format_ts(NOW + delta),
                "used": used,
            }
            for label, (p, delta, used) in NONCES.items()
        ],
        "pair_codes": [
            {"code": nonce(label), "expires": format_ts(NOW + delta), "used": used}
            for label, (delta, used) in PAIR_CODES.items()
        ],
    }


# --- ecdsa.json ------------------------------------------------------------------

# A signature made by a real Secure Enclave key on an iPhone (stage 1 acceptance,
# exported from the app's Debug screen): a ping signed object over "{}" with a
# zero nonce. Fixed data, not generated; only the public key is known.
SECURE_ENCLAVE = {
    "pub_x963_b64": (
        "BGbjEA7W0EtbOrd6XZb6fUu7qbhen+YIJIMwP9kiheUqHlj1imbS2xR50nyh1bmGdpCXIVmeXFXpUAe6mZxg8wk="
    ),
    "message_b64": (
        "eyJib2R5IjoiNDQxMzZmYTM1NWIzNjc4YTExNDZhZDE2ZjdlODY0OWU5NGZiNGZjMjFmZTc3ZTgzMTBjMDYwZjYxY2Fh"
        "ZmY4YSIsImRldmljZSI6Ijk0ZjEzYTA0MzIyMWYwNWRiM2YwYjBkYWIwYjE2YTk5IiwiZXhwIjoiMjAyNi0xMC0xOVQw"
        "OTo0Njo0OVoiLCJrZXkiOiJub3JtYWwiLCJub25jZSI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB"
        "QUFBQUFBQUE9Iiwib3AiOiJwaW5nIiwidHMiOiIyMDI2LTEwLTE5VDA5OjQ1OjQ5WiIsInYiOjF9"
    ),
    "sig_der_b64": (
        "MEQCIC1sglu98o5ruwQV6W+dP6FcNGxRxE+WzVY+7uwgZwy+AiA0BxPXjsSFbSzWZtWaMi4RCSu3RVsWakGqCR+eNeYRhQ=="
    ),
}


def secure_enclave_case() -> tuple[bytes, bytes, bytes]:
    public = b64d(SECURE_ENCLAVE["pub_x963_b64"])
    message = b64d(SECURE_ENCLAVE["message_b64"])
    obj = json.loads(message)
    # The app signs the canonical signed object of the protocol, for its own device id.
    assert canonicalize(obj) == message
    assert obj["device"] == device_id(public)
    assert obj["body"] == hashlib.sha256(b"{}").hexdigest()
    return public, message, b64d(SECURE_ENCLAVE["sig_der_b64"])


def ecdsa_vectors() -> dict[str, Any]:
    message = build_signed_object(
        device=dev_id("A"), key="normal", nonce=nonce("fresh"), op="ping", body=b"{}", now=NOW
    ).canonical()
    good = sign("A.normal", message)
    r, s = decode_dss_signature(good)
    high_s = encode_dss_signature(r, CURVE_ORDER - s) if s < CURVE_ORDER // 2 else good
    low_s = encode_dss_signature(r, CURVE_ORDER - s) if s > CURVE_ORDER // 2 else good
    cases = [
        ("valid", pub("A.normal"), message, good, True),
        ("valid-low-s", pub("A.normal"), message, low_s, True),
        ("valid-high-s", pub("A.normal"), message, high_s, True),
        ("message-changed", pub("A.normal"), message.replace(b"ping", b"pong"), good, False),
        ("other-key", pub("B.normal"), message, good, False),
        ("der-truncated", pub("A.normal"), message, good[:-1], False),
        ("der-empty", pub("A.normal"), message, b"", False),
        ("r-s-swapped", pub("A.normal"), message, encode_dss_signature(s, r), False),
        (
            "raw-r-s-not-der",
            pub("A.normal"),
            message,
            r.to_bytes(32, "big") + s.to_bytes(32, "big"),
            False,
        ),
    ]
    se_pub, se_msg, se_sig = secure_enclave_case()
    cases += [
        ("secure-enclave-device", se_pub, se_msg, se_sig, True),
        (
            "secure-enclave-message-changed",
            se_pub,
            se_msg.replace(b"ping", b"pong"),
            se_sig,
            False,
        ),
    ]
    vectors = []
    for name, public, msg, sig, valid in cases:
        assert verify_der(public, msg, sig) is valid, name
        vectors.append(
            {
                "name": name,
                "pub_x963_b64": b64e(public),
                "message_b64": b64e(msg),
                "sig_der_b64": b64e(sig),
                "valid": valid,
            }
        )
    return {
        "description": (
            "ECDSA P-256 / SHA-256, DER signatures over message bytes. "
            "High-S signatures are valid (Security.framework may emit either form)."
        ),
        "version": 1,
        "vectors": vectors,
    }


# --- request_build.json ---------------------------------------------------------------


def request_build_vectors() -> dict[str, Any]:
    cases = [
        ("ping", "A", "normal", "fresh", "ping", b"{}", NOW),
        ("status-get-empty-body", "A", "normal", "fresh", "status", b"", NOW),
        (
            "devices-revoke-critical",
            "A",
            "critical",
            "fresh",
            "devices.revoke",
            json.dumps({"device_id": dev_id("R")}).encode(),
            NOW,
        ),
        (
            "unicode-body",
            "A",
            "normal",
            "fresh",
            "chat.send",
            json.dumps({"text": "Привет, проверь сборку 🚀"}, ensure_ascii=False).encode(),
            NOW + timedelta(seconds=7),
        ),
    ]
    vectors = []
    for name, p, level, nonce_label, op, body, now in cases:
        obj = build_signed_object(
            device=dev_id(p),
            key=level,
            nonce=nonce(nonce_label),
            op=op,
            body=body,
            now=now,  # type: ignore[arg-type]
        )
        auth = obj.canonical()
        sig = sign(f"{p}.{level}", auth)
        vectors.append(
            {
                "name": name,
                "priv_scalar_b64": b64e(scalar(f"{p}.{level}")),
                "pub_x963_b64": b64e(pub(f"{p}.{level}")),
                "normal_pub_x963_b64": b64e(pub(f"{p}.normal")),
                "device": obj.device,
                "key": obj.key,
                "nonce": obj.nonce,
                "ts": obj.ts,
                "exp": obj.exp,
                "op": obj.op,
                "body_b64": b64e(body),
                "expected_body_sha256": obj.body,
                "expected_auth_text": auth.decode("utf-8"),
                "expected_auth_b64": b64e(auth),
                "sig_der_b64": b64e(sig),
            }
        )
    return {
        "description": (
            "Build X-RH-Auth from fields. device = first 32 hex of sha256(normal key). "
            "expected_auth_b64 must match byte for byte; ECDSA is randomized on iOS, so "
            "check your own signature with verify, and sig_der_b64 (RFC 6979) verifies too."
        ),
        "version": 1,
        "vectors": vectors,
    }


# --- signed_requests.json ---------------------------------------------------------------

ENDPOINTS = {
    "ping": ("POST", "/v1/ping", "ping", "normal"),
    "status": ("GET", "/v1/status", "status", "normal"),
    "revoke": ("POST", "/v1/devices/revoke", "devices.revoke", "critical"),
    "pair": ("POST", "/v1/pair", "pair", "normal+critical"),
}


def _signed(
    *,
    p: str = "A",
    level: str = "normal",
    signer: str | None = None,
    nonce_label: str = "fresh",
    op: str = "ping",
    body: bytes = b"{}",
    signed_body: bytes | None = None,
    ts: datetime = NOW,
    lifetime: timedelta = timedelta(seconds=60),
    mutate: Callable[[dict[str, Any]], None] | None = None,
    raw_auth: bytes | None = None,
) -> tuple[dict[str, str], bytes]:
    obj = build_signed_object(
        device=dev_id(p),
        key=level,  # type: ignore[arg-type]
        nonce=nonce(nonce_label),
        op=op,
        body=body if signed_body is None else signed_body,
        now=ts,
        lifetime=lifetime,
    )
    auth = obj.canonical()
    if mutate is not None:
        doc = obj.to_dict()
        mutate(doc)
        auth = canonicalize(doc)
    if raw_auth is not None:
        auth = raw_auth
    sig = sign(signer or f"{p}.{level}", auth)
    return {HEADER_AUTH: b64e(auth), HEADER_SIG: b64e(sig)}, body


def _pair(
    *,
    p: str = "P",
    code_label: str = "pair-fresh",
    op: str = "pair",
    replaces: str | None = None,
    critical_signer: str | None = None,
    device_override: str | None = None,
    signed_body: bytes | None = None,
    drop_critical: bool = False,
) -> tuple[dict[str, str], bytes]:
    doc: dict[str, Any] = {"name": "Мой iPhone", "keys": keyset_b64(p)}
    if replaces:
        doc["replaces"] = replaces
    body = json.dumps(doc, ensure_ascii=False).encode()
    obj = build_signed_object(
        device=device_override or dev_id(p),
        key="normal",
        nonce=nonce(code_label),
        op=op,
        body=body if signed_body is None else signed_body,
        now=NOW,
    )
    auth = obj.canonical()
    headers = {
        HEADER_AUTH: b64e(auth),
        HEADER_SIG: b64e(sign(f"{p}.normal", auth)),
        HEADER_SIG_CRITICAL: b64e(sign(critical_signer or f"{p}.critical", auth)),
    }
    if drop_critical:
        del headers[HEADER_SIG_CRITICAL]
    return headers, body


def _noncanonical(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc, separators=(", ", ": ")).encode()


def signed_request_cases() -> list[tuple[str, str, tuple[dict[str, str], bytes], str | None, bool]]:
    """(name, endpoint, (headers, body), expected code or None, nonce consumed)."""
    revoke_body = json.dumps({"device_id": dev_id("R")}).encode()
    base_obj = build_signed_object(
        device=dev_id("A"), key="normal", nonce=nonce("fresh"), op="ping", body=b"{}", now=NOW
    ).to_dict()
    float_v = canonicalize({**base_obj, "v": 1}).replace(b'"v":1', b'"v":1.0')
    no_sig = _signed()
    del no_sig[0][HEADER_SIG]
    no_auth = _signed()
    del no_auth[0][HEADER_AUTH]
    not_b64 = _signed()
    not_b64[0][HEADER_AUTH] = "not base64!"
    return [
        ("ping-ok", "ping", _signed(), None, True),
        ("status-get-empty-body-ok", "status", _signed(op="status", body=b""), None, True),
        (
            "revoke-critical-ok",
            "revoke",
            _signed(level="critical", op="devices.revoke", body=revoke_body),
            None,
            True,
        ),
        ("clock-ahead-100s-ok", "ping", _signed(ts=NOW + timedelta(seconds=100)), None, True),
        ("clock-behind-50s-ok", "ping", _signed(ts=NOW - timedelta(seconds=50)), None, True),
        ("missing-auth", "ping", no_auth, "malformed_auth", False),
        ("missing-sig", "ping", no_sig, "malformed_auth", False),
        ("auth-not-base64", "ping", not_b64, "malformed_auth", False),
        (
            "auth-not-canonical",
            "ping",
            _signed(raw_auth=_noncanonical(base_obj)),
            "malformed_auth",
            False,
        ),
        ("auth-number-as-double", "ping", _signed(raw_auth=float_v), "malformed_auth", False),
        (
            "auth-extra-field",
            "ping",
            _signed(mutate=lambda d: d.update(extra="x")),
            "malformed_auth",
            False,
        ),
        (
            "auth-ts-with-fraction",
            "ping",
            _signed(mutate=lambda d: d.update(ts=d["ts"].replace("Z", ".000Z"))),
            "malformed_auth",
            False,
        ),
        (
            "auth-lifetime-61s",
            "ping",
            _signed(lifetime=timedelta(seconds=61)),
            "malformed_auth",
            False,
        ),
        (
            "auth-body-uppercase-hex",
            "ping",
            _signed(mutate=lambda d: d.update(body=d["body"].upper())),
            "malformed_auth",
            False,
        ),
        ("unknown-device", "ping", _signed(p="P"), "unknown_device", False),
        ("revoked-device", "ping", _signed(p="R", nonce_label="for-R"), "revoked_device", False),
        ("op-mismatch", "ping", _signed(op="devices.list"), "op_mismatch", False),
        (
            "normal-key-for-critical-op",
            "revoke",
            _signed(level="normal", op="devices.revoke", body=revoke_body),
            "wrong_key_level",
            False,
        ),
        ("critical-key-for-normal-op", "ping", _signed(level="critical"), "wrong_key_level", False),
        ("signed-by-other-device-key", "ping", _signed(signer="B.normal"), "bad_signature", False),
        (
            "signed-by-own-critical-key",
            "ping",
            _signed(signer="A.critical"),
            "bad_signature",
            False,
        ),
        ("nonce-unknown", "ping", _signed(nonce_label="never-issued"), "nonce_unknown", False),
        ("nonce-of-other-device", "ping", _signed(nonce_label="for-B"), "nonce_unknown", False),
        ("nonce-used", "ping", _signed(nonce_label="used"), "nonce_used", False),
        ("nonce-expired", "ping", _signed(nonce_label="stale"), "nonce_expired", True),
        (
            "exp-in-past",
            "ping",
            _signed(ts=NOW - timedelta(seconds=90), lifetime=timedelta(seconds=60)),
            "expired",
            True,
        ),
        ("clock-ahead-150s", "ping", _signed(ts=NOW + timedelta(seconds=150)), "clock_skew", True),
        (
            "body-changed",
            "ping",
            _signed(body=b'{"x":1}', signed_body=b"{}"),
            "body_mismatch",
            True,
        ),
        ("pair-ok", "pair", _pair(), None, False),
        ("pair-ok-replaces", "pair", _pair(replaces=dev_id("A")), None, False),
        ("pair-missing-critical-sig", "pair", _pair(drop_critical=True), "malformed_auth", False),
        (
            "pair-device-not-from-key",
            "pair",
            _pair(device_override=dev_id("A")),
            "malformed_auth",
            False,
        ),
        ("pair-wrong-op", "pair", _pair(op="ping"), "op_mismatch", False),
        ("pair-code-unknown", "pair", _pair(code_label="never-issued"), "bad_pair_code", False),
        ("pair-code-used", "pair", _pair(code_label="pair-used"), "bad_pair_code", False),
        ("pair-code-expired", "pair", _pair(code_label="pair-stale"), "bad_pair_code", False),
        (
            "pair-critical-sig-by-normal-key",
            "pair",
            _pair(critical_signer="P.normal"),
            "bad_signature",
            False,
        ),
        (
            "pair-body-changed",
            "pair",
            _pair(signed_body=b'{"name":"other"}'),
            "body_mismatch",
            False,
        ),
    ]


def evaluate(endpoint: str, headers: dict[str, str], body: bytes) -> tuple[str | None, bool]:
    """Run the reference verifier against the fixture state."""
    _, _, op, level = ENDPOINTS[endpoint]
    if endpoint == "pair":
        codes = pair_code_table()
        try:
            verify_pair(headers=headers, body=body, now=NOW, find_code=codes.get)
        except ProtocolError as e:
            return e.code, False
        return None, False
    devices, nonces = registry(), nonce_table()
    verdict = verify_request(
        headers=headers,
        body=body,
        op=op,
        key_level=level,  # type: ignore[arg-type]
        now=NOW,
        find_device=devices.get,
        find_nonce=nonces.get,
    )
    return (verdict.error.code if verdict.error else None), verdict.consume_nonce


def signed_requests_vectors() -> dict[str, Any]:
    vectors = []
    for name, endpoint, (headers, body), code, consumed in signed_request_cases():
        got, got_consumed = evaluate(endpoint, headers, body)
        if (got, got_consumed) != (code, consumed):
            raise SystemExit(
                f"{name}: expected {code}/{consumed}, verifier says {got}/{got_consumed}"
            )
        method, path, op, level = ENDPOINTS[endpoint]
        expect: dict[str, Any] = (
            {"result": "accept"}
            if code is None
            else {"result": "reject", "code": code, "status": ERROR_STATUS[code]}
        )
        vector: dict[str, Any] = {
            "name": name,
            "endpoint": {"method": method, "path": path, "op": op, "key": level},
            "headers": headers,
            "body_b64": b64e(body),
            "expect": expect,
        }
        if endpoint != "pair":
            vector["nonce_consumed"] = consumed
        vectors.append(vector)
    return {
        "description": (
            "Signed requests the core must accept or reject, evaluated independently "
            "against the fixture state at fixture.now. Checks run in the order: "
            "malformed_auth, unknown_device, revoked_device, op_mismatch, wrong_key_level, "
            "bad_signature, nonce_unknown, nonce_used, nonce_expired, expired, clock_skew, "
            "body_mismatch. nonce_consumed: the core marks the nonce used. Pair requests "
            "use fixture.pair_codes; their device keys are derived from labels P.*."
        ),
        "version": 1,
        "fixture": fixture(),
        "vectors": vectors,
    }


# --- server_sig.json ---------------------------------------------------------------


def server_sig_vectors() -> dict[str, Any]:
    pong = json.dumps({"pong": True, "server_time": format_ts(NOW)}).encode()
    challenge = json.dumps(
        {
            "nonce": nonce("fresh"),
            "expires": format_ts(NOW + timedelta(seconds=60)),
            "server_time": format_ts(NOW),
        }
    ).encode()
    refused = json.dumps(
        {"error": {"code": "revoked_device", "message": "device is revoked"}}
    ).encode()
    unauthorized = json.dumps(
        {"error": {"code": "nonce_used", "message": "nonce was already used"}}
    ).encode()
    paired = json.dumps({"device_id": dev_id("P"), "mac_name": "Mac", "ssh_host_keys": []}).encode()

    def sig(n: str, status: int, body: bytes, signer: str = "core") -> bytes:
        return sign(signer, server_sig_message(nonce=n, status=status, body=body))

    cases = [
        ("ping-200", nonce("fresh"), 200, pong, sig(nonce("fresh"), 200, pong), True),
        (
            "challenge-200-signs-issued-nonce",
            nonce("fresh"),
            200,
            challenge,
            sig(nonce("fresh"), 200, challenge),
            True,
        ),
        ("challenge-403-signs-empty-nonce", "", 403, refused, sig("", 403, refused), True),
        (
            "pair-200-signs-code",
            nonce("pair-fresh"),
            200,
            paired,
            sig(nonce("pair-fresh"), 200, paired),
            True,
        ),
        (
            "rejection-401-is-signed",
            nonce("used"),
            401,
            unauthorized,
            sig(nonce("used"), 401, unauthorized),
            True,
        ),
        ("empty-body-204", nonce("fresh"), 204, b"", sig(nonce("fresh"), 204, b""), True),
        ("status-changed", nonce("fresh"), 200, refused, sig(nonce("fresh"), 403, refused), False),
        (
            "body-changed",
            nonce("fresh"),
            200,
            pong.replace(b"true", b"false"),
            sig(nonce("fresh"), 200, pong),
            False,
        ),
        ("nonce-changed", nonce("used"), 200, pong, sig(nonce("fresh"), 200, pong), False),
        (
            "signed-by-other-key",
            nonce("fresh"),
            200,
            pong,
            sig(nonce("fresh"), 200, pong, "A.normal"),
            False,
        ),
    ]
    vectors = []
    for name, n, status, body, signature, valid in cases:
        message = server_sig_message(nonce=n, status=status, body=body)
        assert verify_der(pub("core"), message, signature) is valid, name
        vectors.append(
            {
                "name": name,
                "request_nonce": n,
                "status": status,
                "body_b64": b64e(body),
                "expected_message_text": message.decode(),
                "sig_der_b64": b64e(signature),
                "valid": valid,
            }
        )
    return {
        "description": (
            "X-RH-Server-Sig: DER signature by the core key over JCS "
            '{"v":1,"nonce":<request nonce>,"status":<HTTP status>,"body":<sha256 hex of body>}. '
            "For /v1/challenge the nonce is the issued one ('' when refused); for /v1/pair "
            "the pairing code. expected_message_text is what you should rebuild."
        ),
        "version": 1,
        "core_pub_x963_b64": b64e(pub("core")),
        "vectors": vectors,
    }


# --- pairing.json -------------------------------------------------------------------


def pairing_vectors() -> dict[str, Any]:
    core = b64e(pub("core"))
    code = nonce("pair-fresh")
    exp = format_ts(NOW + timedelta(minutes=5))

    def raw(doc: dict[str, Any]) -> str:
        return "rhpair:" + b64url_e(canonicalize(doc))

    base = {
        "v": 1,
        "url": "https://mac.tail1234.ts.net:8443",
        "core_key": core,
        "code": code,
        "exp": exp,
    }
    valid = [
        ("production", PairingString(url=base["url"], core_key=core, code=code, exp=exp).encode()),
        (
            "dev",
            PairingString(url="http://127.0.0.1:8787", core_key=core, code=code, exp=exp).encode(),
        ),
    ]
    invalid = [
        ("wrong-prefix", "rhpairing:" + valid[0][1][len("rhpair:") :]),
        ("padded-base64url", valid[0][1] + "="),
        ("standard-base64-alphabet", "rhpair:+" + valid[0][1][8:]),
        ("http-not-local", raw({**base, "url": "http://mac.tail1234.ts.net:8787"})),
        ("url-with-path", raw({**base, "url": base["url"] + "/v1"})),
        ("missing-exp", raw({k: v for k, v in base.items() if k != "exp"})),
        ("extra-field", raw({**base, "name": "mac"})),
        ("version-2", raw({**base, "v": 2})),
        ("short-code", raw({**base, "code": b64e(b"12345678")})),
        ("core-key-compressed", raw({**base, "core_key": b64e(b"\x02" + pub("core")[1:33])})),
    ]
    vectors: list[dict[str, Any]] = []
    for name, text in valid:
        parsed = decode_pairing_string(text)
        vectors.append(
            {
                "name": name,
                "string": text,
                "expected": {
                    "v": 1,
                    "url": parsed.url,
                    "core_key": parsed.core_key,
                    "code": parsed.code,
                    "exp": parsed.exp,
                },
            }
        )
    for name, text in invalid:
        try:
            decode_pairing_string(text)
        except ValueError:
            vectors.append({"name": name, "string": text, "expect_error": True})
        else:
            raise SystemExit(f"pairing {name}: expected an error")
    fingerprints = [
        {"name": f"device-{p}", "keys": keyset_b64(p), "expected": fingerprint(keyset_b64(p))}
        for p in ("A", "P")
    ]
    return {
        "description": (
            'Pairing string: "rhpair:" + base64url without padding of JCS '
            '{"v":1,"url","core_key","code","exp"}. url is https://host[:port], or '
            "http://127.0.0.1:port in dev mode. code is at least 16 random bytes, base64. "
            "fingerprints: first 16 hex of sha256(JCS of the three base64 keys), groups of 4."
        ),
        "version": 1,
        "vectors": vectors,
        "fingerprints": fingerprints,
    }


# --- ws_frames.json -------------------------------------------------------------------


def ws_frame_vectors() -> dict[str, Any]:
    ws_nonce = nonce("fresh")

    def frame(
        seq: int,
        type_: str,
        data: dict[str, Any],
        *,
        sig_seq: int | None = None,
        sig_payload: str | None = None,
        signer: str = "core",
    ) -> dict[str, Any]:
        payload = json.dumps({"seq": seq, "type": type_, "data": data}, ensure_ascii=False)
        signed = sig_payload if sig_payload is not None else payload
        message = frame_sig_message(
            ws_nonce=ws_nonce, seq=sig_seq if sig_seq is not None else seq, payload=signed.encode()
        )
        return {"seq": seq, "payload": payload, "sig": b64e(sign(signer, message))}

    hello = {"device": dev_id("A"), "server_time": format_ts(NOW)}
    cases = [
        ("hello", frame(1, "hello", hello), True),
        (
            "event-with-unicode-and-double",
            frame(2, "status", {"text": "Агент работает", "cpu": 12.5}),
            True,
        ),
        ("seq-changed", {**frame(3, "hello", hello), "seq": 4}, False),
        ("payload-changed", frame(5, "hello", hello, sig_payload='{"seq":5}'), False),
        ("signed-by-other-key", frame(6, "hello", hello, signer="A.normal"), False),
    ]
    vectors = []
    for name, f, valid in cases:
        message = frame_sig_message(ws_nonce=ws_nonce, seq=f["seq"], payload=f["payload"].encode())
        ok = (
            verify_der(pub("core"), message, b64d(f["sig"]))
            and json.loads(f["payload"])["seq"] == f["seq"]
        )
        assert ok is valid, name
        vectors.append({"name": name, "frame": f, "valid": valid})
    return {
        "description": (
            'WebSocket frame: {"seq":n,"payload":"<JSON text>","sig":"<base64 DER>"}. sig is '
            'the core key over JCS {"v":1,"nonce":<ws.open nonce>,"seq":n,"body":<sha256 hex of '
            "payload UTF-8 bytes>}. payload parses to {seq,type,data} and its seq must equal "
            "the frame seq. seq starts at 1 per connection."
        ),
        "version": 1,
        "core_pub_x963_b64": b64e(pub("core")),
        "ws_open_nonce": ws_nonce,
        "vectors": vectors,
    }


GENERATED: dict[str, Callable[[], dict[str, Any]]] = {
    "ecdsa.json": ecdsa_vectors,
    "request_build.json": request_build_vectors,
    "signed_requests.json": signed_requests_vectors,
    "server_sig.json": server_sig_vectors,
    "pairing.json": pairing_vectors,
    "ws_frames.json": ws_frame_vectors,
}
