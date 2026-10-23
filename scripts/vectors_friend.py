"""friend.send vectors: request bodies, core acceptance, the signed device list and
the envelopes the Friend verifier must pass or block.

Imported by gen_vectors.py. Keys, devices and nonces are the stage 1 fixture
(vectors_trust); existing vector files are not touched.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import vectors_trust as t
from rh_common.crypto import b64e
from rh_common.friend import (
    OP_SEND,
    DeviceEntry,
    Envelope,
    build_devices_doc,
    parse_body,
    pointer,
    read_devices_doc,
    spool_id,
)
from rh_common.protocol import ERROR_STATUS, HEADER_AUTH, HEADER_SIG, verify_request
from rh_friend.verify import Reject, check_envelope

WINDOW = timedelta(seconds=900)


def body(text: str = "Проверь сборку 🚀", *, to: str = "Friend", msg_id: str = "m-1") -> bytes:
    """The phone's encoding: sorted keys, no spaces, UTF-8 as is."""
    doc = {"id": msg_id, "text": text, "to": to}
    return json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def devices(*, signer: str = "core") -> bytes:
    entries = [
        DeviceEntry(id=d.id, name=d.name, status=d.status, keys=d.keys)
        for d in t.registry().values()
    ]
    return build_devices_doc(entries, core_key=t.key(signer), core_pub=t.pub("core"), now=t.NOW)


def _deterministic_devices(signer: str = "core") -> bytes:
    # build_devices_doc signs with randomized ECDSA; re-sign the payload with RFC 6979
    # so the committed file is stable.
    doc = json.loads(devices(signer=signer))
    payload = doc["payload"].encode("utf-8")
    return json.dumps(
        {"payload": doc["payload"], "sig": b64e(t.sign(signer, payload))},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


# --- core acceptance --------------------------------------------------------------------


def core_cases() -> list[tuple[str, tuple[dict[str, str], bytes], str | None]]:
    return [
        ("send-ok", t._signed(op=OP_SEND, body=body()), None),
        (
            "send-critical-key",
            t._signed(level="critical", op=OP_SEND, body=body()),
            "wrong_key_level",
        ),
        ("send-op-mismatch", t._signed(op="ping", body=body()), "op_mismatch"),
        (
            "send-revoked-device",
            t._signed(p="R", nonce_label="for-R", op=OP_SEND, body=body()),
            "revoked_device",
        ),
        ("send-wrong-recipient", t._signed(op=OP_SEND, body=body(to="RemoteHands")), "bad_request"),
        ("send-empty-text", t._signed(op=OP_SEND, body=body(text="  ")), "bad_request"),
        ("send-bad-id", t._signed(op=OP_SEND, body=body(msg_id="no spaces")), "bad_request"),
        (
            "send-extra-field",
            t._signed(op=OP_SEND, body=b'{"id":"m-1","text":"x","to":"Friend","x":1}'),
            "bad_request",
        ),
        (
            "send-body-changed",
            t._signed(op=OP_SEND, body=body("другое"), signed_body=body()),
            "body_mismatch",
        ),
    ]


def evaluate_core(headers: dict[str, str], raw: bytes) -> str | None:
    devices, nonces = t.registry(), t.nonce_table()
    verdict = verify_request(
        headers=headers,
        body=raw,
        op=OP_SEND,
        key_level="normal",
        now=t.NOW,
        find_device=devices.get,
        find_nonce=nonces.get,
    )
    if verdict.error is not None:
        return verdict.error.code
    try:
        parse_body(raw)
    except ValueError:
        return "bad_request"
    return None


# --- envelopes ---------------------------------------------------------------------------


def _envelope(headers: dict[str, str], raw: bytes) -> Envelope:
    return Envelope(auth=headers[HEADER_AUTH], sig=headers[HEADER_SIG], body=raw)


def envelope_cases() -> list[dict[str, Any]]:
    ok_h, ok_b = t._signed(op=OP_SEND, body=body())
    ok_sid = spool_id(t.nonce("fresh"))
    cases: list[dict[str, Any]] = []

    def add(
        name: str,
        env: Envelope,
        expect: str | None,
        *,
        sid: str = ok_sid,
        devices_doc: str = "valid",
        seen: list[str] | None = None,
        now: str = "now",
    ) -> None:
        cases.append(
            {
                "name": name,
                "id": sid,
                "envelope": env,
                "devices": devices_doc,
                "seen_nonces": seen or [],
                "now": now,
                "expect": expect,
            }
        )

    add("valid", _envelope(ok_h, ok_b), None)
    add(
        "tampered-body",
        Envelope(ok_h[HEADER_AUTH], ok_h[HEADER_SIG], body("подмена")),
        "body_mismatch",
    )
    h, b = t._signed(op="ping", body=body())
    add("wrong-op", _envelope(h, b), "op_mismatch")
    h, b = t._signed(op=OP_SEND, body=body(to="RemoteHands"))
    add("wrong-to", _envelope(h, b), "bad_body")
    h, b = t._signed(level="critical", op=OP_SEND, body=body())
    add("wrong-key-level", _envelope(h, b), "wrong_key_level")
    h, b = t._signed(op=OP_SEND, body=body(), signer="B.normal")
    add("signed-by-other-device", _envelope(h, b), "bad_signature")
    h, b = t._signed(p="R", nonce_label="for-R", op=OP_SEND, body=body())
    add("revoked-device", _envelope(h, b), "revoked_device", sid=spool_id(t.nonce("for-R")))
    h, b = t._signed(p="U", op=OP_SEND, body=body())
    add("unknown-device", _envelope(h, b), "unknown_device")
    add("replayed-nonce", _envelope(ok_h, ok_b), "replayed", seen=[t.nonce("fresh")])
    add("expired", _envelope(ok_h, ok_b), "too_old", now="now+16m")
    add("from-future", _envelope(ok_h, ok_b), "from_future", now="now-5m")
    add("pointer-mismatch", _envelope(ok_h, ok_b), "pointer_mismatch", sid="0" * 32)
    add("devices-bad-signature", _envelope(ok_h, ok_b), "devices_untrusted", devices_doc="tampered")
    add("devices-other-core", _envelope(ok_h, ok_b), "devices_untrusted", devices_doc="other_core")
    return cases


NOWS = {
    "now": t.NOW,
    "now+16m": t.NOW + timedelta(minutes=16),
    "now-5m": t.NOW - timedelta(minutes=5),
}


def devices_docs() -> dict[str, str]:
    valid = _deterministic_devices()
    doc = json.loads(valid)
    tampered = json.dumps(
        {"payload": doc["payload"].replace("Мой iPhone", "Чужой iPhone"), "sig": doc["sig"]},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return {
        "valid": valid.decode("utf-8"),
        "tampered": tampered,
        "other_core": _deterministic_devices("other-core").decode("utf-8"),
    }


def evaluate_envelope(case: dict[str, Any], docs: dict[str, str]) -> str | None:
    try:
        devs = read_devices_doc(docs[case["devices"]].encode("utf-8"), core_pub=t.pub("core"))
    except ValueError:
        return "devices_untrusted"
    try:
        check_envelope(
            case["envelope"],
            sid=case["id"],
            devices=devs,
            now=NOWS[case["now"]],
            window=WINDOW,
            seen=set(case["seen_nonces"]).__contains__,
        )
    except Reject as e:
        return e.code
    return None


def friend_vectors() -> dict[str, Any]:
    build = []
    for name, text in (("ascii", "check the build"), ("unicode", "Проверь сборку 🚀")):
        raw = body(text)
        headers, _ = t._signed(op=OP_SEND, body=raw)
        build.append(
            {
                "name": name,
                "id": "m-1",
                "text": text,
                "expected_body_b64": b64e(raw),
                "expected_body_text": raw.decode("utf-8"),
                "headers": headers,
            }
        )
    core = []
    for name, (headers, raw), code in core_cases():
        got = evaluate_core(headers, raw)
        if got != code:
            raise SystemExit(f"{name}: expected {code}, core says {got}")
        expect: dict[str, Any] = (
            {"result": "accept", "spool_id": spool_id(t.nonce("fresh"))}
            if code is None
            else {"result": "reject", "code": code, "status": ERROR_STATUS[code]}
        )
        core.append({"name": name, "headers": headers, "body_b64": b64e(raw), "expect": expect})
    docs = devices_docs()
    envelopes = []
    for case in envelope_cases():
        got = evaluate_envelope(case, docs)
        if got != case["expect"]:
            raise SystemExit(f"{case['name']}: expected {case['expect']}, verifier says {got}")
        env: Envelope = case["envelope"]
        envelopes.append(
            {
                "name": case["name"],
                "pointer": pointer(case["id"]),
                "envelope": env.to_json().decode("utf-8"),
                "devices": case["devices"],
                "seen_nonces": case["seen_nonces"],
                "now": NOWS[case["now"]].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expect": (
                    {"result": "accept", "text": body_text(env)}
                    if case["expect"] is None
                    else {"result": "block", "code": case["expect"]}
                ),
            }
        )
    return {
        "description": (
            "friend.send. build: the phone's body is JSON with sorted keys and no spaces, "
            '{"id","text","to":"Friend"}, signed with the normal key at POST /v1/friend. '
            "core: requests against signed_requests.json fixture; accept spools the request "
            "as received under spool_id = first 32 hex of sha256(nonce). devices: the core's "
            'signed device list {"payload":"<JCS>","sig":"<core key over payload>"}. '
            "envelopes: what the Friend verifier must pass or block for a pointer "
            f"⟦rh:<spool_id>⟧ at `now` with a {int(WINDOW.total_seconds())} s window "
            "and the listed nonces already seen."
        ),
        "version": 1,
        "core_pub_x963_b64": b64e(t.pub("core")),
        "window_s": int(WINDOW.total_seconds()),
        "build": build,
        "core": core,
        "devices": docs,
        "envelopes": envelopes,
    }


def body_text(env: Envelope) -> str:
    return parse_body(env.body).text


GENERATED = {"friend.json": friend_vectors}
