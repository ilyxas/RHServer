"""Stage 1 vectors checked against rh_common, using only what the JSON files say.

The generator also asserts its expectations, but these tests rebuild the state
from the fixture, so a bug shared by generator and verifier still has to agree
with the committed files.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from rh_common.crypto import b64d, load_private_scalar, public_x963, verify_der
from rh_common.protocol import (
    ERROR_STATUS,
    Device,
    NonceRecord,
    PairCode,
    ProtocolError,
    SignedObject,
    decode_pairing_string,
    device_id,
    fingerprint,
    frame_sig_message,
    parse_ts,
    server_sig_message,
    verify_pair,
    verify_request,
)

VECTORS = Path(__file__).parent.parent / "contracts" / "vectors"


def load(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def ids(vs: list[dict[str, Any]]) -> list[str]:
    return [v["name"] for v in vs]


ECDSA = load("ecdsa.json")["vectors"]


@pytest.mark.parametrize("v", ECDSA, ids=ids(ECDSA))
def test_ecdsa(v: dict[str, Any]) -> None:
    ok = verify_der(b64d(v["pub_x963_b64"]), b64d(v["message_b64"]), b64d(v["sig_der_b64"]))
    assert ok is v["valid"]


BUILD = load("request_build.json")["vectors"]


@pytest.mark.parametrize("v", BUILD, ids=ids(BUILD))
def test_request_build(v: dict[str, Any]) -> None:
    from rh_common.protocol import body_hash

    body = b64d(v["body_b64"])
    assert v["device"] == device_id(b64d(v["normal_pub_x963_b64"]))
    assert public_x963(load_private_scalar(b64d(v["priv_scalar_b64"]))) == b64d(v["pub_x963_b64"])
    obj = SignedObject(
        device=v["device"],
        key=v["key"],
        nonce=v["nonce"],
        ts=v["ts"],
        exp=v["exp"],
        op=v["op"],
        body=body_hash(body),
    )
    assert obj.body == v["expected_body_sha256"]
    assert obj.canonical().decode() == v["expected_auth_text"]
    assert obj.canonical() == b64d(v["expected_auth_b64"])
    assert verify_der(b64d(v["pub_x963_b64"]), obj.canonical(), b64d(v["sig_der_b64"]))


SIGNED = load("signed_requests.json")
FIX = SIGNED["fixture"]
NOW = parse_ts(FIX["now"])


def _devices() -> dict[str, Device]:
    return {
        d["id"]: Device(
            id=d["id"],
            name=d["name"],
            status=d["status"],
            keys={level: b64d(k) for level, k in d["keys"].items()},
        )
        for d in FIX["devices"]
    }


def _nonces() -> dict[str, NonceRecord]:
    return {
        n["nonce"]: NonceRecord(device=n["device"], expires=parse_ts(n["expires"]), used=n["used"])
        for n in FIX["nonces"]
    }


def _codes() -> dict[str, PairCode]:
    return {
        c["code"]: PairCode(code=c["code"], expires=parse_ts(c["expires"]), used=c["used"])
        for c in FIX["pair_codes"]
    }


@pytest.mark.parametrize("v", SIGNED["vectors"], ids=ids(SIGNED["vectors"]))
def test_signed_request(v: dict[str, Any]) -> None:
    body = b64d(v["body_b64"])
    ep = v["endpoint"]
    if ep["op"] == "pair":
        try:
            verify_pair(headers=v["headers"], body=body, now=NOW, find_code=_codes().get)
            got = None
        except ProtocolError as e:
            got = e
    else:
        verdict = verify_request(
            headers=v["headers"],
            body=body,
            op=ep["op"],
            key_level=ep["key"],
            now=NOW,
            find_device=_devices().get,
            find_nonce=_nonces().get,
        )
        got = verdict.error
        assert verdict.consume_nonce is v["nonce_consumed"]
    if v["expect"]["result"] == "accept":
        assert got is None
    else:
        assert got is not None
        assert got.code == v["expect"]["code"]
        assert got.status == v["expect"]["status"] == ERROR_STATUS[got.code]


def test_signed_requests_cover_every_request_error_code() -> None:
    covered = {v["expect"].get("code") for v in SIGNED["vectors"]}
    # peer_mismatch (whois), pair_rejected (terminal "n") and bad_request (the body of an
    # operation) are not decided by signatures.
    assert set(ERROR_STATUS) - {"peer_mismatch", "pair_rejected", "bad_request"} <= covered


SERVER = load("server_sig.json")


@pytest.mark.parametrize("v", SERVER["vectors"], ids=ids(SERVER["vectors"]))
def test_server_sig(v: dict[str, Any]) -> None:
    message = server_sig_message(
        nonce=v["request_nonce"], status=v["status"], body=b64d(v["body_b64"])
    )
    assert message.decode() == v["expected_message_text"]
    ok = verify_der(b64d(SERVER["core_pub_x963_b64"]), message, b64d(v["sig_der_b64"]))
    assert ok is v["valid"]


PAIRING = load("pairing.json")


@pytest.mark.parametrize("v", PAIRING["vectors"], ids=ids(PAIRING["vectors"]))
def test_pairing_string(v: dict[str, Any]) -> None:
    if v.get("expect_error"):
        with pytest.raises(ValueError):
            decode_pairing_string(v["string"])
        return
    parsed = decode_pairing_string(v["string"])
    assert {
        "v": 1,
        "url": parsed.url,
        "core_key": parsed.core_key,
        "code": parsed.code,
        "exp": parsed.exp,
    } == v["expected"]
    assert parsed.encode() == v["string"]


@pytest.mark.parametrize("v", PAIRING["fingerprints"], ids=ids(PAIRING["fingerprints"]))
def test_fingerprint(v: dict[str, Any]) -> None:
    assert fingerprint(v["keys"]) == v["expected"]


WS = load("ws_frames.json")


@pytest.mark.parametrize("v", WS["vectors"], ids=ids(WS["vectors"]))
def test_ws_frame(v: dict[str, Any]) -> None:
    f = v["frame"]
    message = frame_sig_message(
        ws_nonce=WS["ws_open_nonce"], seq=f["seq"], payload=f["payload"].encode()
    )
    ok = verify_der(b64d(WS["core_pub_x963_b64"]), message, b64d(f["sig"]))
    ok = ok and json.loads(f["payload"])["seq"] == f["seq"]
    assert ok is v["valid"]


def test_ws_frames_match_events_schema() -> None:
    from jsonschema import Draft202012Validator

    schema = json.loads((VECTORS.parent / "api" / "events.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    frame = Draft202012Validator(schema)
    payload = Draft202012Validator({**schema, "$ref": "#/$defs/Payload"})
    for v in WS["vectors"]:
        frame.validate(v["frame"])
        if v["name"] == "hello":
            payload.validate(json.loads(v["frame"]["payload"]))
