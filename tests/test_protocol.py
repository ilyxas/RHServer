from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from rh_common.crypto import (
    b64d,
    b64e,
    b64url_d,
    b64url_e,
    generate_private_key,
    public_x963,
    sign_der,
)
from rh_common.protocol import (
    HEADER_AUTH,
    HEADER_SIG,
    Device,
    NonceRecord,
    ProtocolError,
    build_signed_object,
    decode_pairing_string,
    device_id,
    format_ts,
    parse_auth,
    parse_ts,
    verify_request,
)

NOW = datetime(2026, 10, 19, 12, 0, 0, tzinfo=UTC)


def test_timestamps_round_trip_and_are_strict() -> None:
    assert format_ts(NOW) == "2026-10-19T12:00:00Z"
    assert parse_ts("2026-10-19T12:00:00Z") == NOW
    for bad in (
        "2026-10-19T12:00:00.000Z",
        "2026-10-19T12:00:00+00:00",
        "2026-10-19 12:00:00Z",
        "",
    ):
        with pytest.raises(ValueError):
            parse_ts(bad)


def test_base64_is_strict() -> None:
    assert b64d(b64e(b"\xfb\xff")) == b"\xfb\xff"
    for bad in ("+/8", "-_8=", "AAAA\n", "AB=A"):
        with pytest.raises(ValueError):
            b64d(bad)
    assert b64url_d(b64url_e(b"\xfb\xff")) == b"\xfb\xff"
    with pytest.raises(ValueError):
        b64url_d("-_8=")


def test_parse_auth_rejects_garbage() -> None:
    for header in (None, "", "%%%", b64e(b"[]"), b64e(b'{"v":1}')):
        with pytest.raises(ProtocolError) as e:
            parse_auth(header)
        assert e.value.code == "malformed_auth"


def test_round_trip_with_fresh_keys() -> None:
    normal, critical = generate_private_key(), generate_private_key()
    dev = Device(
        id=device_id(public_x963(normal)),
        name="test",
        keys={"normal": public_x963(normal), "critical": public_x963(critical)},
    )
    n = b64e(b"\x01" * 32)
    obj = build_signed_object(device=dev.id, key="normal", nonce=n, op="ping", body=b"{}", now=NOW)
    headers = {
        HEADER_AUTH: b64e(obj.canonical()),
        HEADER_SIG: b64e(sign_der(normal, obj.canonical())),
    }
    verdict = verify_request(
        headers=headers,
        body=b"{}",
        op="ping",
        key_level="normal",
        now=NOW + timedelta(seconds=1),
        find_device={dev.id: dev}.get,
        find_nonce={n: NonceRecord(device=dev.id, expires=NOW + timedelta(seconds=60))}.get,
    )
    assert verdict.ok and verdict.consume_nonce and verdict.device == dev


def test_pairing_string_type_errors_are_value_errors() -> None:
    from rh_common.jcs import canonicalize

    doc = {"v": 1, "url": "https://a", "core_key": 5, "code": [], "exp": 1}
    with pytest.raises(ValueError):
        decode_pairing_string("rhpair:" + b64url_e(canonicalize(doc)))
