"""contracts/vectors/signed_requests.json, sent over HTTP to the real app.

The core's registry is seeded from the vector fixture and its clock is frozen at
the fixture's `now`, so each vector must get exactly the status and error code
it names, with a response signed by the core.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from rh_common.crypto import b64d, public_x963, verify_der
from rh_common.protocol import (
    HEADER_SERVER_SIG,
    Device,
    NonceRecord,
    PairCode,
    ProtocolError,
    parse_auth,
    parse_ts,
    server_sig_message,
)
from rh_core.app import Core, create_app
from rh_core.config import dev_config
from rh_core.journal import verify

VECTORS = Path(__file__).parent.parent / "contracts" / "vectors"
SIGNED = json.loads((VECTORS / "signed_requests.json").read_text(encoding="utf-8"))
FIX = SIGNED["fixture"]
NOW = parse_ts(FIX["now"])


def seeded_core(data: Path) -> Core:
    core = Core(dev_config(data), clock=lambda: NOW, ssh_host_keys=str(data / "none-*"))
    for d in FIX["devices"]:
        device = Device(
            id=d["id"],
            name=d["name"],
            status=d["status"],
            keys={level: b64d(k) for level, k in d["keys"].items()},
        )
        core.store.add_device_record(device, now=NOW, peer="local")
    for n in FIX["nonces"]:
        record = NonceRecord(device=n["device"], expires=parse_ts(n["expires"]), used=n["used"])
        core.store.put_nonce(n["nonce"], record)
    return core


@pytest.fixture
def core(short_dir: Path) -> Iterator[Core]:
    c = seeded_core(short_dir)
    yield c
    c.store.close()


def _request_nonce(headers: dict[str, str]) -> str:
    try:
        return parse_auth(headers.get("X-RH-Auth"))[0].nonce
    except ProtocolError:
        return ""


def _open_code_for(core: Core, v: dict[str, Any]) -> None:
    """Pair vectors name a code from the fixture; open a session for the one they use."""
    nonce = _request_nonce(v["headers"])
    for c in FIX["pair_codes"]:
        if c["code"] == nonce:
            core.pairing.open(
                PairCode(code=c["code"], expires=parse_ts(c["expires"]), used=c["used"])
            )
            break
    else:  # unknown code: some other session is open
        core.pairing.open(
            PairCode(
                code=FIX["pair_codes"][0]["code"], expires=parse_ts(FIX["pair_codes"][0]["expires"])
            )
        )
    core.pairing.auto_accept = True


def _send(client: TestClient, v: dict[str, Any]) -> Any:
    ep = v["endpoint"]
    return client.request(
        ep["method"], ep["path"], headers=v["headers"], content=b64d(v["body_b64"])
    )


@pytest.mark.parametrize("v", SIGNED["vectors"], ids=[v["name"] for v in SIGNED["vectors"]])
def test_vector_over_http(core: Core, v: dict[str, Any]) -> None:
    if v["endpoint"]["op"] == "pair":
        _open_code_for(core, v)
    client = TestClient(create_app(core, admin_socket=False))
    r = _send(client, v)
    expect = v["expect"]
    if expect["result"] == "accept":
        assert r.status_code == 200, r.text
    else:
        assert r.status_code == expect["status"], r.text
        assert r.json()["error"]["code"] == expect["code"]

    # Every response, rejections included, is signed over the request nonce.
    nonce = _request_nonce(v["headers"])
    message = server_sig_message(nonce=nonce, status=r.status_code, body=r.content)
    assert verify_der(public_x963(core.key), message, b64d(r.headers[HEADER_SERVER_SIG]))

    # The nonce is spent exactly when the vector says so.
    if "nonce_consumed" in v and nonce:
        record = core.store.nonce(nonce)
        fixture_used = next((n["used"] for n in FIX["nonces"] if n["nonce"] == nonce), None)
        if record is not None and fixture_used is False:
            assert record.used is v["nonce_consumed"]

    # And the journal saw it, with the reason.
    lines = [
        json.loads(line)
        for p in sorted(core.config.journal_dir.iterdir())
        for line in p.read_text().splitlines()
    ]
    events = [e for e in lines if e["event"] in ("request", "pairing")]
    assert events, "request not journaled"
    last = events[-1]
    if expect["result"] == "accept":
        assert last["result"] == "accepted"
    else:
        assert last["result"] == "rejected" and last["reason"] == expect["code"]
    assert verify(core.config.journal_dir) == []


def test_replay_of_accepted_request_is_refused(core: Core) -> None:
    v = next(v for v in SIGNED["vectors"] if v["name"] == "ping-ok")
    client = TestClient(create_app(core, admin_socket=False))
    assert _send(client, v).status_code == 200
    r = _send(client, v)
    assert r.status_code == 401 and r.json()["error"]["code"] == "nonce_used"


def test_pair_ok_replaces_revokes_old_device(core: Core) -> None:
    v = next(v for v in SIGNED["vectors"] if v["name"] == "pair-ok-replaces")
    replaces = json.loads(b64d(v["body_b64"]))["replaces"]
    assert core.store.device(replaces).status == "active"
    _open_code_for(core, v)
    r = _send(TestClient(create_app(core, admin_socket=False)), v)
    assert r.status_code == 200
    assert core.store.device(replaces).status == "revoked"
    assert core.store.device(r.json()["device_id"]).status == "active"


def test_pair_code_spent_after_success(core: Core) -> None:
    v = next(v for v in SIGNED["vectors"] if v["name"] == "pair-ok")
    _open_code_for(core, v)
    client = TestClient(create_app(core, admin_socket=False))
    assert _send(client, v).status_code == 200
    r = _send(client, v)
    assert r.status_code == 403 and r.json()["error"]["code"] == "bad_pair_code"
