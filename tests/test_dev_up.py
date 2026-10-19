"""Integration: a Python client pairs, gets a challenge and pings a real
`rhcore dev up` (uvicorn, plain HTTP on 127.0.0.1), then opens the WebSocket."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from websockets.exceptions import InvalidStatus
from websockets.sync.client import connect

from refclient import Phone
from rh_common.crypto import b64d
from rh_common.protocol import decode_pairing_string
from rh_core.journal import verify


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def dev_core(short_dir: Path) -> Iterator[tuple[str, Path, Path]]:
    port = free_port()
    pairing = short_dir / "pairing.txt"
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys; from rh_cli.rhcore import main; sys.exit(main())",
            "dev",
            "up",
            "--data",
            str(short_dir / "data"),
            "--port",
            str(port),
            "--auto-pair",
            "--pairing-file",
            str(pairing),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.monotonic() + 20
        while not pairing.exists():
            assert proc.poll() is None, proc.stdout.read() if proc.stdout else ""
            assert time.monotonic() < deadline, "dev core did not start"
            time.sleep(0.1)
        yield f"127.0.0.1:{port}", pairing, short_dir / "data"
    finally:
        proc.terminate()
        proc.wait(10)


def test_pair_challenge_ping_ws(dev_core: tuple[str, Path, Path]) -> None:
    addr, pairing, data = dev_core
    ps = decode_pairing_string(pairing.read_text().strip())
    assert ps.url == f"http://{addr}"
    phone = Phone()
    phone.core_key = b64d(ps.core_key)

    with httpx.Client(base_url=ps.url, timeout=10) as http:
        body = phone.pair_body()
        r = http.post("/v1/pair", headers=phone.pair_headers(ps.code, body), content=body)
        assert r.status_code == 200, r.text
        phone.check_response(ps.code, 200, r.headers, r.content)
        assert r.json()["device_id"] == phone.id

        def challenge() -> str:
            ch = http.post("/v1/challenge", json={"device": phone.id})
            assert ch.status_code == 200, ch.text
            nonce: str = ch.json()["nonce"]
            phone.check_response(nonce, 200, ch.headers, ch.content)
            return nonce

        nonce = challenge()
        r = http.post(
            "/v1/ping",
            headers=phone.headers(op="ping", key="normal", nonce=nonce, body=b"{}"),
            content=b"{}",
        )
        assert r.status_code == 200, r.text
        phone.check_response(nonce, 200, r.headers, r.content)

        nonce = challenge()
        headers = phone.headers(op="ws.open", key="normal", nonce=nonce, body=b"")
        with connect(f"ws://{addr}/v1/ws", additional_headers=headers) as ws:
            hello: Any = phone.check_frame(nonce, json.loads(ws.recv(timeout=5)))
            assert hello["type"] == "hello"

        # A refused upgrade still carries a signed error body.
        nonce = challenge()
        bad = phone.headers(op="ping", key="normal", nonce=nonce, body=b"")
        with pytest.raises(InvalidStatus) as exc:
            connect(f"ws://{addr}/v1/ws", additional_headers=bad)
        resp = exc.value.response
        assert resp.status_code == 401
        assert json.loads(resp.body)["error"]["code"] == "op_mismatch"
        phone.check_response(nonce, 401, resp.headers, resp.body)

    assert verify(data / "journal") == []
