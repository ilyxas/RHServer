"""Integration: a Python client pairs, gets a challenge and pings a real
`rhcore dev up` (uvicorn, plain HTTP on 127.0.0.1), then opens the WebSocket."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
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


@contextmanager
def run_dev_core(data: Path, *extra: str, ready: Path) -> Iterator[str]:
    """`rhcore dev up` in a subprocess; yields host:port once `ready` exists."""
    port = free_port()
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys; from rh_cli.rhcore import main; sys.exit(main())",
            "dev",
            "up",
            "--data",
            str(data),
            "--port",
            str(port),
            *extra,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        deadline = time.monotonic() + 20
        while not ready.exists():
            assert proc.poll() is None, proc.stdout.read() if proc.stdout else ""
            assert time.monotonic() < deadline, "dev core did not start"
            time.sleep(0.1)
        # admin.sock can appear before uvicorn listens: wait for the port too.
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                assert proc.poll() is None, proc.stdout.read() if proc.stdout else ""
                assert time.monotonic() < deadline, "dev core did not listen"
                time.sleep(0.1)
        yield f"127.0.0.1:{port}"
    finally:
        proc.terminate()
        proc.wait(10)


@pytest.fixture
def dev_core(short_dir: Path) -> Iterator[tuple[str, Path, Path]]:
    pairing = short_dir / "pairing.txt"
    data = short_dir / "data"
    with run_dev_core(data, "--auto-pair", "--pairing-file", str(pairing), ready=pairing) as addr:
        yield addr, pairing, data


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


def test_phone_hanging_up_while_waiting_keeps_the_code(short_dir: Path) -> None:
    """The phone drops /v1/pair before the terminal answers: its request is withdrawn,
    nothing is registered, and the same QR code works on the retry."""
    data = short_dir / "data"
    with run_dev_core(data, ready=data / "admin.sock") as addr:
        admin = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        admin.settimeout(15)
        admin.connect(str(data / "admin.sock"))
        af = admin.makefile("rw", encoding="utf-8")

        def admin_send(msg: dict[str, Any]) -> None:
            af.write(json.dumps(msg) + "\n")
            af.flush()

        def admin_recv() -> dict[str, Any]:
            line = af.readline()
            assert line, "admin socket closed"
            out: dict[str, Any] = json.loads(line)
            return out

        admin_send({"cmd": "pair.start"})
        ps = decode_pairing_string(admin_recv()["string"])
        phone = Phone()
        phone.core_key = b64d(ps.core_key)
        body = phone.pair_body()

        # First attempt: raw HTTP, then hang up while the terminal is asked.
        host, port = addr.split(":")
        raw = socket.create_connection((host, int(port)))
        head = "".join(f"{k}: {v}\r\n" for k, v in phone.pair_headers(ps.code, body).items())
        raw.sendall(
            f"POST /v1/pair HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n{head}\r\n".encode()
            + body
        )
        assert admin_recv()["event"] == "pair.request"
        raw.close()
        assert admin_recv() == {"event": "pair.withdrawn", "device_id": phone.id}

        # Retry with the same code.
        result: dict[str, Any] = {}

        def retry() -> None:
            with httpx.Client(base_url=ps.url, timeout=30) as http:
                result["r"] = http.post(
                    "/v1/pair", headers=phone.pair_headers(ps.code, body), content=body
                )

        t = threading.Thread(target=retry)
        t.start()
        req = admin_recv()
        assert req["event"] == "pair.request"
        admin_send({"cmd": "pair.decide", "accept": True, "fingerprint": phone.fingerprint})
        assert admin_recv() == {"event": "pair.done", "result": "accepted", "device_id": phone.id}
        t.join(30)
        r = result["r"]
        assert r.status_code == 200, r.text
        phone.check_response(ps.code, 200, r.headers, r.content)
        af.close()
        admin.close()

    records = [
        json.loads(x)
        for p in sorted((data / "journal").iterdir())
        for x in p.read_text().splitlines()
    ]
    assert [e["result"] for e in records if e["event"] == "pairing"] == ["withdrawn", "accepted"]
    assert verify(data / "journal") == []
