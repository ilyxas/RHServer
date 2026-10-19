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


class Admin:
    """The terminal side of the admin socket (what `rhcore pair` does)."""

    def __init__(self, data: Path) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(15)
        self.sock.connect(str(data / "admin.sock"))
        self.file = self.sock.makefile("rw", encoding="utf-8")

    def send(self, msg: dict[str, Any]) -> None:
        self.file.write(json.dumps(msg) + "\n")
        self.file.flush()

    def recv(self) -> dict[str, Any]:
        line = self.file.readline()
        assert line, "admin socket closed"
        out: dict[str, Any] = json.loads(line)
        return out

    def close(self) -> None:
        self.file.close()
        self.sock.close()


def journal_results(data: Path) -> list[str]:
    records = [
        json.loads(x)
        for p in sorted((data / "journal").iterdir())
        for x in p.read_text().splitlines()
    ]
    return [e["result"] for e in records if e["event"] == "pairing"]


def send_raw_pair(addr: str, phone: Phone, code: str, body: bytes) -> socket.socket:
    """POST /v1/pair over a bare socket, so the test decides when the phone 'drops'."""
    host, port = addr.split(":")
    raw = socket.create_connection((host, int(port)))
    head = "".join(f"{k}: {v}\r\n" for k, v in phone.pair_headers(code, body).items())
    raw.sendall(
        f"POST /v1/pair HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n{head}\r\n".encode()
        + body
    )
    return raw


def test_phone_hanging_up_while_waiting_keeps_the_code(short_dir: Path) -> None:
    """The phone drops /v1/pair before the terminal answers: its request is withdrawn,
    nothing is registered, and the same QR code works on the retry."""
    data = short_dir / "data"
    with run_dev_core(data, ready=data / "admin.sock") as addr:
        admin = Admin(data)
        admin_send, admin_recv = admin.send, admin.recv
        admin_send({"cmd": "pair.start"})
        ps = decode_pairing_string(admin_recv()["string"])
        phone = Phone()
        phone.core_key = b64d(ps.core_key)
        body = phone.pair_body()

        # First attempt: raw HTTP, then hang up while the terminal is asked.
        raw = send_raw_pair(addr, phone, ps.code, body)
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
        admin.close()

    assert journal_results(data) == ["withdrawn", "accepted"]
    assert verify(data / "journal") == []


def test_retry_takes_over_a_request_the_core_still_waits_on(short_dir: Path) -> None:
    """The first connection is lost without the core noticing (no FIN, e.g. the app
    went to the background): the retry with the same keys replaces it instead of
    getting bad_pair_code, and the terminal is asked again."""
    data = short_dir / "data"
    with run_dev_core(data, ready=data / "admin.sock") as addr:
        admin = Admin(data)
        admin.send({"cmd": "pair.start"})
        ps = decode_pairing_string(admin.recv()["string"])
        phone = Phone()
        phone.core_key = b64d(ps.core_key)
        body = phone.pair_body()

        stale = send_raw_pair(addr, phone, ps.code, body)  # stays open, nobody reads it
        assert admin.recv()["event"] == "pair.request"

        other = Phone()  # other keys while the first request waits: the code is busy
        other.core_key = phone.core_key
        other_body = other.pair_body()
        with httpx.Client(base_url=ps.url, timeout=10) as http:
            r = http.post(
                "/v1/pair", headers=other.pair_headers(ps.code, other_body), content=other_body
            )
        assert r.status_code == 403 and r.json()["error"]["code"] == "bad_pair_code"

        result: dict[str, Any] = {}

        def retry() -> None:
            with httpx.Client(base_url=ps.url, timeout=30) as http:
                result["r"] = http.post(
                    "/v1/pair", headers=phone.pair_headers(ps.code, body), content=body
                )

        t = threading.Thread(target=retry)
        t.start()
        assert admin.recv() == {"event": "pair.withdrawn", "device_id": phone.id}
        assert admin.recv()["event"] == "pair.request"
        admin.send({"cmd": "pair.decide", "accept": True, "fingerprint": phone.fingerprint})
        assert admin.recv() == {"event": "pair.done", "result": "accepted", "device_id": phone.id}
        t.join(30)
        r = result["r"]
        assert r.status_code == 200, r.text
        phone.check_response(ps.code, 200, r.headers, r.content)
        stale.close()
        admin.close()

    assert journal_results(data) == ["rejected", "withdrawn", "accepted"]
    assert verify(data / "journal") == []
