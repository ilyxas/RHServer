"""rh-core end to end in-process: pairing over the admin socket, challenge,
signed requests, devices, WebSocket, revocation, peer check."""

from __future__ import annotations

import io
import json
import socket
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from refclient import Phone
from rh_cli import rhcore
from rh_common.crypto import b64d
from rh_common.protocol import decode_pairing_string
from rh_core.app import WS_CLOSE_REVOKED, Core, create_app
from rh_core.config import dev_config
from rh_core.journal import verify


class Clock:
    def __init__(self) -> None:
        self.offset = timedelta()

    def __call__(self) -> datetime:
        return datetime.now(UTC).replace(microsecond=0) + self.offset


class Peers:
    def __init__(self) -> None:
        self.node_id: str | None = "local"

    def node(self, host: str, port: int) -> str | None:
        return self.node_id


class Admin:
    """The terminal side of `rhcore pair`, speaking raw JSON Lines."""

    def __init__(self, path: Path) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect(str(path))
        self.f = self.sock.makefile("rw", encoding="utf-8")

    def send(self, msg: dict[str, Any]) -> None:
        self.f.write(json.dumps(msg) + "\n")
        self.f.flush()

    def recv(self) -> dict[str, Any]:
        line = self.f.readline()
        assert line, "admin socket closed"
        return json.loads(line)

    def close(self) -> None:
        self.f.close()
        self.sock.close()


@pytest.fixture
def env(short_dir: Path) -> Iterator[tuple[Core, TestClient, Clock, Peers]]:
    clock, peers = Clock(), Peers()
    ssh = short_dir / "ssh"
    ssh.mkdir()
    (ssh / "ssh_host_ed25519_key.pub").write_text("ssh-ed25519 AAAAtest root@mac\n")
    core = Core(
        dev_config(short_dir / "data"), clock=clock, peers=peers, ssh_host_keys=str(ssh / "*.pub")
    )
    with TestClient(create_app(core)) as client:
        yield core, client, clock, peers
    core.store.close()


def start_pair(core: Core) -> tuple[Admin, str]:
    admin = Admin(core.config.admin_socket)
    admin.send({"cmd": "pair.start"})
    msg = admin.recv()
    assert msg["event"] == "pair.code"
    return admin, msg["string"]


def send_pair(client: TestClient, phone: Phone, string: str, replaces: str | None = None) -> Any:
    ps = decode_pairing_string(string)
    phone.core_key = b64d(ps.core_key)
    body = phone.pair_body(replaces)
    result: dict[str, Any] = {}

    def run() -> None:
        result["r"] = client.post(
            "/v1/pair", headers=phone.pair_headers(ps.code, body), content=body
        )

    t = threading.Thread(target=run)
    t.start()
    result["thread"] = t
    result["code"] = ps.code
    return result


def finish(pending: dict[str, Any]) -> Any:
    pending["thread"].join(10)
    return pending["r"]


def pair(
    core: Core, client: TestClient, phone: Phone, replaces: str | None = None
) -> dict[str, Any]:
    admin, string = start_pair(core)
    pending = send_pair(client, phone, string, replaces)
    req = admin.recv()
    assert req["event"] == "pair.request"
    admin.send({"cmd": "pair.decide", "accept": True})
    done = admin.recv()
    admin.close()
    r = finish(pending)
    assert r.status_code == 200, r.text
    phone.check_response(pending["code"], 200, r.headers, r.content)
    return {"request": req, "done": done, "response": r.json()}


def signed(
    client: TestClient, phone: Phone, method: str, path: str, op: str, key: str, body: bytes = b""
) -> Any:
    ch = client.post("/v1/challenge", json={"device": phone.id})
    assert ch.status_code == 200, ch.text
    nonce = ch.json()["nonce"]
    phone.check_response(nonce, 200, ch.headers, ch.content)
    r = client.request(
        method, path, headers=phone.headers(op=op, key=key, nonce=nonce, body=body), content=body
    )
    phone.check_response(nonce, r.status_code, r.headers, r.content)
    return r


def ping(client: TestClient, phone: Phone) -> Any:
    return signed(client, phone, "POST", "/v1/ping", "ping", "normal", b"{}")


def test_pair_then_ping(env: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    out = pair(core, client, phone)
    assert out["request"]["fingerprint"] == phone.fingerprint
    assert out["request"]["revokes"] == []
    assert out["done"] == {"event": "pair.done", "result": "accepted", "device_id": phone.id}
    assert out["response"] == {
        "device_id": phone.id,
        "mac_name": core.config.mac_name,
        "ssh_host_keys": ["ssh-ed25519 AAAAtest root@mac"],
    }
    r = ping(client, phone)
    assert r.status_code == 200 and r.json()["pong"] is True

    st = signed(client, phone, "GET", "/v1/status", "status", "normal")
    assert st.json()["mode"] == "dev" and st.json()["agent_version"] is None

    devs = signed(client, phone, "GET", "/v1/devices", "devices.list", "normal").json()["devices"]
    assert [(d["id"], d["current"], d["fingerprint"]) for d in devs] == [
        (phone.id, True, phone.fingerprint)
    ]
    assert verify(core.config.journal_dir) == []


def test_declined_in_terminal(env: Any) -> None:
    core, client, _, _ = env
    admin, string = start_pair(core)
    pending = send_pair(client, Phone(), string)
    assert admin.recv()["event"] == "pair.request"
    admin.send({"cmd": "pair.decide", "accept": False})
    assert admin.recv() == {"event": "pair.done", "result": "rejected"}
    r = finish(pending)
    assert r.status_code == 403 and r.json()["error"]["code"] == "pair_rejected"
    assert core.store.devices() == []


def test_terminal_closed_cancels(env: Any) -> None:
    core, client, _, _ = env
    admin, string = start_pair(core)
    admin.close()
    phone = Phone()
    ps = decode_pairing_string(string)
    for _ in range(50):  # the core notices the closed terminal asynchronously
        if core.pairing.current() is None:
            break
        threading.Event().wait(0.05)
    body = phone.pair_body()
    r = client.post("/v1/pair", headers=phone.pair_headers(ps.code, body), content=body)
    assert r.json()["error"]["code"] == "bad_pair_code"


def test_code_expires(env: Any) -> None:
    core, client, clock, _ = env
    clock.offset = timedelta(minutes=-5, seconds=-1)  # the code is issued "5 minutes ago"
    admin, string = start_pair(core)
    clock.offset = timedelta()
    assert admin.recv() == {"event": "pair.done", "result": "expired"}
    admin.close()
    phone = Phone()
    body = phone.pair_body()
    r = client.post(
        "/v1/pair",
        headers=phone.pair_headers(decode_pairing_string(string).code, body),
        content=body,
    )
    assert r.json()["error"]["code"] == "bad_pair_code"


def test_new_pair_cancels_previous(env: Any) -> None:
    core, _, _, _ = env
    first, _ = start_pair(core)
    second, _ = start_pair(core)
    assert first.recv() == {"event": "pair.done", "result": "cancelled"}
    first.close()
    second.close()


def test_repair_same_name_revokes_old(env: Any) -> None:
    core, client, _, _ = env
    old, other = Phone(), Phone(name="iPad")
    pair(core, client, old)
    pair(core, client, other)
    new = Phone()
    out = pair(core, client, new)
    assert out["request"]["revokes"] == [{"id": old.id, "name": old.name}]
    assert core.store.device(old.id).status == "revoked"
    assert core.store.device(other.id).status == "active"
    r = client.post("/v1/challenge", json={"device": old.id})
    assert r.status_code == 403 and r.json()["error"]["code"] == "revoked_device"


def test_replaces_revokes_only_named_device(env: Any) -> None:
    core, client, _, _ = env
    a, b = Phone(name="iPhone"), Phone(name="iPhone старый")
    pair(core, client, a)
    pair(core, client, b)
    new = Phone(name="iPhone")
    out = pair(core, client, new, replaces=b.id)
    assert out["request"]["revokes"] == [{"id": b.id, "name": b.name}]
    assert core.store.device(b.id).status == "revoked"
    assert core.store.device(a.id).status == "active"


def test_same_keys_cannot_pair_twice(env: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    admin, string = start_pair(core)
    r = finish(send_pair(client, phone, string))
    assert r.status_code == 403 and r.json()["error"]["code"] == "pair_rejected"
    admin.close()


def test_peer_mismatch(env: Any) -> None:
    core, client, _, peers = env
    phone = Phone()
    pair(core, client, phone)
    peers.node_id = "other-node"
    r = ping(client, phone)
    assert r.status_code == 403 and r.json()["error"]["code"] == "peer_mismatch"
    peers.node_id = None  # whois failed: refuse too
    assert ping(client, phone).json()["error"]["code"] == "peer_mismatch"
    lines = [
        json.loads(x) for p in core.config.journal_dir.iterdir() for x in p.read_text().splitlines()
    ]
    assert any(e.get("reason") == "peer_mismatch" for e in lines)


def test_pair_refused_without_peer(env: Any) -> None:
    core, client, _, peers = env
    peers.node_id = None
    admin, string = start_pair(core)
    r = finish(send_pair(client, Phone(), string))
    assert r.status_code == 403 and r.json()["error"]["code"] == "peer_mismatch"
    admin.close()


def test_revoke_with_critical_key(env: Any) -> None:
    core, client, _, _ = env
    phone, ipad = Phone(), Phone(name="iPad")
    pair(core, client, phone)
    pair(core, client, ipad)
    body = json.dumps({"device_id": ipad.id}).encode()
    r = signed(client, phone, "POST", "/v1/devices/revoke", "devices.revoke", "critical", body)
    assert r.status_code == 200 and r.json() == {"device_id": ipad.id, "status": "revoked"}
    missing = json.dumps({"device_id": "0" * 32}).encode()
    r = signed(client, phone, "POST", "/v1/devices/revoke", "devices.revoke", "critical", missing)
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"


def ws_headers(client: TestClient, phone: Phone) -> tuple[str, dict[str, str]]:
    nonce = client.post("/v1/challenge", json={"device": phone.id}).json()["nonce"]
    return nonce, phone.headers(op="ws.open", key="normal", nonce=nonce, body=b"")


def test_websocket_hello_and_close_on_revoke(env: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    nonce, headers = ws_headers(client, phone)
    with client.websocket_connect("/v1/ws", headers=headers) as ws:
        hello = phone.check_frame(nonce, ws.receive_json())
        assert hello["type"] == "hello" and hello["seq"] == 1
        assert hello["data"]["device"] == phone.id
        admin = Admin(core.config.admin_socket)
        admin.send({"cmd": "devices.revoke", "device_id": phone.id})
        assert admin.recv() == {"ok": True, "device_id": phone.id, "status": "revoked"}
        admin.close()
        with pytest.raises(WebSocketDisconnect) as exc:
            ws.receive_json()
        assert exc.value.code == WS_CLOSE_REVOKED


def test_websocket_refused_with_signed_denial(env: Any) -> None:
    from starlette.testclient import WebSocketDenialResponse

    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    nonce, headers = ws_headers(client, phone)
    headers["X-RH-Sig"] = Phone().headers(op="ws.open", key="normal", nonce=nonce, body=b"")[
        "X-RH-Sig"
    ]
    with (
        pytest.raises(WebSocketDenialResponse) as exc,
        client.websocket_connect("/v1/ws", headers=headers),
    ):
        pass
    r = exc.value
    assert r.status_code == 401 and r.json()["error"]["code"] == "bad_signature"
    phone.check_response(nonce, 401, r.headers, r.content)


def test_admin_devices_and_status(env: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    admin = Admin(core.config.admin_socket)
    admin.send({"cmd": "devices.list"})
    devs = admin.recv()["devices"]
    admin.close()
    assert [d["id"] for d in devs] == [phone.id]
    admin = Admin(core.config.admin_socket)
    admin.send({"cmd": "nope"})
    assert admin.recv()["error"] == "bad_request"
    admin.close()


def test_cli_pair_and_devices(env: Any, capsys: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    out = io.StringIO()
    config = core.config.data_dir / "core.toml"
    from rh_core.config import to_toml

    config.write_text(to_toml(core.config), encoding="utf-8")
    pending: dict[str, Any] = {}

    class Stdin(io.StringIO):
        def readline(self, *a: Any) -> str:  # type: ignore[override]
            return "y\n"

    def run_cli() -> None:
        pending["rc"] = rhcore._pair(core.config, Stdin(), out)

    t = threading.Thread(target=run_cli)
    t.start()
    for _ in range(100):
        if "rhpair:" in out.getvalue():
            break
        threading.Event().wait(0.05)
    string = next(w for w in out.getvalue().split() if w.startswith("rhpair:"))
    r = finish(send_pair(client, phone, string))
    t.join(10)
    assert r.status_code == 200
    assert pending["rc"] == 0
    text = out.getvalue()
    assert phone.fingerprint in text and "добавлено" in text

    assert rhcore.main(["devices", "list", "--config", str(config)]) == 0
    assert phone.id in capsys.readouterr().out
    assert rhcore.main(["devices", "revoke", phone.id, "--config", str(config)]) == 0
    assert core.store.device(phone.id).status == "revoked"
    assert rhcore.main(["journal", "verify", "--config", str(config)]) == 0
    assert "журнал в порядке" in capsys.readouterr().out
