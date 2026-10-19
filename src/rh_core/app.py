"""rh-core HTTP and WebSocket API (contracts/api/openapi.yaml), stage 1.

Every response, rejections included, is signed with the core key
(X-RH-Server-Sig). Every accepted and rejected request goes to the journal.
"""

from __future__ import annotations

import asyncio
import contextlib
import glob
import json
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import anyio
from cryptography.hazmat.primitives.asymmetric import ec
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from rh_common import __version__
from rh_common.crypto import b64e, public_x963, sign_der
from rh_common.protocol import (
    ERROR_STATUS,
    HEADER_AUTH,
    HEADER_SERVER_SIG,
    KeyLevel,
    PairRequest,
    ProtocolError,
    Verdict,
    fingerprint,
    format_ts,
    frame_sig_message,
    parse_auth,
    server_sig_message,
    verify_pair,
    verify_request,
)
from rh_core import admin, keys
from rh_core.config import Config
from rh_core.journal import Journal
from rh_core.pairing import Candidate, Pairing, Session
from rh_core.peers import LocalPeers, PeerLookup
from rh_core.store import Store

_DEVICE_RE = re.compile(r"\A[0-9a-f]{32}\Z")
WS_CLOSE_REVOKED = 4403
SSH_HOST_KEYS = "/etc/ssh/ssh_host_*_key.pub"


@dataclass(eq=False)  # kept in sets by identity
class Connection:
    websocket: WebSocket
    device: str
    nonce: str
    seq: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def send(
        self, core_key: ec.EllipticCurvePrivateKey, type_: str, data: dict[str, Any]
    ) -> None:
        async with self.lock:
            self.seq += 1
            payload = json.dumps({"seq": self.seq, "type": type_, "data": data}, ensure_ascii=False)
            sig = sign_der(
                core_key,
                frame_sig_message(ws_nonce=self.nonce, seq=self.seq, payload=payload.encode()),
            )
            frame = {"seq": self.seq, "payload": payload, "sig": b64e(sig)}
            await self.websocket.send_text(json.dumps(frame, ensure_ascii=False))


class Core:
    def __init__(
        self,
        config: Config,
        *,
        clock: Callable[[], datetime] | None = None,
        peers: PeerLookup | None = None,
        ssh_host_keys: str = SSH_HOST_KEYS,
    ) -> None:
        self.config = config
        self.clock = clock or (lambda: datetime.now(UTC).replace(microsecond=0))
        self.peers: PeerLookup = peers or LocalPeers()
        self.ssh_host_keys_glob = ssh_host_keys
        config.data_dir.mkdir(parents=True, exist_ok=True)
        config.data_dir.chmod(0o700)
        self.store = Store(config.db_path)
        self.journal = Journal(config.journal_dir, clock=lambda: datetime.now(UTC))
        self.key = keys.load_or_create(config.key_path)
        self.public_key = public_x963(self.key)
        self.pairing = Pairing(
            url=config.public_url, core_key_b64=b64e(self.public_key), clock=self.clock
        )
        self.connections: dict[str, set[Connection]] = {}

    # --- responses -----------------------------------------------------------

    def signed(self, status: int, payload: dict[str, Any] | None, nonce: str) -> Response:
        body = (
            b""
            if payload is None
            else json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        )
        sig = sign_der(self.key, server_sig_message(nonce=nonce, status=status, body=body))
        return Response(
            body,
            status_code=status,
            media_type="application/json" if payload is not None else None,
            headers={HEADER_SERVER_SIG: b64e(sig)},
        )

    def refuse(self, error: ProtocolError, nonce: str) -> Response:
        return self.signed(
            error.status, {"error": {"code": error.code, "message": error.message}}, nonce
        )

    def ssh_host_keys(self) -> list[str]:
        lines = []
        for path in sorted(glob.glob(self.ssh_host_keys_glob)):
            with contextlib.suppress(OSError):
                lines.append(Path(path).read_text(encoding="utf-8").strip())
        return [line for line in lines if line]

    # --- device lifecycle ------------------------------------------------------

    async def revoke(self, device_id: str, *, by: str) -> bool:
        if not self.store.revoke(device_id, now=self.clock()):
            return False
        self.journal.append("device.revoked", device=device_id, by=by)
        for conn in list(self.connections.get(device_id, ())):
            with contextlib.suppress(Exception):
                await conn.websocket.close(code=WS_CLOSE_REVOKED)
        return True

    def replaced_by(self, req: PairRequest) -> list[str]:
        """Devices one `y` revokes (SPEC §4.2): `replaces`, else active ones with the same name."""
        active = [
            d for d in self.store.devices() if d.status == "active" and d.id != req.obj.device
        ]
        if req.replaces:
            return [d.id for d in active if d.id == req.replaces]
        return [d.id for d in active if d.name == req.name]


# --- signed endpoints -----------------------------------------------------------------

Handler = Callable[[Core, Verdict, bytes], Awaitable[tuple[int, dict[str, Any] | None]]]


def signed_endpoint(
    op: str, key: KeyLevel, handler: Handler
) -> Callable[[Request], Awaitable[Response]]:
    async def endpoint(request: Request) -> Response:
        core: Core = request.app.state.core
        body = await request.body()
        verdict = _verify(core, request.headers, body, op, key, request.client)
        nonce = verdict.obj.nonce if verdict.obj else ""
        if verdict.error is not None:
            return core.refuse(verdict.error, nonce)
        status, payload = await handler(core, verdict, body)
        return core.signed(status, payload, nonce)

    return endpoint


def _verify(
    core: Core,
    headers: Any,
    body: bytes,
    op: str,
    key: KeyLevel,
    client: Any,
) -> Verdict:
    verdict = verify_request(
        headers=headers,
        body=body,
        op=op,
        key_level=key,
        now=core.clock(),
        find_device=core.store.device,
        find_nonce=core.store.nonce,
    )
    lost_race = False
    if verdict.consume_nonce and verdict.obj is not None:
        lost_race = not core.store.consume_nonce(verdict.obj.nonce)
    if lost_race and verdict.error is None:  # a replay of the same nonce got there first
        verdict = Verdict(
            obj=verdict.obj,
            device=verdict.device,
            error=ProtocolError("nonce_used", "nonce was already used"),
            consume_nonce=False,
        )
    if verdict.error is None and verdict.device is not None:
        row = core.store.device_row(verdict.device.id)
        node = core.peers.node(client.host, client.port) if client else None
        if row is not None and (node is None or node != row.peer):
            verdict = Verdict(
                obj=verdict.obj,
                device=verdict.device,
                error=ProtocolError("peer_mismatch", f"request came from Tailscale node {node!r}"),
                consume_nonce=False,
            )
    obj = verdict.obj
    core.journal.append(
        "request",
        op=op,
        device=obj.device if obj else None,
        result="rejected" if verdict.error else "accepted",
        reason=verdict.error.code if verdict.error else None,
        detail=verdict.error.message if verdict.error else None,
        peer=f"{client.host}:{client.port}" if client else None,
    )
    return verdict


async def ping(core: Core, verdict: Verdict, body: bytes) -> tuple[int, dict[str, Any]]:
    return 200, {"pong": True, "server_time": format_ts(core.clock())}


async def status(core: Core, verdict: Verdict, body: bytes) -> tuple[int, dict[str, Any]]:
    return 200, {
        "mac_name": core.config.mac_name,
        "core_version": __version__,
        "agent_version": None,
        "mode": core.config.mode,
        "server_time": format_ts(core.clock()),
    }


async def devices_list(core: Core, verdict: Verdict, body: bytes) -> tuple[int, dict[str, Any]]:
    current = verdict.device.id if verdict.device else None
    return 200, {"devices": [d.to_api(current=current) for d in core.store.devices()]}


async def devices_revoke(core: Core, verdict: Verdict, body: bytes) -> tuple[int, dict[str, Any]]:
    try:
        doc = json.loads(body)
        target = doc["device_id"]
        if set(doc) != {"device_id"} or not isinstance(target, str) or not _DEVICE_RE.match(target):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        return 400, {
            "error": {"code": "malformed_auth", "message": 'body must be {"device_id": "<id>"}'}
        }
    by = verdict.device.id if verdict.device else "?"
    if not await core.revoke(target, by=by):
        return 404, {"error": {"code": "not_found", "message": f"no device {target}"}}
    return 200, {"device_id": target, "status": "revoked"}


# --- unsigned and special endpoints ------------------------------------------------------


async def challenge(request: Request) -> Response:
    core: Core = request.app.state.core
    body = await request.body()
    try:
        doc = json.loads(body)
        device = doc["device"]
        if set(doc) != {"device"} or not isinstance(device, str) or not _DEVICE_RE.match(device):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        error = ProtocolError("malformed_auth", 'body must be {"device": "<id>"}')
        core.journal.append("challenge", result="rejected", reason=error.code)
        return core.refuse(error, "")
    record = core.store.device(device)
    if record is None or record.status != "active":
        code = "unknown_device" if record is None else "revoked_device"
        error = ProtocolError(
            code, f"device {device} is {'not paired' if record is None else 'revoked'}"
        )
        core.journal.append("challenge", device=device, result="rejected", reason=code)
        return core.refuse(error, "")
    now = core.clock()
    nonce, expires = core.store.issue_nonce(device, now=now)
    payload = {"nonce": nonce, "expires": format_ts(expires), "server_time": format_ts(now)}
    return core.signed(200, payload, nonce)


async def pair(request: Request) -> Response:
    core: Core = request.app.state.core
    body = await request.body()
    client = request.client
    peer = core.peers.node(client.host, client.port) if client else None
    try:  # sign the refusal over the code when the header can be read at all
        nonce = parse_auth(request.headers.get(HEADER_AUTH))[0].nonce
    except ProtocolError:
        nonce = ""
    try:
        req = verify_pair(
            headers=request.headers, body=body, now=core.clock(), find_code=core.pairing.find_code
        )
        nonce = req.obj.nonce
        if peer is None:
            raise ProtocolError(
                "peer_mismatch", "cannot tell which Tailscale node this request came from"
            )
        existing = core.store.device(req.obj.device)
        if existing is not None:
            raise ProtocolError(
                "pair_rejected", "these keys are already registered; generate new keys"
            )
        candidate = _candidate(core, req, peer)
        session = core.pairing.submit(candidate)
        if session is None:
            raise ProtocolError("bad_pair_code", "pairing code is unknown, used or expired")
    except ProtocolError as e:
        core.journal.append(
            "pairing", result="rejected", reason=e.code, detail=e.message, peer=_peer(request)
        )
        return core.refuse(e, nonce)
    return await _finish_pair(core, session, candidate, req, peer, request)


def _candidate(core: Core, req: PairRequest, peer: str | None) -> Candidate:
    return Candidate(request=req, fingerprint=fingerprint(req.keys_b64), peer=peer)


async def _finish_pair(
    core: Core,
    session: Session,
    candidate: Candidate,
    req: PairRequest,
    peer: str,
    request: Request,
) -> Response:
    result = "expired"
    try:
        if await _wait_decision(core, session, candidate, request) or candidate.withdrawn:
            # The phone is gone, or its retry took this request's place: nobody would get
            # device_id and ssh_host_keys here. Keep the code open for the retry.
            result = "withdrawn"
            core.journal.append(
                "pairing", device=req.obj.device, result="withdrawn", peer=_peer(request)
            )
            return Response(status_code=499)
        if not candidate.accepted:
            if candidate.decided.is_set() and not session.closed:
                result = "rejected"
                error = ProtocolError("pair_rejected", "pairing was declined in the terminal")
            else:
                result = session.result or "expired"
                error = ProtocolError(
                    "bad_pair_code", "pairing code expired before it was confirmed"
                )
            core.journal.append(
                "pairing",
                device=req.obj.device,
                result="rejected",
                reason=error.code,
                detail=result,
            )
            return core.refuse(error, req.obj.nonce)
        replaced = core.replaced_by(req)
        core.store.add_device(
            device_id=req.obj.device, name=req.name, keys=req.keys, now=core.clock(), peer=peer
        )
        result = "accepted"
        core.journal.append(
            "pairing",
            device=req.obj.device,
            result="accepted",
            name=req.name,
            fingerprint=candidate.fingerprint,
            peer=_peer(request),
            node=peer,
            auto=True if core.pairing.auto_accept else None,
        )
        for old in replaced:
            await core.revoke(old, by=req.obj.device)
        payload = {
            "device_id": req.obj.device,
            "mac_name": core.config.mac_name,
            "ssh_host_keys": core.ssh_host_keys(),
        }
        return core.signed(200, payload, req.obj.nonce)
    finally:
        if result != "withdrawn":
            core.pairing.finish(session, result)


async def _wait_decision(
    core: Core, session: Session, candidate: Candidate, request: Request
) -> bool:
    """Wait for y/n or expiry; True if the phone disconnected first and was withdrawn."""
    while not candidate.decided.is_set():
        left = core.pairing.seconds_left(session)
        if left <= 0:
            return False
        await anyio.to_thread.run_sync(candidate.decided.wait, min(left, 1.0))
        if (
            not candidate.decided.is_set()
            and await request.is_disconnected()
            and core.pairing.withdraw(session, candidate)
        ):
            return True
    return False


def _peer(request: Request) -> str | None:
    return f"{request.client.host}:{request.client.port}" if request.client else None


async def ws_open(websocket: WebSocket) -> None:
    core: Core = websocket.app.state.core
    verdict = _verify(core, websocket.headers, b"", "ws.open", "normal", websocket.client)
    if verdict.error is not None or verdict.obj is None or verdict.device is None:
        error = verdict.error or ProtocolError("malformed_auth", "bad ws.open")
        nonce = verdict.obj.nonce if verdict.obj else ""
        try:
            await websocket.send_denial_response(core.refuse(error, nonce))
        except RuntimeError:  # server without the denial-response extension
            await websocket.close(code=4000 + ERROR_STATUS[error.code])
        return
    await websocket.accept()
    conn = Connection(websocket=websocket, device=verdict.device.id, nonce=verdict.obj.nonce)
    core.connections.setdefault(conn.device, set()).add(conn)
    try:
        await conn.send(
            core.key, "hello", {"device": conn.device, "server_time": format_ts(core.clock())}
        )
        while True:
            await (
                websocket.receive_text()
            )  # the client sends nothing meaningful; keeps the socket read
    except WebSocketDisconnect:
        pass
    finally:
        core.connections.get(conn.device, set()).discard(conn)


def create_app(
    core: Core,
    *,
    admin_socket: bool = True,
    background: Sequence[Callable[[Core], Awaitable[None]]] = (),
) -> Starlette:
    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        server = await admin.serve(core) if admin_socket else None
        core.journal.append("core.started", mode=core.config.mode, version=__version__)
        tasks: list[asyncio.Future[None]] = [asyncio.ensure_future(job(core)) for job in background]
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if server is not None:
                server.close()
                await server.wait_closed()
                with contextlib.suppress(FileNotFoundError):
                    core.config.admin_socket.unlink()
            core.journal.append("core.stopped")

    routes = [
        Route("/v1/challenge", challenge, methods=["POST"]),
        Route("/v1/pair", pair, methods=["POST"]),
        Route("/v1/ping", signed_endpoint("ping", "normal", ping), methods=["POST"]),
        Route("/v1/status", signed_endpoint("status", "normal", status), methods=["GET"]),
        Route(
            "/v1/devices", signed_endpoint("devices.list", "normal", devices_list), methods=["GET"]
        ),
        Route(
            "/v1/devices/revoke",
            signed_endpoint("devices.revoke", "critical", devices_revoke),
            methods=["POST"],
        ),
        WebSocketRoute("/v1/ws", ws_open),
    ]
    app = Starlette(routes=routes, lifespan=lifespan)
    app.state.core = core
    return app
