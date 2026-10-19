"""Admin socket: how `rhcore pair` and `rhcore devices` talk to a running core.

A Unix socket `admin.sock` in the data directory (mode 600, the directory 700),
JSON Lines both ways. Each connection sends one command:

    {"cmd": "status"}
    {"cmd": "devices.list"}
    {"cmd": "devices.revoke", "device_id": "<id>"}
    {"cmd": "pair.start"}

`pair.start` is a conversation. The core answers with
`{"event": "pair.code", "string", "expires"}`, then, when a phone's /v1/pair
request passes verification, `{"event": "pair.request", "device_id", "name",
"fingerprint", "revokes": [{"id", "name"}]}`. The terminal answers
`{"cmd": "pair.decide", "accept": true|false}` and the core ends with
`{"event": "pair.done", "result": "accepted"|"rejected"|"expired"|"cancelled"}`.
Closing the connection cancels the session.

Not part of contracts/: the phone never sees this socket.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

import anyio

from rh_common.protocol import format_ts

if TYPE_CHECKING:
    from rh_core.app import Core


class AdminError(RuntimeError):
    pass


async def serve(core: Core) -> asyncio.AbstractServer:
    path = core.config.admin_socket
    _claim(path)

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await reader.readline()
            try:
                msg = json.loads(line)
                if not isinstance(msg, dict):
                    raise ValueError
            except ValueError:
                await _send(
                    writer,
                    {"ok": False, "error": "bad_request", "message": "expected one JSON object"},
                )
                return
            await _dispatch(core, msg, reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    server = await asyncio.start_unix_server(handle, path=str(path))
    os.chmod(path, 0o600)
    return server


def _claim(path: Path) -> None:
    """Remove a socket left by a core that died; refuse if one is still listening."""
    if not path.exists():
        return
    probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        probe.connect(str(path))
    except OSError:
        path.unlink()
    else:
        raise AdminError(f"another rh-core is already running ({path})")
    finally:
        probe.close()


async def _send(writer: asyncio.StreamWriter, msg: dict[str, Any]) -> None:
    writer.write(json.dumps(msg, ensure_ascii=False).encode() + b"\n")
    await writer.drain()


async def _dispatch(
    core: Core, msg: dict[str, Any], reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> None:
    cmd = msg.get("cmd")
    if cmd == "status":
        await _send(
            writer,
            {
                "ok": True,
                "mode": core.config.mode,
                "mac_name": core.config.mac_name,
                "url": core.config.public_url,
                "server_time": format_ts(core.clock()),
            },
        )
    elif cmd == "devices.list":
        await _send(writer, {"ok": True, "devices": [d.to_api() for d in core.store.devices()]})
    elif cmd == "devices.revoke":
        target = msg.get("device_id")
        if not isinstance(target, str) or not await core.revoke(target, by="terminal"):
            await _send(
                writer, {"ok": False, "error": "not_found", "message": f"no device {target}"}
            )
        else:
            await _send(writer, {"ok": True, "device_id": target, "status": "revoked"})
    elif cmd == "pair.start":
        await _pair(core, reader, writer)
    else:
        await _send(
            writer, {"ok": False, "error": "bad_request", "message": f"unknown command {cmd!r}"}
        )


async def _pair(core: Core, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    pairing = core.pairing
    session = pairing.start()
    core.journal.append("pairing.started", expires=format_ts(session.code.expires))
    await _send(
        writer,
        {
            "event": "pair.code",
            "string": session.string,
            "expires": format_ts(session.code.expires),
        },
    )
    lines = _Lines(reader)
    try:
        # Wait for a verified request, the code to expire, or the terminal to go away.
        arrived = await lines.race(session.arrived, lambda: pairing.seconds_left(session))
        if arrived is None:
            pairing.cancel(session)
            return
        if not arrived or session.candidate is None:
            pairing.cancel(session, "expired")
            await _send(writer, {"event": "pair.done", "result": session.result})
            return
        req = session.candidate.request
        revokes = set(core.replaced_by(req))
        await _send(
            writer,
            {
                "event": "pair.request",
                "device_id": req.obj.device,
                "name": req.name,
                "fingerprint": session.candidate.fingerprint,
                "revokes": [
                    {"id": d.id, "name": d.name} for d in core.store.devices() if d.id in revokes
                ],
            },
        )
        if not session.candidate.decided.is_set():
            line = await lines.next(pairing.seconds_left(session))
            if line is None:
                pairing.cancel(session, "expired")
            elif not line:
                pairing.cancel(session, "cancelled")
            else:
                pairing.decide(session, _accepts(line))
        await anyio.to_thread.run_sync(session.done.wait, pairing.seconds_left(session) + 30)
        out: dict[str, Any] = {"event": "pair.done", "result": session.result}
        if session.result == "accepted":
            out["device_id"] = req.obj.device
        await _send(writer, out)
    finally:
        await lines.close()
        if not session.closed:
            pairing.cancel(session)


class _Lines:
    """Lines from the terminal, read by one task so waits can race against them."""

    def __init__(self, reader: asyncio.StreamReader) -> None:
        self._reader = reader
        self._pending: asyncio.Task[bytes] | None = None

    def _task(self) -> asyncio.Task[bytes]:
        if self._pending is None:
            self._pending = asyncio.ensure_future(self._reader.readline())
        return self._pending

    async def race(self, event: threading.Event, left: Callable[[], float]) -> bool | None:
        """True if the event fired, False once no time is left, None if the terminal went away.

        Time left is re-read every second, so a jump of the clock (the Mac waking from
        sleep) still ends the wait on time. Lines sent before the terminal is asked
        anything are ignored.
        """
        while True:
            if event.is_set():
                return True
            remaining = left()
            if remaining <= 0:
                return False
            waiter = asyncio.ensure_future(
                anyio.to_thread.run_sync(event.wait, min(remaining, 1.0))
            )
            line = self._task()
            done, _ = await asyncio.wait({waiter, line}, return_when=asyncio.FIRST_COMPLETED)
            if line in done:
                self._pending = None
                if not line.result():
                    with contextlib.suppress(BaseException):
                        await waiter  # at most a second
                    return None
            if not waiter.done():
                await waiter

    async def next(self, timeout: float) -> bytes | None:
        """The next line (b"" at EOF), or None on timeout."""
        done, _ = await asyncio.wait({self._task()}, timeout=timeout)
        if not done:
            return None
        line = self._pending
        self._pending = None
        assert line is not None
        return line.result()

    async def close(self) -> None:
        if self._pending is not None:
            self._pending.cancel()
            with contextlib.suppress(BaseException):
                await self._pending


def _accepts(line: bytes) -> bool:
    try:
        msg = json.loads(line)
    except ValueError:
        return False
    return isinstance(msg, dict) and msg.get("cmd") == "pair.decide" and msg.get("accept") is True
