"""Run rh-core under uvicorn: `rhcore serve` and `rhcore dev up`."""

from __future__ import annotations

import contextlib
import errno
import os
import socket
from collections.abc import Awaitable, Callable
from pathlib import Path

import anyio
import uvicorn

from rh_common.protocol import format_ts
from rh_core.app import Core, create_app
from rh_core.config import DEV_HOST, DEV_PORT, Config
from rh_core.peers import LocalPeers, PeerLookup, TailscaleWhois
from rh_core.system import SystemProbe

Job = Callable[[Core], Awaitable[None]]


def build_core(config: Config, *, probe: SystemProbe | None = None) -> Core:
    config.validate()
    peers: PeerLookup = TailscaleWhois(config.tailscale) if config.whois else LocalPeers()
    return Core(config, peers=peers, probe=probe)


def auto_pair(announce: Callable[[str], None], pairing_file: Path | None) -> Job:
    """Dev mode: keep a pairing session open that accepts any verified request.

    A new code is issued after every pairing and on expiry; the current pairing
    string is printed and, if asked, written to `pairing_file` for UI tests.
    Run through `run`, it starts only once the port listens, and the file is
    removed when the core stops.
    """

    async def job(core: Core) -> None:
        assert core.config.mode == "dev"
        core.pairing.auto_accept = True
        try:
            await loop(core)
        finally:
            # A stopped core leaves no string behind for the next UI test to trust.
            if pairing_file is not None:
                pairing_file.unlink(missing_ok=True)

    async def loop(core: Core) -> None:
        while True:
            session = core.pairing.start()
            if pairing_file is not None:
                # Readers (UI tests) must never see a half-written file.
                tmp = pairing_file.with_name(pairing_file.name + ".tmp")
                tmp.write_text(session.string + "\n", encoding="utf-8")
                os.replace(tmp, pairing_file)
            announce(f"pairing (до {format_ts(session.code.expires)}): {session.string}")
            done = await anyio.to_thread.run_sync(
                session.done.wait, core.pairing.seconds_left(session), abandon_on_cancel=True
            )
            if not done:
                core.pairing.cancel(session, "expired")
            elif session.result == "accepted":
                announce("устройство добавлено")

    return job


def dev_socket(port: int | None = None) -> socket.socket:
    """The bound 127.0.0.1 socket for a dev core.

    An explicit port must be free. Without one the core takes DEV_PORT, or any
    free port when something else already listens there; the pairing string
    carries the URL, so clients learn the port from it.
    """
    if port is not None:
        return _bind(port)
    with contextlib.suppress(OSError):
        return _bind(DEV_PORT)
    return _bind(0)


def _bind(port: int) -> socket.socket:
    if port:
        # On macOS SO_REUSEADDR lets 127.0.0.1:N bind next to a 0.0.0.0:N listener;
        # whoever answers there owns the port.
        try:
            socket.create_connection((DEV_HOST, port), timeout=0.5).close()
        except OSError:
            pass
        else:
            raise OSError(errno.EADDRINUSE, os.strerror(errno.EADDRINUSE))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((DEV_HOST, port))
    except OSError:
        sock.close()
        raise
    return sock


def run(
    config: Config,
    *,
    background: list[Job] | None = None,
    sock: socket.socket | None = None,
    probe: SystemProbe | None = None,
) -> None:
    """Serve until stopped; `sock` is an already bound socket (dev mode), `probe` a
    fake system (dev fixtures)."""
    core = build_core(config, probe=probe)
    server: uvicorn.Server

    def after_bind(job: Job) -> Job:
        # Lifespan starts before uvicorn binds the port; a job must not announce
        # a core that then fails to listen (e.g. the port is taken).
        async def gated(core: Core) -> None:
            while not server.started:
                await anyio.sleep(0.05)
            await job(core)

        return gated

    app = create_app(core, background=[after_bind(job) for job in background or []])
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=config.host,
            port=config.port,
            ssl_certfile=str(config.tls_cert) if config.tls_cert else None,
            ssl_keyfile=str(config.tls_key) if config.tls_key else None,
            proxy_headers=False,  # the peer address must be the real one for whois
            server_header=False,
            log_level="info",
        )
    )
    server.run(sockets=[sock] if sock is not None else None)
