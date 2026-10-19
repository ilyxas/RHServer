"""Run rh-core under uvicorn: `rhcore serve` and `rhcore dev up`."""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from pathlib import Path

import anyio
import uvicorn

from rh_common.protocol import format_ts
from rh_core.app import Core, create_app
from rh_core.config import Config
from rh_core.peers import LocalPeers, PeerLookup, TailscaleWhois

Job = Callable[[Core], Awaitable[None]]


def build_core(config: Config) -> Core:
    config.validate()
    peers: PeerLookup = TailscaleWhois(config.tailscale) if config.whois else LocalPeers()
    return Core(config, peers=peers)


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


def run(config: Config, *, background: list[Job] | None = None) -> None:
    core = build_core(config)
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
    server.run()
