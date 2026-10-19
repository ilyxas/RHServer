"""Who is on the other end of a connection, per Tailscale (SPEC §3.3).

The core records the Tailscale node a device paired from and refuses requests
from any other node (peer_mismatch). The real lookup goes through the Tailscale
LocalAPI whois; dev mode uses LocalPeers, which knows only "local".
"""

from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
import threading
import time
from typing import Protocol


class PeerLookup(Protocol):
    def node(self, host: str, port: int) -> str | None:
        """Stable id of the Tailscale node at host:port, or None if unknown."""


class LocalPeers:
    """Dev mode: every connection comes from this Mac."""

    def node(self, host: str, port: int) -> str | None:
        return "local"


class TailscaleWhois:
    """Production: ask Tailscale which node owns the source address.

    Uses the `tailscale whois --json <ip>` CLI, which finds the LocalAPI for
    every macOS variant (App Store, Standalone, tailscaled) by itself; the id
    is the node's StableID. See docs/decisions/002-tailscale-whois.md.
    Answers are cached per address for a minute: a Tailscale address belongs
    to one node.
    """

    TTL = 60.0

    def __init__(self, binary: str | None = None, *, timeout: float = 3.0) -> None:
        self.binary = binary or find_tailscale()
        self.timeout = timeout
        self._cache: dict[str, tuple[float, str | None]] = {}
        self._lock = threading.Lock()

    def node(self, host: str, port: int) -> str | None:
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(host)
            if hit is not None and now - hit[0] < self.TTL:
                return hit[1]
        node = self._lookup(host)
        if node is not None:
            with self._lock:
                self._cache[host] = (now, node)
        return node

    def _lookup(self, host: str) -> str | None:
        try:
            ipaddress.ip_address(host)
            out = subprocess.run(
                [self.binary, "whois", "--json", host],
                capture_output=True,
                timeout=self.timeout,
                check=True,
            ).stdout
            return parse_whois(out)
        except (ValueError, OSError, subprocess.SubprocessError):
            return None


def parse_whois(output: bytes) -> str | None:
    doc = json.loads(output)
    node = doc.get("Node") if isinstance(doc, dict) else None
    stable = node.get("StableID") if isinstance(node, dict) else None
    return stable if isinstance(stable, str) and stable else None


MACOS_APP_CLI = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"


def find_tailscale() -> str:
    return shutil.which("tailscale") or MACOS_APP_CLI
