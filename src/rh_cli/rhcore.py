"""rhcore: manage rh-core (pairing, devices, dev mode). Commands arrive from stage 1."""

from __future__ import annotations

from rh_cli._common import parser


def main(argv: list[str] | None = None) -> int:
    p = parser("rhcore", "RemoteHands core")
    p.parse_args(argv)
    p.print_help()
    return 0
