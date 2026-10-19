"""rhpage: validate and publish rh.page/1 pages. Commands arrive in stage 5."""

from __future__ import annotations

from rh_cli._common import parser


def main(argv: list[str] | None = None) -> int:
    p = parser("rhpage", "RemoteHands pages")
    p.parse_args(argv)
    p.print_help()
    return 0
