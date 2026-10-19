"""rh-agent entry point. The agent host arrives in stage 3."""

from __future__ import annotations

import sys

from rh_cli._common import parser


def main(argv: list[str] | None = None) -> int:
    p = parser("rh-agent", "RemoteHands agent host")
    p.parse_args(argv)
    p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
