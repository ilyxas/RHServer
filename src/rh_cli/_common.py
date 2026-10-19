from __future__ import annotations

import argparse

from rh_common import __version__


def parser(prog: str, description: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=prog, description=description)
    p.add_argument("--version", action="version", version=f"{prog} {__version__}")
    return p
