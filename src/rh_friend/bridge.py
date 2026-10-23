"""Bridge from the core's friend inbox to the Friend tmux session.

    rh-friend-bridge --config <friend.toml> [--once]

For each new envelope in inbox_dir it types one line, `⟦rh:<id>⟧`, into the
configured tmux target and presses Enter. It never reads the message: the
Friend verifier loads and checks the envelope itself. Delivered ids are kept in
[bridge] state_file, so a restart does not type them again.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from rh_common.friend import pointer
from rh_friend import config as friend_config
from rh_friend.config import BridgeConfig

Runner = Callable[[Sequence[str]], None]


def _run(cmd: Sequence[str]) -> None:
    subprocess.run(list(cmd), check=True, capture_output=True, timeout=10)


def pending(inbox: Path, delivered: set[str]) -> list[str]:
    """Spool ids not yet delivered, oldest first."""
    try:
        files = [p for p in inbox.iterdir() if p.suffix == ".json" and not p.name.startswith(".")]
    except FileNotFoundError:
        return []
    files.sort(key=lambda p: (p.stat().st_mtime, p.name))
    return [p.stem for p in files if p.stem not in delivered]


def type_pointer(bridge: BridgeConfig, sid: str, run: Runner = _run) -> None:
    line = pointer(sid)
    run([bridge.tmux, "send-keys", "-t", bridge.target, "-l", line])
    run([bridge.tmux, "send-keys", "-t", bridge.target, "Enter"])


def _load_state(path: Path) -> set[str]:
    try:
        return set(json.loads(path.read_text(encoding="utf-8"))["delivered"])
    except (OSError, ValueError, KeyError, TypeError):
        return set()


def _save_state(path: Path, delivered: set[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps({"delivered": sorted(delivered)}), encoding="utf-8")
    os.replace(tmp, path)


def step(inbox: Path, bridge: BridgeConfig, run: Runner = _run) -> list[str]:
    """Deliver everything pending once; return the ids typed."""
    delivered = _load_state(bridge.state_file)
    typed = []
    for sid in pending(inbox, delivered):
        try:
            pointer(sid)
        except ValueError:
            continue  # not an envelope name; the core never writes one
        type_pointer(bridge, sid, run)
        delivered.add(sid)
        _save_state(bridge.state_file, delivered)
        typed.append(sid)
    return typed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rh-friend-bridge", description=__doc__)
    parser.add_argument("--config", type=Path, default=friend_config.DEFAULT_PATH)
    parser.add_argument("--once", action="store_true", help="deliver what is pending and exit")
    parser.add_argument("--interval", type=float, default=1.0, help="seconds between scans")
    args = parser.parse_args(argv)
    try:
        cfg = friend_config.load(args.config)
    except friend_config.ConfigError as e:
        print(f"rh-friend-bridge: {e}", file=sys.stderr)
        return 2
    if cfg.bridge is None:
        print("rh-friend-bridge: the config has no [bridge] table", file=sys.stderr)
        return 2
    while True:
        try:
            for sid in step(cfg.inbox_dir, cfg.bridge):
                print(f"typed {pointer(sid)} into {cfg.bridge.target}", flush=True)
        except (OSError, subprocess.SubprocessError) as e:
            print(f"rh-friend-bridge: {e}", file=sys.stderr, flush=True)
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
