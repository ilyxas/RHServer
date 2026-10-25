"""Bridge from the core's inbox to the channel agent's tmux session.

    rh-friend-bridge --config <friend.toml> [--once]

For each new envelope in inbox_dir it presses Escape (the owner's message interrupts;
`[bridge] interrupt`), types one line, `⟦rh:<id>⟧`, into the configured tmux target
and presses Enter. It never reads the message: the
agent-side verifier loads and checks the envelope itself. Delivered ids are kept in
[bridge] state_file, so a restart does not type them again.

While the gate waits for the owner's answer (`.gate-wait` in the inbox, fresher than
GATE_WAIT_MAX_S), a friend.decide envelope is not typed: the gate reads it, and the
Escape before a typed line would cancel the very call the gate holds. The bridge only
reads the envelope's op for this, unverified; trust stays with the gate and the verifier.
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

from rh_common.friend import OP_DECIDE, parse_envelope, pointer
from rh_common.protocol import ProtocolError, parse_auth
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


GATE_WAIT_MARK = ".gate-wait"  # rh_friend.gate.WAIT_MARK
GATE_WAIT_MAX_S = 660  # longer than the gate hook's timeout: an older mark is left over


def gate_waiting(inbox: Path, now: float | None = None) -> bool:
    try:
        age = (time.time() if now is None else now) - (inbox / GATE_WAIT_MARK).stat().st_mtime
    except OSError:
        return False
    return age <= GATE_WAIT_MAX_S


def is_decision(inbox: Path, sid: str) -> bool:
    try:
        obj, _ = parse_auth(parse_envelope((inbox / f"{sid}.json").read_bytes()).auth)
    except (OSError, ValueError, ProtocolError):
        return False
    return obj.op == OP_DECIDE


ESCAPE_PAUSE_S = 0.3  # Claude Code needs a moment to stop the turn before the next line


def type_pointer(
    bridge: BridgeConfig,
    sid: str,
    run: Runner = _run,
    sleep: Callable[[float], None] = time.sleep,
) -> None:
    """One Escape first (the owner's message interrupts a working agent and keeps what it
    did; idle, it is a no-op; on a permission prompt it declines), then the pointer, then
    Enter. Exactly one Escape: two on an empty line open Claude Code's rewind menu."""
    line = pointer(sid)
    if bridge.interrupt:
        run([bridge.tmux, "send-keys", "-t", bridge.target, "Escape"])
        sleep(ESCAPE_PAUSE_S)
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


def step(
    inbox: Path,
    bridge: BridgeConfig,
    run: Runner = _run,
    sleep: Callable[[float], None] = time.sleep,
) -> list[str]:
    """Deliver everything pending once; return the ids typed."""
    delivered = _load_state(bridge.state_file)
    typed = []
    for sid in pending(inbox, delivered):
        try:
            pointer(sid)
        except ValueError:
            continue  # not an envelope name; the core never writes one
        held = gate_waiting(inbox) and is_decision(inbox, sid)  # the gate reads this one
        if not held:
            type_pointer(bridge, sid, run, sleep)
        delivered.add(sid)
        _save_state(bridge.state_file, delivered)
        if not held:
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
