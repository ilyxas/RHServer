"""The agent side's line to the core: one JSON command per connection over the admin socket.

Two ways to use it. `call` is for commands whose answer matters (ask a question, spend a
decision): it raises CoreUnreachable when the core does not answer. `report` is for facts
the hooks tell the core (a message was received or rejected, the agent replied): it never
raises and never slows a hook down for long, and a reply that could not be delivered is
kept in a pending file and sent again by the next hook call or `rh-friend-reply --flush`.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from rh_friend.config import FriendConfig

SOCKET_TIMEOUT_S = 5.0  # a command whose answer matters
REPORT_TIMEOUT_S = 2.0  # a fact; UserPromptSubmit has 30 s in all
PENDING_FILE = Path("state/rh_pending.jsonl")  # inside the agent's project folder


class CoreUnreachable(Exception):
    pass


def call(socket_path: Path, msg: dict[str, Any], *, timeout: float = SOCKET_TIMEOUT_S) -> Any:
    """Send one command and return the core's answer (a dict). Raises CoreUnreachable."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(str(socket_path))
        f = s.makefile("rw", encoding="utf-8", newline="\n")
        f.write(json.dumps(msg, ensure_ascii=False) + "\n")
        f.flush()
        line = f.readline()
    except OSError as e:
        raise CoreUnreachable(f"rh-core is not running ({socket_path}: {e})") from e
    finally:
        s.close()
    if not line:
        raise CoreUnreachable("the core closed the admin socket without an answer")
    try:
        answer = json.loads(line)
    except ValueError as e:
        raise CoreUnreachable("unreadable answer from the core") from e
    if not isinstance(answer, dict):
        raise CoreUnreachable("unreadable answer from the core")
    return answer


def report(cfg: FriendConfig, msg: dict[str, Any]) -> dict[str, Any] | None:
    """Tell the core a fact; the answer, or None when the core could not be reached or the
    config has no [gate] (and so no admin socket). Never raises."""
    if cfg.gate is None:
        return None
    try:
        out: dict[str, Any] = call(cfg.gate.admin_socket, msg, timeout=cfg.gate.report_timeout_s)
    except CoreUnreachable:
        return None
    return out


def pending_file(cfg: FriendConfig) -> Path:
    return cfg.project_dir / PENDING_FILE


def defer(cfg: FriendConfig, msg: dict[str, Any]) -> None:
    """Keep a report for later (the core was not reachable)."""
    path = pending_file(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(msg, ensure_ascii=False) + "\n")


def flush_pending(cfg: FriendConfig) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Send the deferred reports in order; stop at the first that still fails. Returns the
    (report, answer) pairs that went through. Never raises."""
    path = pending_file(cfg)
    try:
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except OSError:
        return []
    delivered: list[tuple[dict[str, Any], dict[str, Any]]] = []
    sent = 0
    for line in lines:
        try:
            msg = json.loads(line)
        except ValueError:
            sent += 1  # unreadable: drop it
            continue
        if not isinstance(msg, dict):
            sent += 1
            continue
        answer = report(cfg, msg)
        if answer is None:
            break
        delivered.append((msg, answer))
        sent += 1
    rest = lines[sent:]
    with contextlib.suppress(OSError):
        if rest:
            tmp = path.with_name(f".{path.name}.tmp")
            tmp.write_text("\n".join(rest) + "\n", encoding="utf-8")
            os.replace(tmp, path)
        else:
            path.unlink(missing_ok=True)
    return delivered


__all__ = [
    "PENDING_FILE",
    "REPORT_TIMEOUT_S",
    "SOCKET_TIMEOUT_S",
    "CoreUnreachable",
    "call",
    "defer",
    "flush_pending",
    "pending_file",
    "report",
]
