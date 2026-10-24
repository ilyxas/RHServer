"""Stop hook for the channel agent's session: the turn's last answer goes to the phone.

    rh-friend-reply --config <friend.toml> --project <agent's project folder>   (hook JSON)
    rh-friend-reply --config <friend.toml> --progress "<text>"      (the agent, mid-task)
    rh-friend-reply --config <friend.toml> --flush                  (send deferred replies)

Claude Code runs the Stop hook when the agent has finished responding (not when the turn
was interrupted) and hands it `last_assistant_message`. If the verifier noted an owner's
message the session is on (`state/rh_current.json`), that text is sent to the core as
`friend.reply` for it; the core marks the message answered, or waiting when the agent
asked the owner a decision since. A turn the owner did not cause (no open message)
sends nothing. A core that does not answer gets the reply later: it is kept in
`state/rh_pending.jsonl` and sent by the next hook call or `--flush`.

The hook never blocks and prints nothing to stdout; a problem goes to stderr only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from rh_common.friend import MAX_TEXT
from rh_friend import config as friend_config
from rh_friend import core_socket
from rh_friend.config import FriendConfig
from rh_friend.verify import Report, apply_reply_answer, read_current, settle_pending


def reply(
    cfg: FriendConfig,
    text: str,
    *,
    prompt_id: str | None,
    progress: bool,
    report: Report | None = None,
) -> dict[str, Any] | None:
    """Send `text` as the reply to the open message. Returns the core's answer, a
    {"deferred": True} when the core was unreachable, or None when there is nothing to
    reply to (no open message, empty text)."""
    current = read_current(cfg)
    if current is None:
        return None
    text = text.strip()
    if not text:
        return None
    msg = {
        "cmd": "friend.reply",
        "in_reply_to": current["id"],
        "text": text[:MAX_TEXT],
        "prompt_id": prompt_id if prompt_id is not None else current.get("prompt_id"),
        "progress": progress,
    }
    answer = report(msg) if report is not None else core_socket.report(cfg, msg)
    if answer is None:
        core_socket.defer(cfg, msg)
        return {"deferred": True}
    if not isinstance(answer, dict):
        return None
    apply_reply_answer(cfg, msg, answer)  # answered or closed: nothing more to say
    return answer


def handle_stop(
    event: dict[str, Any], cfg: FriendConfig, *, report: Report | None = None
) -> dict[str, Any] | None:
    """The Stop hook: the last assistant message answers the open owner's message."""
    text = event.get("last_assistant_message")
    if not isinstance(text, str):
        return None
    prompt_id = event.get("prompt_id") if isinstance(event.get("prompt_id"), str) else None
    return reply(cfg, text, prompt_id=prompt_id, progress=False, report=report)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rh-friend-reply", description=__doc__)
    parser.add_argument("--config", type=Path, default=friend_config.DEFAULT_PATH)
    parser.add_argument(
        "--project",
        type=Path,
        help="as a hook: act only in this project (CLAUDE_PROJECT_DIR must match)",
    )
    parser.add_argument("--progress", metavar="TEXT", help="a progress note from the agent")
    parser.add_argument("--flush", action="store_true", help="send deferred replies and exit")
    args = parser.parse_args(argv)
    try:
        cfg = friend_config.load(args.config)
    except friend_config.ConfigError as e:
        print(f"rh-friend-reply: {e}", file=sys.stderr)
        return 0 if args.progress is None and not args.flush else 2
    if args.flush:
        pending = core_socket.pending_file(cfg)

        def count() -> int:
            return len(pending.read_text().splitlines()) if pending.exists() else 0

        before = count()
        settle_pending(cfg)
        print(f"sent {before - count()} of {before} deferred report(s)", file=sys.stderr)
        return 0
    if args.progress is not None:
        answer = reply(cfg, args.progress, prompt_id=None, progress=True)
        if answer is None:
            print("rh-friend-reply: no open message from the owner to report to", file=sys.stderr)
            return 1
        if answer.get("deferred"):
            print("rh-friend-reply: the core is not reachable; kept for later", file=sys.stderr)
        elif not answer.get("ok"):
            print(
                f"rh-friend-reply: {answer.get('error')}: {answer.get('message')}", file=sys.stderr
            )
            return 1
        return 0
    # The Stop hook. Never block, never print to stdout.
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    want = args.project if args.project is not None else cfg.project_dir
    if not project_dir or os.path.realpath(project_dir) != os.path.realpath(want):
        return 0
    if os.path.realpath(cfg.project_dir) != os.path.realpath(want):
        print("rh-friend-reply: --project and the config's project_dir differ", file=sys.stderr)
        return 0
    try:
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            raise ValueError("hook input is not an object")
    except ValueError as e:
        print(f"rh-friend-reply: {e}", file=sys.stderr)
        return 0
    try:
        settle_pending(cfg)
        handle_stop(event, cfg)
    except Exception as e:  # a reply must never break the session
        print(f"rh-friend-reply: {type(e).__name__}: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
