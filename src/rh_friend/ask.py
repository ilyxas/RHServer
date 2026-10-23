"""Ask the owner, from the channel agent's session, for a decision on one exact tool call.

    rh-friend-ask --config <friend.toml> --question "<why>" --tool Bash \\
                  --input '{"command": "kill -CONT 4242", "description": "resume the agent"}'
    rh-friend-ask --config <friend.toml> --question "<why>" --bash "kill -CONT 4242" \\
                  --description "resume the agent"
    rh-friend-ask --config <friend.toml> --list
    rh-friend-ask --config <friend.toml> --withdraw <question id>

The question and the exact action go to the core over the admin socket; the phone
lists them (friend.questions) and answers with a signed friend.decide. The gate then
lets through exactly the call that was asked about: the same tool with the same
input, character for character. `--bash` is a shorthand for tool Bash with input
{"command": "<text>", "description": "<text>"}: Claude Code's Bash tool sends a description
with every command, so one is required here too, exactly as the call will carry it. When
the call will carry other fields as well (timeout, run_in_background), ask with --input
and the full object, and run it with the same fields.

Claude Code fills some fields in before the hook sees the call: an Edit call reaches the
gate with `"replace_all": false` even when the model did not send it (found in the live
switch of 2026-10-24: an allow for the input without it never matched). `--input` gets
those defaults added when they are missing (TOOL_DEFAULTS), and the printed input shows
them, so the asked action is the one the gate will see.

A plain call of this program is never a protected action for the gate, whatever the
question says: asking must not need an answer first.
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path
from typing import Any

from rh_common.friend import action_text, question_sha256
from rh_friend import config as friend_config
from rh_friend.config import GateConfig
from rh_friend.gate import SOCKET_TIMEOUT_S, CoreUnreachable

# Fields Claude Code adds to a tool's input before PreToolUse, with the value it adds.
# Only what was seen in a real hook input goes here.
TOOL_DEFAULTS: dict[str, dict[str, Any]] = {
    "Edit": {"replace_all": False},
}


def with_defaults(tool: str, tool_input: Any) -> Any:
    """The input as the gate will see it: the tool's defaults added where missing."""
    defaults = TOOL_DEFAULTS.get(tool)
    if not defaults or not isinstance(tool_input, dict):
        return tool_input
    return {**defaults, **tool_input}


def call(gate: GateConfig, msg: dict[str, Any]) -> dict[str, Any]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(SOCKET_TIMEOUT_S)
    try:
        s.connect(str(gate.admin_socket))
        f = s.makefile("rw", encoding="utf-8", newline="\n")
        f.write(json.dumps(msg, ensure_ascii=False) + "\n")
        f.flush()
        line = f.readline()
    except OSError as e:
        raise CoreUnreachable(f"rh-core is not running ({gate.admin_socket}: {e})") from e
    finally:
        s.close()
    if not line:
        raise CoreUnreachable("the core closed the admin socket without an answer")
    answer = json.loads(line)
    if not isinstance(answer, dict):
        raise CoreUnreachable("unreadable answer from the core")
    return answer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rh-friend-ask", description=__doc__)
    parser.add_argument("--config", type=Path, default=friend_config.DEFAULT_PATH)
    parser.add_argument("--question", help="what the owner should decide, in full")
    parser.add_argument("--tool", help="tool name of the call, e.g. Bash, Edit, Write")
    parser.add_argument("--input", help="the tool input as JSON, exactly as the call will run")
    parser.add_argument(
        "--bash", help='shorthand: --tool Bash --input \'{"command": ..., "description": ...}\''
    )
    parser.add_argument(
        "--description",
        help="with --bash: the description the Bash call will carry (Claude Code always sends one)",
    )
    parser.add_argument("--list", action="store_true", help="open questions")
    parser.add_argument("--withdraw", metavar="ID", help="withdraw an open question")
    args = parser.parse_args(argv)
    try:
        cfg = friend_config.load(args.config)
    except friend_config.ConfigError as e:
        print(f"rh-friend-ask: {e}", file=sys.stderr)
        return 2
    if cfg.gate is None:
        print("rh-friend-ask: the config has no [gate] table", file=sys.stderr)
        return 2
    try:
        if args.list:
            answer = call(cfg.gate, {"cmd": "friend.questions"})
            for q in answer.get("questions", []):
                print(f"{q['id']}  {q['asked_at']}  {q['text']}")
                print(f"    {q['action']}")
            if not answer.get("questions"):
                print("no open questions")
            return 0
        if args.withdraw:
            answer = call(cfg.gate, {"cmd": "friend.question.withdraw", "id": args.withdraw})
            if not answer.get("ok"):
                print(f"rh-friend-ask: {answer.get('message')}", file=sys.stderr)
                return 1
            print(f"withdrawn: {args.withdraw}")
            return 0
        if not args.question:
            parser.error("--question is required")
        tool_input: Any
        if args.bash is not None:
            if args.tool or args.input:
                parser.error("--bash cannot be combined with --tool/--input")
            if not args.description:
                parser.error(
                    "--bash needs --description: Claude Code's Bash tool sends a description "
                    "with the command, and the gate compares the whole input; give the exact "
                    "description the call will carry, or use --tool Bash --input with the "
                    "full object"
                )
            tool, tool_input = "Bash", {"command": args.bash, "description": args.description}
        else:
            if args.description:
                parser.error("--description goes with --bash")
            if not args.tool or args.input is None:
                parser.error("--tool and --input (or --bash) are required")
            tool = args.tool
            try:
                tool_input = with_defaults(tool, json.loads(args.input))
            except ValueError as e:
                parser.error(f"--input is not JSON: {e}")
        action = action_text(tool, tool_input)
        answer = call(cfg.gate, {"cmd": "friend.ask", "text": args.question, "action": action})
        if not answer.get("ok"):
            print(f"rh-friend-ask: {answer.get('error')}: {answer.get('message')}", file=sys.stderr)
            return 1
        print(f"asked: {answer['id']} at {answer['asked_at']}")
        print(f"question_sha256: {question_sha256(args.question)}")
        print("run exactly this call once the owner allows it:")
        print(f"  tool:  {tool}")
        print(f"  input: {json.dumps(tool_input, ensure_ascii=False)}")
        return 0
    except CoreUnreachable as e:
        print(f"rh-friend-ask: {e}", file=sys.stderr)
        return 2
    except ValueError as e:
        print(f"rh-friend-ask: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
