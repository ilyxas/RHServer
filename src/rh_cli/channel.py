"""The channel agent on the command line: `rhcore friend-config` and `rhcore channel set`.

`[channel]` in the core config is the only place the agent's name is set. Both commands
derive the agent-side config (verifier, bridge, gate) from it, so the two sides cannot
name different agents.

`channel set` switches the agent: it checks the new id, the team file and the tmux
session first, then writes both configs (each with a backup), restarts the core, and
reports success only when the running core says the channel is the new agent. On start
the core withdraws the previous agent's open questions and voids its unused allows
(journal `friend.channel.changed`). Hooks in the new agent's project are the owner's
step: the command prints them.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tomllib
from collections.abc import Callable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

from rh_common.crypto import b64e, public_x963
from rh_common.friend import check_agent_id
from rh_core import keys
from rh_core.agents import parse_team
from rh_core.config import Channel, Config, ConfigError, channel_from_dict, channel_toml, from_dict
from rh_friend import config as friend_config

DEFAULT_OWNER_NAMES = "owner|владелец"
_TABLE_RE = re.compile(r"^\s*\[")
_OLD_TABLES = ("channel", "friend")


def agent_config_text(
    cfg: Config,
    *,
    tmux: str,
    ask: Path,
    owner_names: str = DEFAULT_OWNER_NAMES,
    rules_text: str | None = None,
) -> str:
    """The agent-side config for the core's [channel], with the core key pinned.

    `rules_text`: the `[[gate.protected]]` tables to keep as they are (the owner's edits
    survive a switch); None writes the default rules with `owner_names`."""
    from rh_friend.config import DEFAULT_QUESTION_BASH, DEFAULT_QUESTION_TOOLS, default_protected

    ch = cfg.ch
    if not cfg.key_path.exists():
        raise ConfigError(f"no core key at {cfg.key_path}: start the core once first")
    core_pub = public_x963(keys.load_or_create(cfg.key_path))

    def q(value: object) -> str:
        return json.dumps(str(value), ensure_ascii=False)

    lines = [
        f"agent = {q(ch.agent)}",
        f"project_dir = {q(ch.project_dir)}",
        f"inbox_dir = {q(cfg.inbox_dir)}",
        f"devices_file = {q(cfg.devices_path)}",
        f"core_key = {q(b64e(core_pub))}",
        "window_s = 900",
        'owner_label = "owner"',
        "",
        "[bridge]",
        f"tmux = {q(tmux)}",
        f"target = {q(ch.target)}",
        "interrupt = true   # one Escape before each message: the owner's message interrupts",
        "",
        "# PreToolUse gate (rh-friend-gate): a protected call needs a fresh allow decision",
        "# from the phone for exactly that call. Any matching rule protects the call.",
        "[gate]",
        f"admin_socket = {q(cfg.admin_socket)}",
        f"decide_window_s = {cfg.decide_window_s}",
        f"ask = {q(ask)}",
        "# Question mode (the owner's message is a question, not a task): these tools and",
        "# read-only shell commands run freely; anything else needs a decision or a task.",
        "question_tools = [" + ", ".join(q(t) for t in DEFAULT_QUESTION_TOOLS) + "]",
        "question_bash = [",
        *[f"  {q(b)}," for b in DEFAULT_QUESTION_BASH],
        "]",
    ]
    text = "\n".join(lines) + "\n"
    if rules_text is not None:
        return text + "\n" + rules_text.strip("\n") + "\n"
    for rule in default_protected(owner_names):
        lines += ["", "[[gate.protected]]", f"name = {q(rule['name'])}"]
        lines.append(f"tools = [{', '.join(q(t) for t in rule['tools'])}]")
        if rule.get("field"):
            lines.append(f"field = {q(rule['field'])}")
        lines.append("match = [")
        lines += [f"  {_toml_literal(m)}," for m in rule["match"]]
        lines.append("]")
        if rule.get("ignore_case"):
            lines.append("ignore_case = true")
    return "\n".join(lines) + "\n"


def _toml_literal(regex: str) -> str:
    """A regex as a TOML literal string (no escaping) when it has no single quote."""
    if "'" not in regex and "\n" not in regex:
        return f"'{regex}'"
    return json.dumps(regex, ensure_ascii=False)


def rules_of(text: str) -> str | None:
    """The `[[gate.protected]]` tables of an agent-side config, as written, or None."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == "[[gate.protected]]":
            return "\n".join(lines[i:]) + "\n"
    return None


def replace_channel(text: str, channel: Channel) -> str:
    """The core config text with [channel] (and an old [friend]) replaced by `channel`;
    every other line stays as written."""
    out: list[str] = []
    skipping = False
    for line in text.splitlines():
        if _TABLE_RE.match(line):
            name = line.strip().strip("[]").strip()
            skipping = name in _OLD_TABLES
        if not skipping:
            out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join([*out, "", *channel_toml(channel)]) + "\n"


def _backup(path: Path, stamp: str) -> Path | None:
    if not path.exists():
        return None
    target = path.with_name(f"{path.name}.bak-{stamp}")
    shutil.copy2(path, target)
    return target


def _write(path: Path, text: str, mode: int) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.chmod(mode)
    os.replace(tmp, path)


def _seed_bridge_state(state_file: Path, inbox: Path, out: TextIO) -> None:
    """A new agent's bridge starts with no delivered ids and would type every envelope
    already in the inbox (each one blocked as wrong_recipient or replayed). Mark them
    delivered, unless this agent's bridge has a state of its own."""
    if state_file.exists():
        return
    try:
        ids = sorted(p.stem for p in inbox.iterdir() if p.suffix == ".json")
    except FileNotFoundError:
        ids = []
    state_file.parent.mkdir(parents=True, exist_ok=True)
    _write(state_file, json.dumps({"delivered": ids}), 0o644)
    print(f"bridge state: {len(ids)} old envelope(s) marked delivered in {state_file}", file=out)


Runner = Callable[[Sequence[str]], "subprocess.CompletedProcess[str]"]


def _run(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(cmd), capture_output=True, text=True, timeout=30, check=False)


@dataclasses.dataclass
class SetRequest:
    config_path: Path
    agent: str
    project_dir: Path
    target: str
    agent_config: Path
    core_label: str
    bridge_label: str | None = None
    tmux: str | None = None
    owner_names: str | None = None
    timeout_s: float = 30.0


def channel_set(
    req: SetRequest,
    *,
    out: TextIO,
    status: Callable[[Config], dict[str, Any]],
    run: Runner = _run,
    ask: Path | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], datetime] = datetime.now,
) -> int:
    """Switch the channel agent. 0: the running core reports the new agent; else 1/2 with
    the reason on stderr (2: nothing was changed)."""

    def fail(message: str, code: int = 2) -> int:
        print(f"rhcore channel set: {message}", file=sys.stderr)
        return code

    # 1. Checks; nothing is written until they all pass.
    try:
        old_text = req.config_path.read_text(encoding="utf-8")
        doc = tomllib.loads(old_text)
        # A config from before [channel] may still have [friend]: its paths and window carry
        # over into the new [channel], and replace_channel() drops the table.
        old_friend = doc.pop("friend", None) or {}
        current = from_dict(doc, base=req.config_path.parent)
        check_agent_id(req.agent)
        project = req.project_dir.expanduser().resolve()
        base = current.channel or channel_from_dict(
            {
                "agent": req.agent,
                "project_dir": str(project),
                "target": req.target,
                **{
                    k: v
                    for k, v in old_friend.items()
                    if k in ("inbox_dir", "devices_file", "decide_window_s")
                },
            },
            req.config_path.parent,
        )
        new_channel = channel_from_dict(
            {
                k: v
                for k, v in {
                    "agent": req.agent,
                    "project_dir": str(project),
                    "target": req.target,
                    "inbox_dir": str(base.inbox_dir) if base.inbox_dir else None,
                    "devices_file": str(base.devices_file) if base.devices_file else None,
                    "decide_window_s": base.decide_window_s,
                }.items()
                if v is not None
            },
            req.config_path.parent,
        )
    except (OSError, tomllib.TOMLDecodeError, ValueError) as e:
        return fail(str(e))
    if not project.is_dir():
        return fail(f"project folder {project} does not exist")
    if current.team_file is None:
        return fail("no [agents] team_file in the core config: the id cannot be checked")
    try:
        members = [m.id for m in parse_team(current.team_file.read_text(encoding="utf-8"))]
    except OSError as e:
        return fail(f"cannot read the team file {current.team_file}: {e}")
    # The id takes part in paths and the Mac's file system ignores case.
    collisions = [m for m in members if m != req.agent and m.lower() == req.agent.lower()]
    if collisions:
        return fail(f"{req.agent} differs only in case from {collisions[0]} in the team file")
    if req.agent not in members:
        return fail(f"{req.agent} is not in the team file {current.team_file}")
    old_agent_text = (
        req.agent_config.read_text(encoding="utf-8") if req.agent_config.exists() else ""
    )
    tmux = req.tmux
    if tmux is None:
        try:
            tmux = str(tomllib.loads(old_agent_text).get("bridge", {}).get("tmux") or "tmux")
        except tomllib.TOMLDecodeError:
            tmux = "tmux"
    has = run([tmux, "has-session", "-t", req.target])
    if has.returncode != 0:
        return fail(f"no tmux session {req.target!r}: start the agent's session first")
    new_cfg = dataclasses.replace(current, channel=new_channel)
    new_text = replace_channel(old_text, new_channel)
    try:
        if from_dict(tomllib.loads(new_text), base=req.config_path.parent).channel != new_channel:
            return fail("the rewritten core config does not read back as the new channel")
        rules = rules_of(old_agent_text) if req.owner_names is None else None
        agent_text = agent_config_text(
            new_cfg,
            tmux=tmux,
            ask=ask or Path(sys.argv[0]).resolve().parent / "rh-friend-ask",
            owner_names=req.owner_names or DEFAULT_OWNER_NAMES,
            rules_text=rules,
        )
        parsed = friend_config.from_dict(tomllib.loads(agent_text), base=req.agent_config.parent)
        if parsed.agent != req.agent:
            return fail("the agent-side config does not read back as the new agent")
    except (ValueError, tomllib.TOMLDecodeError) as e:
        return fail(f"agent-side config: {e}")

    # 2. Write both configs, each with a backup.
    previous = current.channel.agent if current.channel else None
    stamp = clock().strftime("%Y%m%d-%H%M%S")
    backups = [b for b in (_backup(req.config_path, stamp), _backup(req.agent_config, stamp)) if b]
    _write(req.config_path, new_text, 0o600)
    _write(req.agent_config, agent_text, 0o644)
    for b in backups:
        print(f"backup: {b}", file=out)
    if parsed.bridge is not None:
        _seed_bridge_state(parsed.bridge.state_file, new_cfg.inbox_dir, out)

    # 3. Restart the core and wait until it reports the new agent.
    uid = os.getuid()
    restart = run(["launchctl", "kickstart", "-k", f"gui/{uid}/{req.core_label}"])
    if restart.returncode != 0:
        detail = (restart.stderr or restart.stdout).strip()
        return fail(f"core restart failed: {detail}; configs written, backups above", 1)
    deadline = time.monotonic() + req.timeout_s
    seen: str | None = None
    while True:
        try:
            seen = status(new_cfg).get("channel", {}).get("agent")
        except Exception:  # noqa: BLE001  (the core is still starting)
            seen = None
        if seen == req.agent:
            break
        if time.monotonic() >= deadline:
            return fail(
                f"the core does not report channel {req.agent!r} (got {seen!r}) after "
                f"{req.timeout_s:.0f} s; configs written, backups above",
                1,
            )
        sleep(0.5)
    if req.bridge_label:
        bridge = run(["launchctl", "kickstart", "-k", f"gui/{uid}/{req.bridge_label}"])
        if bridge.returncode != 0:
            detail = (bridge.stderr or bridge.stdout).strip()
            return fail(f"core switched, bridge restart failed: {detail}", 1)

    print(f"channel: {previous or '—'} → {req.agent} (core reports {seen})", file=out)
    print("Still yours to do:", file=out)
    print(
        f"  - hooks rh-friend-verify (UserPromptSubmit), rh-friend-gate (PreToolUse) and "
        f"rh-friend-reply (Stop) in {project}/.claude/settings.json "
        f"(--config {req.agent_config} --project {project})",
        file=out,
    )
    if previous and previous != req.agent:
        print(f"  - remove those hooks from {previous}'s project", file=out)
    if not req.bridge_label:
        print("  - restart the bridge (launchctl kickstart -k gui/<uid>/<bridge label>)", file=out)
    return 0


__all__ = ["SetRequest", "agent_config_text", "channel_set", "replace_channel", "rules_of"]
