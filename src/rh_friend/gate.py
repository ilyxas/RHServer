"""PreToolUse hook for the channel agent's session: a protected tool call runs only on a fresh,
unused `allow` decision signed on the owner's phone for exactly that call.

    rh-friend-gate --config <friend.toml> --project <agent's project folder>   (hook JSON)

The gate must never paralyse the session. Its first step for every call is a local check
against the `[[gate.protected]]` rules; only a call that matches goes any further. So:

- Another project (CLAUDE_PROJECT_DIR differs from --project / the config): exit 0, nothing.
- The call matches no rule: exit 0, no output, whatever the state of the config, the core
  or the socket. Claude Code's own permission flow applies as usual.
- Protected: the action is the canonical JSON `{"input": <tool_input>, "tool": <name>}`.
  The gate reads every `friend.decide` envelope in the inbox for this action, re-checks the
  phone's signature against the device list signed by the pinned core key, and takes the
  newest one (by signed `ts`; a deny wins a tie). A deny blocks. An allow must be signed
  with the critical key and be at most `decide_window_s` old; then the core is asked over
  the admin socket to spend it (`friend.decision.use`, first use wins) and the call goes
  through with a label for the model. Anything else blocks (exit 2, the reason on stderr,
  appended to the rejected log): no decision, expired, already used, superseded by a newer
  question or deny, the core not answering, a broken config, a crash. The hook entry
  carries `"onFailure": "block"`, so a hook that cannot start or times out blocks a
  protected call as well (docs/decisions/004-pretooluse-onfailure.md); an unprotected call
  is only ever let through by this hook's silence, never blocked by its failure.
- No CLAUDE_PROJECT_DIR at all: protected calls are blocked, unprotected ones pass.

A plain call of `rh-friend-ask` (one command, no shell operators) is never protected,
whatever its arguments say: asking must not need an answer first.

Paths in `file_path`-like fields are resolved against the call's `cwd` before the rules
see them, so a relative "CLAUDE.md" is the file it names.

The gate never waits for the owner. It only looks for a decision that already exists;
asking is `rh-friend-ask`.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import os
import re
import shlex
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from rh_common.crypto import sha256_hex
from rh_common.friend import OP_DECIDE, Envelope, action_text, parse_envelope
from rh_common.protocol import ProtocolError, parse_auth, parse_ts
from rh_friend import config as friend_config
from rh_friend import core_socket
from rh_friend.config import FriendConfig, GateConfig, ProtectedRule, default_rules
from rh_friend.core_socket import SOCKET_TIMEOUT_S, CoreUnreachable
from rh_friend.verify import (
    VERIFIED_MARK,
    Reject,
    Verified,
    check_envelope,
    check_protected_path,
    read_current,
    read_protected,
)

QUESTION_RULE = "question mode"
ASK_PROGRAM = "rh-friend-ask"
# tool_input keys that name a file; resolved against cwd before the rules look at them.
PATH_FIELDS = ("file_path", "notebook_path", "path")

# Spend an allow decision: (decision id, action, question_sha256) -> the core's answer
# {"ok": True, ...} or {"ok": False, "error": <code>, "message": ...}. Raises
# CoreUnreachable when the core does not answer.
Spend = Callable[[str, str, str], dict[str, Any]]


@dataclass(frozen=True)
class Outcome:
    """What the hook does: nothing (None), allow (with a label) or block (code, detail)."""

    kind: str  # "none" | "allow" | "block"
    code: str | None = None
    detail: str | None = None
    label: str | None = None
    rule: str | None = None
    action: str | None = None
    decision_id: str | None = None

    @property
    def blocked(self) -> bool:
        return self.kind == "block"


# --- is this call protected? ----------------------------------------------------------------


def match_view(tool_input: Any, cwd: str | None) -> Any:
    """tool_input as the rules should see it: file paths made absolute (~ and cwd).

    The action text keeps the original input; only the matching uses this view."""
    if not isinstance(tool_input, dict):
        return tool_input
    view = dict(tool_input)
    for key in PATH_FIELDS:
        value = view.get(key)
        if isinstance(value, str) and value:
            view[key] = resolve_path(value, cwd)
    return view


def resolve_path(value: str, cwd: str | None) -> str:
    path = os.path.expanduser(value)
    if not os.path.isabs(path) and cwd:
        path = os.path.join(cwd, path)
    return os.path.normpath(path) if os.path.isabs(path) else path


def protected_by(
    rules: tuple[ProtectedRule, ...], tool_name: str, tool_input: Any, *, cwd: str | None = None
) -> str | None:
    """Name of the first rule the call matches, or None."""
    view = match_view(tool_input, cwd)
    for rule in rules:
        if rule.applies(tool_name, view):
            return rule.name
    return None


def ask_program(gate: GateConfig | None) -> Path:
    """The rh-friend-ask that is exempt: configured, else the one next to this interpreter."""
    if gate is not None and gate.ask is not None:
        return gate.ask
    return Path(sys.executable).parent / ASK_PROGRAM


_OPERATORS = {";", "&", "&&", "|", "||", "(", ")", "<", ">", ">>", "<<", ">|", "&>", "|&"}


def is_ask_call(tool_name: str, tool_input: Any, program: Path) -> bool:
    """A Bash call that runs exactly `<program> <args>` and nothing else.

    Quoted operators are arguments to the program and fine; an unquoted one, a newline,
    a backtick or `$(` means more than one command, and the rules decide as usual."""
    if tool_name != "Bash" or not isinstance(tool_input, dict):
        return False
    command = tool_input.get("command")
    if not isinstance(command, str) or not command.strip():
        return False
    if "\n" in command or "`" in command or "$(" in command:
        return False
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        tokens = list(lexer)
    except ValueError:
        return False
    if not tokens or any(t in _OPERATORS or set(t) <= set(";&|<>()") for t in tokens):
        return False
    first = os.path.expanduser(tokens[0])
    if not os.path.isabs(first):
        return False
    want = str(program)
    return first == want or os.path.realpath(first) == os.path.realpath(want)


def rule_for(
    cfg: FriendConfig | None, tool_name: str, tool_input: Any, cwd: str | None
) -> str | None:
    """The protected rule this call matches, or None. Without a usable config the default
    rules decide, so a broken config still tells protected calls from the rest. With a
    config, question mode (the owner's current message is a question) protects every call
    that is not read-only, after the rules."""
    gate = cfg.gate if cfg is not None else None
    if is_ask_call(tool_name, tool_input, ask_program(gate)):
        return None
    rules = gate.protected if gate is not None else default_rules()
    rule = protected_by(rules, tool_name, tool_input, cwd=cwd)
    if rule is None and cfg is not None:
        rule = question_rule(cfg, tool_name, tool_input)
    return rule


# --- question mode ------------------------------------------------------------------------

_SPLIT_RE = re.compile(r"\|\||&&|[|;\n]")
_REDIRECT_RE = re.compile(r"(^|[^<>])[<>]|&>|\$\(|`")


def read_only_bash(command: str, allowed: tuple[str, ...]) -> bool:
    """True when every segment of the command (split at |, ||, &&, ; and newlines) starts
    with one of the allowed spellings (first word, or first words such as "git log") and
    nothing redirects, substitutes or escalates (no < > &> `backticks` $( ), no sudo, tee,
    xargs, env or eval as a word). The list is a convenience for the owner's questions,
    not a sandbox: the protected rules still apply first, and a task lifts the mode."""
    if not isinstance(command, str) or not command.strip():
        return False
    if _REDIRECT_RE.search(command):
        return False
    for segment in _SPLIT_RE.split(command):
        words = segment.strip().split()
        if not words:
            continue
        if any(w in _NEVER_READ_ONLY or _runs_something(w) for w in words):
            return False
        head = " ".join(words[:3])
        if not any(head == a or head.startswith(a + " ") for a in allowed):
            return False
    return True


_NEVER_READ_ONLY = frozenset({"sudo", "tee", "xargs", "env", "eval", "exec", "nohup", "source"})
_DASHED_RUNNERS = frozenset({"exec", "execdir", "ok", "okdir", "delete"})  # find's actions


def _runs_something(word: str) -> bool:
    return word.startswith("-") and word.lstrip("-") in _DASHED_RUNNERS


def question_rule(cfg: FriendConfig, tool_name: str, tool_input: Any) -> str | None:
    """In question mode, the synthetic rule a non-read-only call falls under, else None.
    No note, a closed one or an unreadable one means no mode (the rules alone)."""
    current = read_current(cfg)
    if current is None or current.get("kind") != "question":
        return None
    gate = cfg.gate
    tools = gate.question_tools if gate is not None else friend_config.DEFAULT_QUESTION_TOOLS
    if tool_name in tools:
        return None
    if tool_name == "Bash" and isinstance(tool_input, dict):
        spellings = gate.question_bash if gate is not None else friend_config.DEFAULT_QUESTION_BASH
        if read_only_bash(str(tool_input.get("command", "")), spellings):
            return None
    return f"{QUESTION_RULE} ⟦rh:{current['id']}⟧"


# --- decisions in the inbox -----------------------------------------------------------------


@dataclass(frozen=True)
class Candidate:
    sid: str
    verified: Verified | None
    code: str | None  # why it does not fit, or None when it is a usable allow
    detail: str | None
    signed_at: datetime | None
    written_ns: int = 0  # the envelope file's mtime: breaks ties within one second
    decision: str | None = None  # "allow" | "deny" as the body says, verified or not

    @property
    def is_deny(self) -> bool:
        return self.decision == "deny"


def candidates(
    inbox: Path,
    *,
    action: str,
    devices: Any,
    now: datetime,
    window: timedelta,
    agent: str,
) -> list[Candidate]:
    """Every decide envelope for this action, newest first (a deny before an allow signed
    at the same second), with why it fails if it does.

    Envelopes for other actions and friend.send envelopes are not candidates at all."""
    found: list[Candidate] = []
    try:
        files = [p for p in inbox.iterdir() if p.suffix == ".json" and not p.name.startswith(".")]
    except FileNotFoundError:
        return []
    for path in files:
        sid = path.stem
        try:
            envelope = parse_envelope(path.read_bytes())
            obj, _ = parse_auth(envelope.auth)
            written_ns = path.stat().st_mtime_ns
        except (OSError, ValueError, ProtocolError):
            continue  # not an envelope; the verifier reports those when they are delivered
        if obj.op != OP_DECIDE:
            continue
        said = _body_fields(envelope)
        if said.get("action") != action:
            continue
        decision = said.get("decision") if said.get("decision") in ("allow", "deny") else None
        signed_at: datetime | None = None
        with contextlib.suppress(ValueError):
            signed_at = parse_ts(obj.ts)
        try:
            verified = check_envelope(
                envelope,
                sid=sid,
                devices=devices,
                now=now,
                window=window,
                seen=lambda nonce: False,  # single use is the core's count, not a ledger here
                agent=agent,
                ops=(OP_DECIDE,),
            )
        except Reject as e:
            code = "expired" if e.code == "too_old" else e.code
            found.append(Candidate(sid, None, code, e.detail, signed_at, written_ns, decision))
            continue
        assert verified.decision is not None
        if verified.decision.action != action:
            continue
        if verified.decision.decision != "allow":
            found.append(
                Candidate(
                    sid,
                    verified,
                    "denied",
                    "the owner denied this action",
                    signed_at,
                    written_ns,
                    "deny",
                )
            )
            continue
        found.append(Candidate(sid, verified, None, None, signed_at, written_ns, "allow"))
    found.sort(
        key=lambda c: (
            c.signed_at or datetime.min.replace(tzinfo=UTC),
            c.is_deny,  # at the same instant the deny comes first
            c.written_ns,
            c.sid,
        ),
        reverse=True,
    )
    return found


def _body_fields(envelope: Envelope) -> dict[str, Any]:
    """The raw body as a dict (pre-filter; the signature check comes later), or {}."""
    try:
        doc = json.loads(envelope.body)
    except (ValueError, UnicodeDecodeError):
        return {}
    return doc if isinstance(doc, dict) else {}


def decide(
    tool_name: str,
    tool_input: Any,
    cfg: FriendConfig,
    *,
    now: datetime,
    spend: Spend,
    cwd: str | None = None,
) -> Outcome:
    """The gate's verdict for one tool call (the protected check included).

    For one action the newest decision counts: a deny blocks even when an older unused
    allow exists; an allow is spent only when nothing newer is in the inbox."""
    rule = rule_for(cfg, tool_name, tool_input, cwd)
    if rule is None:
        return Outcome("none")
    gate = cfg.gate
    if gate is None:
        return Outcome(
            "block", code="no_gate_config", detail="friend.toml has no [gate] table", rule=rule
        )
    try:
        action = action_text(tool_name, tool_input)
    except ValueError as e:
        return Outcome("block", code="bad_tool_input", detail=str(e), rule=rule)
    if cfg.require_protected:
        check_protected_path(cfg.devices_file)
        if cfg.source is not None:
            check_protected_path(cfg.source)
    devices = _load_devices(cfg)
    window = timedelta(seconds=gate.decide_window_s)
    found = candidates(
        cfg.inbox_dir, action=action, devices=devices, now=now, window=window, agent=cfg.agent
    )
    if not found:
        detail = f"no decision for this {tool_name} call"
        if rule.startswith(QUESTION_RULE):
            detail = (
                f"the owner asked a question ({rule[len(QUESTION_RULE) + 1 :]}), not for work: "
                f"answer in text, or ask with rh-friend-ask for exactly this {tool_name} call, "
                "or tell the owner it needs a task"
            )
        return Outcome("block", code="no_decision", detail=detail, rule=rule, action=action)
    latest = found[0]
    if latest.code is not None or latest.verified is None or latest.verified.decision is None:
        return Outcome(
            "block",
            code=latest.code or "refused",
            detail=latest.detail or "",
            rule=rule,
            action=action,
        )
    try:
        answer = spend(latest.sid, action, latest.verified.decision.question_sha256)
    except CoreUnreachable as e:
        return Outcome("block", code="core_unreachable", detail=str(e), rule=rule, action=action)
    if answer.get("ok") is True:
        signed = latest.verified.obj.ts
        label = (
            f"[{VERIFIED_MARK} {cfg.owner_label} · {latest.verified.device.name} · "
            f"{parse_ts(signed).astimezone():%H:%M:%S} · allow ⟦rh:{latest.sid}⟧]"
        )
        return Outcome("allow", label=label, rule=rule, action=action, decision_id=latest.sid)
    return Outcome(
        "block",
        code=str(answer.get("error") or "refused"),
        detail=str(answer.get("message", "")),
        rule=rule,
        action=action,
    )


def _load_devices(cfg: FriendConfig) -> Any:
    from rh_common.friend import read_devices_doc

    data = (
        read_protected(cfg.devices_file) if cfg.require_protected else cfg.devices_file.read_bytes()
    )
    return read_devices_doc(data, core_pub=cfg.core_key)


# --- the admin socket ---------------------------------------------------------------------


def spend_over_socket(gate: GateConfig) -> Spend:
    def spend(decision_id: str, action: str, question_sha256: str) -> dict[str, Any]:
        answer: dict[str, Any] = core_socket.call(
            gate.admin_socket,
            {
                "cmd": "friend.decision.use",
                "id": decision_id,
                "action": action,
                "question_sha256": question_sha256,
            },
            timeout=SOCKET_TIMEOUT_S,
        )
        return answer

    return spend


# --- the hook ------------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


def _ts(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append(path: Path | None, record: dict[str, Any]) -> None:
    if path is None:
        return
    with contextlib.suppress(OSError):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def handle(
    event: dict[str, Any],
    cfg: FriendConfig,
    *,
    project_dir: str | None,
    now: Callable[[], datetime] = _now,
    spend: Spend | None = None,
) -> Outcome:
    """Outcome for one PreToolUse event; logs it.

    Unprotected calls are never touched. A protected call fails closed on anything
    unexpected, including a missing CLAUDE_PROJECT_DIR."""
    if project_dir is not None and os.path.realpath(project_dir) != os.path.realpath(
        cfg.project_dir
    ):
        return Outcome("none")
    tool_name = str(event.get("tool_name", ""))
    tool_input = event.get("tool_input")
    cwd = event.get("cwd") if isinstance(event.get("cwd"), str) else None
    try:
        rule = rule_for(cfg, tool_name, tool_input, cwd)
    except Exception as e:  # the rules could not be applied: treat the call as protected
        rule = f"error: {type(e).__name__}"
    if rule is None:
        return Outcome("none")
    at = now()
    if project_dir is None:
        return _log(
            cfg,
            Outcome(
                "block",
                code="no_project_dir",
                detail="CLAUDE_PROJECT_DIR is not set; protected calls need it",
                rule=rule,
                action=_safe_action(tool_name, tool_input),
            ),
            at,
            tool_name=tool_name,
        )
    try:
        if spend is None:
            if cfg.gate is None:
                raise friend_config.ConfigError("friend.toml has no [gate] table")
            spend = spend_over_socket(cfg.gate)
        out = decide(tool_name, tool_input, cfg, now=at, spend=spend, cwd=cwd)
    except friend_config.ConfigError as e:
        out = Outcome(
            "block", "no_gate_config", str(e), rule=rule, action=_safe_action(tool_name, tool_input)
        )
    except CoreUnreachable as e:
        out = Outcome(
            "block",
            "core_unreachable",
            str(e),
            rule=rule,
            action=_safe_action(tool_name, tool_input),
        )
    except Reject as e:
        out = Outcome(
            "block", e.code, e.detail, rule=rule, action=_safe_action(tool_name, tool_input)
        )
    except Exception as e:  # fail closed, protected calls only
        out = Outcome(
            "block",
            "error",
            f"{type(e).__name__}: {e}",
            rule=rule,
            action=_safe_action(tool_name, tool_input),
        )
    return _log(cfg, out, at, tool_name=tool_name)


def _safe_action(tool_name: str, tool_input: Any) -> str | None:
    try:
        return action_text(tool_name, tool_input)
    except ValueError:
        return None


def _log(cfg: FriendConfig, out: Outcome, at: datetime, *, tool_name: str = "") -> Outcome:
    if out.kind == "none":
        return out
    record: dict[str, Any] = {
        "at": _ts(at),
        "hook": "gate",
        "agent": cfg.agent,
        "tool": tool_name,
        "rule": out.rule,
        "action_sha256": sha256_hex(out.action.encode("utf-8")) if out.action else None,
        "result": out.kind,
        "code": out.code,
        "detail": out.detail,
        "decision": out.decision_id,
    }
    record = {k: v for k, v in record.items() if v is not None}
    if out.blocked:
        _append(cfg.rejected_log, record)
    _append(cfg.gate.log if cfg.gate else None, record)
    return out


def _print_allow(out: Outcome) -> None:
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "additionalContext": f"{out.label}\n"
                    "RemoteHands gate: decision spent for this call.",
                }
            },
            ensure_ascii=False,
        )
    )


def _block(code: str, detail: str) -> int:
    print(f"RemoteHands gate: blocked ({code}): {detail}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rh-friend-gate", description=__doc__)
    parser.add_argument("--config", type=Path, default=friend_config.DEFAULT_PATH)
    parser.add_argument(
        "--project",
        type=Path,
        help="act only in this project; checked before the config is read",
    )
    parser.add_argument(
        "--require-protected",
        action="store_true",
        help="managed install: the config and the device list must not be changeable by "
        "this user (the config cannot turn this off)",
    )
    args = parser.parse_args(argv)
    project_dir = os.environ.get("CLAUDE_PROJECT_DIR")
    if (
        args.project is not None
        and project_dir
        and os.path.realpath(project_dir) != os.path.realpath(args.project)
    ):
        return 0  # another project: not ours
    try:
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            raise ValueError("hook input is not an object")
    except ValueError as e:
        return _block("unreadable_input", str(e))  # cannot tell protected from not: closed
    tool_name = str(event.get("tool_name", ""))
    tool_input = event.get("tool_input")
    cwd = event.get("cwd") if isinstance(event.get("cwd"), str) else None

    cfg: FriendConfig | None = None
    config_error: str | None = None
    try:
        if args.require_protected:
            check_protected_path(args.config)
        cfg = friend_config.load(args.config)
        if args.require_protected:
            cfg = dataclasses.replace(cfg, require_protected=True)
        if args.project is not None and os.path.realpath(cfg.project_dir) != os.path.realpath(
            args.project
        ):
            raise ValueError("--project and the config's project_dir differ")
    except Exception as e:
        config_error = f"{type(e).__name__}: {e}"
    # The protected check comes first, with the default rules when the config is unusable:
    # an unprotected call is never blocked by a broken config or a missing variable.
    try:
        rule = rule_for(cfg if config_error is None else None, tool_name, tool_input, cwd)
    except Exception as e:
        rule = f"error: {type(e).__name__}"
    if rule is None:
        return 0
    if config_error is not None or cfg is None:
        return _block("config", config_error or "no config")
    out = handle(event, cfg, project_dir=project_dir)
    if out.kind == "none":
        return 0
    if out.kind == "allow":
        _print_allow(out)
        return 0
    return _block(out.code or "blocked", out.detail or "")


if __name__ == "__main__":
    sys.exit(main())
