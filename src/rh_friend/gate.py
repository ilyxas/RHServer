"""PreToolUse hook for the Friend session: a protected tool call runs only on a fresh,
unused `allow` decision signed on the owner's phone for exactly that call.

    rh-friend-gate --config <friend.toml> --project <Friend folder>   (hook JSON on stdin)

- Not the Friend project (CLAUDE_PROJECT_DIR differs): exit 0 at once, no output.
- The call matches no `[[gate.protected]]` rule: exit 0, no output; Claude Code's own
  permission flow applies as usual.
- Protected: the action is the canonical JSON `{"input": <tool_input>, "tool": <name>}`.
  The gate reads every `friend.decide` envelope in the inbox, re-checks the phone's
  signature against the device list signed by the pinned core key, and keeps the ones
  that say `allow`, are signed with the critical key, name this exact action and are
  at most `decide_window_s` old. For each, newest first, it asks the core over the
  admin socket to spend the decision (`friend.decision.use`, first use wins). The first
  one spent lets the call through, with a label for the model. Otherwise the call is
  blocked (exit 2, the reason on stderr) and the reason appended to the rejected log.
- Anything unexpected (bad config, a crash, the core not answering) blocks too. The hook
  entry must carry `"onFailure": "block"`, so a hook that cannot start or times out
  blocks as well (docs/decisions/004-pretooluse-onfailure.md).

The gate never waits for the owner. It only looks for a decision that already exists;
asking is `rh-friend-ask`.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import os
import socket
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
from rh_friend.config import FriendConfig, GateConfig, ProtectedRule
from rh_friend.verify import (
    VERIFIED_MARK,
    Reject,
    Verified,
    check_envelope,
    check_protected_path,
    read_protected,
)

SOCKET_TIMEOUT_S = 5.0

# Spend an allow decision: (decision id, action, question_sha256) -> the core's answer
# {"ok": True, ...} or {"ok": False, "error": <code>, "message": ...}. Raises
# CoreUnreachable when the core does not answer.
Spend = Callable[[str, str, str], dict[str, Any]]


class CoreUnreachable(Exception):
    pass


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


def protected_by(rules: tuple[ProtectedRule, ...], tool_name: str, tool_input: Any) -> str | None:
    """Name of the first rule the call matches, or None."""
    for rule in rules:
        if rule.applies(tool_name, tool_input):
            return rule.name
    return None


@dataclass(frozen=True)
class Candidate:
    sid: str
    verified: Verified | None
    code: str | None  # why it does not fit, or None when it is a usable allow
    detail: str | None
    signed_at: datetime | None
    written_ns: int = 0  # the envelope file's mtime: breaks ties within one second


def candidates(
    inbox: Path,
    *,
    action: str,
    devices: Any,
    now: datetime,
    window: timedelta,
) -> list[Candidate]:
    """Every decide envelope for this action, newest first, with why it fails if it does.

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
        if not _names_action(envelope, action):
            continue
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
                ops=(OP_DECIDE,),
            )
        except Reject as e:
            code = "expired" if e.code == "too_old" else e.code
            found.append(Candidate(sid, None, code, e.detail, signed_at, written_ns))
            continue
        assert verified.decision is not None
        if verified.decision.action != action:
            continue
        if verified.decision.decision != "allow":
            found.append(
                Candidate(
                    sid, verified, "denied", "the owner denied this action", signed_at, written_ns
                )
            )
            continue
        found.append(Candidate(sid, verified, None, None, signed_at, written_ns))
    found.sort(
        key=lambda c: (c.signed_at or datetime.min.replace(tzinfo=UTC), c.written_ns, c.sid),
        reverse=True,
    )
    return found


def _names_action(envelope: Envelope, action: str) -> bool:
    """Cheap pre-filter on the raw body: the exact action text must be in it."""
    try:
        doc = json.loads(envelope.body)
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(doc, dict) and doc.get("action") == action


def decide(
    tool_name: str,
    tool_input: Any,
    cfg: FriendConfig,
    *,
    now: datetime,
    spend: Spend,
) -> Outcome:
    """The gate's verdict for one tool call (the protected check included)."""
    gate = cfg.gate
    if gate is None:
        return Outcome("block", code="no_gate_config", detail="friend.toml has no [gate] table")
    rule = protected_by(gate.protected, tool_name, tool_input)
    if rule is None:
        return Outcome("none")
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
    found = candidates(cfg.inbox_dir, action=action, devices=devices, now=now, window=window)
    for c in found:
        if c.code is not None or c.verified is None or c.verified.decision is None:
            continue
        try:
            answer = spend(c.sid, action, c.verified.decision.question_sha256)
        except CoreUnreachable as e:
            return Outcome(
                "block", code="core_unreachable", detail=str(e), rule=rule, action=action
            )
        if answer.get("ok") is True:
            signed = c.verified.obj.ts
            label = (
                f"[{VERIFIED_MARK} {cfg.owner_label} · {c.verified.device.name} · "
                f"{parse_ts(signed).astimezone():%H:%M:%S} · allow ⟦rh:{c.sid}⟧]"
            )
            return Outcome("allow", label=label, rule=rule, action=action, decision_id=c.sid)
        code = str(answer.get("error") or "refused")
        refused = dataclasses.replace(c, code=code, detail=str(answer.get("message", "")))
        found = [refused if x is c else x for x in found]  # keep the order, record the reason
    if not found:
        return Outcome(
            "block",
            code="no_decision",
            detail=f"no allow decision for this {tool_name} call",
            rule=rule,
            action=action,
        )
    first = found[0]
    return Outcome(
        "block", code=first.code or "refused", detail=first.detail or "", rule=rule, action=action
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
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(SOCKET_TIMEOUT_S)
        try:
            s.connect(str(gate.admin_socket))
            f = s.makefile("rw", encoding="utf-8", newline="\n")
            f.write(
                json.dumps(
                    {
                        "cmd": "friend.decision.use",
                        "id": decision_id,
                        "action": action,
                        "question_sha256": question_sha256,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
            f.flush()
            line = f.readline()
        except OSError as e:
            raise CoreUnreachable(f"{gate.admin_socket}: {e}") from e
        finally:
            s.close()
        if not line:
            raise CoreUnreachable("the core closed the admin socket without an answer")
        try:
            answer = json.loads(line)
        except ValueError as e:
            raise CoreUnreachable(f"unreadable answer from the core: {e}") from e
        if not isinstance(answer, dict):
            raise CoreUnreachable("unreadable answer from the core")
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
    """Outcome for one PreToolUse event; logs it. Fails closed on anything unexpected."""
    if not project_dir or os.path.realpath(project_dir) != os.path.realpath(cfg.project_dir):
        return Outcome("none")
    tool_name = str(event.get("tool_name", ""))
    tool_input = event.get("tool_input")
    at = now()
    try:
        if spend is None:
            if cfg.gate is None:
                return _log(
                    cfg,
                    Outcome(
                        "block", code="no_gate_config", detail="friend.toml has no [gate] table"
                    ),
                    at,
                )
            spend = spend_over_socket(cfg.gate)
        out = decide(tool_name, tool_input, cfg, now=at, spend=spend)
    except CoreUnreachable as e:
        out = Outcome(
            "block", "core_unreachable", str(e), action=_safe_action(tool_name, tool_input)
        )
    except Reject as e:
        out = Outcome("block", e.code, e.detail, action=_safe_action(tool_name, tool_input))
    except Exception as e:  # fail closed
        out = Outcome(
            "block", "error", f"{type(e).__name__}: {e}", action=_safe_action(tool_name, tool_input)
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
    if args.project is not None and (
        not project_dir or os.path.realpath(project_dir) != os.path.realpath(args.project)
    ):
        return 0
    try:
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            raise ValueError("hook input is not an object")
    except ValueError as e:
        return _block("unreadable_input", str(e))
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
    except Exception as e:  # no config: every call in this project is blocked? No: only
        # protected ones should be, but without rules nothing can be told apart. Fail closed.
        return _block("config", f"{type(e).__name__}: {e}")
    out = handle(event, cfg, project_dir=project_dir)
    if out.kind == "none":
        return 0
    if out.kind == "allow":
        _print_allow(out)
        return 0
    return _block(out.code or "blocked", out.detail or "")


if __name__ == "__main__":
    sys.exit(main())
