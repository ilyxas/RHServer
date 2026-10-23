"""UserPromptSubmit hook for the Friend session: label every input by its proof.

    rh-friend-verify --config <friend.toml>      (reads the hook JSON on stdin)

- The input is exactly a pointer `⟦rh:<id>⟧`: load the envelope the core spooled
  under that id and re-check the phone's signature against the device list signed
  by the pinned core key. Valid: the text goes to the model with the label
  `[RH ✔ <owner> · <device> · <time>]`. Invalid: the input is blocked and the
  reason appended to the rejected log.
- Any other input: the label `[unsigned]`. What the input says about itself does
  not matter: only this hook's own context carries a verdict, and every input gets one.
- Outside the configured project the hook does nothing.
- With `require_protected = true` (managed install) a pointer is accepted only when
  the config and the device list, and their directories, cannot be changed by the
  user the hook runs as: they hold the trust anchors (pinned core key, devices).

The signed `exp` (60 s after `ts`) is not applied: delivery to a busy session can
take longer, so the hook uses its own window on `ts` instead.

The core, the spool and the bridge are transport only; a broken or replaced one
can make a message fail, never pass.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import fcntl
import json
import os
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from rh_common.crypto import b64d, verify_der
from rh_common.friend import (
    OP_SEND,
    POINTER_RE,
    DeviceEntry,
    Envelope,
    FriendMessage,
    parse_body,
    parse_envelope,
    read_devices_doc,
    spool_id,
)
from rh_common.protocol import ProtocolError, SignedObject, body_hash, parse_auth, parse_ts
from rh_friend import config as friend_config
from rh_friend.config import MAX_FUTURE_S, FriendConfig

VERIFIED_MARK = "RH ✔"
UNSIGNED_LABEL = "[unsigned]"


class Reject(Exception):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Verified:
    message: FriendMessage
    device: DeviceEntry
    obj: SignedObject


def check_envelope(
    envelope: Envelope,
    *,
    sid: str,
    devices: dict[str, DeviceEntry],
    now: datetime,
    window: timedelta,
    seen: Callable[[str], bool],
) -> Verified:
    """Order: malformed → pointer_mismatch → unknown_device → revoked_device →
    op_mismatch → wrong_key_level → bad_signature → body_mismatch → bad_body →
    too_old → from_future → replayed. Raises Reject."""
    try:
        obj, raw = parse_auth(envelope.auth)
        sig = b64d(envelope.sig)
    except (ProtocolError, ValueError) as e:
        raise Reject("malformed", str(e)) from e
    if spool_id(obj.nonce) != sid:
        raise Reject("pointer_mismatch", "the envelope does not belong to this pointer")
    device = devices.get(obj.device)
    if device is None:
        raise Reject("unknown_device", f"device {obj.device} is not in the device list")
    if device.status != "active":
        raise Reject("revoked_device", f"device {obj.device} is {device.status}")
    if obj.op != OP_SEND:
        raise Reject("op_mismatch", f"signed op {obj.op!r}, expected {OP_SEND!r}")
    if obj.key != "normal":
        raise Reject("wrong_key_level", f"{OP_SEND} is signed with the normal key")
    if not verify_der(device.keys["normal"], raw, sig):
        raise Reject("bad_signature", "signature does not match the device's normal key")
    if body_hash(envelope.body) != obj.body:
        raise Reject("body_mismatch", "body hash does not match the signed object")
    try:
        message = parse_body(envelope.body)
    except ValueError as e:
        raise Reject("bad_body", str(e)) from e
    ts = parse_ts(obj.ts)
    if now - ts > window:
        raise Reject("too_old", f"signed at {obj.ts}, older than {int(window.total_seconds())} s")
    if ts - now > timedelta(seconds=MAX_FUTURE_S):
        raise Reject("from_future", f"signed at {obj.ts}, ahead of this clock")
    if seen(obj.nonce):
        raise Reject("replayed", "this message was already delivered")
    return Verified(message=message, device=device, obj=obj)


# --- ledger and logs -----------------------------------------------------------------


@contextlib.contextmanager
def _locked(path: Path) -> Any:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a+", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            fh.seek(0)
            yield fh
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def _seen_nonces(fh: Any) -> set[str]:
    out = set()
    for line in fh.read().splitlines():
        with contextlib.suppress(ValueError, KeyError, TypeError):
            out.add(json.loads(line)["nonce"])
    return out


def _append(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


# --- the hook --------------------------------------------------------------------------


def _now() -> datetime:
    return datetime.now(UTC)


def handle(
    event: dict[str, Any],
    cfg: FriendConfig,
    *,
    project_dir: str | None,
    now: Callable[[], datetime] = _now,
) -> dict[str, Any] | None:
    """Hook output for one input, or None to do nothing (another project)."""
    if not project_dir or os.path.realpath(project_dir) != os.path.realpath(cfg.project_dir):
        return None
    prompt = str(event.get("prompt", ""))
    match = POINTER_RE.match(prompt.strip())
    if match is None:
        return _context(UNSIGNED_LABEL)
    sid = match.group(1)
    at = now()
    try:
        if cfg.require_protected:
            _check_protected(cfg)
        envelope = _load_envelope(cfg, sid)
        devices = _load_devices(cfg)
        with _locked(cfg.seen_file) as ledger:
            seen = _seen_nonces(ledger)
            verified = check_envelope(
                envelope,
                sid=sid,
                devices=devices,
                now=at,
                window=timedelta(seconds=cfg.window_s),
                seen=seen.__contains__,
            )
            ledger.seek(0, os.SEEK_END)
            ledger.write(json.dumps({"nonce": verified.obj.nonce, "id": sid, "at": _ts(at)}) + "\n")
            ledger.flush()
    except Reject as e:
        return _block(cfg, sid, e.code, e.detail)
    except Exception as e:  # fail closed on anything unexpected
        return _block(cfg, sid, "error", f"{type(e).__name__}: {e}")
    signed_at = parse_ts(verified.obj.ts).astimezone().strftime("%H:%M:%S")
    label = f"[{VERIFIED_MARK} {cfg.owner_label} · {verified.device.name} · {signed_at}]"
    return _context(f"{label}\n{verified.message.text}")


def _load_envelope(cfg: FriendConfig, sid: str) -> Envelope:
    path = cfg.inbox_dir / f"{sid}.json"
    try:
        data = path.read_bytes()
    except OSError as e:
        raise Reject("no_envelope", f"no envelope {sid}: {e.strerror}") from e
    try:
        return parse_envelope(data)
    except ValueError as e:
        raise Reject("malformed", str(e)) from e


def _load_devices(cfg: FriendConfig) -> dict[str, DeviceEntry]:
    try:
        data = (
            read_protected(cfg.devices_file)
            if cfg.require_protected
            else cfg.devices_file.read_bytes()
        )
    except OSError as e:
        raise Reject("devices_untrusted", f"cannot read the device list: {e.strerror}") from e
    try:
        return read_devices_doc(data, core_pub=cfg.core_key)
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise Reject("devices_untrusted", str(e) or type(e).__name__) from e


def _check_protected(cfg: FriendConfig) -> None:
    """The trust anchors must not be changeable by the user the hook runs as."""
    check_protected_path(cfg.devices_file)
    if cfg.source is not None:
        check_protected_path(cfg.source)


def check_protected_path(path: Path) -> None:
    """Neither the file nor any directory above it (as written and fully resolved) may be
    owned or writable by this user, so nothing on the way can be renamed or replaced.
    A world-writable directory passes only with the sticky bit and another owner."""
    uid = os.getuid()
    chains = {_chain(Path(os.path.abspath(path))), _chain(Path(os.path.realpath(path)))}
    for chain in chains:
        for p in chain:
            try:
                st = os.lstat(p)
            except OSError as e:
                raise Reject("unprotected", f"cannot stat {p}: {e.strerror}") from e
            if st.st_uid == uid:
                raise Reject("unprotected", f"{p} belongs to this user")
            if stat.S_ISLNK(st.st_mode):
                continue  # a link owned by someone else; its target is the resolved chain
            sticky = stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX
            if not sticky and (st.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or os.access(p, os.W_OK)):
                raise Reject("unprotected", f"{p} can be changed by this user")


def _chain(path: Path) -> tuple[Path, ...]:
    return (path, *path.parents)


def read_protected(path: Path) -> bytes:
    """Read a checked anchor without following a final symlink, from one descriptor."""
    check_protected_path(path)
    fd = os.open(os.path.realpath(path), os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if st.st_uid == os.getuid() or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise Reject("unprotected", f"{path} can be changed by this user")
        chunks = []
        while chunk := os.read(fd, 1 << 16):
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _ts(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _context(text: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": text}}


def _block(cfg: FriendConfig, sid: str | None, code: str, detail: str) -> dict[str, Any]:
    with contextlib.suppress(OSError):
        _append(cfg.rejected_log, {"at": _ts(_now()), "id": sid, "code": code, "detail": detail})
    return {
        "decision": "block",
        "reason": f"RemoteHands: message rejected ({code}): {detail}",
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
    }


def _unreadable(reason: str) -> dict[str, Any]:
    return {
        "decision": "block",
        "reason": f"RemoteHands: unreadable hook input ({reason})",
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
    }


def fallback(prompt: str, reason: str) -> dict[str, Any]:
    """When the hook cannot do its job: never pass a pointer, mark the rest unsigned."""
    if POINTER_RE.match(prompt.strip()):
        return {
            "decision": "block",
            "reason": f"RemoteHands: cannot verify ({reason})",
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
        }
    return _context(UNSIGNED_LABEL)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rh-friend-verify", description=__doc__)
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
    raw = sys.stdin.read()
    try:
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError("hook input is not an object")
    except ValueError as e:
        print(f"rh-friend-verify: {e}", file=sys.stderr)
        print(json.dumps(_unreadable(str(e))))
        return 0
    prompt = str(event.get("prompt", ""))
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
        out = handle(event, cfg, project_dir=project_dir)
    except Exception as e:  # config missing or broken, or a bug: fail closed
        print(f"rh-friend-verify: {type(e).__name__}: {e}", file=sys.stderr)
        out = fallback(prompt, type(e).__name__)
    if out is not None:
        print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
