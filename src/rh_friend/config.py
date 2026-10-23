"""Configuration of the Friend verifier and bridge (TOML).

Every path, the tmux target, the pinned core key and the freshness window come
from here; nothing about a particular Mac or person is built in.

    project_dir  = "~/Friend"                    # the hook acts only in this project
    inbox_dir    = "<core [friend] inbox_dir>"
    devices_file = "<core [friend] devices_file>"
    core_key     = "<base64 X9.63 core public key>"
    seen_file    = "~/Friend/state/rh_seen.jsonl"   # replay ledger; writable by the hook's
                                                 # user, so wiping it allows one repeat of
                                                 # a genuine message within window_s
    rejected_log = "~/Friend/log/rh_rejected.jsonl"
    window_s     = 900                           # how old a message may be when it arrives
    owner_label  = "owner"                       # shown in the verified label
    require_protected = false                    # true for the managed (root-owned) install

    [bridge]
    tmux   = "/opt/homebrew/bin/tmux"
    target = "friend"                            # tmux target (session or session:window.pane)
    state_file = "~/Friend/state/rh_bridge.json"
"""

from __future__ import annotations

import dataclasses
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rh_common.crypto import b64d, load_public_x963

DEFAULT_PATH = Path("~/Library/Application Support/RemoteHands/friend.toml").expanduser()
DEFAULT_WINDOW_S = 900
MAX_FUTURE_S = 120  # same clock tolerance as the core


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class BridgeConfig:
    tmux: str
    target: str
    state_file: Path


@dataclass(frozen=True)
class FriendConfig:
    project_dir: Path
    inbox_dir: Path
    devices_file: Path
    core_key: bytes
    seen_file: Path
    rejected_log: Path
    window_s: int = DEFAULT_WINDOW_S
    owner_label: str = "owner"
    bridge: BridgeConfig | None = None
    require_protected: bool = False  # managed install: anchors not writable by the hook's user
    source: Path | None = None  # the file this config was read from


_TOP = {
    "project_dir",
    "inbox_dir",
    "devices_file",
    "core_key",
    "seen_file",
    "rejected_log",
    "window_s",
    "owner_label",
    "bridge",
    "require_protected",
}
_REQUIRED = ("project_dir", "inbox_dir", "devices_file", "core_key", "seen_file", "rejected_log")


def load(path: Path) -> FriendConfig:
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"cannot read {path}: {e}") from e
    cfg = from_dict(doc, base=path.parent)
    return dataclasses.replace(cfg, source=path)


def from_dict(doc: dict[str, Any], *, base: Path = Path(".")) -> FriendConfig:
    unknown = set(doc) - _TOP
    if unknown:
        raise ConfigError(f"unknown keys: {sorted(unknown)}")
    missing = [k for k in _REQUIRED if not isinstance(doc.get(k), str) or not doc[k]]
    if missing:
        raise ConfigError(f"required: {missing}")

    def path(value: str) -> Path:
        p = Path(value).expanduser()
        return p if p.is_absolute() else base / p

    try:
        core_key = b64d(doc["core_key"])
        load_public_x963(core_key)
    except ValueError as e:
        raise ConfigError(f"core_key: {e}") from e
    window = doc.get("window_s", DEFAULT_WINDOW_S)
    if isinstance(window, bool) or not isinstance(window, int) or window < 1:
        raise ConfigError("window_s must be a positive integer (seconds)")
    protected = doc.get("require_protected", False)
    if not isinstance(protected, bool):
        raise ConfigError("require_protected must be true or false")
    label = doc.get("owner_label", "owner")
    if not isinstance(label, str) or not label:
        raise ConfigError("owner_label must be a non-empty string")
    return FriendConfig(
        project_dir=path(doc["project_dir"]),
        inbox_dir=path(doc["inbox_dir"]),
        devices_file=path(doc["devices_file"]),
        core_key=core_key,
        seen_file=path(doc["seen_file"]),
        rejected_log=path(doc["rejected_log"]),
        window_s=window,
        owner_label=label,
        bridge=_bridge(doc["bridge"], path) if "bridge" in doc else None,
        require_protected=protected,
    )


def _bridge(table: Any, path: Any) -> BridgeConfig:
    if not isinstance(table, dict):
        raise ConfigError("[bridge] must be a table")
    unknown = set(table) - {"tmux", "target", "state_file"}
    if unknown:
        raise ConfigError(f"unknown [bridge] keys: {sorted(unknown)}")
    for key in ("target", "state_file"):
        if not isinstance(table.get(key), str) or not table[key]:
            raise ConfigError(f"[bridge] {key} is required")
    tmux = table.get("tmux", "tmux")
    if not isinstance(tmux, str) or not tmux:
        raise ConfigError("[bridge] tmux must be a string")
    return BridgeConfig(tmux=tmux, target=table["target"], state_file=path(table["state_file"]))
