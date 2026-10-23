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

    [gate]                                       # PreToolUse gate (rh-friend-gate)
    admin_socket = "<core data_dir>/admin.sock"  # where decisions are spent, once each
    decide_window_s = 120                        # how old an allow decision may be
    log = "~/Friend/log/rh_gate.jsonl"           # every allow the gate let through

    [[gate.protected]]                           # any matching rule makes a call protected
    name  = "resume or pause a process"
    tools = ["Bash"]                             # tool names; ["*"] for any tool
    field = "command"                            # a key of tool_input; omit for the whole input
    match = ["<regex>", ...]                     # all must be found (re.search)
    ignore_case = false
"""

from __future__ import annotations

import dataclasses
import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rh_common.crypto import b64d, load_public_x963
from rh_common.jcs import JCSError, canonicalize

DEFAULT_PATH = Path("~/Library/Application Support/RemoteHands/friend.toml").expanduser()
DEFAULT_WINDOW_S = 900
DEFAULT_DECIDE_WINDOW_S = 120  # an allow decision is good for two minutes
MAX_FUTURE_S = 120  # same clock tolerance as the core


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class BridgeConfig:
    tmux: str
    target: str
    state_file: Path


@dataclass(frozen=True)
class ProtectedRule:
    """A tool call is protected when its tool is listed and every regex is found in the
    chosen field of tool_input (or in the canonical JSON of the whole input)."""

    name: str
    tools: tuple[str, ...]  # exact tool names, or ("*",)
    match: tuple[re.Pattern[str], ...]
    field: str | None = None

    def applies(self, tool_name: str, tool_input: Any) -> bool:
        if "*" not in self.tools and tool_name not in self.tools:
            return False
        if self.field is None:
            try:
                hay = canonicalize(tool_input).decode("utf-8")
            except (JCSError, TypeError, ValueError):
                hay = json.dumps(tool_input, ensure_ascii=False, sort_keys=True, default=str)
        else:
            if not isinstance(tool_input, dict) or self.field not in tool_input:
                return False
            value = tool_input[self.field]
            hay = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        return all(p.search(hay) for p in self.match)


@dataclass(frozen=True)
class GateConfig:
    admin_socket: Path
    protected: tuple[ProtectedRule, ...]
    decide_window_s: int = DEFAULT_DECIDE_WINDOW_S
    log: Path | None = None


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
    gate: GateConfig | None = None
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
    "gate",
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
        gate=_gate(doc["gate"], path) if "gate" in doc else None,
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


def _gate(table: Any, path: Any) -> GateConfig:
    if not isinstance(table, dict):
        raise ConfigError("[gate] must be a table")
    unknown = set(table) - {"admin_socket", "decide_window_s", "log", "protected"}
    if unknown:
        raise ConfigError(f"unknown [gate] keys: {sorted(unknown)}")
    if not isinstance(table.get("admin_socket"), str) or not table["admin_socket"]:
        raise ConfigError("[gate] admin_socket is required")
    window = table.get("decide_window_s", DEFAULT_DECIDE_WINDOW_S)
    if isinstance(window, bool) or not isinstance(window, int) or window < 1:
        raise ConfigError("[gate] decide_window_s must be a positive integer (seconds)")
    log = table.get("log")
    if log is not None and (not isinstance(log, str) or not log):
        raise ConfigError("[gate] log must be a path")
    rules = table.get("protected", [])
    if not isinstance(rules, list):
        raise ConfigError("[[gate.protected]] must be an array of tables")
    return GateConfig(
        admin_socket=path(table["admin_socket"]),
        decide_window_s=window,
        log=path(log) if log else None,
        protected=tuple(_rule(r) for r in rules),
    )


def _rule(doc: Any) -> ProtectedRule:
    if not isinstance(doc, dict):
        raise ConfigError("[[gate.protected]] entries must be tables")
    where = f"[[gate.protected]] {doc.get('name', '?')}"
    unknown = set(doc) - {"name", "tools", "field", "match", "ignore_case"}
    if unknown:
        raise ConfigError(f"{where}: unknown keys {sorted(unknown)}")
    name = doc.get("name")
    if not isinstance(name, str) or not name:
        raise ConfigError(f"{where}: name is required")
    tools = doc.get("tools")
    if not isinstance(tools, list) or not tools or not all(isinstance(t, str) and t for t in tools):
        raise ConfigError(f"{where}: tools must be a non-empty list of tool names")
    field = doc.get("field")
    if field is not None and (not isinstance(field, str) or not field):
        raise ConfigError(f"{where}: field must be a non-empty string")
    patterns = doc.get("match")
    if not isinstance(patterns, list) or not patterns:
        raise ConfigError(f"{where}: match must be a non-empty list of regular expressions")
    ignore_case = doc.get("ignore_case", False)
    if not isinstance(ignore_case, bool):
        raise ConfigError(f"{where}: ignore_case must be true or false")
    flags = re.DOTALL | (re.IGNORECASE if ignore_case else 0)
    compiled = []
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern:
            raise ConfigError(f"{where}: match entries must be non-empty strings")
        try:
            compiled.append(re.compile(pattern, flags))
        except re.error as e:
            raise ConfigError(f"{where}: bad regex {pattern!r}: {e}") from e
    return ProtectedRule(name=name, tools=tuple(tools), match=tuple(compiled), field=field)


# Rules `rhcore friend-config` writes; the owner edits the file afterwards.
DEFAULT_PROTECTED: tuple[dict[str, Any], ...] = (
    {
        "name": "resume or pause a process (kill -CONT / -STOP)",
        "tools": ["Bash"],
        "field": "command",
        "match": [
            r"(^|[;&|(`]\s*)(sudo\s+)?(kill|pkill|killall)\b[^;&|]*"
            r"(\s-(s\s+)?(SIG)?(CONT|STOP)\b|\s-(17|18|19)\b)"
        ],
    },
    {
        "name": "a record that the owner allowed something (CGC)",
        "tools": ["Bash", "Write", "Edit", "MultiEdit"],
        # {owner}: the owner's names as written in records, e.g. "owner|владелец";
        # `rhcore friend-config --owner-names` fills it in, the file never names anyone here.
        "match": [r"CGC", r"({owner})[^\"\n]{0,40}(разреш|одобр|allow|approv)"],
        "ignore_case": True,
    },
    {
        "name": "rules and access: edit a settings or rules file",
        "tools": ["Write", "Edit", "MultiEdit", "NotebookEdit"],
        "field": "file_path",
        "match": [
            r"(/\.claude/|/CLAUDE\.md$|/LaunchAgents/|/LaunchDaemons/|managed-settings"
            r"|/friend\.toml$|/core\.toml$|/\.ssh/|authorized_keys|/sudoers)"
        ],
    },
    {
        "name": "rules and access: change a settings or rules file from the shell",
        "tools": ["Bash"],
        "field": "command",
        "match": [
            r"(\.claude/|CLAUDE\.md|LaunchAgents|LaunchDaemons|managed-settings"
            r"|friend\.toml|core\.toml|\.ssh/|authorized_keys|sudoers)",
            r"(>|\btee\b|\bsed\s+-i|\bcp\b|\bmv\b|\brm\b|\bln\b|\bchmod\b|\bchown\b"
            r"|\blaunchctl\s+(load|unload|bootstrap|bootout|enable|disable|kickstart)"
            r"|\bdefaults\s+write|\bpython3?\b|\bperl\b|\bruby\b|\bnode\b)",
        ],
    },
)


DEFAULT_OWNER_NAMES = "owner|владелец"


def default_protected(owner_names: str = DEFAULT_OWNER_NAMES) -> list[dict[str, Any]]:
    """The default rules with the owner's names (a regex alternation) filled in."""
    out = []
    for rule in DEFAULT_PROTECTED:
        doc = dict(rule)
        doc["match"] = [m.replace("{owner}", owner_names) for m in rule["match"]]
        out.append(doc)
    return out


def default_rules(owner_names: str = DEFAULT_OWNER_NAMES) -> tuple[ProtectedRule, ...]:
    return tuple(_rule(r) for r in default_protected(owner_names))
