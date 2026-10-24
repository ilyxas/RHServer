"""Configuration of the agent-side verifier, bridge and gate (TOML).

Every path, the agent's id, the tmux target, the pinned core key and the freshness
window come from here; nothing about a particular Mac, person or agent is built in.
`rhcore friend-config` and `rhcore channel set` write it from the core's [channel].

    agent        = "<[channel] agent>"           # messages must be addressed to it
    project_dir  = "<[channel] project_dir>"     # the hook acts only in this project
    inbox_dir    = "<core inbox_dir>"
    devices_file = "<core devices_file>"
    core_key     = "<base64 X9.63 core public key>"
    seen_file    = "<project_dir>/state/rh_seen.jsonl"   # default; replay ledger, writable
                                                 # by the hook's user, so wiping it allows
                                                 # one repeat of a genuine message
    rejected_log = "<project_dir>/log/rh_rejected.jsonl" # default
    window_s     = 900                           # how old a message may be when it arrives
    owner_label  = "owner"                       # shown in the verified label
    require_protected = false                    # true for the managed (root-owned) install

    [bridge]
    tmux   = "/opt/homebrew/bin/tmux"
    target = "<[channel] target>"                # tmux target (session or session:window.pane)
    state_file = "<project_dir>/state/rh_bridge.json"    # default

    [gate]                                       # PreToolUse gate (rh-friend-gate)
    admin_socket = "<core data_dir>/admin.sock"  # where decisions are spent, once each
    decide_window_s = 120                        # how old an allow decision may be
    log = "<project_dir>/log/rh_gate.jsonl"      # default; every verdict on a protected call
    ask = "<venv>/bin/rh-friend-ask"             # a plain call of this program is never
                                                 # protected (asking must not need an answer)

    [[gate.protected]]                           # any matching rule makes a call protected
    name  = "resume or pause a process"
    tools = ["Bash"]                             # tool names; ["*"] for any tool
    field = "command"                            # a key of tool_input; omit for the whole input
    match = ["<regex>", ...]                     # all must be found (re.search; DOTALL,
                                                 # MULTILINE)
    ignore_case = false

The rules are a seat belt, not a sandbox: they catch the obvious spelling of a protected
action so the owner is asked. Another spelling, a script or Python can do the same thing
under the same user; the honest guarantee comes with separate users (stage 7), when the
core does the dangerous actions under its own user on a signed decision.
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
from rh_common.friend import check_agent_id
from rh_common.jcs import JCSError, canonicalize

DEFAULT_PATH = Path("~/Library/Application Support/RemoteHands/friend.toml").expanduser()
DEFAULT_WINDOW_S = 900
DEFAULT_DECIDE_WINDOW_S = 120  # an allow decision is good for two minutes
MAX_FUTURE_S = 120  # same clock tolerance as the core
# Defaults inside the agent's project folder.
SEEN_FILE = Path("state/rh_seen.jsonl")
REJECTED_LOG = Path("log/rh_rejected.jsonl")
BRIDGE_STATE_FILE = Path("state/rh_bridge.json")
GATE_LOG = Path("log/rh_gate.jsonl")
STATE_FILE = Path("state/rh_current.json")  # the owner's message the session is on
DEFAULT_REPORT_TIMEOUT_S = 2.0
# Question mode (the owner sent a question, not a task): these tools run freely, every
# other call is treated as protected and goes through a decision or a task.
DEFAULT_QUESTION_TOOLS = (
    "Read",
    "Glob",
    "Grep",
    "LS",
    "WebFetch",
    "WebSearch",
    "TodoWrite",
    "Task",
    "AskUserQuestion",
)
# Read-only shell commands, by first word of every segment; see gate.read_only_bash.
DEFAULT_QUESTION_BASH = (
    "ps",
    "top",
    "vm_stat",
    "memory_pressure",
    "df",
    "du",
    "ls",
    "cat",
    "head",
    "tail",
    "wc",
    "grep",
    "rg",
    "find",
    "stat",
    "file",
    "uptime",
    "who",
    "whoami",
    "id",
    "date",
    "uname",
    "sw_vers",
    "sysctl",
    "lsof",
    "netstat",
    "ifconfig",
    "pgrep",
    "launchctl list",
    "launchctl print",
    "git status",
    "git log",
    "git diff",
    "git show",
    "git branch",
    "git remote",
    "git rev-parse",
    "gh pr view",
    "gh pr list",
    "gh pr checks",
    "gh run list",
    "uv run pytest",
    "uv run ruff check",
    "uv run mypy",
    "tmux list-sessions",
    "tmux list-windows",
    "tmux capture-pane",
    "echo",
    "printf",
    "sort",
    "uniq",
    "cut",
    "awk",
    "sed",
    "tr",
    "xxd",
    "jq",
    "python3 -c",
    "python -c",
)


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class BridgeConfig:
    tmux: str
    target: str
    state_file: Path
    interrupt: bool = True  # one Escape before the pointer: the owner's message interrupts


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
    ask: Path | None = None  # rh-friend-ask; None: the one next to this interpreter
    question_tools: tuple[str, ...] = DEFAULT_QUESTION_TOOLS
    question_bash: tuple[str, ...] = DEFAULT_QUESTION_BASH
    report_timeout_s: float = DEFAULT_REPORT_TIMEOUT_S  # for the hooks' receipts and replies


@dataclass(frozen=True)
class FriendConfig:
    agent: str  # the channel agent this session is; `to` of every envelope must match
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
    state_file: Path | None = None  # None: project_dir/state/rh_current.json

    @property
    def current_file(self) -> Path:
        """Where the verifier notes the owner's message the session is on (id, kind,
        prompt_id); the gate reads the kind, the Stop hook the id."""
        return self.state_file or self.project_dir / STATE_FILE


_TOP = {
    "agent",
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
    "state_file",
}
_REQUIRED = ("agent", "project_dir", "inbox_dir", "devices_file", "core_key")


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
        agent = check_agent_id(doc["agent"])
    except ValueError as e:
        raise ConfigError(str(e)) from e
    project = path(doc["project_dir"])
    for key in ("seen_file", "rejected_log", "state_file"):
        if key in doc and (not isinstance(doc[key], str) or not doc[key]):
            raise ConfigError(f"{key} must be a path")
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
        agent=agent,
        project_dir=project,
        inbox_dir=path(doc["inbox_dir"]),
        devices_file=path(doc["devices_file"]),
        core_key=core_key,
        seen_file=path(doc["seen_file"]) if "seen_file" in doc else project / SEEN_FILE,
        rejected_log=(
            path(doc["rejected_log"]) if "rejected_log" in doc else project / REJECTED_LOG
        ),
        window_s=window,
        owner_label=label,
        bridge=_bridge(doc["bridge"], path, project) if "bridge" in doc else None,
        gate=_gate(doc["gate"], path, project) if "gate" in doc else None,
        require_protected=protected,
        state_file=path(doc["state_file"]) if "state_file" in doc else None,
    )


def _bridge(table: Any, path: Any, project: Path) -> BridgeConfig:
    if not isinstance(table, dict):
        raise ConfigError("[bridge] must be a table")
    unknown = set(table) - {"tmux", "target", "state_file", "interrupt"}
    if unknown:
        raise ConfigError(f"unknown [bridge] keys: {sorted(unknown)}")
    interrupt = table.get("interrupt", True)
    if not isinstance(interrupt, bool):
        raise ConfigError("[bridge] interrupt must be true or false")
    if not isinstance(table.get("target"), str) or not table["target"]:
        raise ConfigError("[bridge] target is required")
    state = table.get("state_file")
    if state is not None and (not isinstance(state, str) or not state):
        raise ConfigError("[bridge] state_file must be a path")
    tmux = table.get("tmux", "tmux")
    if not isinstance(tmux, str) or not tmux:
        raise ConfigError("[bridge] tmux must be a string")
    return BridgeConfig(
        tmux=tmux,
        target=table["target"],
        state_file=path(state) if state else project / BRIDGE_STATE_FILE,
        interrupt=interrupt,
    )


def _gate(table: Any, path: Any, project: Path) -> GateConfig:
    if not isinstance(table, dict):
        raise ConfigError("[gate] must be a table")
    unknown = set(table) - {
        "admin_socket",
        "decide_window_s",
        "log",
        "protected",
        "ask",
        "question_tools",
        "question_bash",
        "report_timeout_s",
    }
    if unknown:
        raise ConfigError(f"unknown [gate] keys: {sorted(unknown)}")
    lists: dict[str, tuple[str, ...]] = {}
    for key, default in (
        ("question_tools", DEFAULT_QUESTION_TOOLS),
        ("question_bash", DEFAULT_QUESTION_BASH),
    ):
        value = table.get(key)
        if value is None:
            lists[key] = default
            continue
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            raise ConfigError(f"[gate] {key} must be a list of non-empty strings")
        lists[key] = tuple(value)
    report_timeout = table.get("report_timeout_s", DEFAULT_REPORT_TIMEOUT_S)
    if isinstance(report_timeout, bool) or not isinstance(report_timeout, int | float):
        raise ConfigError("[gate] report_timeout_s must be a number of seconds")
    if not 0 < float(report_timeout) <= 20:
        raise ConfigError("[gate] report_timeout_s must be between 0 and 20 seconds")
    if not isinstance(table.get("admin_socket"), str) or not table["admin_socket"]:
        raise ConfigError("[gate] admin_socket is required")
    window = table.get("decide_window_s", DEFAULT_DECIDE_WINDOW_S)
    if isinstance(window, bool) or not isinstance(window, int) or window < 1:
        raise ConfigError("[gate] decide_window_s must be a positive integer (seconds)")
    log = table.get("log")
    if log is not None and (not isinstance(log, str) or not log):
        raise ConfigError("[gate] log must be a path")
    ask = table.get("ask")
    if ask is not None and (not isinstance(ask, str) or not ask):
        raise ConfigError("[gate] ask must be a path")
    rules = table.get("protected", [])
    if not isinstance(rules, list):
        raise ConfigError("[[gate.protected]] must be an array of tables")
    return GateConfig(
        admin_socket=path(table["admin_socket"]),
        decide_window_s=window,
        log=path(log) if log else project / GATE_LOG,
        ask=path(ask) if ask else None,
        protected=tuple(_rule(r) for r in rules),
        question_tools=lists["question_tools"],
        question_bash=lists["question_bash"],
        report_timeout_s=float(report_timeout),
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
    flags = re.DOTALL | re.MULTILINE | (re.IGNORECASE if ignore_case else 0)
    compiled = []
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern:
            raise ConfigError(f"{where}: match entries must be non-empty strings")
        try:
            compiled.append(re.compile(pattern, flags))
        except re.error as e:
            raise ConfigError(f"{where}: bad regex {pattern!r}: {e}") from e
    return ProtectedRule(name=name, tools=tuple(tools), match=tuple(compiled), field=field)


# Rules `rhcore friend-config` writes; the owner edits the file afterwards. They match the
# usual spellings, including the ones a review found slipping through (a path before kill,
# `command kill`, `bash -c "kill …"`, `xargs kill`, `kill -s 19`, os.kill in Python). What
# they do not catch is listed in docs/friend-gate.md, "Known limitations".
DEFAULT_PROTECTED: tuple[dict[str, Any], ...] = (
    {
        "name": "resume or pause a process (kill -CONT / -STOP)",
        "tools": ["Bash"],
        "field": "command",
        # kill/pkill/killall anywhere (after a path, a quote, `command`, `xargs`, a newline),
        # then CONT/STOP by name or number on the same command segment.
        "match": [
            r"(?<![\w.-])(kill|pkill|killall)\b[^\n;&|]*?"
            r"(\s-(s\s+)?(SIG)?(CONT|STOP)\b|\s-(s\s+)?(17|18|19)\b)"
        ],
    },
    {
        "name": "resume or pause a process from a script (os.kill, SIGCONT, SIGSTOP)",
        "tools": ["Bash"],
        "field": "command",
        "match": [
            r"(os\.kill\s*\(|signal\.SIG(CONT|STOP)\b"
            r"|[\"']kill[\"']\s*,\s*[\"']-(SIG)?(CONT|STOP|1[789])\b)"
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
        # The gate resolves file_path against the call's cwd first, so "CLAUDE.md" and
        # "~/Alpha/.claude/settings.json" are seen as full paths.
        "match": [
            r"((^|/)\.claude(/|$)|(^|/)CLAUDE\.md$|/LaunchAgents/|/LaunchDaemons/"
            r"|managed-settings|(^|/)friend\.toml$|(^|/)core\.toml$|(^|/)\.ssh(/|$)"
            r"|authorized_keys|/sudoers|(^|/)settings(\.local)?\.json$"
            r"|(^|/)rh_current\.json$|(^|/)rh_pending\.jsonl$)"
        ],
    },
    {
        "name": "rules and access: change a settings or rules file from the shell",
        "tools": ["Bash"],
        "field": "command",
        "match": [
            r"(\.claude\b|CLAUDE\.md|LaunchAgents|LaunchDaemons|managed-settings"
            r"|friend\.toml|core\.toml|\.ssh\b|authorized_keys|sudoers"
            r"|settings(\.local)?\.json|rh_current\.json|rh_pending\.jsonl)",
            r"(>|\btee\b|\bsed\s+-i|\bcp\b|\bmv\b|\brm\b|\bln\b|\bchmod\b|\bchown\b"
            r"|\btruncate\b|\binstall\b|\bpatch\b"
            r"|\blaunchctl\s+(load|unload|bootstrap|bootout|enable|disable|kickstart)"
            r"|\bdefaults\s+write|\bpython3?\b|\bperl\b|\bruby\b|\bnode\b|\bswift\b"
            r"|\bosascript\b|\b(ba|z)?sh\s+-c\b)",
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
