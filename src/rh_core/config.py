"""rh-core configuration (TOML).

Dev mode (SPEC §9.1) is switched on only by `mode = "dev"` in the config: it
listens on 127.0.0.1 over plain HTTP, keeps data in a scratch directory and skips
the Tailscale peer check. A production config can never turn any of that on.
"""

from __future__ import annotations

import getpass
import json
import socket
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from rh_core.agent_rules import WHEN_RUNNING, Rule

Mode = Literal["dev", "production"]

DEV_HOST = "127.0.0.1"
DEV_PORT = 8787
PRODUCTION_PORT = 8443
CORE_USER = "_rhcore"
TEAM_FILE = Path("~/Friend/CLAUDE.md").expanduser()


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Config:
    mode: Mode
    data_dir: Path
    journal_dir: Path
    host: str
    port: int
    mac_name: str = field(default_factory=lambda: socket.gethostname().removesuffix(".local"))
    tls_cert: Path | None = None
    tls_key: Path | None = None
    whois: bool = True
    tailscale: str | None = None  # path to the tailscale CLI; found automatically if unset
    team_file: Path | None = TEAM_FILE  # agents.status; None: no team
    team_skip: tuple[str, ...] = ()  # team ids that are not agents (the owner)
    agent_rules: tuple[Rule, ...] = ()  # agents.status rules; agents without one: unknown

    @property
    def db_path(self) -> Path:
        return self.data_dir / "core.sqlite3"

    @property
    def key_path(self) -> Path:
        return self.data_dir / "core_key.pem"

    @property
    def admin_socket(self) -> Path:
        return self.data_dir / "admin.sock"

    @property
    def public_url(self) -> str:
        if self.mode == "dev":
            return f"http://{self.host}:{self.port}"
        return f"https://{self.host}:{self.port}"

    def validate(self, *, user: str | None = None) -> None:
        user = user if user is not None else getpass.getuser()
        if self.mode == "dev":
            if user == CORE_USER:
                raise ConfigError("dev mode is not available in a production install")
            if self.host != DEV_HOST:
                raise ConfigError(f"dev mode listens only on {DEV_HOST}")
            if self.tls_cert or self.tls_key:
                raise ConfigError("dev mode is plain HTTP; remove tls_cert/tls_key")
            if self.whois:
                raise ConfigError("dev mode has no Tailscale peer check; set whois = false")
            return
        if self.host in {"0.0.0.0", "::", "", DEV_HOST, "localhost"}:
            raise ConfigError("production listens only on the Tailscale address or MagicDNS name")
        if not (self.tls_cert and self.tls_key):
            raise ConfigError("production needs tls_cert and tls_key from `tailscale cert`")
        if not self.whois:
            raise ConfigError("production always checks the Tailscale peer (whois)")


DEFAULT_PATH = Path("~/Library/Application Support/RemoteHands/core.toml").expanduser()


def load(path: Path) -> Config:
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"cannot read {path}: {e}") from e
    return from_dict(doc, base=path.parent)


def from_dict(doc: dict[str, Any], *, base: Path = Path(".")) -> Config:
    known = {
        "mode",
        "data_dir",
        "journal_dir",
        "host",
        "port",
        "mac_name",
        "tls_cert",
        "tls_key",
        "whois",
        "tailscale",
        "agents",
    }
    unknown = set(doc) - known
    if unknown:
        raise ConfigError(f"unknown config keys: {sorted(unknown)}")
    mode = doc.get("mode")
    if mode not in ("dev", "production"):
        raise ConfigError('mode must be "dev" or "production"')

    def path(name: str) -> Path | None:
        value = doc.get(name)
        if value is None:
            return None
        p = Path(str(value)).expanduser()
        return p if p.is_absolute() else base / p

    data_dir = path("data_dir")
    if data_dir is None:
        raise ConfigError("data_dir is required")
    kwargs: dict[str, Any] = {
        "mode": mode,
        "data_dir": data_dir,
        "journal_dir": path("journal_dir") or data_dir / "journal",
        "host": doc.get("host", DEV_HOST if mode == "dev" else ""),
        "port": int(doc.get("port", DEV_PORT if mode == "dev" else PRODUCTION_PORT)),
        "tls_cert": path("tls_cert"),
        "tls_key": path("tls_key"),
        "whois": bool(doc.get("whois", mode == "production")),
    }
    if "tailscale" in doc:
        kwargs["tailscale"] = str(doc["tailscale"])
    if "mac_name" in doc:
        kwargs["mac_name"] = str(doc["mac_name"])
    kwargs.update(_agents(doc.get("agents", {}), base))
    return Config(**kwargs)


def _agents(table: Any, base: Path) -> dict[str, Any]:
    """[agents]: team_file (path or "" for no team), skip (ids that are not agents),
    [[agents.rule]] (status rules, see rh_core.agent_rules)."""
    if not isinstance(table, dict):
        raise ConfigError("[agents] must be a table")
    unknown = set(table) - {"team_file", "skip", "rule"}
    if unknown:
        raise ConfigError(f"unknown [agents] keys: {sorted(unknown)}")
    out: dict[str, Any] = {}
    if "team_file" in table:
        value = str(table["team_file"])
        p = Path(value).expanduser()
        out["team_file"] = None if not value else (p if p.is_absolute() else base / p)
    skip = table.get("skip", [])
    if not isinstance(skip, list) or not all(isinstance(s, str) for s in skip):
        raise ConfigError("[agents] skip must be a list of strings")
    out["team_skip"] = tuple(skip)
    rules = table.get("rule", [])
    if not isinstance(rules, list):
        raise ConfigError("[[agents.rule]] must be an array of tables")
    out["agent_rules"] = tuple(_rule(r, base) for r in rules)
    ids = [r.id for r in out["agent_rules"]]
    if len(set(ids)) != len(ids):
        raise ConfigError("[[agents.rule]]: one rule per agent id")
    return out


_RULE_KEYS = {
    "id",
    "process",
    "cwd",
    "transcripts",
    "working_within_s",
    "when_running",
    "stale_after_s",
}


def _rule(doc: Any, base: Path) -> Rule:
    if not isinstance(doc, dict):
        raise ConfigError("[[agents.rule]] entries must be tables")
    where = f"[[agents.rule]] {doc.get('id', '?')}"
    unknown = set(doc) - _RULE_KEYS
    if unknown:
        raise ConfigError(f"{where}: unknown keys {sorted(unknown)}")
    for key in ("id", "process"):
        if not isinstance(doc.get(key), str) or not doc[key]:
            raise ConfigError(f"{where}: {key} is required")
    for key in ("cwd", "transcripts", "when_running"):
        if key in doc and not isinstance(doc[key], str):
            raise ConfigError(f"{where}: {key} must be a string")
    for key in ("working_within_s", "stale_after_s"):
        value = doc.get(key)
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, int) or value < 1
        ):
            raise ConfigError(f"{where}: {key} must be a positive integer (seconds)")
    when = doc.get("when_running")
    if when is not None and when not in WHEN_RUNNING:
        raise ConfigError(f"{where}: when_running must be one of {list(WHEN_RUNNING)}")
    cwd = None
    if "cwd" in doc:
        cwd = Path(doc["cwd"]).expanduser()
        if not cwd.is_absolute():
            raise ConfigError(f"{where}: cwd must be absolute or start with ~")
    return Rule(
        id=doc["id"],
        process=doc["process"],
        cwd=cwd,
        transcripts=doc.get("transcripts"),
        working_within_s=doc.get("working_within_s", Rule.working_within_s),
        when_running=when,
        stale_after_s=doc.get("stale_after_s"),
    )


def dev_config(data_dir: Path, *, port: int = DEV_PORT, team_file: Path | None = None) -> Config:
    """Dev core: no team unless one is given (UI tests use tests/fixtures/stage2/team.md)."""
    return Config(
        mode="dev",
        data_dir=data_dir,
        journal_dir=data_dir / "journal",
        host=DEV_HOST,
        port=port,
        whois=False,
        team_file=team_file,
    )


def to_toml(cfg: Config) -> str:
    def q(value: object) -> str:
        return json.dumps(
            str(value), ensure_ascii=False
        )  # a JSON string is a valid TOML basic string

    lines = [
        f"mode = {q(cfg.mode)}",
        f"data_dir = {q(cfg.data_dir)}",
        f"journal_dir = {q(cfg.journal_dir)}",
        f"host = {q(cfg.host)}",
        f"port = {cfg.port}",
        f"mac_name = {q(cfg.mac_name)}",
        f"whois = {'true' if cfg.whois else 'false'}",
    ]
    for name in ("tls_cert", "tls_key", "tailscale"):
        value = getattr(cfg, name)
        if value:
            lines.append(f"{name} = {q(value)}")
    lines += ["", "[agents]", f"team_file = {q(cfg.team_file or '')}"]
    lines.append(f"skip = [{', '.join(q(s) for s in cfg.team_skip)}]")
    return "\n".join(lines) + "\n"
