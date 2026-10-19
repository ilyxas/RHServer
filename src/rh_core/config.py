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

Mode = Literal["dev", "production"]

DEV_HOST = "127.0.0.1"
DEV_PORT = 8787
PRODUCTION_PORT = 8443
CORE_USER = "_rhcore"


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
    return Config(**kwargs)


def dev_config(data_dir: Path, *, port: int = DEV_PORT) -> Config:
    return Config(
        mode="dev",
        data_dir=data_dir,
        journal_dir=data_dir / "journal",
        host=DEV_HOST,
        port=port,
        whois=False,
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
    return "\n".join(lines) + "\n"
