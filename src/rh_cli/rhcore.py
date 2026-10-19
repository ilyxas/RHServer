"""rhcore: run and manage rh-core (pairing, devices, journal, dev mode)."""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any, TextIO

from rh_cli._common import parser
from rh_common.protocol import parse_ts
from rh_core import journal
from rh_core.config import DEFAULT_PATH, DEV_PORT, Config, ConfigError, dev_config, load, to_toml
from rh_core.system import FakeProbe


def main(argv: list[str] | None = None) -> int:
    p = parser("rhcore", "RemoteHands core")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    def with_config(sp: argparse.ArgumentParser) -> argparse.ArgumentParser:
        sp.add_argument(
            "--config",
            type=Path,
            default=Path(os.environ.get("RH_CORE_CONFIG", DEFAULT_PATH)),
            help=f"core config (default: $RH_CORE_CONFIG or {DEFAULT_PATH})",
        )
        return sp

    with_config(sub.add_parser("serve", help="run the core with a config"))

    dev = sub.add_parser("dev", help="dev mode (SPEC §9.1)")
    dev_sub = dev.add_subparsers(dest="dev_command", metavar="COMMAND", required=True)
    up = dev_sub.add_parser("up", help="run a dev core on 127.0.0.1 over plain HTTP")
    up.add_argument("--data", type=Path, help="data directory (default: a new /tmp/rh-dev-*)")
    up.add_argument(
        "--port",
        type=int,
        help=f"port on 127.0.0.1 (default: {DEV_PORT}, or a free one if {DEV_PORT} is taken)",
    )
    up.add_argument(
        "--auto-pair", action="store_true", help="accept every verified pairing request"
    )
    up.add_argument(
        "--pairing-file", type=Path, help="with --auto-pair: keep the current pairing string here"
    )
    up.add_argument(
        "--fixture",
        type=Path,
        help="fixture directory for UI tests: team.md (agents.status), system.json "
        '({"cpu", "memory", "disk_free"} instead of the real Mac); e.g. tests/fixtures/stage2',
    )

    with_config(sub.add_parser("pair", help="pair a new iPhone or iPad"))
    with_config(sub.add_parser("status", help="ask the running core"))

    devices = sub.add_parser("devices", help="paired devices")
    dev_cmds = devices.add_subparsers(dest="devices_command", metavar="COMMAND", required=True)
    with_config(dev_cmds.add_parser("list", help="list devices"))
    revoke = with_config(dev_cmds.add_parser("revoke", help="revoke a device"))
    revoke.add_argument("device_id")

    jr = sub.add_parser("journal", help="core journal")
    jr_cmds = jr.add_subparsers(dest="journal_command", metavar="COMMAND", required=True)
    verify = with_config(jr_cmds.add_parser("verify", help="check the hash chain of the journal"))
    verify.add_argument("--dir", type=Path, help="journal directory (default: from the config)")

    args = p.parse_args(argv)
    try:
        if args.command == "serve":
            return _serve(args)
        if args.command == "dev":
            return _dev_up(args)
        if args.command == "pair":
            return _pair(_config(args), sys.stdin, sys.stdout)
        if args.command == "status":
            return _status(_config(args))
        if args.command == "devices":
            return _devices(args)
        if args.command == "journal":
            return _journal_verify(args)
    except (ConfigError, AdminUnavailable) as e:
        print(f"rhcore: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nОтменено.", file=sys.stderr)
        return 130
    p.print_help()
    return 0


def _config(args: argparse.Namespace) -> Config:
    return load(args.config)


def _serve(args: argparse.Namespace) -> int:
    from rh_core.server import run

    run(_config(args))
    return 0


def _dev_up(args: argparse.Namespace) -> int:
    from rh_core.server import Job, auto_pair, dev_socket, run

    try:
        sock = dev_socket(args.port)
    except OSError as e:
        print(f"rhcore: порт {args.port} занят ({e.strerror})", file=sys.stderr)
        return 2
    port = sock.getsockname()[1]
    if args.port is None and port != DEV_PORT:
        print(f"порт {DEV_PORT} занят, ядро слушает {port}")
    data = args.data or Path(tempfile.mkdtemp(prefix="rh-dev-", dir="/tmp"))
    data = data.expanduser().resolve()
    try:
        team_file, probe = _fixture(args.fixture)
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"rhcore: fixture {args.fixture}: {e}", file=sys.stderr)
        return 2
    cfg = dev_config(data, port=port, team_file=team_file)
    cfg.validate()
    data.mkdir(parents=True, exist_ok=True)
    config_path = data / "core.toml"
    config_path.write_text(to_toml(cfg), encoding="utf-8")
    print(f"rh-core dev: {cfg.public_url}")
    print(f"данные: {data}")
    print(f"pairing: rhcore pair --config {config_path}")
    jobs: list[Job] = []
    if args.auto_pair:
        jobs.append(auto_pair(lambda line: print(line, flush=True), args.pairing_file))
    elif args.pairing_file:
        print("rhcore: --pairing-file works only with --auto-pair", file=sys.stderr)
        return 2
    sys.stdout.flush()
    run(cfg, background=jobs, sock=sock, probe=probe)
    return 0


def _fixture(directory: Path | None) -> tuple[Path | None, FakeProbe | None]:
    if directory is None:
        return None, None
    directory = directory.expanduser().resolve()
    if not directory.is_dir():
        raise ValueError("not a directory")
    team = directory / "team.md"
    system = directory / "system.json"
    probe = None
    if system.exists():
        doc = json.loads(system.read_text(encoding="utf-8"))
        if set(doc) != {"cpu", "memory", "disk_free"}:
            raise ValueError('system.json must be {"cpu", "memory", "disk_free"}')
        probe = FakeProbe(
            cpu=float(doc["cpu"]), memory=float(doc["memory"]), disk=int(doc["disk_free"])
        )
    return (team if team.exists() else None), probe


# --- admin socket client ------------------------------------------------------------


class AdminUnavailable(RuntimeError):
    pass


@contextmanager
def _admin(cfg: Config) -> Iterator[tuple[socket.socket, TextIO]]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(str(cfg.admin_socket))
    except OSError as e:
        s.close()
        raise AdminUnavailable(f"rh-core is not running ({cfg.admin_socket}: {e.strerror})") from e
    f = s.makefile("rw", encoding="utf-8", newline="\n")
    try:
        yield s, f
    finally:
        f.close()
        s.close()


def _send(f: TextIO, msg: dict[str, Any]) -> None:
    f.write(json.dumps(msg, ensure_ascii=False) + "\n")
    f.flush()


def _recv(f: TextIO) -> dict[str, Any]:
    line = f.readline()
    if not line:
        raise AdminUnavailable("rh-core closed the connection")
    msg = json.loads(line)
    assert isinstance(msg, dict)
    return msg


def _call(cfg: Config, msg: dict[str, Any]) -> dict[str, Any]:
    with _admin(cfg) as (_, f):
        _send(f, msg)
        return _recv(f)


def _status(cfg: Config) -> int:
    r = _call(cfg, {"cmd": "status"})
    print(f"{r['mac_name']}: {r['mode']}, {r['url']}, время ядра {r['server_time']}")
    return 0


def _devices(args: argparse.Namespace) -> int:
    cfg = _config(args)
    if args.devices_command == "list":
        r = _call(cfg, {"cmd": "devices.list"})
        if not r["devices"]:
            print("устройств нет")
        for d in r["devices"]:
            state = (
                "активно"
                if d["status"] == "active"
                else f"отозвано {d.get('revoked_at', '')}".strip()
            )
            print(f"{d['id']}  {d['name']}  [{d['fingerprint']}]  с {d['paired_at']}  {state}")
        return 0
    r = _call(cfg, {"cmd": "devices.revoke", "device_id": args.device_id})
    if not r["ok"]:
        print(f"rhcore: нет устройства {args.device_id}", file=sys.stderr)
        return 1
    print(f"отозвано: {args.device_id}")
    return 0


def _pair(cfg: Config, stdin: TextIO, out: TextIO) -> int:
    import segno

    with _admin(cfg) as (_, f):
        _send(f, {"cmd": "pair.start"})
        code = _recv(f)
        until = parse_ts(code["expires"]).astimezone()
        segno.make(code["string"], error="m").terminal(out=out, compact=True)
        print("Отсканируйте QR в приложении RemoteHands или вставьте строку:", file=out)
        print(code["string"], file=out)
        print(
            f"Код действует до {until:%H:%M:%S}. Жду запрос с телефона… (Ctrl+C — отмена)",
            file=out,
            flush=True,
        )
        msg = _recv(f)
        while msg.get("event") == "pair.request":
            print("", file=out)
            print("Запрос на pairing:", file=out)
            print(f"  устройство: {msg['name']}", file=out)
            print(f"  id:         {msg['device_id']}", file=out)
            print(f"  отпечаток:  {msg['fingerprint']}", file=out)
            for d in msg["revokes"]:
                print(f"  будет отозвано: {d['name']} ({d['id']})", file=out)
            print(
                "Сверьте отпечаток с экраном телефона. Подтвердить? [y/N] ",
                end="",
                file=out,
                flush=True,
            )
            answer = stdin.readline().strip().lower()
            _send(
                f,
                {
                    "cmd": "pair.decide",
                    "accept": answer in ("y", "yes", "д", "да"),
                    "fingerprint": msg["fingerprint"],
                },
            )
            msg = _recv(f)
            while msg.get("event") == "pair.withdrawn":
                print(
                    "Телефон отключился до ответа, устройство не добавлено. "
                    "Жду повтор с тем же кодом…",
                    file=out,
                    flush=True,
                )
                msg = _recv(f)
        result = msg.get("result")
        text = {
            "accepted": f"Готово: устройство {msg.get('device_id')} добавлено.",
            "rejected": "Отклонено.",
            "expired": "Код истёк. Запустите rhcore pair снова.",
            "cancelled": "Отменено.",
        }.get(str(result), f"Не получилось: {msg}")
        print(text, file=out)
        return 0 if result == "accepted" else 1


def _journal_verify(args: argparse.Namespace) -> int:
    directory = args.dir or _config(args).journal_dir
    files = journal.journal_files(directory)
    problems = journal.verify(directory)
    count = sum(1 for _ in journal.read(directory))
    for pr in problems:
        print(f"{pr.file}:{pr.line}: {pr.message}")
    if problems:
        print(
            f"журнал повреждён: {len(problems)} проблем(ы), {count} записей в {len(files)} файлах"
        )
        return 1
    print(f"журнал в порядке: {count} записей в {len(files)} файлах ({directory})")
    return 0
