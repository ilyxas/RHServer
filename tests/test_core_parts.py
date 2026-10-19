"""Journal, config, store and Tailscale whois parsing."""

from __future__ import annotations

import json
import os
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from refclient import Phone
from rh_cli import rhcore
from rh_common.protocol import NonceRecord, PairCode, PairRequest, SignedObject, fingerprint
from rh_core import journal
from rh_core.admin import _decision
from rh_core.config import Config, ConfigError, dev_config, from_dict, load, to_toml
from rh_core.keys import load_or_create
from rh_core.pairing import Candidate, Pairing
from rh_core.peers import TailscaleWhois, parse_whois
from rh_core.store import Store

T0 = datetime(2026, 10, 19, 12, 0, 0, tzinfo=UTC)


# --- journal -------------------------------------------------------------------------


class Ticking:
    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        self.now += timedelta(milliseconds=1500)
        return self.now


def write_two_days(d: Path) -> journal.Journal:
    clock = Ticking(T0)
    j = journal.Journal(d, clock=clock)
    j.append("core.started", mode="dev")
    j.append("request", op="ping", result="accepted", device="a" * 32)
    clock.now += timedelta(days=1)
    j.append("request", op="ping", result="rejected", reason="nonce_used", detail=None)
    return j


def test_journal_chain_across_files(tmp_path: Path) -> None:
    write_two_days(tmp_path)
    files = journal.journal_files(tmp_path)
    assert len(files) == 2 and all(len(f.stem) == 8 and f.stem.isdigit() for f in files)
    assert journal.verify(tmp_path) == []
    first = json.loads(files[0].read_text().splitlines()[0])
    assert first["prev"] == journal.GENESIS and first["ts"].endswith("Z") and "." in first["ts"]
    second_day = json.loads(files[1].read_text().splitlines()[0])
    assert "detail" not in second_day  # None fields are left out


def test_journal_reopen_continues_chain(tmp_path: Path) -> None:
    write_two_days(tmp_path)
    journal.Journal(tmp_path).append("core.stopped")
    assert journal.verify(tmp_path) == []


@pytest.mark.parametrize("how", ["edit", "delete", "swap", "garbage"])
def test_journal_tampering_is_caught(tmp_path: Path, how: str) -> None:
    write_two_days(tmp_path)
    path = journal.journal_files(tmp_path)[0]
    lines = path.read_text().splitlines()
    if how == "edit":
        lines[1] = lines[1].replace("accepted", "rejected")
    elif how == "delete":
        del lines[0]
    elif how == "swap":
        lines.reverse()
    else:
        lines[0] = "{not json"
    path.write_text("\n".join(lines) + "\n")
    assert journal.verify(tmp_path) != []
    assert rhcore.main(["journal", "verify", "--dir", str(tmp_path)]) == 1


def test_journal_verify_cli_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_two_days(tmp_path)
    assert rhcore.main(["journal", "verify", "--dir", str(tmp_path)]) == 0
    assert "3 записей в 2 файлах" in capsys.readouterr().out


# --- config --------------------------------------------------------------------------


def prod(**kw: object) -> Config:
    doc: dict[str, object] = {
        "mode": "production",
        "data_dir": "/var/rh",
        "host": "mac.tail1234.ts.net",
        "tls_cert": "/var/rh/mac.crt",
        "tls_key": "/var/rh/mac.key",
    }
    doc.update(kw)
    return from_dict({k: v for k, v in doc.items() if v is not None})


def test_dev_config_is_valid_for_ilya(tmp_path: Path) -> None:
    cfg = dev_config(tmp_path)
    cfg.validate(user="ilya")
    assert cfg.public_url == "http://127.0.0.1:8787"


def test_dev_mode_refused_for_core_user(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="production install"):
        dev_config(tmp_path).validate(user="_rhcore")


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"host": "0.0.0.0"}, "Tailscale address"),
        ({"host": "127.0.0.1"}, "Tailscale address"),
        ({"tls_cert": None}, "tls_cert"),
        ({"whois": False}, "whois"),
    ],
)
def test_production_cannot_be_loosened(change: dict[str, object], message: str) -> None:
    prod().validate(user="ilya")
    with pytest.raises(ConfigError, match=message):
        prod(**change).validate(user="ilya")


@pytest.mark.parametrize(
    "doc",
    [
        {"mode": "dev", "data_dir": "/tmp/x", "host": "100.64.0.1"},
        {"mode": "dev", "data_dir": "/tmp/x", "tls_cert": "a", "tls_key": "b"},
        {"mode": "dev", "data_dir": "/tmp/x", "whois": True},
    ],
)
def test_dev_cannot_be_exposed(doc: dict[str, object]) -> None:
    with pytest.raises(ConfigError):
        from_dict(doc).validate(user="ilya")


def test_config_rejects_unknown_keys_and_modes() -> None:
    with pytest.raises(ConfigError, match="unknown"):
        from_dict({"mode": "dev", "data_dir": "/tmp/x", "debug": True})
    with pytest.raises(ConfigError, match="mode"):
        from_dict({"mode": "test", "data_dir": "/tmp/x"})


def test_config_toml_round_trip(tmp_path: Path) -> None:
    cfg = Config(
        mode="production",
        data_dir=tmp_path / 'data "q"',
        journal_dir=tmp_path / "Hst" / "RemoteHands",
        host="mac.tail1234.ts.net",
        port=8443,
        mac_name="MacBook Ильи",
        tls_cert=tmp_path / "c.crt",
        tls_key=tmp_path / "c.key",
        tailscale="/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    )
    path = tmp_path / "core.toml"
    path.write_text(to_toml(cfg), encoding="utf-8")
    assert load(path) == cfg


def test_serve_refuses_bad_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "core.toml"
    path.write_text('mode = "production"\ndata_dir = "d"\nhost = "0.0.0.0"\n', encoding="utf-8")
    assert rhcore.main(["serve", "--config", str(path)]) == 2
    assert "Tailscale" in capsys.readouterr().err


# --- store and keys ----------------------------------------------------------------------


def test_nonce_consumed_once(tmp_path: Path) -> None:
    store = Store(tmp_path / "db.sqlite3")
    store.put_nonce("n", NonceRecord(device="a" * 32, expires=T0, used=False))
    assert store.consume_nonce("n") is True
    assert store.consume_nonce("n") is False
    assert store.nonce("n") == NonceRecord(device="a" * 32, expires=T0, used=True)


def test_store_reopens_without_migrating_twice(tmp_path: Path) -> None:
    keys = {
        "normal": b"\x04" + b"1" * 64,
        "critical": b"\x04" + b"2" * 64,
        "ssh": b"\x04" + b"3" * 64,
    }
    store = Store(tmp_path / "db.sqlite3")
    store.add_device(device_id="a" * 32, name="iPhone", keys=keys, now=T0)
    store.close()
    again = Store(tmp_path / "db.sqlite3")
    assert [d.name for d in again.devices()] == ["iPhone"]
    assert again.revoke("a" * 32, now=T0) is True
    assert again.revoke("b" * 32, now=T0) is False
    assert again.device_row("a" * 32).revoked_at == "2026-10-19T12:00:00Z"


def test_core_key_created_private(tmp_path: Path) -> None:
    path = tmp_path / "core_key.pem"
    key = load_or_create(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert load_or_create(path).private_numbers() == key.private_numbers()


# --- Tailscale whois ---------------------------------------------------------------------

WHOIS = {
    "Node": {"ID": 123, "StableID": "nABCDEF1CNTRL", "Name": "iphone.tail1234.ts.net."},
    "UserProfile": {"LoginName": "ilya@example.com"},
}


def test_parse_whois() -> None:
    assert parse_whois(json.dumps(WHOIS).encode()) == "nABCDEF1CNTRL"
    assert parse_whois(b'{"Node": {}}') is None


@pytest.mark.skipif(sys.platform == "win32", reason="shell script")
def test_whois_cli_called_and_cached(tmp_path: Path) -> None:
    calls = tmp_path / "calls"
    script = tmp_path / "tailscale"
    script.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> "{calls}"\n'
        f'if [ "$3" = "100.64.0.7" ]; then echo \'{json.dumps(WHOIS)}\'\n'
        'else echo "no match" >&2; exit 1; fi\n'
    )
    script.chmod(0o755)
    whois = TailscaleWhois(str(script))
    assert whois.node("100.64.0.7", 50000) == "nABCDEF1CNTRL"
    assert whois.node("100.64.0.7", 50001) == "nABCDEF1CNTRL"
    assert whois.node("100.64.0.8", 1) is None
    assert whois.node("not-an-ip", 1) is None
    assert calls.read_text().splitlines() == ["whois --json 100.64.0.7", "whois --json 100.64.0.8"]


def test_whois_missing_binary() -> None:
    assert TailscaleWhois(os.devnull + "/nope").node("100.64.0.7", 1) is None


# --- pairing session -----------------------------------------------------------------------


def make_candidate(code: str) -> Candidate:
    phone = Phone()
    obj = SignedObject(device=phone.id, key="normal", nonce=code, ts="", exp="", op="pair", body="")
    req = PairRequest(obj=obj, name=phone.name, keys={}, keys_b64=phone.pub, replaces=None)
    return Candidate(request=req, fingerprint=fingerprint(phone.pub), peer="local")


def test_withdrawn_request_frees_the_code() -> None:
    pairing = Pairing(url="http://127.0.0.1:8787", core_key_b64="", clock=lambda: T0)
    session = pairing.open(PairCode(code="c", expires=T0 + timedelta(minutes=5)))
    first = make_candidate("c")
    assert pairing.submit(first) is session
    assert pairing.find_code("c") == PairCode(code="c", expires=session.code.expires, used=True)
    assert pairing.withdraw(session, first) is True
    assert first.withdrawn and first.decided.is_set() and not first.accepted
    assert session.candidate is None and not session.arrived.is_set() and not session.closed
    assert pairing.find_code("c") == PairCode(code="c", expires=session.code.expires, used=False)
    pairing.decide(session, True, first)  # a late answer to the withdrawn request
    assert session.used is False
    assert pairing.withdraw(session, first) is False
    second = make_candidate("c")
    assert pairing.submit(second) is session
    pairing.decide(session, True, second)
    assert second.accepted and pairing.withdraw(session, second) is False


def test_answer_must_name_the_shown_fingerprint() -> None:
    line = json.dumps({"cmd": "pair.decide", "accept": True, "fingerprint": "aaaa"}).encode()
    assert _decision(line, "aaaa") is True
    assert _decision(line, "bbbb") is None
    assert _decision(b'{"cmd": "pair.decide", "accept": true}', "aaaa") is None
    assert _decision(b"garbage", "aaaa") is False
    assert _decision(b'{"cmd": "nope"}', "aaaa") is False
