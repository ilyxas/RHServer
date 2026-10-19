"""Stage 2: data sources, agents.status, the Log feed and their endpoints."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from openapi_util import check_response
from refclient import Phone
from rh_cli import rhcore
from rh_core import logfeed
from rh_core.agents import Member, Team, parse_team
from rh_core.app import Core, create_app
from rh_core.config import ConfigError, dev_config, from_dict, load, to_toml
from rh_core.data import parse_ids
from rh_core.journal import Journal, verify
from rh_core.system import FakeProbe
from test_core_flow import Clock, Peers, pair, signed

ROOT = Path(__file__).parent.parent
FIXTURE = ROOT / "tests/fixtures/stage2"

TEAM_TEXT = """# CLAUDE.md — observer

Intro text with a **Bold** word.

- **NotYet** — a bullet before the team section.

## Команда (идентификаторы)

Use these ids:

- **Owner** — the only one whose word decides.
- **Friend** — observer.
- **Agent-Alpha** — builds things.
* **Agent-Beta**
- plain bullet without an id

### Notes inside the section

- **Agent-Gamma** — still in the section (lower level heading).

## Остальное

- **Outside** — not in the team.
"""


# --- agents.status -------------------------------------------------------------------


def test_parse_team_reads_only_the_team_section() -> None:
    members = parse_team(TEAM_TEXT)
    assert [m.id for m in members] == [
        "Owner",
        "Friend",
        "Agent-Alpha",
        "Agent-Beta",
        "Agent-Gamma",
    ]
    assert members[1] == Member("Friend", "observer")
    assert members[3] == Member("Agent-Beta", "")


def test_parse_team_without_section() -> None:
    assert parse_team("# Title\n\n- **A** — b\n") == []


def test_team_rows_skip_and_unknown_until_rules(tmp_path: Path) -> None:
    team_file = tmp_path / "CLAUDE.md"
    team_file.write_text(TEAM_TEXT, encoding="utf-8")
    rows = Team(team_file, skip=["Owner"]).rows()
    assert [r["id"] for r in rows] == ["Friend", "Agent-Alpha", "Agent-Beta", "Agent-Gamma"]
    assert rows[0] == {
        "id": "Friend",
        "title": "Friend",
        "subtitle": "observer",
        "status": {"state": "off", "text": "unknown"},
    }
    assert "subtitle" not in rows[2]


class FixedRules:
    def __init__(self, states: dict[str, str]) -> None:
        self.states = states

    def evaluate(self, members: list[Member]) -> dict[str, Any]:
        return {m.id: self.states[m.id] for m in members if m.id in self.states}


def test_team_rows_map_states(tmp_path: Path) -> None:
    team_file = tmp_path / "CLAUDE.md"
    team_file.write_text(TEAM_TEXT, encoding="utf-8")
    states = {
        "Owner": "working",
        "Friend": "monitoring",
        "Agent-Alpha": "idle",
        "Agent-Beta": "stopped",
    }
    got = {r["id"]: r["status"] for r in Team(team_file, rules=FixedRules(states)).rows()}
    assert got["Owner"] == {"state": "ok", "text": "working"}
    assert got["Friend"] == {"state": "ok", "text": "monitoring"}
    assert got["Agent-Alpha"] == {"state": "off", "text": "idle"}
    assert got["Agent-Beta"] == {"state": "off", "text": "stopped"}
    assert got["Agent-Gamma"] == {"state": "off", "text": "unknown"}  # no state from the rules


def test_no_team_file_means_no_rows() -> None:
    assert Team(None).rows() == []


# --- the Log feed ----------------------------------------------------------------------


class StepClock:
    """Journal clock: one second per record, crossing local midnight on purpose."""

    def __init__(self, start: datetime) -> None:
        self.now = start

    def __call__(self) -> datetime:
        self.now += timedelta(seconds=1)
        return self.now


DEV_A = "a" * 32
DEV_B = "b" * 32
NAMES = {DEV_A: "Мой iPhone"}


def names(device: str) -> str | None:
    return NAMES.get(device)


def fill(journal: Journal) -> None:
    journal.append("core.started", mode="dev", version="0.0.1")
    journal.append("pairing.started", expires="2026-10-19T12:05:00Z")
    journal.append(
        "pairing",
        device=DEV_A,
        result="accepted",
        name="Мой iPhone",
        fingerprint="3f2a 9c0d 1e4b 5a6f",
    )
    journal.append("request", op="status", device=DEV_A, result="accepted")
    journal.append("request", op="data.get", device=DEV_A, result="accepted")
    journal.append(
        "request",
        op="ping",
        device=DEV_B,
        result="rejected",
        reason="bad_signature",
        detail="signature does not verify",
    )
    journal.append("challenge", device=DEV_B, result="rejected", reason="unknown_device")
    journal.append("request", op="devices.revoke", device=DEV_A, result="accepted")
    journal.append("device.revoked", device=DEV_B, by=DEV_A)
    journal.append("chat.message", author="owner", text="hello")
    journal.append("approval.requested", approval="x1")
    journal.append("pairing", result="rejected", reason="bad_pair_code", detail="expired")
    journal.append("core.stopped")


@pytest.fixture
def journal_dir(tmp_path: Path) -> Path:
    # 23:59:55 local time: the records spill over into the next day's file.
    start = datetime(2026, 10, 19, 23, 59, 55).astimezone()
    fill(Journal(tmp_path, clock=StepClock(start)))
    assert len(list(tmp_path.iterdir())) == 2
    assert verify(tmp_path) == []
    return tmp_path


def titles(entries: list[dict[str, Any]]) -> list[str]:
    return [e["title"] for e in entries]


def test_feed_all_newest_first(journal_dir: Path) -> None:
    entries, nxt = logfeed.page(journal_dir, names=names)
    assert nxt is None
    assert titles(entries) == [
        "Core stopped",
        "Pairing rejected: bad_pair_code",
        "approval.requested",
        "chat.message",
        "Revoked b" + "b" * 7,
        "Rejected challenge: unknown_device",
        "Rejected ping: bad_signature",
        "Paired Мой iPhone",
        "Core started",
    ]
    for e in entries:
        check_response_entry(e)
    ts = [e["ts"] for e in entries]
    assert ts == sorted(ts, reverse=True)


def check_response_entry(e: dict[str, Any]) -> None:
    check_response("/v1/log", "post", 200, {"entries": [e], "next": None})


def test_feed_entry_fields(journal_dir: Path) -> None:
    entries, _ = logfeed.page(journal_dir, names=names, filter="errors")
    ping = entries[-1]
    assert ping["kind"] == "error"
    assert ping["op"] == "ping"
    assert ping["device"] == DEV_B
    assert ping["detail"] == "signature does not verify"
    lines = [ln for p in sorted(journal_dir.iterdir()) for ln in p.read_bytes().split(b"\n") if ln]
    from rh_common.crypto import sha256_hex

    assert ping["id"] in {sha256_hex(ln) for ln in lines}
    revoked, _ = logfeed.page(
        journal_dir, names={DEV_B: "Old iPad", DEV_A: "Мой iPhone"}.get, filter="commands"
    )
    assert revoked[0]["title"] == "Revoked Old iPad"
    assert revoked[0]["detail"] == "by Мой iPhone"


@pytest.mark.parametrize(
    ("filter_", "expected"),
    [
        ("commands", ["Revoked bbbbbbbb", "Paired Мой iPhone"]),
        ("approvals", ["approval.requested"]),
        ("chat", ["chat.message"]),
        (
            "errors",
            [
                "Pairing rejected: bad_pair_code",
                "Rejected challenge: unknown_device",
                "Rejected ping: bad_signature",
            ],
        ),
    ],
)
def test_feed_filters(journal_dir: Path, filter_: str, expected: list[str]) -> None:
    entries, _ = logfeed.page(journal_dir, names=names, filter=filter_)
    assert titles(entries) == expected


def test_feed_search(journal_dir: Path) -> None:
    assert titles(logfeed.page(journal_dir, names=names, query="PING")[0]) == [
        "Rejected ping: bad_signature"
    ]
    assert titles(logfeed.page(journal_dir, names=names, query=DEV_B[:10])[0]) == [
        "Revoked bbbbbbbb",
        "Rejected challenge: unknown_device",
        "Rejected ping: bad_signature",
    ]
    assert titles(logfeed.page(journal_dir, names=names, query="мой iphone")[0]) == [
        "Revoked bbbbbbbb",  # detail "by Мой iPhone"
        "Paired Мой iPhone",
    ]
    assert logfeed.page(journal_dir, names=names, query="nothing like this")[0] == []


def test_feed_include_reads(journal_dir: Path) -> None:
    entries, _ = logfeed.page(journal_dir, names=names, include_reads=True)
    accepted = [e for e in entries if e["title"].startswith("Accepted")]
    assert titles(accepted) == ["Accepted devices.revoke", "Accepted data.get", "Accepted status"]
    assert {e["kind"] for e in accepted} == {"system"}
    commands, _ = logfeed.page(journal_dir, names=names, filter="commands", include_reads=True)
    assert titles(commands) == ["Revoked bbbbbbbb", "Paired Мой iPhone"]


def test_feed_pagination_matches_one_page(journal_dir: Path) -> None:
    full, _ = logfeed.page(journal_dir, names=names, include_reads=True)
    got: list[dict[str, Any]] = []
    cursor = None
    while True:
        entries, cursor = logfeed.page(
            journal_dir, names=names, include_reads=True, limit=2, before=cursor
        )
        got += entries
        if cursor is None:
            break
        assert len(entries) == 2
    assert got == full


def test_feed_cursor_survives_new_records(journal_dir: Path) -> None:
    first, cursor = logfeed.page(journal_dir, names=names, limit=3)
    assert cursor is not None
    rest_before, _ = logfeed.page(journal_dir, names=names, before=cursor)
    Journal(journal_dir).append("core.started", mode="dev", version="0.0.2")
    rest_after, _ = logfeed.page(journal_dir, names=names, before=cursor)
    assert rest_after == rest_before
    newest, _ = logfeed.page(journal_dir, names=names, limit=1)
    assert newest[0]["detail"] == "dev, version 0.0.2"


def test_feed_exact_limit_has_no_next(journal_dir: Path) -> None:
    entries, cursor = logfeed.page(journal_dir, names=names, filter="errors", limit=3)
    assert len(entries) == 3 and cursor is None


def test_feed_empty_directory(tmp_path: Path) -> None:
    assert logfeed.page(tmp_path / "missing", names=names) == ([], None)


def test_feed_skips_broken_lines(journal_dir: Path) -> None:
    newest = sorted(journal_dir.iterdir())[-1]
    with newest.open("ab") as f:
        f.write(b"not json\n[1,2]\n")
    entries, _ = logfeed.page(journal_dir, names=names, limit=1)
    assert entries[0]["title"] == "Core stopped"


@pytest.mark.parametrize(
    "doc",
    [
        [],
        {"filter": "everything"},
        {"query": 5},
        {"query": "x" * 201},
        {"before": "%%%"},
        {"before": "bm90IGEgY3Vyc29y"},  # "not a cursor"
        {"limit": 0},
        {"limit": 201},
        {"limit": True},
        {"limit": "5"},
        {"include_reads": "yes"},
        {"page": 2},
    ],
)
def test_parse_query_rejects(doc: Any) -> None:
    with pytest.raises(ValueError):
        logfeed.parse_query(doc)


def test_parse_query_defaults() -> None:
    q = logfeed.parse_query({})
    assert (q.filter, q.query, q.before, q.limit, q.include_reads) == ("all", None, None, 50, False)
    cursor = logfeed.Position("20261019", 7).cursor()
    assert logfeed.parse_query({"before": cursor, "query": ""}).before == cursor
    assert logfeed.Position.from_cursor(cursor) == logfeed.Position("20261019", 7)


@pytest.mark.parametrize(
    "doc",
    [
        {},
        [],
        {"ids": []},
        {"ids": "sys.cpu"},
        {"ids": ["sys.cpu", "sys.cpu"]},
        {"ids": ["cpu"]},
        {"ids": ["Sys.cpu"]},
        {"ids": ["sys." + "x" * 64]},
        {"ids": [f"a.b{i}" for i in range(33)]},
        {"ids": ["sys.cpu"], "extra": 1},
    ],
)
def test_parse_ids_rejects(doc: Any) -> None:
    with pytest.raises(ValueError):
        parse_ids(doc)


# --- config ------------------------------------------------------------------------


def test_config_agents_section(tmp_path: Path) -> None:
    base = {"mode": "dev", "data_dir": str(tmp_path), "whois": False}
    cfg = from_dict({**base, "agents": {"team_file": "team.md", "skip": ["Owner"]}}, base=tmp_path)
    assert cfg.team_file == tmp_path / "team.md"
    assert cfg.team_skip == ("Owner",)
    assert from_dict({**base, "agents": {"team_file": ""}}).team_file is None
    assert from_dict(base).team_file == Path("~/Friend/CLAUDE.md").expanduser()
    for bad in ({"skip": "Owner"}, {"rules": []}, "x"):
        with pytest.raises(ConfigError):
            from_dict({**base, "agents": bad})


def test_config_toml_round_trip(tmp_path: Path) -> None:
    for team in (None, tmp_path / "team.md"):
        cfg = dev_config(tmp_path, team_file=team)
        path = tmp_path / "core.toml"
        path.write_text(to_toml(cfg), encoding="utf-8")
        assert load(path) == cfg


def test_dev_fixture_option() -> None:
    team, probe = rhcore._fixture(FIXTURE)
    assert team == FIXTURE / "team.md"
    assert probe == FakeProbe(cpu=38.4, memory=61.2, disk=112_400_000_000)
    assert [m.id for m in parse_team(team.read_text(encoding="utf-8"))] == [
        "Friend",
        "Agent-Alpha",
        "Agent-Beta",
        "RemoteHands",
    ]
    assert rhcore._fixture(None) == (None, None)


def test_dev_fixture_bad_system(tmp_path: Path) -> None:
    (tmp_path / "system.json").write_text('{"cpu": 1}')
    with pytest.raises(ValueError):
        rhcore._fixture(tmp_path)


# --- endpoints ---------------------------------------------------------------------


class BrokenProbe(FakeProbe):
    def memory_percent(self) -> float:
        raise OSError("no memory stats")


@pytest.fixture
def home(short_dir: Path) -> Iterator[tuple[Core, TestClient, Phone]]:
    core = Core(
        dev_config(short_dir / "data", team_file=FIXTURE / "team.md"),
        clock=Clock(),
        peers=Peers(),
        probe=FakeProbe(),
        ssh_host_keys=str(short_dir / "none" / "*.pub"),
    )
    phone = Phone()
    with TestClient(create_app(core)) as client:
        pair(core, client, phone)
        yield core, client, phone
    core.store.close()


def post(client: TestClient, phone: Phone, path: str, op: str, doc: Any) -> Any:
    body = json.dumps(doc).encode() if not isinstance(doc, bytes) else doc
    return signed(client, phone, "POST", path, op, "normal", body)


BUILTIN = [
    "sys.cpu",
    "sys.memory",
    "sys.disk_free",
    "rh.status",
    "rh.approvals",
    "rh.questions",
    "rh.activity",
    "agents.status",
]


def test_data_get_builtins(home: tuple[Core, TestClient, Phone]) -> None:
    core, client, phone = home
    r = post(client, phone, "/v1/data", "data.get", {"ids": [*BUILTIN, "render.queue"]})
    assert r.status_code == 200, r.text
    doc = r.json()
    check_response("/v1/data", "post", 200, doc)
    v = doc["values"]
    assert list(v) == [*BUILTIN, "render.queue"]
    assert v["sys.cpu"] | {"at": "-"} == {
        "status": "active",
        "type": "number",
        "value": 12.5,
        "unit": "%",
        "at": "-",
    }
    assert (v["sys.memory"]["value"], v["sys.memory"]["unit"]) == (48.0, "%")
    assert (v["sys.disk_free"]["value"], v["sys.disk_free"]["unit"]) == (112_400_000_000, "bytes")
    assert v["rh.status"]["value"]["state"] == "warn"
    assert "agent not running" in v["rh.status"]["value"]["text"]
    assert v["rh.approvals"]["value"] == [] and v["rh.questions"]["value"] == []
    assert [row["id"] for row in v["agents.status"]["value"]] == [
        "Friend",
        "Agent-Alpha",
        "Agent-Beta",
        "RemoteHands",
    ]
    activity = v["rh.activity"]["value"]
    assert activity[0]["title"] == "Paired Мой iPhone"
    assert activity[0]["at"].endswith("Z") and "subtitle" in activity[0]
    assert v["render.queue"] == {"status": "pending"}


def test_data_get_one_broken_source(home: tuple[Core, TestClient, Phone]) -> None:
    core, client, phone = home
    core.data.probe = BrokenProbe()
    r = post(client, phone, "/v1/data", "data.get", {"ids": ["sys.memory", "sys.cpu"]})
    doc = r.json()
    check_response("/v1/data", "post", 200, doc)
    assert doc["values"]["sys.memory"] == {"status": "error", "message": "OSError: no memory stats"}
    assert doc["values"]["sys.cpu"]["status"] == "active"


def test_data_get_missing_team_file(home: tuple[Core, TestClient, Phone], tmp_path: Path) -> None:
    core, client, phone = home
    core.data.team = Team(tmp_path / "missing.md")
    doc = post(client, phone, "/v1/data", "data.get", {"ids": ["agents.status"]}).json()
    assert doc["values"]["agents.status"]["status"] == "error"


@pytest.mark.parametrize(
    "body",
    [b"", b"not json", b'{"ids": []}', b'{"ids": ["CPU"]}', b'{"ids": ["sys.cpu"], "x": 1}'],
)
def test_data_get_bad_request(home: tuple[Core, TestClient, Phone], body: bytes) -> None:
    core, client, phone = home
    r = post(client, phone, "/v1/data", "data.get", body)
    assert r.status_code == 400
    check_response("/v1/data", "post", 400, r.json())
    assert r.json()["error"]["code"] == "bad_request"
    errors, _ = logfeed.page(core.config.journal_dir, names=core.device_name, filter="errors")
    assert errors[0]["title"] == "Rejected data.get: bad_request"
    assert errors[0]["device"] == phone.id


def test_bad_request_still_needs_a_valid_signature(home: tuple[Core, TestClient, Phone]) -> None:
    core, client, phone = home
    nonce = client.post("/v1/challenge", json={"device": phone.id}).json()["nonce"]
    headers = phone.headers(op="data.get", key="normal", nonce=nonce, body=b"{}")
    r = client.post("/v1/data", headers=headers, content=b"not json")
    assert r.json()["error"]["code"] == "body_mismatch"


def test_log_list_endpoint(home: tuple[Core, TestClient, Phone]) -> None:
    core, client, phone = home
    post(client, phone, "/v1/data", "data.get", {"ids": ["sys.cpu"]})
    signed(client, phone, "GET", "/v1/quick", "quick.list", "normal")
    bad_nonce = client.post("/v1/challenge", json={"device": phone.id}).json()["nonce"]
    client.post(
        "/v1/ping",
        headers=phone.headers(op="status", key="normal", nonce=bad_nonce, body=b"{}"),
        content=b"{}",
    )

    r = post(client, phone, "/v1/log", "log.list", {})
    assert r.status_code == 200, r.text
    doc = r.json()
    check_response("/v1/log", "post", 200, doc)
    assert titles(doc["entries"]) == [
        "Rejected ping: op_mismatch",
        "Paired Мой iPhone",
        "Core started",
    ]
    assert doc["next"] is None

    doc = post(client, phone, "/v1/log", "log.list", {"include_reads": True, "limit": 3}).json()
    check_response("/v1/log", "post", 200, doc)
    assert titles(doc["entries"]) == [
        "Accepted log.list",  # this request: journaled before it is answered
        "Accepted log.list",
        "Rejected ping: op_mismatch",
    ]
    assert doc["next"]
    older = post(
        client, phone, "/v1/log", "log.list", {"include_reads": True, "before": doc["next"]}
    ).json()
    assert titles(older["entries"])[:2] == ["Accepted quick.list", "Accepted data.get"]

    errors = post(
        client, phone, "/v1/log", "log.list", {"filter": "errors", "query": "OP_MISMATCH"}
    )
    assert titles(errors.json()["entries"]) == ["Rejected ping: op_mismatch"]

    r = post(client, phone, "/v1/log", "log.list", {"limit": 500})
    assert r.status_code == 400 and r.json()["error"]["code"] == "bad_request"


def test_quick_list(home: tuple[Core, TestClient, Phone]) -> None:
    _, client, phone = home
    r = signed(client, phone, "GET", "/v1/quick", "quick.list", "normal")
    assert r.status_code == 200
    check_response("/v1/quick", "get", 200, r.json())
    assert r.json() == {"items": []}


def test_stage2_ops_need_the_normal_key_and_right_op(home: tuple[Core, TestClient, Phone]) -> None:
    _, client, phone = home
    body = b'{"ids":["sys.cpu"]}'
    nonce = client.post("/v1/challenge", json={"device": phone.id}).json()["nonce"]
    r = client.post(
        "/v1/data",
        headers=phone.headers(op="log.list", key="normal", nonce=nonce, body=body),
        content=body,
    )
    assert r.json()["error"]["code"] == "op_mismatch"
    nonce = client.post("/v1/challenge", json={"device": phone.id}).json()["nonce"]
    r = client.post(
        "/v1/data",
        headers=phone.headers(op="data.get", key="critical", nonce=nonce, body=body),
        content=body,
    )
    assert r.json()["error"]["code"] == "wrong_key_level"


def test_status_and_devices_still_fit_contract(home: tuple[Core, TestClient, Phone]) -> None:
    _, client, phone = home
    r = signed(client, phone, "GET", "/v1/status", "status", "normal")
    check_response("/v1/status", "get", 200, r.json())
    r = signed(client, phone, "GET", "/v1/devices", "devices.list", "normal")
    check_response("/v1/devices", "get", 200, r.json())


# --- the real Mac --------------------------------------------------------------------


@pytest.mark.mac
def test_psutil_probe_on_the_mac() -> None:
    from rh_core.system import PsutilProbe

    probe = PsutilProbe()
    cpu = probe.cpu_percent()
    assert 0.0 <= cpu <= 100.0
    assert 0.0 <= probe.cpu_percent() <= 100.0  # second call: no fresh sample needed
    assert 0.0 < probe.memory_percent() < 100.0
    assert probe.disk_free() > 1_000_000_000
    print(f"cpu {cpu:.1f}%, memory {probe.memory_percent():.1f}%, disk free {probe.disk_free()}")
