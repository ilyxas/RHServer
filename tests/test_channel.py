"""Any single agent on the channel (docs/any_single_agent.md): the agent's name comes from
`[channel] agent` only; switching it withdraws the previous agent's questions and voids its
unused allows; `rhcore channel set` checks first, writes both configs, restarts the core
and succeeds only when the running core reports the new agent; no "Friend" literal is
left in code, contracts or fixtures.
"""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import tomllib
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from rh_cli.channel import SetRequest, channel_set, replace_channel, rules_of
from rh_common.friend import Question, action_text, question_sha256
from rh_core import app
from rh_core.app import Core
from rh_core.config import Channel, Config, dev_config, from_dict, to_toml
from rh_core.store import DecisionRow, Store
from rh_friend.config import from_dict as agent_config_from_dict

ROOT = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
ACTION = action_text("Bash", {"command": "kill -CONT 4242", "description": "resume"})


def channel(agent: str, data: Path) -> Channel:
    return Channel(agent=agent, project_dir=data / agent, target=agent.lower())


def make_core(data: Path, agent: str, *, team: Path | None = None) -> Core:
    cfg = dev_config(data, team_file=team, channel=channel(agent, data))
    return Core(cfg, clock=lambda: NOW, ssh_host_keys=str(data / "none-*"))


def events(core: Core, name: str) -> list[dict[str, Any]]:
    out = []
    for f in sorted(core.config.journal_dir.glob("*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            if record["event"] == name:
                out.append(record)
    return out


def allow(core: Core, question: Question, decision_id: str) -> None:
    row = DecisionRow(
        id=decision_id,
        question_id=question.id,
        device="d" * 32,
        key="critical",
        decision="allow",
        question_sha256=question_sha256(question.text),
        action=question.action,
        signed_at="2026-10-23T12:00:00Z",
        accepted_at="2026-10-23T12:00:00Z",
        used_at=None,
        agent=core.agent,
    )
    assert core.store.answer_question(row)


# --- the core -------------------------------------------------------------------------------


def test_status_and_admin_name_the_channel_agent(short_dir: Path) -> None:
    core = make_core(short_dir, "Agent-Beta")
    status, doc = asyncio.run(app.status(core, None, b""))  # type: ignore[arg-type]
    assert status == 200 and doc["channel"] == {"agent": "Agent-Beta", "title": "Agent-Beta"}
    core.store.close()


def test_records_carry_the_agent(short_dir: Path) -> None:
    core = make_core(short_dir, "Agent-Beta")
    q = core.ask("Resume?", ACTION)
    (record,) = events(core, "friend.question")
    assert record["agent"] == "Agent-Beta" and record["id"] == q.id
    rows = core.data.get(["rh.questions"])["rh.questions"]["value"]
    assert rows[0]["subtitle"] == "Agent-Beta asks · Bash"
    core.store.close()


def test_switching_the_agent_withdraws_questions_and_voids_allows(short_dir: Path) -> None:
    first = make_core(short_dir, "Agent-Alpha")
    asked = first.ask("Resume?", ACTION)
    allowed = first.ask("Resume again?", ACTION)
    allow(first, allowed, "a" * 32)
    first.store.close()

    # Same agent again: nothing changes.
    same = make_core(short_dir, "Agent-Alpha")
    assert same.store.question(asked.id) == (asked, "open")
    assert events(same, "friend.channel.changed") == []
    same.store.close()

    second = make_core(short_dir, "Agent-Beta")
    assert second.store.question(asked.id) == (asked, "withdrawn")
    row = second.store.decision("a" * 32)
    assert row is not None and row.voided_by == "channel:Agent-Beta"
    (change,) = events(second, "friend.channel.changed")
    assert (change["from"], change["to"]) == ("Agent-Alpha", "Agent-Beta")
    assert change["withdrawn"] == [asked.id] and change["voided"] == ["a" * 32]
    # The previous agent's allow can no longer be spent, whoever asks.
    used = second.use_decision(
        "a" * 32, action=ACTION, question_sha256_=question_sha256(allowed.text)
    )
    assert used["ok"] is False and used["error"] == "superseded"
    assert second.store.open_questions() == []
    second.store.close()


def test_rows_from_before_schema_4_belong_to_the_first_configured_agent(tmp_path: Path) -> None:
    store = Store(tmp_path / "core.sqlite3")
    store.add_question(Question("q" * 32, "x", ACTION, "2026-10-23T12:00:00Z"), agent="tmp")
    store._db.execute("UPDATE friend_questions SET agent = NULL")  # as migrated from schema 3
    assert store.bind_channel("Agent-Alpha", now=NOW) is None
    row = store._db.execute("SELECT agent FROM friend_questions").fetchone()
    assert row["agent"] == "Agent-Alpha" and store.channel_agent() == "Agent-Alpha"
    store.close()


def test_agent_missing_from_the_team_file_is_a_warning_not_a_stop(short_dir: Path) -> None:
    team = short_dir / "team.md"
    team.write_text("## Команда\n\n- **Agent-Alpha** — builds.\n", encoding="utf-8")
    core = make_core(short_dir, "Agent-Zeta", team=team)
    (warning,) = events(core, "friend.channel.warning")
    assert warning["agent"] == "Agent-Zeta" and "not in the team file" in warning["reason"]
    assert core.agent_title == "Agent-Zeta"
    core.store.close()


def test_channel_agent_gets_a_status_rule_from_its_project(short_dir: Path) -> None:
    team = short_dir / "team.md"
    team.write_text("## Команда\n\n- **Agent-Alpha** — builds.\n", encoding="utf-8")
    core = make_core(short_dir, "Agent-Alpha", team=team)
    assert [r.id for r in core.config.rules] == ["Agent-Alpha"]
    assert core.config.rules[0].cwd == short_dir / "Agent-Alpha"
    core.store.close()


# --- rhcore channel set ------------------------------------------------------------------------


class Fake:
    """launchctl and tmux as the command sees them, and the running core's status."""

    def __init__(self, *, sessions: Sequence[str] = ("beta",), core_reports: str | None = None):
        self.sessions = set(sessions)
        self.calls: list[list[str]] = []
        self.core_reports = core_reports
        self.restarted = False
        self.config: Config | None = None

    def run(self, cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(cmd))
        if cmd[1:3] == ["has-session", "-t"]:
            code = 0 if cmd[3] in self.sessions else 1
            return subprocess.CompletedProcess(list(cmd), code, "", "no session" if code else "")
        if cmd[:3] == ["launchctl", "kickstart", "-k"]:
            self.restarted = True
            return subprocess.CompletedProcess(list(cmd), 0, "", "")
        raise AssertionError(cmd)

    def status(self, cfg: Config) -> dict[str, Any]:
        self.config = cfg
        if not self.restarted:
            raise ConnectionError("core down")
        agent = self.core_reports or cfg.ch.agent
        return {"ok": True, "channel": {"agent": agent, "title": agent}}


@pytest.fixture
def install(short_dir: Path) -> dict[str, Path]:
    """A core config for Agent-Alpha with a team file, the core key and an agent-side
    config whose gate rules the owner edited."""
    for name in ("Alpha", "Beta"):
        (short_dir / name).mkdir()
    team = short_dir / "team.md"
    team.write_text(
        "## Команда\n\n- **Owner** — decides.\n- **Agent-Alpha** — a.\n- **Agent-Beta** — b.\n"
        "- **agent-gamma** — c.\n",
        encoding="utf-8",
    )
    cfg = dev_config(
        short_dir / "data",
        team_file=team,
        channel=Channel(agent="Agent-Alpha", project_dir=short_dir / "Alpha", target="alpha"),
    )
    Core(cfg, clock=lambda: NOW, ssh_host_keys=str(short_dir / "none-*")).store.close()
    core_toml = short_dir / "core.toml"
    core_toml.write_text("# owner's note\n" + to_toml(cfg), encoding="utf-8")
    agent_toml = short_dir / "agent.toml"
    agent_toml.write_text(
        'agent = "Agent-Alpha"\n[bridge]\ntmux = "/opt/tmux"\ntarget = "alpha"\n\n'
        '[[gate.protected]]\nname = "owner\'s own rule"\ntools = ["Bash"]\nmatch = [\'x\']\n',
        encoding="utf-8",
    )
    return {"dir": short_dir, "core": core_toml, "agent": agent_toml}


def request(install: dict[str, Path], **kw: Any) -> SetRequest:
    doc: dict[str, Any] = {
        "config_path": install["core"],
        "agent": "Agent-Beta",
        "project_dir": install["dir"] / "Beta",
        "target": "beta",
        "agent_config": install["agent"],
        "core_label": "test.rh.core",
        "timeout_s": 2.0,
    }
    doc.update(kw)
    return SetRequest(**doc)


def run_set(install: dict[str, Path], fake: Fake, **kw: Any) -> tuple[int, str, str]:
    import io

    out = io.StringIO()
    code = channel_set(
        request(install, **kw),
        out=out,
        status=fake.status,
        run=fake.run,
        ask=Path("/venv/bin/rh-friend-ask"),
        sleep=lambda s: None,
        clock=lambda: datetime(2026, 10, 23, 12, 0, 0),
    )
    return code, out.getvalue(), ""


def test_channel_set_switches_and_checks_the_running_core(install: dict[str, Path]) -> None:
    fake = Fake()
    code, out, _ = run_set(install, fake)
    assert code == 0, out
    core = from_dict(tomllib.loads(install["core"].read_text(encoding="utf-8")))
    beta = (install["dir"] / "Beta").resolve()
    assert core.ch == Channel(agent="Agent-Beta", project_dir=beta, target="beta")
    assert install["core"].read_text(encoding="utf-8").startswith("# owner's note\n")
    agent = agent_config_from_dict(tomllib.loads(install["agent"].read_text(encoding="utf-8")))
    assert (agent.agent, agent.project_dir) == ("Agent-Beta", beta)
    assert agent.bridge is not None and (agent.bridge.target, agent.bridge.tmux) == (
        "beta",
        "/opt/tmux",
    )
    # The owner's gate rules survive the switch as written.
    assert agent.gate is not None and [r.name for r in agent.gate.protected] == ["owner's own rule"]
    assert ["/opt/tmux", "has-session", "-t", "beta"] in fake.calls
    assert any(
        c[:3] == ["launchctl", "kickstart", "-k"] and c[3].endswith("/test.rh.core")
        for c in fake.calls
    )
    backups = sorted(p.name for p in install["dir"].glob("*.bak-*"))
    assert backups == ["agent.toml.bak-20261023-120000", "core.toml.bak-20261023-120000"]
    assert "Agent-Alpha → Agent-Beta" in out


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"agent": "Agent-Zeta"}, "not in the team file"),
        ({"agent": "Agent-Gamma"}, "differs only in case"),
        ({"agent": "Agent Beta"}, "agent id"),
        ({"target": "nobody"}, "no tmux session"),
        ({"project_dir": Path("/nonexistent/Beta")}, "does not exist"),
    ],
)
def test_channel_set_checks_before_writing(
    install: dict[str, Path],
    change: dict[str, Any],
    message: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    before = {k: install[k].read_text(encoding="utf-8") for k in ("core", "agent")}
    fake = Fake()
    code, _, _ = run_set(install, fake, **change)
    assert code == 2
    assert message in capsys.readouterr().err
    assert {k: install[k].read_text(encoding="utf-8") for k in ("core", "agent")} == before
    assert not fake.restarted and list(install["dir"].glob("*.bak-*")) == []


def test_channel_set_fails_when_the_core_reports_another_agent(
    install: dict[str, Path], capsys: pytest.CaptureFixture[str]
) -> None:
    code, _, _ = run_set(install, Fake(core_reports="Agent-Alpha"), timeout_s=0.0)
    assert code == 1
    assert "does not report channel 'Agent-Beta'" in capsys.readouterr().err


def test_replace_channel_drops_an_old_friend_table() -> None:
    text = 'mode = "dev"\n\n[friend]\ndecide_window_s = 60\n\n[agents]\nskip = ["Owner"]\n'
    new = replace_channel(text, Channel(agent="A", project_dir=Path("/p"), target="a"))
    doc = tomllib.loads(new)
    assert "friend" not in doc and doc["agents"] == {"skip": ["Owner"]}
    assert doc["channel"] == {"agent": "A", "project_dir": "/p", "target": "a"}
    assert rules_of("a = 1\n") is None


# --- no literal ---------------------------------------------------------------------------------


def test_no_agent_name_is_hard_coded() -> None:
    """ "Friend" as a word (not the mechanism's FriendQuestion/FriendDecision/friend.*) must
    not come back into code, contracts or fixtures. The changelog keeps its history."""
    word = re.compile(r"\bFriend\b")
    found = []
    for top in ("src", "contracts", "tests/fixtures", "scripts"):
        for path in sorted((ROOT / top).rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts or path.name == "CHANGELOG.md":
                continue
            if path.suffix not in {".py", ".yaml", ".json", ".md", ".toml", ".txt", ".sh"}:
                continue
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if word.search(line):
                    found.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()[:80]}")
    assert found == []


def test_vectors_name_a_channel_agent_other_than_friend() -> None:
    for name in ("friend.json", "friend_decide.json"):
        doc = json.loads((ROOT / "contracts/vectors" / name).read_text(encoding="utf-8"))
        assert doc["agent"] == "Agent-Alpha"
