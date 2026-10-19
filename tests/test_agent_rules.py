"""agents.status rules: process + working directory + transcript activity."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from rh_core.agent_rules import Proc, ProcessRules, Rule, claude_slug
from rh_core.agents import Member, Team
from rh_core.config import ConfigError, from_dict

NOW = 1_800_000_000.0
HOME = Path("/Users/owner")


@dataclass
class FakeProcesses:
    procs: list[Proc] = field(default_factory=list)
    calls: int = 0

    def processes(self) -> list[Proc]:
        self.calls += 1
        return self.procs


def touch(path: Path, age_s: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}\n")
    os.utime(path, (NOW - age_s, NOW - age_s))


def rules(procs: list[Proc], *rule: Rule) -> tuple[ProcessRules, FakeProcesses]:
    fake = FakeProcesses(procs)
    return ProcessRules(rule, processes=fake, now=lambda: NOW), fake


def test_claude_slug() -> None:
    assert claude_slug(HOME / "Friend") == "-Users-owner-Friend"
    assert claude_slug(HOME / "Development/My.App_x") == "-Users-owner-Development-My-App-x"


def test_default_transcripts_only_for_claude() -> None:
    claude = Rule(id="A", process="claude", cwd=HOME / "proj")
    assert claude.transcript_glob() == str(
        Path("~/.claude/projects").expanduser() / "-Users-owner-proj" / "*.jsonl"
    )
    assert Rule(id="B", process="Voyager").transcript_glob() is None
    assert Rule(id="C", process="claude").transcript_glob() is None  # no cwd, no slug


def test_stopped_without_matching_process(tmp_path: Path) -> None:
    touch(tmp_path / "t.jsonl", 1)
    r, _ = rules(
        [Proc("claude", "/usr/local/bin/claude", str(HOME / "other"))],
        Rule(id="A", process="claude", cwd=HOME / "proj", transcripts=str(tmp_path / "*.jsonl")),
    )
    assert r.evaluate([Member("A", "")]) == {"A": "stopped"}


def test_working_then_idle(tmp_path: Path) -> None:
    proc = Proc("claude", "/opt/claude/bin/claude", str(HOME / "proj"))
    rule = Rule(id="A", process="claude", cwd=HOME / "proj", transcripts=str(tmp_path / "*.jsonl"))
    touch(tmp_path / "old.jsonl", 3600)
    touch(tmp_path / "new.jsonl", 30)
    r, _ = rules([proc], rule)
    assert r.evaluate([Member("A", "")]) == {"A": "working"}
    touch(tmp_path / "new.jsonl", 61)
    assert r.evaluate([Member("A", "")]) == {"A": "idle"}
    r2, _ = rules([proc], Rule(**{**rule.__dict__, "working_within_s": 120}))
    assert r2.evaluate([Member("A", "")]) == {"A": "working"}


def test_idle_without_transcripts(tmp_path: Path) -> None:
    r, _ = rules(
        [Proc("Voyager", "/Applications/Voyager.app/Contents/MacOS/Voyager", None)],
        Rule(id="V", process="Voyager"),
        Rule(id="E", process="claude", cwd=HOME, transcripts=str(tmp_path / "none/*.jsonl")),
    )
    assert r.evaluate([Member("V", ""), Member("E", "")]) == {"V": "idle", "E": "stopped"}


def test_match_by_executable_basename() -> None:
    r, _ = rules(
        [Proc("node", "/usr/local/bin/claude", str(HOME))], Rule(id="A", process="claude", cwd=HOME)
    )
    assert r.evaluate([Member("A", "")]) == {"A": "idle"}


def test_monitoring_while_active_then_idle(tmp_path: Path) -> None:
    proc = Proc("claude", "claude", str(HOME / "Friend"))
    rule = Rule(
        id="Friend",
        process="claude",
        cwd=HOME / "Friend",
        transcripts=str(tmp_path / "*.jsonl"),
        when_running="monitoring",
        stale_after_s=4200,
    )
    r, _ = rules([proc], rule)
    touch(tmp_path / "s.jsonl", 3000)  # hourly check: older than 60 s, still monitoring
    assert r.evaluate([Member("Friend", "")]) == {"Friend": "monitoring"}
    touch(tmp_path / "s.jsonl", 4300)
    assert r.evaluate([Member("Friend", "")]) == {"Friend": "idle"}
    (tmp_path / "s.jsonl").unlink()
    assert r.evaluate([Member("Friend", "")]) == {"Friend": "idle"}
    r2, _ = rules([], rule)
    assert r2.evaluate([Member("Friend", "")]) == {"Friend": "stopped"}


def test_when_running_without_stale_limit() -> None:
    r, _ = rules([Proc("x", "x", None)], Rule(id="X", process="x", when_running="monitoring"))
    assert r.evaluate([Member("X", "")]) == {"X": "monitoring"}


def test_no_rule_is_unknown_and_processes_listed_once() -> None:
    r, fake = rules([], Rule(id="A", process="a"), Rule(id="B", process="b"))
    got = r.evaluate([Member("A", ""), Member("B", ""), Member("Cloud", "")])
    assert got == {"A": "stopped", "B": "stopped", "Cloud": "unknown"}
    assert fake.calls == 1
    r.evaluate([Member("Cloud", "")])
    assert fake.calls == 1  # no rule needed: no process listing


def test_team_rows_with_rules(tmp_path: Path) -> None:
    team_file = tmp_path / "team.md"
    team_file.write_text(
        "## Команда\n\n- **Owner** — person.\n- **A** — agent.\n- **Cloud** — cloud.\n"
    )
    r, _ = rules([Proc("a", "a", None)], Rule(id="A", process="a", when_running="monitoring"))
    rows = Team(team_file, skip=["Owner"], rules=r).rows()
    assert [(row["id"], row["status"]) for row in rows] == [
        ("A", {"state": "ok", "text": "monitoring"}),
        ("Cloud", {"state": "off", "text": "unknown"}),
    ]


BASE = {"mode": "dev", "data_dir": "/tmp/x", "whois": False}


def test_config_rules() -> None:
    cfg = from_dict(
        {
            **BASE,
            "agents": {
                "skip": ["Owner"],
                "rule": [
                    {
                        "id": "Friend",
                        "process": "claude",
                        "cwd": "~/Friend",
                        "when_running": "monitoring",
                        "stale_after_s": 4200,
                    },
                    {"id": "Voyager", "process": "Voyager"},
                ],
            },
        }
    )
    friend, voyager = cfg.agent_rules
    assert friend.cwd == Path("~/Friend").expanduser()
    assert (friend.when_running, friend.stale_after_s, friend.working_within_s) == (
        "monitoring",
        4200,
        60,
    )
    assert voyager == Rule(id="Voyager", process="Voyager")


@pytest.mark.parametrize(
    "rule",
    [
        {"process": "claude"},
        {"id": "A"},
        {"id": "A", "process": "a", "cwd": "relative/dir"},
        {"id": "A", "process": "a", "when_running": "stuck"},
        {"id": "A", "process": "a", "working_within_s": 0},
        {"id": "A", "process": "a", "stale_after_s": "70m"},
        {"id": "A", "process": "a", "app": "Claude"},
        "A",
    ],
)
def test_config_rule_errors(rule: object) -> None:
    with pytest.raises(ConfigError):
        from_dict({**BASE, "agents": {"rule": [rule]}})


def test_config_one_rule_per_agent() -> None:
    with pytest.raises(ConfigError):
        from_dict(
            {**BASE, "agents": {"rule": [{"id": "A", "process": "a"}, {"id": "A", "process": "b"}]}}
        )


@pytest.mark.mac
def test_real_processes_on_the_mac() -> None:
    from rh_core.agent_rules import PsutilProcesses

    procs = PsutilProcesses().processes()
    me = [p for p in procs if p.cwd == os.getcwd() and "python" in (p.name + p.exe).lower()]
    assert me, "this test process should be listed with its cwd"
