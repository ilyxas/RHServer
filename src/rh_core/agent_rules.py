"""Status rules for agents.status (SPEC §5.4), approved by the owner.

A rule finds an agent's process by program name and working directory (never by
app: one app hosts several sessions), then looks at how recently its session
transcript changed:

    no matching process                              -> stopped
    process, newest transcript within working_within_s -> working
    process, otherwise                               -> idle
    when_running (e.g. "monitoring") replaces working/idle while the transcript
      changed within stale_after_s (or always, without stale_after_s); after
      that the agent is idle
    no rule for the agent                            -> unknown

Rules live in the local core config (`[[agents.rule]]`), so paths and ids of the
owner's Mac never enter the repository.
"""

from __future__ import annotations

import glob
import os
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import psutil

from rh_core.agents import AgentState, Member

CLAUDE_PROJECTS = Path("~/.claude/projects")
WORKING_WITHIN_S = 60
WHEN_RUNNING: tuple[AgentState, ...] = ("working", "idle", "monitoring")


@dataclass(frozen=True)
class Rule:
    id: str
    process: str  # program name or executable basename
    cwd: Path | None = None  # working directory of the process; None: any
    transcripts: str | None = None  # glob; None: Claude Code's default for `claude`
    working_within_s: int = WORKING_WITHIN_S
    when_running: AgentState | None = None
    stale_after_s: int | None = None

    def transcript_glob(self) -> str | None:
        if self.transcripts is not None:
            return str(Path(self.transcripts).expanduser())
        if self.process == "claude" and self.cwd is not None:
            return str(CLAUDE_PROJECTS.expanduser() / claude_slug(self.cwd) / "*.jsonl")
        return None


def claude_slug(cwd: Path) -> str:
    """Claude Code's project folder name for a working directory: every character
    other than a letter or digit becomes "-" (/Users/owner/Friend -> -Users-owner-Friend)."""
    return re.sub(r"[^A-Za-z0-9]", "-", str(cwd))


@dataclass(frozen=True)
class Proc:
    name: str
    exe: str
    cwd: str | None


class ProcessList(Protocol):
    def processes(self) -> list[Proc]: ...


class PsutilProcesses:
    """The owner's processes; others' cwd is unreadable without root and is skipped."""

    def processes(self) -> list[Proc]:
        out = []
        for p in psutil.process_iter(["name", "exe", "cwd"]):
            info = p.info
            out.append(Proc(name=info["name"] or "", exe=info["exe"] or "", cwd=info["cwd"]))
        return out


class ProcessRules:
    def __init__(
        self,
        rules: Iterable[Rule],
        *,
        processes: ProcessList | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.rules = {r.id: r for r in rules}
        self.processes = processes or PsutilProcesses()
        self.now = now

    def evaluate(self, members: list[Member]) -> dict[str, AgentState]:
        procs: list[Proc] | None = None
        out: dict[str, AgentState] = {}
        for m in members:
            rule = self.rules.get(m.id)
            if rule is None:
                out[m.id] = "unknown"
                continue
            if procs is None:
                procs = self.processes.processes()  # once per call, only if a rule needs it
            out[m.id] = self.state(rule, procs)
        return out

    def state(self, rule: Rule, procs: list[Proc]) -> AgentState:
        if not any(_matches(rule, p) for p in procs):
            return "stopped"
        age = self.transcript_age(rule)
        if rule.when_running is not None:
            if rule.stale_after_s is not None and (age is None or age > rule.stale_after_s):
                return "idle"
            return rule.when_running
        return "working" if age is not None and age <= rule.working_within_s else "idle"

    def transcript_age(self, rule: Rule) -> float | None:
        """Seconds since the newest transcript changed; None if there is none."""
        pattern = rule.transcript_glob()
        if pattern is None:
            return None
        newest: float | None = None
        for path in glob.glob(pattern):
            try:
                mtime = os.stat(path).st_mtime
            except OSError:
                continue
            newest = mtime if newest is None else max(newest, mtime)
        return None if newest is None else max(0.0, self.now() - newest)


def _matches(rule: Rule, p: Proc) -> bool:
    if rule.process not in (p.name, os.path.basename(p.exe)):
        return False
    return rule.cwd is None or p.cwd == str(rule.cwd)
