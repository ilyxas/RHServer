"""agents.status (SPEC §5.4): the team from ~/Friend/CLAUDE.md and its statuses.

The team is the bullet list under the heading that starts with "Команда"
("## Команда (идентификаторы)"), one member per line:

    - **Agent-Id** — role.

The file is read on every call, so edits show up without restarting the core.
How a status is found from processes is the owner's decision ([утвердить],
SPEC §5.4, §11); until the rules exist every member is "unknown".
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

AgentState = Literal["working", "idle", "monitoring", "stopped", "unknown"]
STATES: tuple[AgentState, ...] = ("working", "idle", "monitoring", "stopped", "unknown")
DEFAULT_HEADING = "Команда"

_HEADING = re.compile(r"\A(#{1,6})\s+(.*?)\s*\Z")
_MEMBER = re.compile(r"\A\s*[-*]\s+\*\*(?P<id>[^*]+?)\*\*\s*(?:[—–-]+\s*(?P<role>.*?))?\s*\Z")


@dataclass(frozen=True)
class Member:
    id: str
    role: str


def parse_team(text: str, heading: str = DEFAULT_HEADING) -> list[Member]:
    """Members listed under the first heading that starts with `heading`, in file order."""
    members: list[Member] = []
    level: int | None = None
    for line in text.splitlines():
        h = _HEADING.match(line)
        if h:
            if level is not None and len(h.group(1)) <= level:
                break
            if level is None and h.group(2).startswith(heading):
                level = len(h.group(1))
            continue
        if level is None:
            continue
        m = _MEMBER.match(line)
        if m:
            role = (m.group("role") or "").rstrip(".").strip()
            members.append(Member(id=m.group("id").strip(), role=role))
    return members


StatusRule = Callable[[Member], AgentState]


def _unknown(member: Member) -> AgentState:
    return "unknown"


class Team:
    def __init__(
        self,
        team_file: Path | None,
        *,
        skip: Iterable[str] = (),
        heading: str = DEFAULT_HEADING,
        rule: StatusRule = _unknown,
    ) -> None:
        self.team_file = team_file
        self.skip = frozenset(skip)
        self.heading = heading
        self.rule = rule

    def members(self) -> list[Member]:
        if self.team_file is None:
            return []
        text = self.team_file.read_text(encoding="utf-8")  # OSError -> data error for the client
        return [m for m in parse_team(text, self.heading) if m.id not in self.skip]

    def rows(self) -> list[dict[str, object]]:
        """Value of agents.status (type rows)."""
        out: list[dict[str, object]] = []
        for m in self.members():
            state = self.rule(m)
            row: dict[str, object] = {
                "id": m.id,
                "title": m.id,
                "status": {
                    "state": "ok" if state in ("working", "monitoring") else "off",
                    "text": state,
                },
            }
            if m.role:
                row["subtitle"] = m.role
            out.append(row)
        return out
