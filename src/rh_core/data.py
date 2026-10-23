"""Built-in data sources (SPEC §5.4) and data.get.

A data_id that is neither built in nor registered (stage 5) is `pending`; a source
that fails returns `error` with a message, and the rest of the batch still comes.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from rh_common.friend import Question
from rh_common.protocol import format_ts
from rh_core import logfeed
from rh_core.agents import Team
from rh_core.system import SystemProbe

DATA_ID_RE = re.compile(r"\A[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+\Z")
MAX_IDS = 32
ACTIVITY_ROWS = 10

# (type, value, unit or None)
Reading = tuple[str, Any, str | None]


class DataSources:
    def __init__(
        self,
        *,
        probe: SystemProbe,
        team: Team,
        journal_dir: Path,
        names: logfeed.Names,
        core_version: str,
        agent_version: Callable[[], str | None],
        clock: Callable[[], datetime],
        questions: Callable[[], list[Question]] = list,
    ) -> None:
        self.probe = probe
        self.team = team
        self.journal_dir = journal_dir
        self.names = names
        self.core_version = core_version
        self.agent_version = agent_version
        self.clock = clock
        self.questions = questions
        self.builtin: dict[str, Callable[[], Reading]] = {
            "sys.cpu": lambda: ("number", round(self.probe.cpu_percent(), 1), "%"),
            "sys.memory": lambda: ("number", round(self.probe.memory_percent(), 1), "%"),
            "sys.disk_free": lambda: ("number", self.probe.disk_free(), "bytes"),
            "rh.status": self._status,
            "rh.approvals": lambda: ("rows", [], None),  # stage 4
            "rh.questions": self._questions,  # Friend's questions; the agent's at stage 3
            "rh.activity": self._activity,
            "agents.status": lambda: ("rows", self.team.rows(), None),
        }

    def _status(self) -> Reading:
        agent = self.agent_version()
        if agent is None:
            return (
                "status",
                {"state": "warn", "text": f"core {self.core_version} · agent not running"},
                None,
            )
        return "status", {"state": "ok", "text": f"core {self.core_version} · agent {agent}"}, None

    def _questions(self) -> Reading:
        """One row per open Friend question: title = the question's first line, subtitle =
        the tool it names; the Chat tab shows text and action in full."""
        rows = []
        for q in self.questions():
            first = q.text.strip().splitlines()[0] if q.text.strip() else q.text
            rows.append(
                {
                    "id": q.id,
                    "title": first[:200],
                    "subtitle": f"Friend asks · {_tool_of(q.action)}",
                    "status": {"state": "warn", "text": "waiting"},
                    "at": q.asked_at,
                }
            )
        return "rows", rows, None

    def _activity(self) -> Reading:
        entries, _ = logfeed.page(self.journal_dir, names=self.names, limit=ACTIVITY_ROWS)
        rows = []
        for e in entries:
            row = {"id": e["id"], "title": e["title"], "at": e["ts"]}
            if "detail" in e:
                row["subtitle"] = e["detail"]
            rows.append(row)
        return "rows", rows, None

    def get(self, ids: list[str]) -> dict[str, dict[str, Any]]:
        """Values for data.get; blocking (CPU sampling), so call off the event loop."""
        values: dict[str, dict[str, Any]] = {}
        for data_id in ids:
            source = self.builtin.get(data_id)
            if source is None:
                values[data_id] = {"status": "pending"}
                continue
            try:
                type_, value, unit = source()
            except Exception as e:  # one broken source must not hide the others
                values[data_id] = {"status": "error", "message": f"{type(e).__name__}: {e}"}
                continue
            out: dict[str, Any] = {
                "status": "active",
                "type": type_,
                "value": value,
                "at": format_ts(self.clock()),
            }
            if unit is not None:
                out["unit"] = unit
            values[data_id] = out
        return values


def _tool_of(action: str) -> str:
    try:
        doc = json.loads(action)
        return str(doc["tool"])
    except (ValueError, KeyError, TypeError):
        return "?"


def parse_ids(doc: Any) -> list[str]:
    """Validate a data.get body; ValueError with the reason if it does not fit."""
    if not isinstance(doc, dict) or set(doc) != {"ids"}:
        raise ValueError('body must be {"ids": [<data_id>, ...]}')
    ids = doc["ids"]
    if not isinstance(ids, list) or not 1 <= len(ids) <= MAX_IDS:
        raise ValueError(f"ids must be a list of 1..{MAX_IDS} data_id")
    for data_id in ids:
        if not isinstance(data_id, str) or len(data_id) > 64 or not DATA_ID_RE.match(data_id):
            raise ValueError(f"not a data_id: {data_id!r}")
    if len(set(ids)) != len(ids):
        raise ValueError("ids must be unique")
    return list(ids)
