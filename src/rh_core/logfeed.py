"""The Log feed (log.list, SPEC §8.5) built from the core journal.

Every journal record gets a kind (command / approval / chat / error / system) or
is left out of the feed: accepted requests are reads (noise) or the cause of a
command whose effect has its own record. The journal file itself keeps all of
them. Entries go newest first; a cursor is the position of the last entry
returned, so pages do not shift when new records are appended.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rh_common.crypto import sha256_hex
from rh_core.journal import journal_files

FILTERS: dict[str, frozenset[str] | None] = {
    "all": None,
    "commands": frozenset({"command"}),
    "approvals": frozenset({"approval"}),
    "chat": frozenset({"chat"}),
    "errors": frozenset({"error"}),
}
MAX_LIMIT = 200
DEFAULT_LIMIT = 50
MAX_QUERY = 200

_DEVICE_RE = re.compile(r"\A[0-9a-f]{32}\Z")
_CURSOR_RE = re.compile(r"\A(\d{8}):([1-9]\d{0,9})\Z")

Names = Callable[[str], str | None]


class BadCursor(ValueError):
    pass


@dataclass(frozen=True, order=True)
class Position:
    day: str  # YYYYMMDD, the journal file name
    line: int  # 1-based line number in that file

    def cursor(self) -> str:
        raw = f"{self.day}:{self.line}".encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    @classmethod
    def from_cursor(cls, cursor: str) -> Position:
        try:
            raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        except (binascii.Error, UnicodeDecodeError, ValueError) as e:
            raise BadCursor("before is not a cursor from next") from e
        m = _CURSOR_RE.match(raw)
        if not m:
            raise BadCursor("before is not a cursor from next")
        return cls(m.group(1), int(m.group(2)))


def kind_of(record: dict[str, Any], *, include_reads: bool = False) -> str | None:
    """The feed kind of a journal record, or None if it stays out of the feed.

    Accepted requests are left out unless `include_reads`: then they are system."""
    event = str(record.get("event", ""))
    result = record.get("result")
    if event.startswith("approval."):
        return "approval"
    if event.startswith("chat."):
        return "chat"
    if event == "friend.message":
        return "chat"
    if event.startswith("friend.question") or event.startswith("friend.decision"):
        return "approval"  # the owner's decisions for Friend, like approvals for the agent
    if result in ("rejected", "error", "failed"):
        return "error"
    if event in ("request", "challenge"):
        # accepted: a read, or a command shown by its effect
        return "system" if include_reads else None
    if event == "pairing":
        return "command" if result == "accepted" else "system"
    if event == "device.revoked":
        return "command"
    if event == "pairing.started":
        return None  # the code itself is not news; the pairing outcome is
    return "system"


def _text(value: Any) -> str | None:
    return None if value is None else str(value)


def _short(value: Any) -> str:
    return value[:8] if isinstance(value, str) else "?"


def render(record: dict[str, Any], names: Names) -> tuple[str, str | None]:
    """Title and detail of an entry: one line, English, ready to show."""
    event = str(record.get("event", ""))
    result = record.get("result")
    reason = record.get("reason")
    detail = _text(record.get("detail"))

    def name(device: Any) -> str:
        if not isinstance(device, str):
            return "?"
        return names(device) or device[:8]

    if event == "request":
        if result == "accepted":
            return f"Accepted {record.get('op')}", detail
        return f"Rejected {record.get('op')}: {reason}", detail
    if event == "challenge":
        return f"Rejected challenge: {reason}", detail
    if event == "pairing":
        if result == "accepted":
            fp = record.get("fingerprint")
            auto = " (dev auto-pair)" if record.get("auto") else ""
            return f"Paired {record.get('name')}{auto}", f"fingerprint {fp}" if fp else None
        if result == "rejected":
            return f"Pairing rejected: {reason}", detail
        if result == "withdrawn":
            return "Pairing request withdrawn", "the phone disconnected before the answer"
    if event == "device.revoked":
        by = record.get("by")
        by_text = "from the terminal" if by == "terminal" else f"by {name(by)}"
        return f"Revoked {name(record.get('device'))}", by_text
    if event == "friend.message":
        return f"Message to Friend from {name(record.get('device'))}", None
    if event == "friend.question":
        return "Friend asks for a decision", f"question {_short(record.get('id'))}"
    if event == "friend.question.withdrawn":
        return "Friend withdrew a question", f"question {_short(record.get('id'))}"
    if event == "friend.decision":
        verb = "Allowed" if record.get("decision") == "allow" else "Denied"
        return (
            f"{verb} Friend's action ({name(record.get('device'))})",
            f"question {_short(record.get('question_id'))}, decision {_short(record.get('id'))}",
        )
    if event == "friend.decision.used":
        return "Friend used a decision", f"decision {_short(record.get('id'))}"
    if event == "friend.decision.refused":
        return f"Friend's decision refused: {reason}", f"decision {_short(record.get('id'))}"
    if event == "core.started":
        return "Core started", f"{record.get('mode')}, version {record.get('version')}"
    if event == "core.stopped":
        return "Core stopped", None
    if result == "rejected":
        return f"{event} rejected: {reason}", detail
    return event, detail


def entry(
    record: dict[str, Any], line: bytes, names: Names, *, include_reads: bool = False
) -> dict[str, Any] | None:
    kind = kind_of(record, include_reads=include_reads)
    if kind is None:
        return None
    title, detail = render(record, names)
    ts = str(record.get("ts", ""))
    out: dict[str, Any] = {
        "id": sha256_hex(line),
        "ts": ts[:19] + "Z",
        "kind": kind,
        "event": str(record.get("event", "")),
        "title": title,
    }
    if detail:
        out["detail"] = detail
    device = record.get("device")
    if isinstance(device, str) and _DEVICE_RE.match(device):
        out["device"] = device
    op = record.get("op")
    if isinstance(op, str):
        out["op"] = op
    return out


def _newest_first(directory: Path) -> Iterator[tuple[Position, bytes]]:
    for path in reversed(journal_files(directory)):
        lines = path.read_bytes().split(b"\n")
        for number in range(len(lines), 0, -1):
            line = lines[number - 1]
            if line:
                yield Position(path.stem, number), line


def _matches(e: dict[str, Any], query: str) -> bool:
    hay = " ".join(str(e.get(k, "")) for k in ("title", "detail", "event", "op", "device"))
    return query in hay.casefold()


def page(
    directory: Path,
    *,
    names: Names,
    filter: str = "all",
    query: str | None = None,
    before: str | None = None,
    limit: int = DEFAULT_LIMIT,
    include_reads: bool = False,
) -> tuple[list[dict[str, Any]], str | None]:
    """One page of the feed and the cursor of the next (older) page, or None."""
    kinds = FILTERS[filter]
    start = Position.from_cursor(before) if before else None
    needle = query.casefold() if query else None
    found: list[tuple[Position, dict[str, Any]]] = []
    for pos, line in _newest_first(directory):
        if start is not None and pos >= start:
            continue
        try:
            record = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue  # `rhcore journal verify` reports broken lines
        if not isinstance(record, dict):
            continue
        e = entry(record, line, names, include_reads=include_reads)
        if e is None or (kinds is not None and e["kind"] not in kinds):
            continue
        if needle is not None and not _matches(e, needle):
            continue
        found.append((pos, e))
        if len(found) > limit:
            break
    more = len(found) > limit
    found = found[:limit]
    return [e for _, e in found], (found[-1][0].cursor() if more else None)


@dataclass(frozen=True)
class Query:
    filter: str = "all"
    query: str | None = None
    before: str | None = None
    limit: int = DEFAULT_LIMIT
    include_reads: bool = False


def parse_query(doc: Any) -> Query:
    """Validate a log.list body; ValueError with the reason if it does not fit."""
    if not isinstance(doc, dict):
        raise ValueError("body must be a JSON object")
    unknown = set(doc) - {"filter", "query", "before", "limit", "include_reads"}
    if unknown:
        raise ValueError(f"unknown keys: {sorted(unknown)}")
    filter_ = doc.get("filter", "all")
    if filter_ not in FILTERS:
        raise ValueError(f"filter must be one of {list(FILTERS)}")
    query = doc.get("query")
    if query is not None and (not isinstance(query, str) or len(query) > MAX_QUERY):
        raise ValueError(f"query must be a string of at most {MAX_QUERY} characters")
    before = doc.get("before")
    if before is not None:
        if not isinstance(before, str):
            raise ValueError("before must be a cursor string")
        Position.from_cursor(before)  # BadCursor is a ValueError
    limit = doc.get("limit", DEFAULT_LIMIT)
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be an integer 1..{MAX_LIMIT}")
    include_reads = doc.get("include_reads", False)
    if not isinstance(include_reads, bool):
        raise ValueError("include_reads must be true or false")
    return Query(
        filter=filter_, query=query or None, before=before, limit=limit, include_reads=include_reads
    )
