"""Core journal (SPEC §5.2): append-only JSON Lines, one file per day.

File name: <YYYYMMDD>.jsonl, the same date format as ~/Hst/CGC<YYYYMMDD>.txt, by
the Mac's local date. Each line is the canonical JSON (RFC 8785) of one record;
`prev` is the sha256 of the previous line's bytes, across file boundaries, so an
edit or deletion after the fact breaks the chain. Times inside records are UTC.
"""

from __future__ import annotations

import json
import os
import re
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rh_common.crypto import sha256_hex
from rh_common.jcs import JCSError, canonicalize, canonicalize_text

GENESIS = "0" * 64
AGENT_ID = "RemoteHands"
_FILE_RE = re.compile(r"\A\d{8}\.jsonl\Z")


def _utc_ms(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class Journal:
    def __init__(self, directory: Path, *, clock: Callable[[], datetime] | None = None) -> None:
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self._clock = clock or (lambda: datetime.now(UTC))
        self._lock = threading.Lock()
        self._prev = self._last_hash()
        files = journal_files(self.dir)
        self._last_day = files[-1].stem if files else ""

    def _last_hash(self) -> str:
        for path in reversed(journal_files(self.dir)):
            data = path.read_bytes()
            lines = data.rstrip(b"\n").split(b"\n") if data.strip() else []
            if lines:
                return sha256_hex(lines[-1])
        return GENESIS

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        """Write one record; fields with value None are left out."""
        with self._lock:
            now = self._clock()
            record = {k: v for k, v in fields.items() if v is not None}
            record.update(ts=_utc_ms(now), event=event, prev=self._prev)
            line = canonicalize(record)
            # Never go back to an older file (clock or time zone moved back): the chain
            # is read in file-name order.
            day = max(f"{now.astimezone():%Y%m%d}", self._last_day)
            path = self.dir / f"{day}.jsonl"
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                os.write(fd, line + b"\n")
                os.fsync(fd)
            finally:
                os.close(fd)
            self._prev = sha256_hex(line)
            self._last_day = day
            return record


def journal_files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.iterdir() if _FILE_RE.match(p.name))


@dataclass(frozen=True)
class Problem:
    file: str
    line: int
    message: str


def read(directory: Path) -> Iterator[tuple[Path, int, bytes]]:
    for path in journal_files(directory):
        for number, line in enumerate(path.read_bytes().split(b"\n"), start=1):
            if line:
                yield path, number, line


def verify(directory: Path) -> list[Problem]:
    """Check every line is canonical JSON and the prev chain is unbroken."""
    problems: list[Problem] = []
    prev = GENESIS
    for path, number, line in read(directory):
        try:
            canonical = canonicalize_text(line)
        except (JCSError, UnicodeDecodeError) as e:
            problems.append(Problem(path.name, number, f"not JSON: {e}"))
            prev = sha256_hex(line)
            continue
        if canonical != line:
            problems.append(Problem(path.name, number, "line is not canonical JSON"))
        record = json.loads(line)
        if record.get("prev") != prev:
            problems.append(Problem(path.name, number, "prev does not match the previous line"))
        prev = sha256_hex(line)
    return problems
