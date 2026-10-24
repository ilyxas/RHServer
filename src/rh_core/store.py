"""SQLite registry of rh-core: devices, nonces (SPEC §5.1), the channel agent's questions and
decisions (friend slice 2), the owner's messages and the agent's replies (friend slice 3).

Later stages add tables (action_id, data_id, approvals, quick access) as new
migrations; existing ones are never edited.
"""

from __future__ import annotations

import secrets
import sqlite3
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from rh_common.crypto import b64e
from rh_common.friend import Question
from rh_common.protocol import NONCE_TTL, Device, NonceRecord, fingerprint, format_ts, parse_ts

MIGRATIONS: list[str] = [
    """
    CREATE TABLE devices (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        key_normal BLOB NOT NULL,
        key_critical BLOB NOT NULL,
        key_ssh BLOB NOT NULL,
        fingerprint TEXT NOT NULL,
        peer TEXT,
        paired_at TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
        revoked_at TEXT
    );
    CREATE TABLE nonces (
        nonce TEXT PRIMARY KEY,
        device TEXT NOT NULL,
        expires TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX nonces_expires ON nonces (expires);
    """,
    # friend slice 2: questions the channel agent asks the owner, and the signed decisions that
    # answer them. A decision is spent once (used_at); the gate asks over the admin socket.
    """
    CREATE TABLE friend_questions (
        id TEXT PRIMARY KEY,
        text TEXT NOT NULL,
        action TEXT NOT NULL,
        asked_at TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('open', 'answered', 'withdrawn')),
        decision_id TEXT,
        closed_at TEXT
    );
    CREATE TABLE friend_decisions (
        id TEXT PRIMARY KEY,
        question_id TEXT NOT NULL,
        device TEXT NOT NULL,
        key TEXT NOT NULL,
        decision TEXT NOT NULL CHECK (decision IN ('allow', 'deny')),
        question_sha256 TEXT NOT NULL,
        action TEXT NOT NULL,
        signed_at TEXT NOT NULL,
        accepted_at TEXT NOT NULL,
        used_at TEXT
    );
    """,
    # friend slice 2, last round: a deny or a new question about the same action voids the
    # unused allows for it (the newest decision counts). voided_by: "deny:<id>" or
    # "question:<id>".
    """
    ALTER TABLE friend_decisions ADD COLUMN voided_at TEXT;
    ALTER TABLE friend_decisions ADD COLUMN voided_by TEXT
    """,
    # any single agent: whose question or decision it is, and which agent the channel is
    # bound to. Rows from before get the configured agent on the first start (bind_channel).
    """
    ALTER TABLE friend_questions ADD COLUMN agent TEXT;
    ALTER TABLE friend_decisions ADD COLUMN agent TEXT;
    CREATE TABLE channel (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        agent TEXT NOT NULL,
        since TEXT NOT NULL
    )
    """,
    # friend slice 3: the owner's messages with their state (what the phone shows under each
    # one) and the agent's replies. `seq` is one counter for both tables: a message takes a
    # new seq on every change, so `friend.messages {since}` returns what changed after it.
    # The texts live here, where they can be deleted; the journal keeps their hashes.
    """
    CREATE TABLE friend_seq (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        value INTEGER NOT NULL
    );
    INSERT INTO friend_seq (id, value) VALUES (1, 0);
    CREATE TABLE friend_messages (
        id TEXT PRIMARY KEY,
        seq INTEGER NOT NULL,
        message_id TEXT NOT NULL,
        device TEXT NOT NULL,
        agent TEXT NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('question', 'task')),
        re TEXT,
        text TEXT NOT NULL,
        body_sha256 TEXT NOT NULL,
        accepted_at TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('accepted', 'received', 'waiting', 'answered',
                                             'rejected', 'superseded')),
        prompt_id TEXT,
        received_at TEXT,
        closed_at TEXT,
        reject_code TEXT,
        superseded_by TEXT
    );
    CREATE UNIQUE INDEX friend_messages_device_message ON friend_messages (device, message_id);
    CREATE INDEX friend_messages_seq ON friend_messages (seq);
    CREATE TABLE friend_replies (
        seq INTEGER PRIMARY KEY,
        message_id TEXT NOT NULL REFERENCES friend_messages (id),
        kind TEXT NOT NULL CHECK (kind IN ('progress', 'final')),
        text TEXT NOT NULL,
        at TEXT NOT NULL
    );
    CREATE INDEX friend_replies_message ON friend_replies (message_id, seq)
    """,
]

OPEN_STATES = ("accepted", "received", "waiting")  # the agent still owes an answer


@dataclass(frozen=True)
class ChannelChange:
    """What bind_channel did when the configured agent differs from the bound one."""

    previous: str
    agent: str
    withdrawn: list[str]  # question ids
    voided: list[str]  # decision ids


@dataclass(frozen=True)
class ReplyRow:
    seq: int
    message_id: str  # spool id of the owner's message
    kind: str  # progress | final
    text: str
    at: str

    def to_api(self) -> dict[str, Any]:
        return {"seq": self.seq, "kind": self.kind, "text": self.text, "at": self.at}


@dataclass(frozen=True)
class MessageRow:
    """The owner's message as the phone sees it: state plus the agent's replies."""

    id: str  # spool id
    seq: int  # bumped on every change
    message_id: str  # the phone's id
    device: str
    agent: str
    kind: str  # question | task
    re: str | None
    text: str
    accepted_at: str
    state: str  # accepted | received | waiting | answered | rejected | superseded
    body_sha256: str = ""  # of the signed body: a retry must carry the same one
    prompt_id: str | None = None
    received_at: str | None = None
    closed_at: str | None = None
    reject_code: str | None = None
    superseded_by: str | None = None
    replies: tuple[ReplyRow, ...] = ()

    def to_api(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id,
            "seq": self.seq,
            "message_id": self.message_id,
            "device": self.device,
            "agent": self.agent,
            "kind": self.kind,
            "text": self.text,
            "accepted_at": self.accepted_at,
            "state": self.state,
            "replies": [r.to_api() for r in self.replies],
        }
        for key in ("re", "received_at", "closed_at", "reject_code", "superseded_by"):
            value = getattr(self, key)
            if value is not None:
                out[key] = value
        return out


@dataclass(frozen=True)
class DecisionRow:
    id: str  # spool id of the envelope
    question_id: str
    device: str
    key: str
    decision: str
    question_sha256: str
    action: str
    signed_at: str
    accepted_at: str
    used_at: str | None
    voided_at: str | None = None
    voided_by: str | None = None
    agent: str | None = None


@dataclass(frozen=True)
class DeviceRow:
    id: str
    name: str
    fingerprint: str
    peer: str | None
    paired_at: str
    status: str
    revoked_at: str | None

    def to_api(self, *, current: str | None = None) -> dict[str, object]:
        out: dict[str, object] = {
            "id": self.id,
            "name": self.name,
            "fingerprint": self.fingerprint,
            "paired_at": self.paired_at,
            "status": self.status,
            "current": self.id == current,
        }
        if self.revoked_at:
            out["revoked_at"] = self.revoked_at
        return out


class Store:
    def __init__(self, path: Path | str) -> None:
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        if str(path) != ":memory:":
            self._db.execute("PRAGMA journal_mode=WAL")
        with self._tx() as db:
            db.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            row = db.execute("SELECT version FROM schema_version").fetchone()
            version = row["version"] if row else 0
            if row is None:
                db.execute("INSERT INTO schema_version VALUES (0)")
            for i, sql in enumerate(MIGRATIONS[version:], start=version + 1):
                # executescript() would commit the open transaction; run statements one by one.
                for statement in filter(str.strip, sql.split(";")):
                    db.execute(statement)
                db.execute("UPDATE schema_version SET version = ?", (i,))

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
            self._db.execute("COMMIT")

    def close(self) -> None:
        self._db.close()

    # --- devices -----------------------------------------------------------

    def add_device(
        self,
        *,
        device_id: str,
        name: str,
        keys: Mapping[str, bytes],
        now: datetime,
        peer: str | None = None,
    ) -> None:
        fp = fingerprint({level: b64e(k) for level, k in keys.items()})
        with self._tx() as db:
            db.execute(
                "INSERT INTO devices (id, name, key_normal, key_critical, key_ssh, fingerprint,"
                " peer, paired_at, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active')",
                (
                    device_id,
                    name,
                    keys["normal"],
                    keys["critical"],
                    keys["ssh"],
                    fp,
                    peer,
                    format_ts(now),
                ),
            )

    def device(self, device_id: str) -> Device | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if row is None:
            return None
        return Device(
            id=row["id"],
            name=row["name"],
            keys={
                "normal": row["key_normal"],
                "critical": row["key_critical"],
                "ssh": row["key_ssh"],
            },
            status=row["status"],
        )

    def device_row(self, device_id: str) -> DeviceRow | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        return _row(row) if row else None

    def devices(self) -> list[DeviceRow]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM devices ORDER BY paired_at DESC, id").fetchall()
        return [_row(r) for r in rows]

    def revoke(self, device_id: str, *, now: datetime) -> bool:
        """Revoke a device; False if there is no such device. Idempotent."""
        with self._tx() as db:
            row = db.execute("SELECT status FROM devices WHERE id = ?", (device_id,)).fetchone()
            if row is None:
                return False
            if row["status"] != "revoked":
                db.execute(
                    "UPDATE devices SET status = 'revoked', revoked_at = ? WHERE id = ?",
                    (format_ts(now), device_id),
                )
        return True

    # --- nonces ------------------------------------------------------------

    def issue_nonce(self, device_id: str, *, now: datetime) -> tuple[str, datetime]:
        nonce = b64e(secrets.token_bytes(32))
        expires = now + NONCE_TTL
        with self._tx() as db:
            db.execute("DELETE FROM nonces WHERE expires < ?", (format_ts(now - NONCE_TTL),))
            db.execute(
                "INSERT INTO nonces (nonce, device, expires) VALUES (?, ?, ?)",
                (nonce, device_id, format_ts(expires)),
            )
        return nonce, expires

    def nonce(self, nonce: str) -> NonceRecord | None:
        with self._lock:
            row = self._db.execute("SELECT * FROM nonces WHERE nonce = ?", (nonce,)).fetchone()
        if row is None:
            return None
        return NonceRecord(
            device=row["device"], expires=parse_ts(row["expires"]), used=bool(row["used"])
        )

    def consume_nonce(self, nonce: str) -> bool:
        """Mark the nonce used; False if it was already used (a concurrent replay won)."""
        with self._tx() as db:
            cur = db.execute("UPDATE nonces SET used = 1 WHERE nonce = ? AND used = 0", (nonce,))
            return cur.rowcount == 1

    def put_nonce(self, nonce: str, record: NonceRecord) -> None:
        """For tests and vector fixtures: insert a nonce with a known value."""
        with self._tx() as db:
            db.execute(
                "INSERT INTO nonces (nonce, device, expires, used) VALUES (?, ?, ?, ?)",
                (nonce, record.device, format_ts(record.expires), int(record.used)),
            )

    def add_device_record(self, device: Device, *, now: datetime, peer: str | None) -> None:
        """For tests and vector fixtures: register a device with a given status."""
        self.add_device(device_id=device.id, name=device.name, keys=device.keys, now=now, peer=peer)
        if device.status != "active":
            self.set_status(device.id, device.status)

    def set_status(self, device_id: str, status: str) -> None:
        """For tests and vector fixtures."""
        with self._tx() as db:
            db.execute("UPDATE devices SET status = ? WHERE id = ?", (status, device_id))

    # --- the channel ------------------------------------------------------------

    def channel_agent(self) -> str | None:
        with self._lock:
            row = self._db.execute("SELECT agent FROM channel WHERE id = 1").fetchone()
        return str(row["agent"]) if row else None

    def bind_channel(self, agent: str, *, now: datetime) -> ChannelChange | None:
        """Bind the channel to the configured agent on start.

        First start (or rows from before schema 4): rows without an agent get this one.
        Another agent than the bound one: its open questions are withdrawn and its unused
        allows voided (voided_by "channel:<new agent>"), in one transaction; the change is
        returned for the journal. The same agent: None."""
        stamp = format_ts(now)
        with self._tx() as db:
            row = db.execute("SELECT agent FROM channel WHERE id = 1").fetchone()
            previous = str(row["agent"]) if row else None
            if previous is None:
                db.execute(
                    "INSERT INTO channel (id, agent, since) VALUES (1, ?, ?)", (agent, stamp)
                )
            for table in ("friend_questions", "friend_decisions"):
                db.execute(
                    f"UPDATE {table} SET agent = ? WHERE agent IS NULL",  # noqa: S608
                    (previous or agent,),
                )
            if previous is None or previous == agent:
                return None
            withdrawn = [
                r["id"]
                for r in db.execute(
                    "SELECT id FROM friend_questions WHERE agent = ? AND status = 'open'"
                    " ORDER BY asked_at, id",
                    (previous,),
                ).fetchall()
            ]
            db.execute(
                "UPDATE friend_questions SET status = 'withdrawn', closed_at = ?"
                " WHERE agent = ? AND status = 'open'",
                (stamp, previous),
            )
            voided = [
                r["id"]
                for r in db.execute(
                    "SELECT id FROM friend_decisions WHERE agent = ? AND decision = 'allow'"
                    " AND used_at IS NULL AND voided_at IS NULL ORDER BY accepted_at, id",
                    (previous,),
                ).fetchall()
            ]
            db.execute(
                "UPDATE friend_decisions SET voided_at = ?, voided_by = ? WHERE agent = ?"
                " AND decision = 'allow' AND used_at IS NULL AND voided_at IS NULL",
                (stamp, f"channel:{agent}", previous),
            )
            db.execute("UPDATE channel SET agent = ?, since = ? WHERE id = 1", (agent, stamp))
            return ChannelChange(previous=previous, agent=agent, withdrawn=withdrawn, voided=voided)

    # --- questions and decisions --------------------------------------------------

    def add_question(self, question: Question, *, agent: str) -> None:
        with self._tx() as db:
            db.execute(
                "INSERT INTO friend_questions (id, text, action, asked_at, status, agent)"
                " VALUES (?, ?, ?, ?, 'open', ?)",
                (question.id, question.text, question.action, question.asked_at, agent),
            )

    def question(self, question_id: str) -> tuple[Question, str] | None:
        """The question and its status, or None."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM friend_questions WHERE id = ?", (question_id,)
            ).fetchone()
        if row is None:
            return None
        return _question(row), str(row["status"])

    def open_questions(self) -> list[Question]:
        """Oldest first: the order the phone shows them."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM friend_questions WHERE status = 'open' ORDER BY asked_at, id"
            ).fetchall()
        return [_question(r) for r in rows]

    def withdraw_question(self, question_id: str, *, now: datetime) -> bool:
        """Close an open question without a decision; False if it is not open."""
        with self._tx() as db:
            cur = db.execute(
                "UPDATE friend_questions SET status = 'withdrawn', closed_at = ?"
                " WHERE id = ? AND status = 'open'",
                (format_ts(now), question_id),
            )
            return cur.rowcount == 1

    def answer_question(self, decision: DecisionRow) -> bool:
        """Record a decision and close its question in one transaction.

        False if the question is not open any more (a second answer loses)."""
        with self._tx() as db:
            cur = db.execute(
                "UPDATE friend_questions SET status = 'answered', decision_id = ?, closed_at = ?"
                " WHERE id = ? AND status = 'open'",
                (decision.id, decision.accepted_at, decision.question_id),
            )
            if cur.rowcount != 1:
                return False
            db.execute(
                "INSERT INTO friend_decisions (id, question_id, device, key, decision,"
                " question_sha256, action, signed_at, accepted_at, used_at, agent)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)",
                (
                    decision.id,
                    decision.question_id,
                    decision.device,
                    decision.key,
                    decision.decision,
                    decision.question_sha256,
                    decision.action,
                    decision.signed_at,
                    decision.accepted_at,
                    decision.agent,
                ),
            )
            return True

    def decision(self, decision_id: str) -> DecisionRow | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM friend_decisions WHERE id = ?", (decision_id,)
            ).fetchone()
        return _decision(row) if row else None

    def use_decision(self, decision_id: str, *, now: datetime) -> bool:
        """Spend a decision; False if it was already spent or voided (the first use wins)."""
        with self._tx() as db:
            cur = db.execute(
                "UPDATE friend_decisions SET used_at = ? WHERE id = ?"
                " AND used_at IS NULL AND voided_at IS NULL",
                (format_ts(now), decision_id),
            )
            return cur.rowcount == 1

    def void_unused_allows(
        self, action: str, *, now: datetime, by: str, keep: str | None = None
    ) -> list[str]:
        """Void every unused, unvoided allow for this action (a deny or a new question
        supersedes them); `keep` is a decision id to leave alone. Returns the ids voided."""
        with self._tx() as db:
            rows = db.execute(
                "SELECT id FROM friend_decisions WHERE action = ? AND decision = 'allow'"
                " AND used_at IS NULL AND voided_at IS NULL AND id IS NOT ?"
                " ORDER BY accepted_at, id",
                (action, keep),
            ).fetchall()
            ids = [row["id"] for row in rows]
            for decision_id in ids:
                db.execute(
                    "UPDATE friend_decisions SET voided_at = ?, voided_by = ? WHERE id = ?",
                    (format_ts(now), by, decision_id),
                )
            return ids

    def put_decision(self, decision: DecisionRow) -> None:
        """For tests and vector fixtures: a decision row as is (used or not)."""
        with self._tx() as db:
            db.execute(
                "INSERT INTO friend_decisions (id, question_id, device, key, decision,"
                " question_sha256, action, signed_at, accepted_at, used_at, agent)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    decision.id,
                    decision.question_id,
                    decision.device,
                    decision.key,
                    decision.decision,
                    decision.question_sha256,
                    decision.action,
                    decision.signed_at,
                    decision.accepted_at,
                    decision.used_at,
                    decision.agent,
                ),
            )

    # --- the owner's messages and the agent's replies (friend slice 3) -----------------

    def _next_seq(self, db: sqlite3.Connection) -> int:
        db.execute("UPDATE friend_seq SET value = value + 1 WHERE id = 1")
        row = db.execute("SELECT value FROM friend_seq WHERE id = 1").fetchone()
        return int(row["value"])

    def last_seq(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT value FROM friend_seq WHERE id = 1").fetchone()
        return int(row["value"]) if row else 0

    def add_message(
        self,
        *,
        id: str,
        message_id: str,
        device: str,
        agent: str,
        kind: str,
        re: str | None,
        text: str,
        body_sha256: str,
        now: datetime,
    ) -> MessageRow:
        with self._tx() as db:
            seq = self._next_seq(db)
            db.execute(
                "INSERT INTO friend_messages (id, seq, message_id, device, agent, kind, re, text,"
                " body_sha256, accepted_at, state)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'accepted')",
                (id, seq, message_id, device, agent, kind, re, text, body_sha256, format_ts(now)),
            )
        found = self.message(id)
        assert found is not None
        return found

    def find_message(self, *, device: str, message_id: str) -> MessageRow | None:
        """The message a device sent under this id, if any (a retry sends the same id)."""
        with self._lock:
            row = self._db.execute(
                "SELECT id FROM friend_messages WHERE device = ? AND message_id = ?",
                (device, message_id),
            ).fetchone()
        return self.message(str(row["id"])) if row else None

    def message(self, message_id: str) -> MessageRow | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM friend_messages WHERE id = ?", (message_id,)
            ).fetchone()
            if row is None:
                return None
            replies = self._db.execute(
                "SELECT * FROM friend_replies WHERE message_id = ? ORDER BY seq", (message_id,)
            ).fetchall()
        return _message(row, replies)

    def set_message_state(
        self,
        message_id: str,
        state: str,
        *,
        now: datetime,
        from_states: tuple[str, ...],
        **fields: Any,
    ) -> MessageRow | None:
        """Move a message to `state` if it is in one of `from_states`; None if it is not
        (the caller reports the current state). Extra fields are columns to set."""
        with self._tx() as db:
            row = db.execute(
                "SELECT state FROM friend_messages WHERE id = ?", (message_id,)
            ).fetchone()
            if row is None or row["state"] not in from_states:
                return None
            fields["state"] = state
            fields["seq"] = self._next_seq(db)
            if state in ("answered", "rejected", "superseded"):
                fields.setdefault("closed_at", format_ts(now))
            assignments = ", ".join(f"{key} = ?" for key in fields)
            db.execute(
                f"UPDATE friend_messages SET {assignments} WHERE id = ?",  # noqa: S608
                (*fields.values(), message_id),
            )
        return self.message(message_id)

    def add_reply(
        self, message_id: str, *, kind: str, text: str, now: datetime, state: str | None
    ) -> MessageRow | None:
        """Record a reply and, when `state` is given, move the message there in the same
        transaction. None if there is no such message."""
        with self._tx() as db:
            row = db.execute(
                "SELECT state FROM friend_messages WHERE id = ?", (message_id,)
            ).fetchone()
            if row is None:
                return None
            stamp = format_ts(now)
            db.execute(
                "INSERT INTO friend_replies (seq, message_id, kind, text, at)"
                " VALUES (?, ?, ?, ?, ?)",
                (self._next_seq(db), message_id, kind, text, stamp),
            )
            fields: dict[str, Any] = {"seq": self._next_seq(db)}
            if state is not None:
                fields["state"] = state
                if state == "answered":
                    fields["closed_at"] = stamp
            assignments = ", ".join(f"{key} = ?" for key in fields)
            db.execute(
                f"UPDATE friend_messages SET {assignments} WHERE id = ?",  # noqa: S608
                (*fields.values(), message_id),
            )
        return self.message(message_id)

    def supersede_open(self, *, by: str, now: datetime) -> list[str]:
        """Every message the agent still owes an answer to, other than `by`, is superseded
        by it (a new message from the owner interrupts the previous one). Returns the ids."""
        with self._tx() as db:
            marks = ", ".join("?" for _ in OPEN_STATES)
            rows = db.execute(
                f"SELECT id FROM friend_messages WHERE state IN ({marks}) AND id != ?"  # noqa: S608
                " ORDER BY seq",
                (*OPEN_STATES, by),
            ).fetchall()
            ids = [str(r["id"]) for r in rows]
            stamp = format_ts(now)
            for message_id in ids:
                db.execute(
                    "UPDATE friend_messages SET state = 'superseded', superseded_by = ?,"
                    " closed_at = ?, seq = ? WHERE id = ?",
                    (by, stamp, self._next_seq(db), message_id),
                )
        return ids

    def messages_since(self, since: int, *, limit: int) -> tuple[list[MessageRow], bool]:
        """Messages changed after `since`, oldest change first, and whether more follow."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM friend_messages WHERE seq > ? ORDER BY seq LIMIT ?",
                (since, limit + 1),
            ).fetchall()
            out = []
            for row in rows[:limit]:
                replies = self._db.execute(
                    "SELECT * FROM friend_replies WHERE message_id = ? ORDER BY seq", (row["id"],)
                ).fetchall()
                out.append(_message(row, replies))
        return out, len(rows) > limit

    def chat_text(self, record: Mapping[str, Any]) -> str | None:
        """The text behind a `chat.message` journal record: the owner's message by `id`, or
        the agent's reply by `reply_seq`. None once it was deleted from the store."""
        message_id, reply_seq = record.get("id"), record.get("reply_seq")
        if not isinstance(message_id, str):
            return None
        with self._lock:
            if isinstance(reply_seq, int) and not isinstance(reply_seq, bool):
                row = self._db.execute(
                    "SELECT text FROM friend_replies WHERE message_id = ? AND seq = ?",
                    (message_id, reply_seq),
                ).fetchone()
            else:
                row = self._db.execute(
                    "SELECT text FROM friend_messages WHERE id = ?", (message_id,)
                ).fetchone()
        return str(row["text"]) if row else None

    def open_messages(self) -> list[MessageRow]:
        """Messages the agent still owes an answer to, oldest first."""
        with self._lock:
            marks = ", ".join("?" for _ in OPEN_STATES)
            rows = self._db.execute(
                f"SELECT id FROM friend_messages WHERE state IN ({marks})"  # noqa: S608
                " ORDER BY accepted_at, seq",
                OPEN_STATES,
            ).fetchall()
        found = [self.message(str(r["id"])) for r in rows]
        return [m for m in found if m is not None]


def _message(row: sqlite3.Row, replies: list[sqlite3.Row]) -> MessageRow:
    return MessageRow(
        id=row["id"],
        seq=int(row["seq"]),
        message_id=row["message_id"],
        device=row["device"],
        agent=row["agent"],
        kind=row["kind"],
        re=row["re"],
        text=row["text"],
        accepted_at=row["accepted_at"],
        state=row["state"],
        body_sha256=row["body_sha256"],
        prompt_id=row["prompt_id"],
        received_at=row["received_at"],
        closed_at=row["closed_at"],
        reject_code=row["reject_code"],
        superseded_by=row["superseded_by"],
        replies=tuple(
            ReplyRow(
                seq=int(r["seq"]),
                message_id=r["message_id"],
                kind=r["kind"],
                text=r["text"],
                at=r["at"],
            )
            for r in replies
        ),
    )


def _question(row: sqlite3.Row) -> Question:
    return Question(id=row["id"], text=row["text"], action=row["action"], asked_at=row["asked_at"])


def _decision(row: sqlite3.Row) -> DecisionRow:
    return DecisionRow(
        id=row["id"],
        question_id=row["question_id"],
        device=row["device"],
        key=row["key"],
        decision=row["decision"],
        question_sha256=row["question_sha256"],
        action=row["action"],
        signed_at=row["signed_at"],
        accepted_at=row["accepted_at"],
        used_at=row["used_at"],
        voided_at=row["voided_at"],
        voided_by=row["voided_by"],
        agent=row["agent"],
    )


def _row(row: sqlite3.Row) -> DeviceRow:
    return DeviceRow(
        id=row["id"],
        name=row["name"],
        fingerprint=row["fingerprint"],
        peer=row["peer"],
        paired_at=row["paired_at"],
        status=row["status"],
        revoked_at=row["revoked_at"],
    )
