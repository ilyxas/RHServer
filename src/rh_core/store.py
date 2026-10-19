"""SQLite registry of rh-core: devices and nonces (SPEC §5.1).

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

from rh_common.crypto import b64e
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
]


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
