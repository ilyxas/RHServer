"""Pairing sessions (SPEC §4.2).

`rhcore pair` opens a session over the admin socket: the core makes a one-time
code (5 minutes) and a pairing string for the QR. When the phone's /v1/pair
request passes verification it waits here until the owner answers y/n in the
terminal or the code expires; the code is spent only when pairing succeeds.
One session at a time: a new `rhcore pair` cancels the previous one.
"""

from __future__ import annotations

import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from rh_common.crypto import b64e
from rh_common.protocol import PAIR_CODE_TTL, PairCode, PairingString, PairRequest, format_ts


@dataclass
class Candidate:
    request: PairRequest
    fingerprint: str
    peer: str | None
    decided: threading.Event = field(default_factory=threading.Event)
    accepted: bool = False
    withdrawn: bool = False  # the phone hung up before the terminal answered


@dataclass
class Session:
    code: PairCode
    string: str
    candidate: Candidate | None = None
    arrived: threading.Event = field(default_factory=threading.Event)
    done: threading.Event = field(default_factory=threading.Event)
    result: str | None = None  # accepted | rejected | expired | cancelled
    closed: bool = False
    used: bool = False


class Pairing:
    def __init__(self, *, url: str, core_key_b64: str, clock: Callable[[], datetime]) -> None:
        self._url = url
        self._core_key = core_key_b64
        self._clock = clock
        self._lock = threading.Lock()
        self._session: Session | None = None
        self.auto_accept = False  # dev mode only: `rhcore dev up --auto-pair`

    def start(self) -> Session:
        code = b64e(secrets.token_bytes(16))
        return self.open(PairCode(code=code, expires=self._clock() + PAIR_CODE_TTL))

    def open(self, code: PairCode) -> Session:
        """Open a session for a given code (start() makes a random one; tests pass their own)."""
        string = PairingString(
            url=self._url, core_key=self._core_key, code=code.code, exp=format_ts(code.expires)
        ).encode()
        with self._lock:
            if self._session is not None:
                self._end(self._session, "cancelled")
            self._session = Session(code=code, string=string, used=code.used)
            return self._session

    def find_code(self, code: str) -> PairCode | None:
        with self._lock:
            s = self._session
            if s is None or s.closed or s.code.code != code:
                return None
            # A request still waiting for y/n does not use the code up: a retry with the
            # same keys may take its place (see submit).
            busy = s.candidate is not None and s.candidate.decided.is_set()
            return PairCode(code=s.code.code, expires=s.code.expires, used=s.used or busy)

    def submit(self, candidate: Candidate) -> Session | None:
        """Attach a verified request to the open session; None if it is gone or busy.

        A request with the same fingerprint as the one waiting for y/n replaces it:
        the phone lost the first connection without the core noticing and retried.
        The replaced request ends as withdrawn, the terminal is asked again.
        """
        with self._lock:
            s = self._session
            if s is None or s.closed or s.used:
                return None
            if s.code.code != candidate.request.obj.nonce:
                return None
            old = s.candidate
            if old is not None:
                if old.decided.is_set() or old.fingerprint != candidate.fingerprint:
                    return None
                old.withdrawn = True
                old.decided.set()
            s.candidate = candidate
            if self.auto_accept:
                candidate.accepted = True
                candidate.decided.set()
            s.arrived.set()
            return s

    def decide(self, session: Session, accept: bool, candidate: Candidate | None = None) -> None:
        with self._lock:
            c = session.candidate
            if c is None or c.decided.is_set() or (candidate is not None and c is not candidate):
                return
            c.accepted = accept
            if accept:
                session.used = True
            c.decided.set()

    def withdraw(self, session: Session, candidate: Candidate) -> bool:
        """The phone disconnected while waiting: drop its request, keep the code.

        False if the terminal already answered (then the outcome stands).
        """
        with self._lock:
            if session.candidate is not candidate or candidate.decided.is_set() or session.closed:
                return False
            candidate.withdrawn = True
            candidate.decided.set()
            session.candidate = None
            session.arrived.clear()
            return True

    def finish(self, session: Session, result: str) -> None:
        """Called once the outcome is written: close the session."""
        with self._lock:
            if result == "accepted":
                session.used = True
            self._end(session, result)

    def cancel(self, session: Session, result: str = "cancelled") -> None:
        with self._lock:
            self._end(session, result)

    def current(self) -> Session | None:
        with self._lock:
            return self._session

    def _end(self, session: Session, result: str) -> None:
        if session.result is None:
            session.result = result
        self._close(session)
        if self._session is session:
            self._session = None

    def seconds_left(self, session: Session) -> float:
        return max(0.0, (session.code.expires - self._clock()).total_seconds())

    @staticmethod
    def _close(session: Session) -> None:
        session.closed = True
        session.arrived.set()
        if session.candidate is not None and not session.candidate.decided.is_set():
            session.candidate.decided.set()
        session.done.set()
