"""rh-core HTTP and WebSocket API (contracts/api/openapi.yaml), stages 1–2.

Every response, rejections included, is signed with the core key
(X-RH-Server-Sig). Every accepted and rejected request goes to the journal.
"""

from __future__ import annotations

import asyncio
import contextlib
import glob
import json
import os
import re
import secrets
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import anyio
from cryptography.hazmat.primitives.asymmetric import ec
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from rh_common import __version__
from rh_common.crypto import b64e, public_x963, sha256_hex, sign_der
from rh_common.friend import (
    MAX_TEXT,
    OP_DECIDE,
    OP_MESSAGES,
    OP_QUESTIONS,
    OP_SEND,
    DeviceEntry,
    FriendDecision,
    FriendMessage,
    Question,
    build_devices_doc,
    check_action,
    check_question_text,
    envelope_from_headers,
    parse_body,
    parse_decide_body,
    question_id,
    question_sha256,
    spool_id,
)
from rh_common.protocol import (
    ERROR_STATUS,
    HEADER_AUTH,
    HEADER_SERVER_SIG,
    KeyLevel,
    PairRequest,
    ProtocolError,
    Verdict,
    fingerprint,
    format_ts,
    frame_sig_message,
    parse_auth,
    parse_ts,
    server_sig_message,
    verify_pair,
    verify_request,
)
from rh_core import admin, keys, logfeed
from rh_core.agent_rules import ProcessRules
from rh_core.agents import Team
from rh_core.config import Config
from rh_core.data import DataSources, parse_ids
from rh_core.journal import Journal
from rh_core.pairing import Candidate, Pairing, Session
from rh_core.peers import LocalPeers, PeerLookup
from rh_core.store import DecisionRow, MessageRow, Store
from rh_core.system import PsutilProbe, SystemProbe

_DEVICE_RE = re.compile(r"\A[0-9a-f]{32}\Z")
WS_CLOSE_REVOKED = 4403
SSH_HOST_KEYS = "/etc/ssh/ssh_host_*_key.pub"


@dataclass(eq=False)  # kept in sets by identity
class Connection:
    websocket: WebSocket
    device: str
    nonce: str
    seq: int = 0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def send(
        self, core_key: ec.EllipticCurvePrivateKey, type_: str, data: dict[str, Any]
    ) -> None:
        async with self.lock:
            self.seq += 1
            payload = json.dumps({"seq": self.seq, "type": type_, "data": data}, ensure_ascii=False)
            sig = sign_der(
                core_key,
                frame_sig_message(ws_nonce=self.nonce, seq=self.seq, payload=payload.encode()),
            )
            frame = {"seq": self.seq, "payload": payload, "sig": b64e(sig)}
            await self.websocket.send_text(json.dumps(frame, ensure_ascii=False))


class Core:
    def __init__(
        self,
        config: Config,
        *,
        clock: Callable[[], datetime] | None = None,
        peers: PeerLookup | None = None,
        ssh_host_keys: str = SSH_HOST_KEYS,
        probe: SystemProbe | None = None,
    ) -> None:
        self.config = config
        self.clock = clock or (lambda: datetime.now(UTC).replace(microsecond=0))
        self.peers: PeerLookup = peers or LocalPeers()
        self.ssh_host_keys_glob = ssh_host_keys
        config.data_dir.mkdir(parents=True, exist_ok=True)
        config.data_dir.chmod(0o700)
        self.store = Store(config.db_path)
        self.journal = Journal(config.journal_dir, clock=lambda: datetime.now(UTC))
        self.key = keys.load_or_create(config.key_path)
        self.public_key = public_x963(self.key)
        self.pairing = Pairing(
            url=config.public_url, core_key_b64=b64e(self.public_key), clock=self.clock
        )
        self.connections: dict[str, set[Connection]] = {}
        self.data = DataSources(
            probe=probe or PsutilProbe(),
            team=Team(
                config.team_file,
                skip=config.team_skip,
                rules=ProcessRules(config.rules) if config.rules else None,
            ),
            journal_dir=config.journal_dir,
            names=self.device_name,
            core_version=__version__,
            agent_version=lambda: None,  # rh-agent arrives at stage 3
            clock=self.clock,
            questions=self.store.open_questions,
            agent_title=lambda: self.agent_title,
        )
        self.export_devices()
        self.bind_channel()

    # --- the channel agent -------------------------------------------------------

    @property
    def agent(self) -> str:
        """The channel agent's id: `[channel] agent`, the only place it is set."""
        return self.config.ch.agent

    @property
    def agent_title(self) -> str:
        """How the app and the Log name the agent. The team file lists ids, so the title
        is the id itself, whether or not the team file has it."""
        return self.agent

    def bind_channel(self) -> None:
        """On start: bind the store to the configured agent. Another agent than last time
        withdraws the previous agent's open questions and voids its unused allows
        (journal `friend.channel.changed`). An id missing from the team file is shown as
        is, with a warning in the journal; the core still starts."""
        change = self.store.bind_channel(self.agent, now=self.clock())
        if change is not None:
            self.journal.append(
                "friend.channel.changed",
                **{"from": change.previous, "to": change.agent},
                withdrawn=change.withdrawn,
                voided=change.voided,
            )
        try:
            members = {m.id for m in self.data.team.members()}
        except OSError as e:
            self.journal.append("friend.channel.warning", agent=self.agent, reason=str(e)[:200])
            return
        if self.config.team_file is not None and self.agent not in members:
            self.journal.append(
                "friend.channel.warning",
                agent=self.agent,
                reason=f"{self.agent} is not in the team file {self.config.team_file}",
            )

    def device_name(self, device_id: str) -> str | None:
        row = self.store.device_row(device_id)
        return row.name if row else None

    # --- responses -----------------------------------------------------------

    def signed(self, status: int, payload: dict[str, Any] | None, nonce: str) -> Response:
        body = (
            b""
            if payload is None
            else json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        )
        sig = sign_der(self.key, server_sig_message(nonce=nonce, status=status, body=body))
        return Response(
            body,
            status_code=status,
            media_type="application/json" if payload is not None else None,
            headers={HEADER_SERVER_SIG: b64e(sig)},
        )

    def refuse(self, error: ProtocolError, nonce: str) -> Response:
        return self.signed(
            error.status, {"error": {"code": error.code, "message": error.message}}, nonce
        )

    def ssh_host_keys(self) -> list[str]:
        lines = []
        for path in sorted(glob.glob(self.ssh_host_keys_glob)):
            with contextlib.suppress(OSError):
                lines.append(Path(path).read_text(encoding="utf-8").strip())
        return [line for line in lines if line]

    # --- device lifecycle ------------------------------------------------------

    def export_devices(self) -> None:
        """Write the signed device list the agent-side verifier reads (start, pairing, revoke)."""
        entries = []
        for row in self.store.devices():
            device = self.store.device(row.id)
            if device is not None:
                entries.append(
                    DeviceEntry(id=row.id, name=row.name, status=row.status, keys=device.keys)
                )
        doc = build_devices_doc(
            entries, core_key=self.key, core_pub=self.public_key, now=self.clock()
        )
        _write_public(self.config.devices_path, doc)

    async def revoke(self, device_id: str, *, by: str) -> bool:
        if not self.store.revoke(device_id, now=self.clock()):
            return False
        self.export_devices()
        self.journal.append("device.revoked", device=device_id, by=by)
        for conn in list(self.connections.get(device_id, ())):
            with contextlib.suppress(Exception):
                await conn.websocket.close(code=WS_CLOSE_REVOKED)
        return True

    # --- the channel agent's questions and decisions ------------------------------

    def ask(self, text: str, action: str) -> Question:
        """Record a question from the gate (admin socket); the phone lists it."""
        text = check_question_text(text)
        action = check_action(action)
        now = self.clock()
        question = Question(
            id=question_id(text, action, b64e(secrets.token_bytes(16))),
            text=text,
            action=action,
            asked_at=format_ts(now),
        )
        self.store.add_question(question, agent=self.agent)
        self.journal.append(
            "friend.question",
            agent=self.agent,
            id=question.id,
            question_sha256=question_sha256(text),
            action_sha256=sha256_hex(action.encode("utf-8")),
        )
        # Asking again about the same action supersedes what was allowed before and not used.
        self._void_allows(action, now=now, by=f"question:{question.id}", reason="new_question")
        return question

    def _void_allows(
        self, action: str, *, now: datetime, by: str, reason: str, keep: str | None = None
    ) -> None:
        for decision_id in self.store.void_unused_allows(action, now=now, by=by, keep=keep):
            self.journal.append(
                "friend.decision.voided",
                agent=self.agent,
                id=decision_id,
                reason=reason,
                by=by,
                action_sha256=sha256_hex(action.encode("utf-8")),
            )

    def withdraw(self, question_id_: str) -> bool:
        ok = self.store.withdraw_question(question_id_, now=self.clock())
        if ok:
            self.journal.append("friend.question.withdrawn", agent=self.agent, id=question_id_)
        return ok

    def check_decision(self, decision: FriendDecision) -> str | None:
        """Why a decision does not fit its question (bad_request message), or None."""
        found = self.store.question(decision.id)
        if found is None:
            return f"no question {decision.id}"
        question, status = found
        if status != "open":
            return f"question {decision.id} is {status}"
        if decision.question_sha256 != question_sha256(question.text):
            return "question_sha256 does not match the question asked"
        if decision.action != question.action:
            return "action does not match the question asked"
        return None

    def use_decision(
        self, decision_id: str, *, action: str, question_sha256_: str
    ) -> dict[str, Any]:
        """Spend an allow decision for exactly this action: the first use wins.

        The core checks everything itself, whatever the gate checked: the decision exists,
        names this action and question, says allow with the critical key, is not voided by
        a later deny or question, is fresh (`[channel] decide_window_s` after both the phone's
        `ts` and the core's `accepted_at`) and unused. Every refusal is journaled.

        Returns {"ok": True, ...} or {"ok": False, "error": code, "message"}.
        Codes: not_found, mismatch, wrong_key_level, denied, superseded, expired, already_used."""
        action_sha = sha256_hex(action.encode("utf-8"))

        def refuse(code: str, message: str) -> dict[str, Any]:
            self.journal.append(
                "friend.decision.refused",
                agent=self.agent,
                id=decision_id,
                reason=code,
                action_sha256=action_sha,
            )
            return _refused(code, message)

        row = self.store.decision(decision_id)
        if row is None:
            return refuse("not_found", f"no decision {decision_id}")
        found = self.store.question(row.question_id)
        if found is None:
            return refuse("mismatch", "the decision's question is gone")
        question, _ = found
        if (
            row.action != action
            or question.action != action
            or row.question_sha256 != question_sha256_
            or question_sha256(question.text) != question_sha256_
        ):
            return refuse("mismatch", "action or question do not match the decision")
        if row.decision != "allow":
            return refuse("denied", "the owner denied this action")
        if row.key != "critical":
            return refuse("wrong_key_level", "an allow must be signed with the critical key")
        if row.voided_at is not None:
            return refuse(
                "superseded", f"a later decision or question replaced it ({row.voided_by})"
            )
        now = self.clock()
        window = timedelta(seconds=self.config.decide_window_s)
        for label, stamp in (("signed", row.signed_at), ("accepted", row.accepted_at)):
            try:
                at = parse_ts(stamp)
            except ValueError:
                return refuse("expired", f"unreadable {label} time {stamp!r}")
            if now - at > window:
                return refuse(
                    "expired", f"{label} at {stamp}, older than {int(window.total_seconds())} s"
                )
        if not self.store.use_decision(decision_id, now=now):
            return refuse("already_used", "this decision was already used")
        self.journal.append(
            "friend.decision.used",
            agent=self.agent,
            id=decision_id,
            question_id=row.question_id,
            action_sha256=sha256_hex(action.encode("utf-8")),
        )
        return {
            "ok": True,
            "id": decision_id,
            "question_id": row.question_id,
            "used_at": format_ts(self.clock()),
        }

    # --- the owner's messages and the agent's replies (friend slice 3) -----------------

    def record_message(
        self, *, sid: str, device: str, message: FriendMessage, now: datetime
    ) -> MessageRow:
        """A new message from the owner: stored with its text, journaled as chat, and every
        message the agent still owed an answer to is superseded by it (the bridge interrupts
        the agent, so the previous turn ends without a reply)."""
        row = self.store.add_message(
            id=sid,
            message_id=message.id,
            device=device,
            agent=self.agent,
            kind=message.kind,
            re=message.re,
            text=message.text,
            now=now,
        )
        self.journal.append(
            "chat.message",
            author="owner",
            agent=self.agent,
            device=device,
            id=sid,
            kind=message.kind,
            re=message.re,
            text=message.text,
        )
        for previous in self.store.supersede_open(by=sid, now=now):
            self.journal.append("friend.message.superseded", agent=self.agent, id=previous, by=sid)
        return row

    def message_received(self, message_id: str, *, prompt_id: str | None) -> dict[str, Any]:
        """The agent-side verifier delivered the message to the session."""
        now = self.clock()
        row = self.store.set_message_state(
            message_id,
            "received",
            now=now,
            from_states=("accepted",),
            prompt_id=prompt_id,
            received_at=format_ts(now),
        )
        if row is None:
            return self._message_refused(message_id)
        self.journal.append(
            "friend.message.received", agent=self.agent, id=message_id, prompt_id=prompt_id
        )
        return {"ok": True, **row.to_api()}

    def message_rejected(self, message_id: str, *, code: str, detail: str) -> dict[str, Any]:
        """The agent-side verifier blocked the message (its reason is the code)."""
        row = self.store.set_message_state(
            message_id,
            "rejected",
            now=self.clock(),
            from_states=("accepted", "received"),
            reject_code=code,
        )
        if row is None:
            return self._message_refused(message_id)
        self.journal.append(
            "friend.message.rejected",
            agent=self.agent,
            id=message_id,
            reason=code,
            detail=detail[:200],
        )
        return {"ok": True, **row.to_api()}

    def reply(
        self, message_id: str, *, text: str, prompt_id: str | None, progress: bool
    ) -> dict[str, Any]:
        """The agent's reply to a message. The final reply of a turn (`progress` false)
        answers the message, unless the agent asked the owner a question since the message
        arrived: then the message waits for the decision and the reply is kept as progress.
        With `[channel] match_prompt_id`, the reply must name the prompt the verifier
        recorded for the message."""
        if not isinstance(text, str) or not text.strip():
            return _refused("bad_request", "text must be a non-empty string")
        text = text[:MAX_TEXT]
        row = self.store.message(message_id)
        if row is None:
            return _refused("not_found", f"no message {message_id}")
        if row.state not in ("accepted", "received", "waiting"):
            return _refused("closed", f"message {message_id} is {row.state}")
        if (
            self.config.ch.match_prompt_id
            and row.prompt_id is not None
            and prompt_id != row.prompt_id
        ):
            self.journal.append(
                "friend.reply.unmatched",
                agent=self.agent,
                id=message_id,
                prompt_id=prompt_id,
                expected=row.prompt_id,
            )
            return _refused("prompt_mismatch", "the reply names another prompt than the message")
        now = self.clock()
        since = row.received_at or row.accepted_at
        waiting = any(q.asked_at >= since for q in self.store.open_questions())
        if progress:
            kind, state, event = "progress", None, "friend.message.progress"
        elif waiting:
            kind, state, event = "progress", "waiting", "friend.message.waiting"
        else:
            kind, state, event = "final", "answered", "friend.message.answered"
        updated = self.store.add_reply(message_id, kind=kind, text=text, now=now, state=state)
        if updated is None:
            return _refused("not_found", f"no message {message_id}")
        self.journal.append(
            "chat.message", author=self.agent, agent=self.agent, id=message_id, kind=kind, text=text
        )
        self.journal.append(event, agent=self.agent, id=message_id)
        return {"ok": True, **updated.to_api()}

    def _message_refused(self, message_id: str) -> dict[str, Any]:
        row = self.store.message(message_id)
        if row is None:
            return _refused("not_found", f"no message {message_id}")
        return _refused("closed", f"message {message_id} is {row.state}")

    def replaced_by(self, req: PairRequest) -> list[str]:
        """Devices one `y` revokes (SPEC §4.2): `replaces`, else active ones with the same name."""
        active = [
            d for d in self.store.devices() if d.status == "active" and d.id != req.obj.device
        ]
        if req.replaces:
            return [d.id for d in active if d.id == req.replaces]
        return [d.id for d in active if d.name == req.name]


# --- signed endpoints -----------------------------------------------------------------

Handler = Callable[[Core, Verdict, Any], Awaitable[tuple[int, dict[str, Any] | None]]]
Parser = Callable[[bytes], Any]


def signed_endpoint(
    op: str, key: KeyLevel, handler: Handler, parse: Parser | None = None
) -> Callable[[Request], Awaitable[Response]]:
    """A signed operation. With `parse`, the handler gets the parsed body; a body
    that does not fit is refused with bad_request (stage 2 operations onwards)."""

    async def endpoint(request: Request) -> Response:
        core: Core = request.app.state.core
        body = await request.body()
        verdict = _verify(core, request.headers, body, op, key, request.client, journal=False)
        params: Any = body
        if verdict.error is None and parse is not None:
            try:
                params = parse(body)
            except ValueError as e:
                verdict = Verdict(
                    obj=verdict.obj,
                    device=verdict.device,
                    error=ProtocolError("bad_request", str(e)),
                    consume_nonce=False,
                )
        _journal_request(core, op, verdict, request.client)
        nonce = verdict.obj.nonce if verdict.obj else ""
        if verdict.error is not None:
            return core.refuse(verdict.error, nonce)
        status, payload = await handler(core, verdict, params)
        return core.signed(status, payload, nonce)

    return endpoint


def _json_body(parse: Callable[[Any], Any]) -> Parser:
    def parser(body: bytes) -> Any:
        try:
            doc = json.loads(body)
        except (ValueError, UnicodeDecodeError) as e:
            raise ValueError("body is not JSON") from e
        return parse(doc)

    return parser


def _verify(
    core: Core,
    headers: Any,
    body: bytes,
    op: str,
    key: KeyLevel,
    client: Any,
    *,
    journal: bool = True,
) -> Verdict:
    verdict = verify_request(
        headers=headers,
        body=body,
        op=op,
        key_level=key,
        now=core.clock(),
        find_device=core.store.device,
        find_nonce=core.store.nonce,
    )
    lost_race = False
    if verdict.consume_nonce and verdict.obj is not None:
        lost_race = not core.store.consume_nonce(verdict.obj.nonce)
    if lost_race and verdict.error is None:  # a replay of the same nonce got there first
        verdict = Verdict(
            obj=verdict.obj,
            device=verdict.device,
            error=ProtocolError("nonce_used", "nonce was already used"),
            consume_nonce=False,
        )
    if verdict.error is None and verdict.device is not None:
        row = core.store.device_row(verdict.device.id)
        node = core.peers.node(client.host, client.port) if client else None
        if row is not None and (node is None or node != row.peer):
            verdict = Verdict(
                obj=verdict.obj,
                device=verdict.device,
                error=ProtocolError("peer_mismatch", f"request came from Tailscale node {node!r}"),
                consume_nonce=False,
            )
    if journal:
        _journal_request(core, op, verdict, client)
    return verdict


def _journal_request(core: Core, op: str, verdict: Verdict, client: Any) -> None:
    obj = verdict.obj
    core.journal.append(
        "request",
        op=op,
        device=obj.device if obj else None,
        result="rejected" if verdict.error else "accepted",
        reason=verdict.error.code if verdict.error else None,
        detail=verdict.error.message if verdict.error else None,
        peer=f"{client.host}:{client.port}" if client else None,
    )


async def ping(core: Core, verdict: Verdict, body: bytes) -> tuple[int, dict[str, Any]]:
    return 200, {"pong": True, "server_time": format_ts(core.clock())}


async def status(core: Core, verdict: Verdict, body: bytes) -> tuple[int, dict[str, Any]]:
    return 200, {
        "mac_name": core.config.mac_name,
        "core_version": __version__,
        "agent_version": None,
        "mode": core.config.mode,
        "server_time": format_ts(core.clock()),
        "channel": {"agent": core.agent, "title": core.agent_title},
    }


async def devices_list(core: Core, verdict: Verdict, body: bytes) -> tuple[int, dict[str, Any]]:
    current = verdict.device.id if verdict.device else None
    return 200, {"devices": [d.to_api(current=current) for d in core.store.devices()]}


async def devices_revoke(core: Core, verdict: Verdict, body: bytes) -> tuple[int, dict[str, Any]]:
    try:
        doc = json.loads(body)
        target = doc["device_id"]
        if set(doc) != {"device_id"} or not isinstance(target, str) or not _DEVICE_RE.match(target):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        return 400, {
            "error": {"code": "malformed_auth", "message": 'body must be {"device_id": "<id>"}'}
        }
    by = verdict.device.id if verdict.device else "?"
    if not await core.revoke(target, by=by):
        return 404, {"error": {"code": "not_found", "message": f"no device {target}"}}
    return 200, {"device_id": target, "status": "revoked"}


async def data_get(core: Core, verdict: Verdict, ids: list[str]) -> tuple[int, dict[str, Any]]:
    values = await anyio.to_thread.run_sync(core.data.get, ids)
    return 200, {"values": values, "server_time": format_ts(core.clock())}


async def log_list(core: Core, verdict: Verdict, q: logfeed.Query) -> tuple[int, dict[str, Any]]:
    entries, next_ = await anyio.to_thread.run_sync(
        lambda: logfeed.page(
            core.config.journal_dir,
            names=core.device_name,
            filter=q.filter,
            query=q.query,
            before=q.before,
            limit=q.limit,
            include_reads=q.include_reads,
        )
    )
    return 200, {"entries": entries, "next": next_}


async def quick_list(core: Core, verdict: Verdict, body: bytes) -> tuple[int, dict[str, Any]]:
    return 200, {"items": []}  # quick.pin / quick.unpin arrive at stage 5


async def friend_questions(core: Core, verdict: Verdict, body: bytes) -> tuple[int, dict[str, Any]]:
    """friend.questions: what the channel agent is waiting for the owner to decide."""
    return 200, {
        "questions": [q.to_api() for q in core.store.open_questions()],
        "server_time": format_ts(core.clock()),
    }


async def friend_messages(
    core: Core, verdict: Verdict, q: MessagesQuery
) -> tuple[int, dict[str, Any]]:
    """friend.messages: the owner's messages changed after `since`, with their state and the
    agent's replies, oldest change first."""
    rows, more = await anyio.to_thread.run_sync(
        lambda: core.store.messages_since(q.since, limit=q.limit)
    )
    return 200, {
        "messages": [m.to_api() for m in rows],
        "next": rows[-1].seq if rows else q.since,
        "more": more,
        "server_time": format_ts(core.clock()),
    }


@dataclass(frozen=True)
class MessagesQuery:
    since: int = 0
    limit: int = 50


MESSAGES_MAX_LIMIT = 200


def parse_messages_query(doc: Any) -> MessagesQuery:
    """Validate a friend.messages body; ValueError with the reason if it does not fit."""
    if not isinstance(doc, dict):
        raise ValueError("body must be a JSON object")
    unknown = set(doc) - {"since", "limit"}
    if unknown:
        raise ValueError(f"unknown keys: {sorted(unknown)}")
    since = doc.get("since", 0)
    if isinstance(since, bool) or not isinstance(since, int) or since < 0:
        raise ValueError("since must be an integer >= 0 (the `next` of the previous answer)")
    limit = doc.get("limit", 50)
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError(f"limit must be an integer 1..{MESSAGES_MAX_LIMIT}")
    if not 1 <= limit <= MESSAGES_MAX_LIMIT:
        raise ValueError(f"limit must be an integer 1..{MESSAGES_MAX_LIMIT}")
    return MessagesQuery(since=since, limit=limit)


def _refused(code: str, message: str) -> dict[str, Any]:
    return {"ok": False, "error": code, "message": message}


async def friend_send(request: Request) -> Response:
    """friend.send: verify like any signed operation, then spool the request exactly as
    received, so the agent-side verifier can check the phone's signature itself."""
    core: Core = request.app.state.core
    body = await request.body()
    verdict = _verify(core, request.headers, body, OP_SEND, "normal", request.client, journal=False)
    if verdict.error is None:
        try:
            message = parse_body(body, core.agent)
        except ValueError as e:
            verdict = Verdict(
                obj=verdict.obj,
                device=verdict.device,
                error=ProtocolError("bad_request", str(e)),
                consume_nonce=False,
            )
    _journal_request(core, OP_SEND, verdict, request.client)
    nonce = verdict.obj.nonce if verdict.obj else ""
    if verdict.error is not None or verdict.device is None:
        error = verdict.error or ProtocolError("malformed_auth", "bad friend.send")
        return core.refuse(error, nonce)
    earlier = core.store.find_message(device=verdict.device.id, message_id=message.id)
    if earlier is not None:
        # The phone sends the same id again when it lost the first answer: one message,
        # not two; the answer it missed, not a second envelope.
        core.journal.append(
            "friend.message.retry", agent=core.agent, device=verdict.device.id, id=earlier.id
        )
        return core.signed(
            200,
            {
                "id": earlier.id,
                "message_id": earlier.message_id,
                "accepted_at": earlier.accepted_at,
            },
            nonce,
        )
    sid = spool_id(nonce)
    now = core.clock()
    envelope = envelope_from_headers(request.headers, body)
    _write_public(core.config.inbox_dir / f"{sid}.json", envelope.to_json())
    core.journal.append(
        "friend.message",
        agent=core.agent,
        device=verdict.device.id,
        id=sid,
        message_id=message.id,
        kind=message.kind,
        body_sha256=sha256_hex(body),
    )
    row = core.record_message(sid=sid, device=verdict.device.id, message=message, now=now)
    return core.signed(
        200, {"id": sid, "message_id": message.id, "accepted_at": row.accepted_at}, nonce
    )


async def friend_decide(request: Request) -> Response:
    """friend.decide: the owner's answer to a question. Verified like any signed operation
    with the key the object names; then the body must fit, the key level must fit the
    decision (allow: critical, deny: normal) and the decision must answer an open question
    exactly. Accepted: recorded, spooled as received for the verifier, question closed."""
    core: Core = request.app.state.core
    body = await request.body()
    try:
        key: KeyLevel = parse_auth(request.headers.get(HEADER_AUTH))[0].key
    except ProtocolError:
        key = "normal"  # the verification below reports malformed_auth
    verdict = _verify(core, request.headers, body, OP_DECIDE, key, request.client, journal=False)
    decision: FriendDecision | None = None
    if verdict.error is None:
        try:
            decision = parse_decide_body(body, core.agent)
            if decision.key_level != key:
                raise ProtocolError(
                    "wrong_key_level",
                    f"{OP_DECIDE} {decision.decision} requires the {decision.key_level} key",
                )
            problem = core.check_decision(decision)
            if problem is not None:
                raise ValueError(problem)
        except ProtocolError as e:
            verdict = Verdict(obj=verdict.obj, device=verdict.device, error=e, consume_nonce=False)
        except ValueError as e:
            verdict = Verdict(
                obj=verdict.obj,
                device=verdict.device,
                error=ProtocolError("bad_request", str(e)),
                consume_nonce=False,
            )
    _journal_request(core, OP_DECIDE, verdict, request.client)
    nonce = verdict.obj.nonce if verdict.obj else ""
    if (
        verdict.error is not None
        or verdict.device is None
        or verdict.obj is None
        or decision is None
    ):
        error = verdict.error or ProtocolError("malformed_auth", "bad friend.decide")
        return core.refuse(error, nonce)
    sid = spool_id(nonce)
    now = core.clock()
    row = DecisionRow(
        id=sid,
        question_id=decision.id,
        device=verdict.device.id,
        key=key,
        decision=decision.decision,
        question_sha256=decision.question_sha256,
        action=decision.action,
        signed_at=verdict.obj.ts,
        accepted_at=format_ts(now),
        used_at=None,
        agent=core.agent,
    )
    if not core.store.answer_question(row):  # a second answer raced this one
        error = ProtocolError("bad_request", f"question {decision.id} is already answered")
        core.journal.append(
            "request",
            op=OP_DECIDE,
            device=verdict.device.id,
            result="rejected",
            reason=error.code,
            detail=error.message,
            peer=_peer(request),
        )
        return core.refuse(error, nonce)
    envelope = envelope_from_headers(request.headers, body)
    _write_public(core.config.inbox_dir / f"{sid}.json", envelope.to_json())
    core.journal.append(
        "friend.decision",
        agent=core.agent,
        device=verdict.device.id,
        id=sid,
        question_id=decision.id,
        decision=decision.decision,
        key=key,
        action_sha256=sha256_hex(decision.action.encode("utf-8")),
        body_sha256=sha256_hex(body),
    )
    if decision.decision == "deny":
        # The newest decision counts: a deny voids every unused allow for the same action.
        core._void_allows(decision.action, now=now, by=f"deny:{sid}", reason="denied")
    return core.signed(
        200,
        {
            "id": sid,
            "question_id": decision.id,
            "decision": decision.decision,
            "accepted_at": format_ts(now),
        },
        nonce,
    )


def _write_public(path: Path, data: bytes) -> None:
    """Atomic write of a file the agent session's user reads (mode 644). A directory it
    creates is 755; an existing one keeps its mode, so the core's own data directory stays
    700 and production points these paths elsewhere (config [friend])."""
    missing = [p for p in (path.parent, *path.parent.parents) if not p.exists()]
    for directory in reversed(missing):
        directory.mkdir()
        directory.chmod(0o755)
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    try:
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


# --- unsigned and special endpoints ------------------------------------------------------


async def challenge(request: Request) -> Response:
    core: Core = request.app.state.core
    body = await request.body()
    try:
        doc = json.loads(body)
        device = doc["device"]
        if set(doc) != {"device"} or not isinstance(device, str) or not _DEVICE_RE.match(device):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        error = ProtocolError("malformed_auth", 'body must be {"device": "<id>"}')
        core.journal.append("challenge", result="rejected", reason=error.code)
        return core.refuse(error, "")
    record = core.store.device(device)
    if record is None or record.status != "active":
        code = "unknown_device" if record is None else "revoked_device"
        error = ProtocolError(
            code, f"device {device} is {'not paired' if record is None else 'revoked'}"
        )
        core.journal.append("challenge", device=device, result="rejected", reason=code)
        return core.refuse(error, "")
    now = core.clock()
    nonce, expires = core.store.issue_nonce(device, now=now)
    payload = {"nonce": nonce, "expires": format_ts(expires), "server_time": format_ts(now)}
    return core.signed(200, payload, nonce)


async def pair(request: Request) -> Response:
    core: Core = request.app.state.core
    body = await request.body()
    client = request.client
    peer = core.peers.node(client.host, client.port) if client else None
    try:  # sign the refusal over the code when the header can be read at all
        nonce = parse_auth(request.headers.get(HEADER_AUTH))[0].nonce
    except ProtocolError:
        nonce = ""
    try:
        req = verify_pair(
            headers=request.headers, body=body, now=core.clock(), find_code=core.pairing.find_code
        )
        nonce = req.obj.nonce
        if peer is None:
            raise ProtocolError(
                "peer_mismatch", "cannot tell which Tailscale node this request came from"
            )
        existing = core.store.device(req.obj.device)
        if existing is not None:
            raise ProtocolError(
                "pair_rejected", "these keys are already registered; generate new keys"
            )
        candidate = _candidate(core, req, peer)
        session = core.pairing.submit(candidate)
        if session is None:
            raise ProtocolError("bad_pair_code", "pairing code is unknown, used or expired")
    except ProtocolError as e:
        core.journal.append(
            "pairing", result="rejected", reason=e.code, detail=e.message, peer=_peer(request)
        )
        return core.refuse(e, nonce)
    return await _finish_pair(core, session, candidate, req, peer, request)


def _candidate(core: Core, req: PairRequest, peer: str | None) -> Candidate:
    return Candidate(request=req, fingerprint=fingerprint(req.keys_b64), peer=peer)


async def _finish_pair(
    core: Core,
    session: Session,
    candidate: Candidate,
    req: PairRequest,
    peer: str,
    request: Request,
) -> Response:
    result = "expired"
    try:
        if await _wait_decision(core, session, candidate, request) or candidate.withdrawn:
            # The phone is gone, or its retry took this request's place: nobody would get
            # device_id and ssh_host_keys here. Keep the code open for the retry.
            result = "withdrawn"
            core.journal.append(
                "pairing", device=req.obj.device, result="withdrawn", peer=_peer(request)
            )
            return Response(status_code=499)
        if not candidate.accepted:
            if candidate.decided.is_set() and not session.closed:
                result = "rejected"
                error = ProtocolError("pair_rejected", "pairing was declined in the terminal")
            else:
                result = session.result or "expired"
                error = ProtocolError(
                    "bad_pair_code", "pairing code expired before it was confirmed"
                )
            core.journal.append(
                "pairing",
                device=req.obj.device,
                result="rejected",
                reason=error.code,
                detail=result,
            )
            return core.refuse(error, req.obj.nonce)
        replaced = core.replaced_by(req)
        core.store.add_device(
            device_id=req.obj.device, name=req.name, keys=req.keys, now=core.clock(), peer=peer
        )
        core.export_devices()
        result = "accepted"
        core.journal.append(
            "pairing",
            device=req.obj.device,
            result="accepted",
            name=req.name,
            fingerprint=candidate.fingerprint,
            peer=_peer(request),
            node=peer,
            auto=True if core.pairing.auto_accept else None,
        )
        for old in replaced:
            await core.revoke(old, by=req.obj.device)
        payload = {
            "device_id": req.obj.device,
            "mac_name": core.config.mac_name,
            "ssh_host_keys": core.ssh_host_keys(),
        }
        return core.signed(200, payload, req.obj.nonce)
    finally:
        if result != "withdrawn":
            core.pairing.finish(session, result)


async def _wait_decision(
    core: Core, session: Session, candidate: Candidate, request: Request
) -> bool:
    """Wait for y/n or expiry; True if the phone disconnected first and was withdrawn."""
    while not candidate.decided.is_set():
        left = core.pairing.seconds_left(session)
        if left <= 0:
            return False
        await anyio.to_thread.run_sync(candidate.decided.wait, min(left, 1.0))
        if (
            not candidate.decided.is_set()
            and await request.is_disconnected()
            and core.pairing.withdraw(session, candidate)
        ):
            return True
    return False


def _peer(request: Request) -> str | None:
    return f"{request.client.host}:{request.client.port}" if request.client else None


async def ws_open(websocket: WebSocket) -> None:
    core: Core = websocket.app.state.core
    verdict = _verify(core, websocket.headers, b"", "ws.open", "normal", websocket.client)
    if verdict.error is not None or verdict.obj is None or verdict.device is None:
        error = verdict.error or ProtocolError("malformed_auth", "bad ws.open")
        nonce = verdict.obj.nonce if verdict.obj else ""
        try:
            await websocket.send_denial_response(core.refuse(error, nonce))
        except RuntimeError:  # server without the denial-response extension
            await websocket.close(code=4000 + ERROR_STATUS[error.code])
        return
    await websocket.accept()
    conn = Connection(websocket=websocket, device=verdict.device.id, nonce=verdict.obj.nonce)
    core.connections.setdefault(conn.device, set()).add(conn)
    try:
        await conn.send(
            core.key, "hello", {"device": conn.device, "server_time": format_ts(core.clock())}
        )
        while True:
            await (
                websocket.receive_text()
            )  # the client sends nothing meaningful; keeps the socket read
    except WebSocketDisconnect:
        pass
    finally:
        core.connections.get(conn.device, set()).discard(conn)


def create_app(
    core: Core,
    *,
    admin_socket: bool = True,
    background: Sequence[Callable[[Core], Awaitable[None]]] = (),
) -> Starlette:
    @contextlib.asynccontextmanager
    async def lifespan(app: Starlette) -> AsyncIterator[None]:
        server = await admin.serve(core) if admin_socket else None
        core.journal.append("core.started", mode=core.config.mode, version=__version__)
        tasks: list[asyncio.Future[None]] = [asyncio.ensure_future(job(core)) for job in background]
        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if server is not None:
                server.close()
                await server.wait_closed()
                with contextlib.suppress(FileNotFoundError):
                    core.config.admin_socket.unlink()
            core.journal.append("core.stopped")

    routes = [
        Route("/v1/challenge", challenge, methods=["POST"]),
        Route("/v1/pair", pair, methods=["POST"]),
        Route("/v1/ping", signed_endpoint("ping", "normal", ping), methods=["POST"]),
        Route("/v1/status", signed_endpoint("status", "normal", status), methods=["GET"]),
        Route(
            "/v1/devices", signed_endpoint("devices.list", "normal", devices_list), methods=["GET"]
        ),
        Route(
            "/v1/devices/revoke",
            signed_endpoint("devices.revoke", "critical", devices_revoke),
            methods=["POST"],
        ),
        Route(
            "/v1/data",
            signed_endpoint("data.get", "normal", data_get, _json_body(parse_ids)),
            methods=["POST"],
        ),
        Route(
            "/v1/log",
            signed_endpoint("log.list", "normal", log_list, _json_body(logfeed.parse_query)),
            methods=["POST"],
        ),
        Route("/v1/quick", signed_endpoint("quick.list", "normal", quick_list), methods=["GET"]),
        Route("/v1/friend", friend_send, methods=["POST"]),
        Route(
            "/v1/friend/questions",
            signed_endpoint(OP_QUESTIONS, "normal", friend_questions),
            methods=["GET"],
        ),
        Route("/v1/friend/decide", friend_decide, methods=["POST"]),
        Route(
            "/v1/friend/messages",
            signed_endpoint(
                OP_MESSAGES, "normal", friend_messages, _json_body(parse_messages_query)
            ),
            methods=["POST"],
        ),
        WebSocketRoute("/v1/ws", ws_open),
    ]
    app = Starlette(routes=routes, lifespan=lifespan)
    app.state.core = core
    return app
