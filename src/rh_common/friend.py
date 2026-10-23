"""Signed messages and decisions from the phone to the channel agent's session
(`friend.send`, `friend.decide`, `friend.questions`).

"friend" is the name of the mechanism, after the agent that designed it and first
worked on it; the agent on the channel is whoever `[channel] agent` names. Its id is
a parameter here, never a constant.

Pure functions shared by rh-core, the agent-side verifier, the gate and the
vector generator: the message and decision bodies, the action text a decision
names, the envelope the core spools for the bridge, the pointer line typed into
tmux, and the device list the core exports for the verifier.

The verifier and the gate trust none of the transport. They re-check the phone's
signature over the original request bytes against a device list signed by the
core key.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from rh_common.crypto import b64d, b64e, load_public_x963, sha256_hex, sign_der, verify_der
from rh_common.jcs import JCSError, canonicalize, canonicalize_text
from rh_common.protocol import HEADER_AUTH, HEADER_SIG, format_ts

OP_SEND = "friend.send"
OP_DECIDE = "friend.decide"
OP_QUESTIONS = "friend.questions"

MAX_TEXT = 8000  # characters; the message goes into the agent session's context
MAX_ACTION = 65536  # characters of canonical JSON naming the exact tool call
DECISIONS = ("allow", "deny")
# allow needs a fresh Face ID (critical); deny is signed like any message (normal).
KEY_FOR_DECISION: dict[str, str] = {"allow": "critical", "deny": "normal"}
AGENT_ID_RE = re.compile(r"\A[A-Za-z0-9_-]{1,32}\Z")
_MSG_ID_RE = re.compile(r"\A[A-Za-z0-9-]{1,64}\Z")
_SPOOL_ID_RE = re.compile(r"\A[0-9a-f]{32}\Z")
_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
POINTER_RE = re.compile(r"\A⟦rh:([0-9a-f]{32})⟧\Z")


# --- message body -----------------------------------------------------------------


@dataclass(frozen=True)
class FriendMessage:
    to: str
    id: str
    text: str


def check_agent_id(agent: Any) -> str:
    """The channel agent's id: 1–32 of A-Za-z0-9_- (it takes part in paths)."""
    if not isinstance(agent, str) or not AGENT_ID_RE.match(agent):
        raise ValueError("agent id must be 1–32 characters A-Z, a-z, 0-9, _ or -")
    return agent


def parse_body(body: bytes, agent: str) -> FriendMessage:
    """{"to": "<agent>", "id": "<1–64 of A-Za-z0-9->", "text": "<1–8000 characters>"};
    nothing else. `to` must be exactly the channel agent's id."""
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError("body is not JSON") from e
    if not isinstance(doc, dict) or set(doc) != {"to", "id", "text"}:
        raise ValueError("body must have exactly to, id, text")
    to, msg_id, text = doc["to"], doc["id"], doc["text"]
    if to != agent:
        raise ValueError(f'to must be "{agent}", the channel agent')
    if not isinstance(msg_id, str) or not _MSG_ID_RE.match(msg_id):
        raise ValueError("id must be 1–64 characters A-Z, a-z, 0-9 or -")
    if not isinstance(text, str) or not text.strip():
        raise ValueError("text must be a non-empty string")
    if len(text) > MAX_TEXT:
        raise ValueError(f"text is longer than {MAX_TEXT} characters")
    return FriendMessage(to=to, id=msg_id, text=text)


# --- questions and decisions ------------------------------------------------------


def action_text(tool_name: str, tool_input: Any) -> str:
    """The exact tool call as one canonical JSON text: {"input": <tool_input>, "tool": <name>}.

    The gate builds it from the PreToolUse input; the core shows it to the phone as is;
    the phone signs it as is; the gate compares the signed text with its own, character
    for character. Raises ValueError if the input cannot be canonical JSON.
    """
    if not isinstance(tool_name, str) or not tool_name:
        raise ValueError("tool name must be a non-empty string")
    try:
        return canonicalize({"tool": tool_name, "input": tool_input}).decode("utf-8")
    except (JCSError, TypeError, ValueError) as e:
        raise ValueError(f"tool input is not canonical JSON: {e}") from e


def question_sha256(text: str) -> str:
    """sha256 of the question text as shown, UTF-8."""
    return sha256_hex(text.encode("utf-8"))


def check_question_text(text: Any) -> str:
    if not isinstance(text, str) or not text.strip():
        raise ValueError("question text must be a non-empty string")
    if len(text) > MAX_TEXT:
        raise ValueError(f"question text is longer than {MAX_TEXT} characters")
    return text


def check_action(action: Any) -> str:
    """An action is canonical JSON text of {"input", "tool"} with a non-empty tool name."""
    if not isinstance(action, str) or not action:
        raise ValueError("action must be a non-empty string")
    if len(action) > MAX_ACTION:
        raise ValueError(f"action is longer than {MAX_ACTION} characters")
    raw = action.encode("utf-8")
    try:
        if canonicalize_text(raw) != raw:
            raise ValueError("action is not canonical JSON (RFC 8785)")
    except JCSError as e:
        raise ValueError(f"action is not JSON: {e}") from e
    doc = json.loads(raw)
    if not isinstance(doc, dict) or set(doc) != {"tool", "input"}:
        raise ValueError('action must be {"input": ..., "tool": "<name>"}')
    if not isinstance(doc["tool"], str) or not doc["tool"]:
        raise ValueError("action tool must be a non-empty string")
    return action


@dataclass(frozen=True)
class FriendDecision:
    to: str
    id: str  # the question answered (32 hex)
    question_sha256: str
    action: str
    decision: str  # allow | deny

    @property
    def key_level(self) -> str:
        return KEY_FOR_DECISION[self.decision]


def parse_decide_body(body: bytes, agent: str) -> FriendDecision:
    """{"to": "<agent>", "id": "<question id>", "question_sha256": "<hex>", "action": "<JCS>",
    "decision": "allow" | "deny"}; nothing else."""
    try:
        doc = json.loads(body)
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError("body is not JSON") from e
    fields = {"to", "id", "question_sha256", "action", "decision"}
    if not isinstance(doc, dict) or set(doc) != fields:
        raise ValueError(f"body must have exactly {sorted(fields)}")
    if doc["to"] != agent:
        raise ValueError(f'to must be "{agent}", the channel agent')
    qid = doc["id"]
    if not isinstance(qid, str) or not _SPOOL_ID_RE.match(qid):
        raise ValueError("id must be the question id, 32 lowercase hex")
    digest = doc["question_sha256"]
    if not isinstance(digest, str) or not _SHA256_RE.match(digest):
        raise ValueError("question_sha256 must be 64 lowercase hex")
    if doc["decision"] not in DECISIONS:
        raise ValueError(f"decision must be one of {list(DECISIONS)}")
    action = check_action(doc["action"])
    return FriendDecision(
        to=agent, id=qid, question_sha256=digest, action=action, decision=doc["decision"]
    )


@dataclass(frozen=True)
class Question:
    """A question the channel agent asked; the phone shows text and action in full."""

    id: str  # 32 hex
    text: str
    action: str
    asked_at: str  # Timestamp

    def to_api(self) -> dict[str, Any]:
        return {"id": self.id, "text": self.text, "action": self.action, "asked_at": self.asked_at}


def question_id(text: str, action: str, nonce: str) -> str:
    """Name of a question: 32 hex of sha256 over its content and a random nonce."""
    return sha256_hex(canonicalize({"text": text, "action": action, "nonce": nonce}))[:32]


# --- envelope and pointer ---------------------------------------------------------------


def spool_id(nonce: str) -> str:
    """Name of the envelope: one per accepted request, since a nonce is used once."""
    return sha256_hex(nonce.encode("utf-8"))[:32]


def pointer(sid: str) -> str:
    """The only text the bridge types into tmux."""
    if not _SPOOL_ID_RE.match(sid):
        raise ValueError("spool id must be 32 lowercase hex")
    return f"⟦rh:{sid}⟧"


@dataclass(frozen=True)
class Envelope:
    """The request exactly as the core received it."""

    auth: str  # X-RH-Auth header value (base64 of the canonical signed object)
    sig: str  # X-RH-Sig header value (base64 DER)
    body: bytes

    def to_json(self) -> bytes:
        doc = {"v": 1, "auth": self.auth, "sig": self.sig, "body": b64e(self.body)}
        return canonicalize(doc)


def envelope_from_headers(headers: Mapping[str, str], body: bytes) -> Envelope:
    return Envelope(auth=headers[HEADER_AUTH], sig=headers[HEADER_SIG], body=body)


def parse_envelope(data: bytes) -> Envelope:
    try:
        doc = json.loads(data)
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError("envelope is not JSON") from e
    if not isinstance(doc, dict) or set(doc) != {"v", "auth", "sig", "body"} or doc["v"] != 1:
        raise ValueError("envelope must be {v: 1, auth, sig, body}")
    if not all(isinstance(doc[k], str) for k in ("auth", "sig", "body")):
        raise ValueError("envelope fields must be strings")
    return Envelope(auth=doc["auth"], sig=doc["sig"], body=b64d(doc["body"]))


# --- device list exported by the core ------------------------------------------------------


@dataclass(frozen=True)
class DeviceEntry:
    id: str
    name: str
    status: str  # active | revoked
    keys: Mapping[str, bytes]  # normal, critical (X9.63)


def build_devices_doc(
    devices: list[DeviceEntry], *, core_key: Any, core_pub: bytes, now: datetime
) -> bytes:
    """{"payload": "<JCS text>", "sig": "<core key over payload bytes>"}.

    The payload names the core key so a verifier can tell which core wrote it, but
    trusts only the core key pinned in its own configuration.
    """
    payload = canonicalize(
        {
            "v": 1,
            "core_key": b64e(core_pub),
            "generated": format_ts(now),
            "devices": [
                {
                    "id": d.id,
                    "name": d.name,
                    "status": d.status,
                    "keys": {level: b64e(d.keys[level]) for level in ("normal", "critical")},
                }
                for d in sorted(devices, key=lambda d: d.id)
            ],
        }
    )
    sig = sign_der(core_key, payload)
    return canonicalize({"payload": payload.decode("utf-8"), "sig": b64e(sig)})


def read_devices_doc(data: bytes, *, core_pub: bytes) -> dict[str, DeviceEntry]:
    """Verify the core signature first, then parse. Raises ValueError with a reason."""
    try:
        outer = json.loads(data)
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError("devices file is not JSON") from e
    if not isinstance(outer, dict) or set(outer) != {"payload", "sig"}:
        raise ValueError("devices file must be {payload, sig}")
    if not isinstance(outer["payload"], str) or not isinstance(outer["sig"], str):
        raise ValueError("devices file fields must be strings")
    payload = outer["payload"].encode("utf-8")
    if not verify_der(core_pub, payload, b64d(outer["sig"])):
        raise ValueError("devices file is not signed by the pinned core key")
    try:
        if canonicalize_text(payload) != payload:
            raise ValueError("devices payload is not canonical JSON")
    except JCSError as e:
        raise ValueError(f"devices payload is not JSON: {e}") from e
    doc = json.loads(payload)
    if doc.get("v") != 1 or doc.get("core_key") != b64e(core_pub):
        raise ValueError("devices payload is for another core or version")
    out: dict[str, DeviceEntry] = {}
    for d in doc.get("devices", []):
        keys = {level: b64d(d["keys"][level]) for level in ("normal", "critical")}
        for k in keys.values():
            load_public_x963(k)
        out[d["id"]] = DeviceEntry(id=d["id"], name=d["name"], status=d["status"], keys=keys)
    return out


__all__ = [
    "AGENT_ID_RE",
    "DECISIONS",
    "KEY_FOR_DECISION",
    "MAX_ACTION",
    "MAX_TEXT",
    "OP_DECIDE",
    "OP_QUESTIONS",
    "OP_SEND",
    "POINTER_RE",
    "DeviceEntry",
    "Envelope",
    "FriendDecision",
    "FriendMessage",
    "Question",
    "action_text",
    "build_devices_doc",
    "check_action",
    "check_agent_id",
    "check_question_text",
    "envelope_from_headers",
    "parse_body",
    "parse_decide_body",
    "parse_envelope",
    "pointer",
    "question_id",
    "question_sha256",
    "read_devices_doc",
    "spool_id",
]
