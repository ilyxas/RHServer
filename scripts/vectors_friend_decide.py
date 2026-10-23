"""friend.decide / friend.questions vectors: the question hash and decide body the phone
builds, core acceptance against the stage 1 fixture plus one open question, the
envelopes the agent-side verifier must pass or block, and the cases the gate must
allow or block.

Imported by gen_vectors.py. Keys, devices and nonces are the stage 1 fixture
(vectors_trust); the device list is the one of friend.json (vectors_friend). Existing
vector files are not touched.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import vectors_friend as f
import vectors_trust as t
from rh_common.crypto import b64e
from rh_common.friend import (
    OP_DECIDE,
    OP_SEND,
    Envelope,
    FriendDecision,
    action_text,
    parse_decide_body,
    pointer,
    question_sha256,
    read_devices_doc,
    spool_id,
)
from rh_common.protocol import ERROR_STATUS, HEADER_AUTH, HEADER_SIG, format_ts, verify_request
from rh_friend.config import default_rules
from rh_friend.gate import Outcome, candidates, protected_by
from rh_friend.verify import Reject, check_envelope

VERIFY_WINDOW = timedelta(seconds=900)  # the verifier's window on delivery
DECIDE_WINDOW = timedelta(seconds=120)  # the gate's window on an allow decision

# The one open question of the fixture: a protected Bash call.
TOOL = "Bash"
TOOL_INPUT = {"command": "kill -CONT 4242", "description": "resume the paused agent"}
ACTION = action_text(TOOL, TOOL_INPUT)
QUESTION_TEXT = "Resume the paused agent (pid 4242)? It was paused at 03:12 for an upload."
QUESTION_ID = "7d3c0b9a8e5f4a6b1c2d3e4f5a6b7c8d"
ASKED_AT = format_ts(t.NOW - timedelta(seconds=30))
OTHER_ACTION = action_text(TOOL, {**TOOL_INPUT, "command": "kill -CONT 4243"})


def question() -> dict[str, Any]:
    return {"id": QUESTION_ID, "text": QUESTION_TEXT, "action": ACTION, "asked_at": ASKED_AT}


def body(
    *,
    decision: str = "allow",
    qid: str = QUESTION_ID,
    digest: str | None = None,
    action: str = ACTION,
    to: str = f.AGENT,
) -> bytes:
    """The phone's encoding: sorted keys, no spaces, UTF-8 as is."""
    doc = {
        "action": action,
        "decision": decision,
        "id": qid,
        "question_sha256": digest if digest is not None else question_sha256(QUESTION_TEXT),
        "to": to,
    }
    return json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _level(decision: str) -> str:
    return "critical" if decision == "allow" else "normal"


def signed(
    *,
    decision: str = "allow",
    level: str | None = None,
    nonce_label: str = "fresh",
    p: str = "A",
    signer: str | None = None,
    op: str = OP_DECIDE,
    body_bytes: bytes | None = None,
    signed_body: bytes | None = None,
    ts: Any = None,
) -> tuple[dict[str, str], bytes]:
    raw = body(decision=decision) if body_bytes is None else body_bytes
    return t._signed(
        p=p,
        level=level or _level(decision),
        signer=signer,
        nonce_label=nonce_label,
        op=op,
        body=raw,
        signed_body=signed_body,
        ts=ts if ts is not None else t.NOW,
    )


# --- core acceptance --------------------------------------------------------------------


def core_cases() -> list[tuple[str, tuple[dict[str, str], bytes], str | None]]:
    tampered_hash = "0" * 64
    return [
        ("allow-critical-ok", signed(), None),
        ("deny-normal-ok", signed(decision="deny"), None),
        ("allow-with-normal-key", signed(level="normal"), "wrong_key_level"),
        ("deny-with-critical-key", signed(decision="deny", level="critical"), "wrong_key_level"),
        ("signed-as-send", signed(op=OP_SEND), "op_mismatch"),
        (
            "revoked-device",
            signed(p="R", nonce_label="for-R"),
            "revoked_device",
        ),
        ("unknown-question", signed(body_bytes=body(qid="f" * 32)), "bad_request"),
        ("question-hash-mismatch", signed(body_bytes=body(digest=tampered_hash)), "bad_request"),
        ("action-mismatch", signed(body_bytes=body(action=OTHER_ACTION)), "bad_request"),
        ("bad-decision", signed(body_bytes=body(decision="maybe"), level="normal"), "bad_request"),
        ("wrong-recipient", signed(body_bytes=body(to=f.OTHER_AGENT)), "bad_request"),
        (
            "extra-field",
            signed(body_bytes=body()[:-1] + b',"x":1}'),
            "bad_request",
        ),
        (
            "action-not-canonical",
            signed(body_bytes=body(action='{"tool":"Bash","input":{}}')),
            "bad_request",
        ),
        (
            "body-changed",
            signed(body_bytes=body(decision="deny"), signed_body=body(), level="critical"),
            "body_mismatch",
        ),
    ]


def evaluate_core(headers: dict[str, str], raw: bytes) -> str | None:
    """What rh_core.app.friend_decide decides, computed with the pure functions."""
    from rh_common.protocol import parse_auth

    devices, nonces = t.registry(), t.nonce_table()
    try:
        key = parse_auth(headers.get(HEADER_AUTH))[0].key
    except Exception:
        key = "normal"
    verdict = verify_request(
        headers=headers,
        body=raw,
        op=OP_DECIDE,
        key_level=key,
        now=t.NOW,
        find_device=devices.get,
        find_nonce=nonces.get,
    )
    if verdict.error is not None:
        return verdict.error.code
    try:
        decision = parse_decide_body(raw, f.AGENT)
    except ValueError:
        return "bad_request"
    if decision.key_level != key:
        return "wrong_key_level"
    q = question()
    if decision.id != q["id"]:
        return "bad_request"
    if decision.question_sha256 != question_sha256(q["text"]) or decision.action != q["action"]:
        return "bad_request"
    return None


# --- envelopes (the verifier) --------------------------------------------------------------


def _envelope(headers: dict[str, str], raw: bytes) -> Envelope:
    return Envelope(auth=headers[HEADER_AUTH], sig=headers[HEADER_SIG], body=raw)


def envelope_cases() -> list[dict[str, Any]]:
    ok_h, ok_b = signed()
    ok_sid = spool_id(t.nonce("fresh"))
    cases: list[dict[str, Any]] = []

    def add(
        name: str, env: Envelope, expect: str | None, *, sid: str = ok_sid, now: str = "now"
    ) -> None:
        cases.append({"name": name, "id": sid, "envelope": env, "now": now, "expect": expect})

    add("allow-valid", _envelope(ok_h, ok_b), None)
    h, b = signed(decision="deny")
    add("deny-valid", _envelope(h, b), None)
    h, b = signed(level="normal")
    add("allow-with-normal-key", _envelope(h, b), "wrong_key_level")
    h, b = signed(decision="deny", level="critical")
    add("deny-with-critical-key", _envelope(h, b), "wrong_key_level")
    add(
        "tampered-body",
        Envelope(ok_h[HEADER_AUTH], ok_h[HEADER_SIG], body(decision="deny")),
        "body_mismatch",
    )
    h, b = signed(signer="B.critical")
    add("signed-by-other-device", _envelope(h, b), "bad_signature")
    h, b = signed(body_bytes=body(decision="maybe"), level="normal")
    add("bad-decision", _envelope(h, b), "bad_body")
    add("expired-for-delivery", _envelope(ok_h, ok_b), "too_old", now="now+16m")
    add("pointer-mismatch", _envelope(ok_h, ok_b), "pointer_mismatch", sid="0" * 32)
    h, b = signed(body_bytes=body(to=f.OTHER_AGENT))
    add("wrong-recipient", _envelope(h, b), "wrong_recipient")
    return cases


NOWS = {
    "now": t.NOW,
    "now+16m": t.NOW + timedelta(minutes=16),
    "now+3m": t.NOW + timedelta(minutes=3),
    "now+119s": t.NOW + timedelta(seconds=119),
    "now-5m": t.NOW - timedelta(minutes=5),
}


def evaluate_envelope(case: dict[str, Any], devices_doc: str) -> str | None:
    devs = read_devices_doc(devices_doc.encode("utf-8"), core_pub=t.pub("core"))
    try:
        check_envelope(
            case["envelope"],
            sid=case["id"],
            devices=devs,
            now=NOWS[case["now"]],
            window=VERIFY_WINDOW,
            seen=lambda nonce: False,
            agent=f.AGENT,
        )
    except Reject as e:
        return e.code
    return None


# --- gate cases -------------------------------------------------------------------------------


def gate_cases() -> list[dict[str, Any]]:
    """Each case: the tool call, the decide envelopes in the inbox (by spool id), which of
    them the core already spent, the clock, and what the gate must do.

    `core` lists the decisions the core knows (accepted ones) with `used`; an envelope the
    core never accepted (a forged one in the inbox) is not in it, so spending it fails."""
    allow_h, allow_b = signed()
    allow_sid = spool_id(t.nonce("fresh"))
    deny_h, deny_b = signed(decision="deny", nonce_label="for-B", p="B")
    deny_sid = spool_id(t.nonce("for-B"))
    # The same deny signed later / earlier than the allow (same nonce: one deny per case).
    later_deny_h, later_deny_b = signed(
        decision="deny", nonce_label="for-B", p="B", ts=t.NOW + timedelta(seconds=10)
    )
    earlier_deny_h, earlier_deny_b = signed(
        decision="deny", nonce_label="for-B", p="B", ts=t.NOW - timedelta(seconds=10)
    )
    other_h, other_b = signed(body_bytes=body(action=OTHER_ACTION), nonce_label="used")
    other_sid = spool_id(t.nonce("used"))
    forged_h, forged_b = signed(level="normal", nonce_label="stale")
    forged_sid = spool_id(t.nonce("stale"))
    tampered_h, tampered_b = signed(body_bytes=body(digest="0" * 64), nonce_label="stale")
    tampered_sid = spool_id(t.nonce("stale"))

    def env(h: dict[str, str], b: bytes) -> str:
        return _envelope(h, b).to_json().decode("utf-8")

    envelopes = {
        allow_sid: env(allow_h, allow_b),
        deny_sid: env(deny_h, deny_b),
        other_sid: env(other_h, other_b),
    }
    accepted = {
        allow_sid: {"question_id": QUESTION_ID, "decision": "allow", "key": "critical"},
        deny_sid: {"question_id": QUESTION_ID, "decision": "deny", "key": "normal"},
        other_sid: {"question_id": QUESTION_ID, "decision": "allow", "key": "critical"},
    }
    changed_input = {**TOOL_INPUT, "command": "kill -CONT 4242 "}
    cases = [
        {
            "name": "not-protected",
            "tool": TOOL,
            "input": {"command": "ls -la"},
            "inbox": [],
            "core": {},
            "now": "now",
            "expect": {"result": "none"},
        },
        {
            "name": "no-decision",
            "tool": TOOL,
            "input": TOOL_INPUT,
            "inbox": [],
            "core": {},
            "now": "now",
            "expect": {"result": "block", "code": "no_decision"},
        },
        {
            "name": "valid-allow",
            "tool": TOOL,
            "input": TOOL_INPUT,
            "inbox": [allow_sid],
            "core": {allow_sid: {**accepted[allow_sid], "used": False}},
            "now": "now",
            "expect": {"result": "allow", "decision": allow_sid},
        },
        {
            "name": "valid-allow-just-inside-window",
            "tool": TOOL,
            "input": TOOL_INPUT,
            "inbox": [allow_sid],
            "core": {allow_sid: {**accepted[allow_sid], "used": False}},
            "now": "now+119s",
            "expect": {"result": "allow", "decision": allow_sid},
        },
        {
            "name": "decision-for-another-action",
            "tool": TOOL,
            "input": TOOL_INPUT,
            "inbox": [other_sid],
            "core": {other_sid: {**accepted[other_sid], "used": False}},
            "now": "now",
            "expect": {"result": "block", "code": "no_decision"},
        },
        {
            "name": "same-action-one-character-changed",
            "tool": TOOL,
            "input": changed_input,
            "inbox": [allow_sid],
            "core": {allow_sid: {**accepted[allow_sid], "used": False}},
            "now": "now",
            "expect": {"result": "block", "code": "no_decision"},
        },
        {
            "name": "reused-decision",
            "tool": TOOL,
            "input": TOOL_INPUT,
            "inbox": [allow_sid],
            "core": {allow_sid: {**accepted[allow_sid], "used": True}},
            "now": "now",
            "expect": {"result": "block", "code": "already_used"},
        },
        {
            "name": "expired-decision",
            "tool": TOOL,
            "input": TOOL_INPUT,
            "inbox": [allow_sid],
            "core": {allow_sid: {**accepted[allow_sid], "used": False}},
            "now": "now+3m",
            "expect": {"result": "block", "code": "expired"},
        },
        {
            "name": "decision-from-the-future",
            "tool": TOOL,
            "input": TOOL_INPUT,
            "inbox": [allow_sid],
            "core": {allow_sid: {**accepted[allow_sid], "used": False}},
            "now": "now-5m",
            "expect": {"result": "block", "code": "from_future"},
        },
        {
            "name": "deny",
            "tool": TOOL,
            "input": TOOL_INPUT,
            "inbox": [deny_sid],
            "core": {deny_sid: {**accepted[deny_sid], "used": False}},
            "now": "now",
            "expect": {"result": "block", "code": "denied"},
        },
        {
            "name": "allow-signed-with-normal-key",
            "tool": TOOL,
            "input": TOOL_INPUT,
            "inbox": [forged_sid],
            "core": {},
            "now": "now",
            "expect": {"result": "block", "code": "wrong_key_level"},
            "_envelopes": {forged_sid: env(forged_h, forged_b)},
        },
        {
            "name": "tampered-question-hash",
            "tool": TOOL,
            "input": TOOL_INPUT,
            "inbox": [tampered_sid],
            "core": {tampered_sid: {**accepted[allow_sid], "used": False}},
            "now": "now",
            "expect": {"result": "block", "code": "mismatch"},
            "_envelopes": {tampered_sid: env(tampered_h, tampered_b)},
        },
        {
            "name": "core-unreachable",
            "tool": TOOL,
            "input": TOOL_INPUT,
            "inbox": [allow_sid],
            "core": None,
            "now": "now",
            "expect": {"result": "block", "code": "core_unreachable"},
        },
        # The newest decision for an action counts; a deny wins a tie.
        {
            "name": "deny-and-allow-signed-at-the-same-time",
            "tool": TOOL,
            "input": TOOL_INPUT,
            "inbox": [deny_sid, allow_sid],
            "core": {
                allow_sid: {**accepted[allow_sid], "used": False},
                deny_sid: {**accepted[deny_sid], "used": False},
            },
            "now": "now",
            "expect": {"result": "block", "code": "denied"},
        },
        {
            "name": "allow-then-a-newer-deny",
            "tool": TOOL,
            "input": TOOL_INPUT,
            "inbox": [deny_sid, allow_sid],
            "core": {
                allow_sid: {**accepted[allow_sid], "used": False},
                deny_sid: {**accepted[deny_sid], "used": False},
            },
            "now": "now",
            "expect": {"result": "block", "code": "denied"},
            "_envelopes": {deny_sid: env(later_deny_h, later_deny_b)},
        },
        {
            "name": "deny-then-a-newer-allow",
            "tool": TOOL,
            "input": TOOL_INPUT,
            "inbox": [deny_sid, allow_sid],
            "core": {
                allow_sid: {**accepted[allow_sid], "used": False},
                deny_sid: {**accepted[deny_sid], "used": False},
            },
            "now": "now",
            "expect": {"result": "allow", "decision": allow_sid},
            "_envelopes": {deny_sid: env(earlier_deny_h, earlier_deny_b)},
        },
    ]
    for c in cases:
        extra = c.pop("_envelopes", {})
        c["envelopes"] = {sid: (extra.get(sid) or envelopes[sid]) for sid in c["inbox"]}
        del c["inbox"]
    return cases


class FakeCore:
    """The core's side of friend.decision.use for gate vectors: accepted decisions with
    their question, spent once; None means the core is down."""

    def __init__(self, state: dict[str, Any] | None) -> None:
        self.state = None if state is None else {k: dict(v) for k, v in state.items()}
        self.q = question()

    def spend(self, decision_id: str, action: str, digest: str) -> dict[str, Any]:
        from rh_friend.gate import CoreUnreachable

        if self.state is None:
            raise CoreUnreachable("down")
        row = self.state.get(decision_id)
        if row is None:
            return {"ok": False, "error": "not_found", "message": "no decision"}
        if action != self.q["action"] or digest != question_sha256(self.q["text"]):
            return {"ok": False, "error": "mismatch", "message": "mismatch"}
        if row["decision"] != "allow":
            return {"ok": False, "error": "denied", "message": "denied"}
        if row["used"]:
            return {"ok": False, "error": "already_used", "message": "already used"}
        row["used"] = True
        return {"ok": True, "id": decision_id}


def evaluate_gate(case: dict[str, Any], devices_doc: str, inbox: Any) -> dict[str, Any]:
    """Run rh_friend.gate.decide over a directory holding the case's envelopes."""
    from rh_friend.config import FriendConfig, GateConfig
    from rh_friend.gate import decide

    for sid, text in case["envelopes"].items():
        (inbox / f"{sid}.json").write_text(text, encoding="utf-8")
    devices = inbox / "devices.json"
    devices.write_text(devices_doc, encoding="utf-8")
    cfg = FriendConfig(
        agent=f.AGENT,
        project_dir=inbox,
        inbox_dir=inbox,
        devices_file=devices,
        core_key=t.pub("core"),
        seen_file=inbox / "seen.jsonl",
        rejected_log=inbox / "rejected.jsonl",
        gate=GateConfig(
            admin_socket=inbox / "admin.sock",
            protected=default_rules(),
            decide_window_s=int(DECIDE_WINDOW.total_seconds()),
        ),
    )
    out: Outcome = decide(
        case["tool"], case["input"], cfg, now=NOWS[case["now"]], spend=FakeCore(case["core"]).spend
    )
    if out.kind == "allow":
        return {"result": "allow", "decision": out.decision_id}
    if out.kind == "block":
        return {"result": "block", "code": out.code}
    return {"result": "none"}


def friend_decide_vectors() -> dict[str, Any]:
    import shutil
    import tempfile
    from pathlib import Path

    build = {
        "question": {
            "text": QUESTION_TEXT,
            "expected_sha256": question_sha256(QUESTION_TEXT),
        },
        "question_unicode": {
            "text": "Снять паузу с агента (pid 4242)? Он стоит с 03:12 из-за загрузки 🚀",
            "expected_sha256": question_sha256(
                "Снять паузу с агента (pid 4242)? Он стоит с 03:12 из-за загрузки 🚀"
            ),
        },
        "action": {
            "tool": TOOL,
            "input": TOOL_INPUT,
            "expected_action": ACTION,
        },
        "decide_body": [
            {
                "name": name,
                "decision": decision,
                "expected_body_text": body(decision=decision).decode("utf-8"),
                "key_level": _level(decision),
            }
            for name, decision in (("allow", "allow"), ("deny", "deny"))
        ],
    }
    core = []
    for name, (headers, raw), code in core_cases():
        got = evaluate_core(headers, raw)
        if got != code:
            raise SystemExit(f"{name}: expected {code}, core says {got}")
        expect: dict[str, Any] = (
            {"result": "accept", "spool_id": spool_id(t.nonce("fresh"))}
            if code is None
            else {"result": "reject", "code": code, "status": ERROR_STATUS[code]}
        )
        core.append({"name": name, "headers": headers, "body_b64": b64e(raw), "expect": expect})
    devices_doc = f.devices_docs()["valid"]
    envelopes = []
    for case in envelope_cases():
        got = evaluate_envelope(case, devices_doc)
        if got != case["expect"]:
            raise SystemExit(f"{case['name']}: expected {case['expect']}, verifier says {got}")
        env: Envelope = case["envelope"]
        decision: FriendDecision | None = None
        if case["expect"] is None:
            decision = parse_decide_body(env.body, f.AGENT)
        envelopes.append(
            {
                "name": case["name"],
                "pointer": pointer(case["id"]),
                "envelope": env.to_json().decode("utf-8"),
                "now": NOWS[case["now"]].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expect": (
                    {"result": "accept", "decision": decision.decision, "action": decision.action}
                    if decision is not None
                    else {"result": "block", "code": case["expect"]}
                ),
            }
        )
    gate = []
    assert protected_by(default_rules(), TOOL, TOOL_INPUT) is not None
    for case in gate_cases():
        tmp = Path(tempfile.mkdtemp(prefix="rh-gate-vec-"))
        try:
            got = evaluate_gate(case, devices_doc, tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        if got != case["expect"]:
            raise SystemExit(f"gate {case['name']}: expected {case['expect']}, gate says {got}")
        gate.append(
            {
                "name": case["name"],
                "tool": case["tool"],
                "input": case["input"],
                "envelopes": case["envelopes"],
                "core": case["core"],
                "now": NOWS[case["now"]].strftime("%Y-%m-%dT%H:%M:%SZ"),
                "expect": case["expect"],
            }
        )
    _ = candidates  # the gate module is exercised through decide()
    return {
        "description": (
            "friend.decide and friend.questions. build: question_sha256 = sha256 of the "
            "question text as shown (UTF-8); action = canonical JSON of "
            '{"input": <tool input>, "tool": <name>}; decide_body = the phone\'s body with '
            "sorted keys and no spaces, and the key level each decision needs. core: "
            "requests against the signed_requests.json fixture with the one open `question`; "
            "accept spools the request under spool_id = first 32 hex of sha256(nonce). "
            "envelopes: what the agent-side verifier must pass or block for a pointer at `now` "
            f"with a {int(VERIFY_WINDOW.total_seconds())} s window (device list: friend.json "
            '"valid"). gate: a tool call, the decide envelopes in the inbox, the decisions the '
            "core accepted (with `used`; null core = unreachable) and the clock → allow with "
            f"the decision spent, block with a code, or none (not protected); allow window "
            f"{int(DECIDE_WINDOW.total_seconds())} s after the signed ts, protected rules = "
            "the defaults of rhcore friend-config. For one action the newest decision by "
            "signed ts counts (a deny wins a tie): a deny blocks even when an older unused "
            "allow is present."
        ),
        "version": 3,
        "agent": f.AGENT,
        "core_pub_x963_b64": b64e(t.pub("core")),
        "verify_window_s": int(VERIFY_WINDOW.total_seconds()),
        "decide_window_s": int(DECIDE_WINDOW.total_seconds()),
        "question": question(),
        "build": build,
        "core": core,
        "envelopes": envelopes,
        "gate": gate,
    }


GENERATED = {"friend_decide.json": friend_decide_vectors}
