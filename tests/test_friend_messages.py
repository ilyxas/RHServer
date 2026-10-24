"""friend slice 3, core side: the owner's messages with their state and the agent's replies
(friend.messages), the receipts and replies over the admin socket, retries, superseding,
the chat entries in the Log, and the contract examples."""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from openapi_util import check_response
from refclient import Phone
from rh_common.crypto import sha256_hex
from rh_common.friend import OP_MESSAGES, OP_SEND, action_text
from rh_core import logfeed
from rh_core.app import Core, parse_messages_query
from rh_core.config import channel_from_dict, channel_toml
from rh_core.journal import verify
from test_core_flow import Admin, env, pair, signed  # noqa: F401  (env is a fixture)

AGENT = "Agent-Alpha"  # the dev core's channel agent


def body(
    text: str, *, kind: str | None = None, re: str | None = None, msg_id: str = "m-1"
) -> bytes:
    doc: dict[str, Any] = {"id": msg_id, "text": text, "to": AGENT}
    if kind:
        doc["kind"] = kind
    if re:
        doc["re"] = re
    return json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def send(client: Any, phone: Phone, raw: bytes) -> dict[str, Any]:
    r = signed(client, phone, "POST", "/v1/friend", OP_SEND, "normal", raw)
    assert r.status_code == 200, r.text
    out: dict[str, Any] = r.json()
    return out


def messages(client: Any, phone: Phone, since: int = 0, **extra: Any) -> dict[str, Any]:
    raw = json.dumps({"since": since, **extra}).encode()
    r = signed(client, phone, "POST", "/v1/friend/messages", OP_MESSAGES, "normal", raw)
    assert r.status_code == 200, r.text
    doc: dict[str, Any] = r.json()
    check_response("/v1/friend/messages", "post", 200, doc)
    return doc


def admin(core: Core, msg: dict[str, Any]) -> dict[str, Any]:
    a = Admin(core.config.admin_socket)
    a.send(msg)
    out = a.recv()
    a.close()
    return out


def events(core: Core) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for f in sorted(core.config.journal_dir.glob("*.jsonl"))
        for line in f.read_text().splitlines()
    ]


def test_message_is_stored_with_its_text_and_state(env: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    assert messages(client, phone) == {
        "messages": [],
        "next": 0,
        "more": False,
        "server_time": messages(client, phone)["server_time"],
    }
    sent = send(client, phone, body("Is the RAM full for a reason?"))
    doc = messages(client, phone)
    assert doc["next"] >= 1 and doc["more"] is False
    (m,) = doc["messages"]
    assert m["id"] == sent["id"] and m["message_id"] == "m-1"
    assert m["state"] == "accepted" and m["kind"] == "question" and "re" not in m
    assert m["text"] == "Is the RAM full for a reason?" and m["replies"] == []
    assert m["device"] == phone.id and m["agent"] == AGENT
    assert m["accepted_at"] == sent["accepted_at"]
    # Nothing changed since: the same cursor, no messages.
    again = messages(client, phone, since=doc["next"])
    assert again["messages"] == [] and again["next"] == doc["next"]
    chat = [e for e in events(core) if e["event"] == "chat.message"]
    assert len(chat) == 1 and "re" not in chat[0]  # None fields stay out of the journal
    # The journal keeps the hash, never the text: it is a chain and cannot forget.
    assert "text" not in chat[0]
    assert chat[0] == {
        **chat[0],
        "author": "owner",
        "agent": AGENT,
        "device": phone.id,
        "id": sent["id"],
        "kind": "question",
        "text_sha256": sha256_hex(b"Is the RAM full for a reason?"),
    }


def test_kind_and_re_are_kept(env: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    first = send(client, phone, body("fix the build", kind="task"))
    second = send(client, phone, body("go on", kind="task", re=first["id"], msg_id="m-2"))
    by_id = {m["id"]: m for m in messages(client, phone)["messages"]}
    assert by_id[first["id"]]["kind"] == "task" and "re" not in by_id[first["id"]]
    assert by_id[second["id"]]["kind"] == "task" and by_id[second["id"]]["re"] == first["id"]


def test_received_then_answered(env: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    sent = send(client, phone, body("what time is it?"))
    before = messages(client, phone)["next"]
    got = admin(core, {"cmd": "friend.received", "id": sent["id"], "prompt_id": "p-1"})
    assert got["ok"] and got["state"] == "received" and got["received_at"]
    doc = messages(client, phone, since=before)
    (m,) = doc["messages"]
    assert m["state"] == "received" and m["received_at"] and "closed_at" not in m
    got = admin(core, {"cmd": "friend.reply", "in_reply_to": sent["id"], "text": "12:00"})
    assert got["ok"] and got["state"] == "answered"
    doc = messages(client, phone, since=doc["next"])
    (m,) = doc["messages"]
    assert m["state"] == "answered" and m["closed_at"]
    assert [(r["kind"], r["text"]) for r in m["replies"]] == [("final", "12:00")]
    names = [e["event"] for e in events(core)]
    assert names.index("friend.message.received") < names.index("friend.message.answered")
    chat = [e for e in events(core) if e["event"] == "chat.message"]
    assert [e["author"] for e in chat] == ["owner", AGENT]
    assert all("text" not in e for e in chat)
    assert chat[1]["text_sha256"] == sha256_hex(b"12:00")
    assert chat[1]["reply_seq"] == m["replies"][0]["seq"]
    assert core.store.chat_text(chat[0]) == "what time is it?"
    assert core.store.chat_text(chat[1]) == "12:00"
    # A closed message takes no more replies.
    got = admin(core, {"cmd": "friend.reply", "in_reply_to": sent["id"], "text": "again"})
    assert got == {"ok": False, "error": "closed", "message": f"message {sent['id']} is answered"}


def test_progress_replies_keep_the_message_open(env: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    sent = send(client, phone, body("fix the build", kind="task"))
    admin(core, {"cmd": "friend.received", "id": sent["id"]})
    got = admin(
        core,
        {"cmd": "friend.reply", "in_reply_to": sent["id"], "text": "found it", "progress": True},
    )
    assert got["ok"] and got["state"] == "received"
    got = admin(core, {"cmd": "friend.reply", "in_reply_to": sent["id"], "text": "done"})
    assert got["ok"] and got["state"] == "answered"
    assert [(r["kind"], r["text"]) for r in got["replies"]] == [
        ("progress", "found it"),
        ("final", "done"),
    ]


def test_turn_that_ends_with_a_question_waits(env: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    sent = send(client, phone, body("why does the build fail?"))
    admin(core, {"cmd": "friend.received", "id": sent["id"]})
    core.ask("Run the build to see the error?", action_text("Bash", {"command": "make"}))
    got = admin(core, {"cmd": "friend.reply", "in_reply_to": sent["id"], "text": "I asked you"})
    assert got["ok"] and got["state"] == "waiting"
    assert [r["kind"] for r in got["replies"]] == ["progress"]
    assert "friend.message.waiting" in [e["event"] for e in events(core)]
    # The decision came, the agent finished: the next final reply answers.
    for q in core.store.open_questions():
        core.withdraw(q.id)
    got = admin(core, {"cmd": "friend.reply", "in_reply_to": sent["id"], "text": "missing SDK"})
    assert got["ok"] and got["state"] == "answered"
    assert [r["kind"] for r in got["replies"]] == ["progress", "final"]


def test_new_message_supersedes_the_open_one(env: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    first = send(client, phone, body("long task", kind="task"))
    admin(core, {"cmd": "friend.received", "id": first["id"]})
    second = send(client, phone, body("stop, look at the disk first", msg_id="m-2"))
    by_id = {m["id"]: m for m in messages(client, phone)["messages"]}
    assert by_id[first["id"]]["state"] == "superseded"
    assert by_id[first["id"]]["superseded_by"] == second["id"]
    assert by_id[first["id"]]["closed_at"]
    assert by_id[second["id"]]["state"] == "accepted"
    # The interrupted turn's late reply, if any, is refused; the new one is answered.
    got = admin(core, {"cmd": "friend.reply", "in_reply_to": first["id"], "text": "late"})
    assert got["error"] == "closed"
    e = [x for x in events(core) if x["event"] == "friend.message.superseded"]
    assert e and e[0]["id"] == first["id"] and e[0]["by"] == second["id"]


def test_rejected_by_the_verifier(env: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    sent = send(client, phone, body("hello"))
    got = admin(
        core,
        {"cmd": "friend.rejected", "id": sent["id"], "code": "too_old", "detail": "15 min"},
    )
    assert got["ok"] and got["state"] == "rejected" and got["reject_code"] == "too_old"
    (m,) = messages(client, phone)["messages"]
    assert m["state"] == "rejected" and m["reject_code"] == "too_old" and m["closed_at"]
    assert admin(core, {"cmd": "friend.received", "id": sent["id"]})["error"] == "closed"


def test_retry_with_the_same_id_creates_nothing(env: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    first = send(client, phone, body("hello"))
    again = send(client, phone, body("hello"))
    assert again == first
    assert len(messages(client, phone)["messages"]) == 1
    assert len(list(core.config.inbox_dir.glob("*.json"))) == 1
    assert [e["event"] for e in events(core)].count("friend.message.retry") == 1
    # The same id with another text is a client bug: refused, never the old message.
    r = signed(client, phone, "POST", "/v1/friend", OP_SEND, "normal", body("other text"))
    assert r.status_code == 400 and r.json()["error"]["code"] == "bad_request"
    assert "already used" in r.json()["error"]["message"]
    assert len(messages(client, phone)["messages"]) == 1
    assert [e["event"] for e in events(core)].count("friend.message.id_reused") == 1
    # Another device may use the same id: ids are per device.
    other = Phone(name="Второй iPhone")  # a second name: pairing the same name revokes
    pair(core, client, other)
    third = send(client, other, body("hello"))
    assert third["id"] != first["id"]
    assert len(messages(client, phone)["messages"]) == 2


def test_prompt_id_is_checked_only_when_configured(env: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    sent = send(client, phone, body("hello"))
    admin(core, {"cmd": "friend.received", "id": sent["id"], "prompt_id": "p-1"})
    strict = dataclasses.replace(core.config.ch, match_prompt_id=True)
    core.config = dataclasses.replace(core.config, channel=strict)
    got = admin(
        core, {"cmd": "friend.reply", "in_reply_to": sent["id"], "text": "x", "prompt_id": "p-2"}
    )
    assert got == {
        "ok": False,
        "error": "prompt_mismatch",
        "message": "the reply names another prompt than the message",
    }
    assert "friend.reply.unmatched" in [e["event"] for e in events(core)]
    got = admin(
        core, {"cmd": "friend.reply", "in_reply_to": sent["id"], "text": "x", "prompt_id": "p-1"}
    )
    assert got["ok"] and got["state"] == "answered"


def test_match_prompt_id_config_round_trip() -> None:
    ch = channel_from_dict(
        {"agent": "A", "project_dir": "/p", "target": "a", "match_prompt_id": True}
    )
    assert ch.match_prompt_id is True
    assert "match_prompt_id = true" in channel_toml(ch)
    assert "match_prompt_id" not in "\n".join(
        channel_toml(channel_from_dict({"agent": "A", "project_dir": "/p", "target": "a"}))
    )


def test_paging_and_query_validation(env: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    ids = []
    for i in range(3):  # each one answered before the next, so none is superseded
        ids.append(send(client, phone, body(f"m{i}", msg_id=f"m-{i}"))["id"])
        admin(core, {"cmd": "friend.reply", "in_reply_to": ids[-1], "text": "ok"})
    page = messages(client, phone, limit=2)
    assert [m["id"] for m in page["messages"]] == ids[:2] and page["more"] is True
    rest = messages(client, phone, since=page["next"], limit=2)
    assert [m["id"] for m in rest["messages"]] == ids[2:] and rest["more"] is False
    for bad in ({"since": -1}, {"since": "0"}, {"limit": 0}, {"limit": 201}, {"x": 1}, []):
        try:
            parse_messages_query(bad)
        except ValueError:
            continue
        raise AssertionError(f"{bad!r} accepted")
    r = signed(
        client, phone, "POST", "/v1/friend/messages", OP_MESSAGES, "normal", b'{"since": -1}'
    )
    assert r.status_code == 400 and r.json()["error"]["code"] == "bad_request"


def test_admin_commands_validate(env: Any) -> None:
    core, _, _, _ = env
    assert admin(core, {"cmd": "friend.received"})["error"] == "bad_request"
    assert admin(core, {"cmd": "friend.received", "id": "0" * 32})["error"] == "not_found"
    assert admin(core, {"cmd": "friend.rejected", "id": "x"})["error"] == "bad_request"
    assert admin(core, {"cmd": "friend.reply", "in_reply_to": "x"})["error"] == "bad_request"
    assert (
        admin(core, {"cmd": "friend.reply", "in_reply_to": "0" * 32, "text": "x"})["error"]
        == "not_found"
    )
    got = admin(core, {"cmd": "friend.reply", "in_reply_to": "x", "text": "y", "progress": "no"})
    assert got["error"] == "bad_request"


def test_store_failure_takes_the_envelope_back(env: Any, monkeypatch: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)

    def broken(**kwargs: Any) -> Any:
        raise RuntimeError("disk full")

    monkeypatch.setattr(core.store, "add_message", broken)
    import pytest

    with pytest.raises(RuntimeError):
        signed(client, phone, "POST", "/v1/friend", OP_SEND, "normal", body("hello"))
    assert list(core.config.inbox_dir.glob("*.json")) == []  # nothing for the bridge
    assert messages(client, phone)["messages"] == []
    assert "friend.message" not in [e["event"] for e in events(core)]


def test_log_chat_filter_shows_both_sides_and_journal_verifies(env: Any) -> None:
    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    sent = send(client, phone, body("hello"))
    admin(core, {"cmd": "friend.received", "id": sent["id"]})
    admin(core, {"cmd": "friend.reply", "in_reply_to": sent["id"], "text": "hi there"})
    entries, _ = logfeed.page(
        core.config.journal_dir, names=core.device_name, filter="chat", texts=core.store.chat_text
    )
    assert [(e["title"], e["detail"]) for e in entries] == [
        (f"{AGENT} → owner", "hi there"),
        (f"owner → {AGENT}", "hello"),
    ]
    assert all(e["kind"] == "chat" for e in entries)
    # Through the API the texts come from the store too, and so does Home's activity.
    r = signed(client, phone, "POST", "/v1/log", "log.list", "normal", b'{"filter":"chat"}')
    assert [e["detail"] for e in r.json()["entries"]] == ["hi there", "hello"]
    rows = signed(
        client, phone, "POST", "/v1/data", "data.get", "normal", b'{"ids":["rh.activity"]}'
    ).json()["values"]["rh.activity"]["value"]
    assert any(row.get("subtitle") == "hi there" for row in rows)
    # Without the store (a journal read on its own) the text is named as absent, not shown.
    entries, _ = logfeed.page(core.config.journal_dir, names=core.device_name, filter="chat")
    assert all(e["detail"].startswith("(text not in the journal") for e in entries)
    entries, _ = logfeed.page(core.config.journal_dir, names=core.device_name)
    titles = [e["title"] for e in entries]
    assert f"{AGENT} answered" in titles and f"{AGENT} received the message" in titles
    for path in sorted(core.config.journal_dir.glob("*.jsonl")):
        verify(path)
