"""rh-friend-reply (the Stop hook) and the shared socket module: the last assistant message
answers the owner's open message, deferred replies, the end-to-end process against a core."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from refclient import Phone
from rh_common.crypto import b64e, public_x963
from rh_common.friend import OP_SEND
from rh_friend import core_socket, reply
from rh_friend.config import FriendConfig, from_dict
from rh_friend.verify import close_current, read_current, write_current
from test_core_flow import Admin, env, pair, signed  # noqa: F401  (env is a fixture)
from test_friend_decide import AGENT, friend_cfg
from test_friend_messages import body

NOW = __import__("datetime").datetime(2026, 10, 25, 9, 0, tzinfo=__import__("datetime").UTC)


def plain_cfg(tmp: Path) -> FriendConfig:
    """A config without [gate]: no admin socket, reports go nowhere."""
    project = tmp / "project"
    project.mkdir(exist_ok=True)
    return from_dict(
        {
            "agent": AGENT,
            "project_dir": str(project),
            "inbox_dir": str(tmp / "inbox"),
            "devices_file": str(tmp / "devices.json"),
            "core_key": b64e(
                public_x963(__import__("rh_core.keys").keys.load_or_create(tmp / "k"))
            ),
        }
    )


def test_no_open_message_means_no_reply(tmp_path: Path) -> None:
    cfg = plain_cfg(tmp_path)
    sent: list[dict[str, Any]] = []
    assert reply.handle_stop({"last_assistant_message": "hi"}, cfg, report=sent.append) is None
    write_current(cfg, id="a" * 32, kind="question", prompt_id="p-1", at=NOW)
    close_current(cfg, "a" * 32)
    assert read_current(cfg) is None
    assert reply.handle_stop({"last_assistant_message": "hi"}, cfg, report=sent.append) is None
    assert sent == []


def test_stop_replies_to_the_open_message_and_closes_it_when_answered(tmp_path: Path) -> None:
    cfg = plain_cfg(tmp_path)
    write_current(cfg, id="a" * 32, kind="question", prompt_id="p-1", at=NOW)
    sent: list[dict[str, Any]] = []

    def core(msg: dict[str, Any]) -> dict[str, Any]:
        sent.append(msg)
        return {"ok": True, "state": "answered"}

    out = reply.handle_stop(
        {"last_assistant_message": "  12:00  ", "prompt_id": "p-1"}, cfg, report=core
    )
    assert out == {"ok": True, "state": "answered"}
    assert sent == [
        {
            "cmd": "friend.reply",
            "in_reply_to": "a" * 32,
            "text": "12:00",
            "prompt_id": "p-1",
            "progress": False,
        }
    ]
    assert read_current(cfg) is None  # answered: the next turn is nobody's reply
    # An empty answer sends nothing; an unrelated Stop later sends nothing.
    write_current(cfg, id="b" * 32, kind="task", prompt_id=None, at=NOW)
    assert reply.handle_stop({"last_assistant_message": "   "}, cfg, report=core) is None
    assert len(sent) == 1


def test_waiting_keeps_the_message_open_and_closed_forgets_it(tmp_path: Path) -> None:
    cfg = plain_cfg(tmp_path)
    write_current(cfg, id="a" * 32, kind="task", prompt_id=None, at=NOW)
    out = reply.handle_stop(
        {"last_assistant_message": "I asked you"},
        cfg,
        report=lambda m: {"ok": True, "state": "waiting"},
    )
    assert out and out["state"] == "waiting" and read_current(cfg) is not None
    # The core says the message is closed (superseded): nothing more to reply to.
    out = reply.handle_stop(
        {"last_assistant_message": "late"},
        cfg,
        report=lambda m: {"ok": False, "error": "closed", "message": "superseded"},
    )
    assert out and out["error"] == "closed" and read_current(cfg) is None


def test_progress_note_uses_the_open_message(tmp_path: Path) -> None:
    cfg = plain_cfg(tmp_path)
    write_current(cfg, id="a" * 32, kind="task", prompt_id="p-9", at=NOW)
    sent: list[dict[str, Any]] = []
    out = reply.reply(
        cfg,
        "found it",
        prompt_id=None,
        progress=True,
        report=lambda m: sent.append(m) or {"ok": True},
    )
    assert out == {"ok": True}
    assert sent[0]["progress"] is True and sent[0]["prompt_id"] == "p-9"
    assert read_current(cfg) is not None


def test_unreachable_core_defers_and_flush_sends_in_order(tmp_path: Path) -> None:
    cfg = plain_cfg(tmp_path)
    write_current(cfg, id="a" * 32, kind="task", prompt_id=None, at=NOW)
    out = reply.handle_stop({"last_assistant_message": "one"}, cfg, report=lambda m: None)
    assert out == {"deferred": True}
    out = reply.reply(cfg, "two", prompt_id=None, progress=True, report=lambda m: None)
    assert out == {"deferred": True}
    pending = core_socket.pending_file(cfg)
    assert [json.loads(line)["text"] for line in pending.read_text().splitlines()] == ["one", "two"]
    assert read_current(cfg) is not None  # not answered until the core says so
    # Without a [gate] there is no socket: nothing goes through, the file stays.
    assert core_socket.flush_pending(cfg) == []
    assert pending.exists()


def test_flush_settles_the_note_when_the_core_answers(env: Any, tmp_path: Path) -> None:
    """A reply deferred while the core was down: the next hook call delivers it, and the
    core's `answered` closes the note, so the next turn is nobody's reply."""
    from rh_friend.verify import handle as verify_handle
    from rh_friend.verify import settle_pending

    core, client, clock, _ = env
    phone = Phone()
    pair(core, client, phone)
    cfg = friend_cfg(core, tmp_path)
    sent = signed(client, phone, "POST", "/v1/friend", OP_SEND, "normal", body("ping?"))
    sid = sent.json()["id"]
    verify_handle({"prompt": f"⟦rh:{sid}⟧"}, cfg, project_dir=str(cfg.project_dir))
    # The Stop hook could not reach the core: deferred.
    assert reply.handle_stop({"last_assistant_message": "pong"}, cfg, report=lambda m: None) == {
        "deferred": True
    }
    assert read_current(cfg) is not None and core_socket.pending_file(cfg).exists()
    # Any later hook call flushes; the core marks it answered; the note is closed.
    settle_pending(cfg)
    assert not core_socket.pending_file(cfg).exists()
    row = core.store.message(sid)
    assert row is not None and row.state == "answered"
    assert read_current(cfg) is None
    # The same through an unsigned prompt of the verifier (the usual next hook call).
    sent = signed(
        client, phone, "POST", "/v1/friend", OP_SEND, "normal", body("again?", msg_id="m-2")
    )
    sid = sent.json()["id"]
    verify_handle({"prompt": f"⟦rh:{sid}⟧"}, cfg, project_dir=str(cfg.project_dir))
    reply.handle_stop({"last_assistant_message": "yes"}, cfg, report=lambda m: None)
    verify_handle({"prompt": "hello"}, cfg, project_dir=str(cfg.project_dir))
    assert core.store.message(sid).state == "answered"  # type: ignore[union-attr]
    assert read_current(cfg) is None


def test_text_is_capped_at_the_contract(tmp_path: Path) -> None:
    cfg = plain_cfg(tmp_path)
    write_current(cfg, id="a" * 32, kind="task", prompt_id=None, at=NOW)
    sent: list[dict[str, Any]] = []
    reply.handle_stop(
        {"last_assistant_message": "x" * 9000}, cfg, report=lambda m: sent.append(m) or {"ok": True}
    )
    assert len(sent[0]["text"]) == 8000


def test_end_to_end_over_the_admin_socket(env: Any, tmp_path: Path) -> None:
    """A real core: the message goes received → answered through the hook programs."""
    core, client, clock, _ = env
    phone = Phone()
    pair(core, client, phone)
    cfg = friend_cfg(core, tmp_path)
    project = str(cfg.project_dir)
    sent = signed(client, phone, "POST", "/v1/friend", OP_SEND, "normal", body("what time?"))
    sid = sent.json()["id"]
    # The verifier (in process) delivers it and reports received.
    from rh_friend.verify import handle as verify_handle

    out = verify_handle({"prompt": f"⟦rh:{sid}⟧", "prompt_id": "p-1"}, cfg, project_dir=project)
    assert out is not None and "decision" not in out
    assert core.store.message(sid).state == "received"  # type: ignore[union-attr]
    # The Stop hook as a subprocess, with the config written to a file.
    toml = tmp_path / "friend.toml"
    toml.write_text(
        "\n".join(
            [
                f'agent = "{AGENT}"',
                f'project_dir = "{cfg.project_dir}"',
                f'inbox_dir = "{cfg.inbox_dir}"',
                f'devices_file = "{cfg.devices_file}"',
                f'core_key = "{b64e(public_x963(core.key))}"',
                f'admin_socket = "{core.config.admin_socket}"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    stdin = json.dumps(
        {
            "hook_event_name": "Stop",
            "prompt_id": "p-1",
            "stop_hook_active": False,
            "last_assistant_message": "It is noon.",
        }
    )
    env_ = {**os.environ, "CLAUDE_PROJECT_DIR": project}
    r = subprocess.run(
        [sys.executable, "-m", "rh_friend.reply", "--config", str(toml), "--project", project],
        input=stdin,
        capture_output=True,
        text=True,
        env=env_,
        check=True,
    )
    assert r.stdout == "" and r.stderr == ""
    row = core.store.message(sid)
    assert row is not None and row.state == "answered"
    assert [(x.kind, x.text) for x in row.replies] == [("final", "It is noon.")]
    assert read_current(cfg) is None
    # Another project's Stop does nothing; --progress with nothing open says so.
    r = subprocess.run(
        [sys.executable, "-m", "rh_friend.reply", "--config", str(toml), "--project", project],
        input=stdin,
        capture_output=True,
        text=True,
        env={**os.environ, "CLAUDE_PROJECT_DIR": str(tmp_path)},
        check=True,
    )
    assert r.stdout == ""
    r = subprocess.run(
        [sys.executable, "-m", "rh_friend.reply", "--config", str(toml), "--progress", "x"],
        capture_output=True,
        text=True,
        env=env_,
    )
    assert r.returncode == 1 and "no open message" in r.stderr
    # A report the admin socket refuses (bad input) is answered, not deferred.
    admin = Admin(core.config.admin_socket)
    admin.send({"cmd": "friend.reply", "in_reply_to": sid, "text": "again"})
    assert admin.recv()["error"] == "closed"
    admin.close()


def test_late_stop_does_not_answer_a_newer_message(tmp_path: Path) -> None:
    cfg = plain_cfg(tmp_path)
    write_current(cfg, id="b" * 32, prompt_id="new-prompt", at=NOW)
    sent: list[dict[str, Any]] = []
    out = reply.handle_stop(
        {"last_assistant_message": "old answer", "prompt_id": "old-prompt"},
        cfg,
        report=lambda m: sent.append(m) or {"ok": True},
    )
    assert out == {"ok": False, "error": "prompt_mismatch"}
    assert sent == [] and read_current(cfg)["id"] == "b" * 32


def test_local_input_detaches_reply_without_granting_a_mode(tmp_path: Path) -> None:
    from rh_friend.verify import handle

    cfg = plain_cfg(tmp_path)
    write_current(cfg, id="a" * 32, kind="question", prompt_id="phone-prompt", at=NOW)
    out = handle(
        {"prompt": "Thanks, change nothing", "prompt_id": "local-prompt"},
        cfg,
        project_dir=str(cfg.project_dir),
        report=lambda m: {"ok": True},
    )
    assert out["hookSpecificOutput"]["additionalContext"] == "[unsigned]"
    assert read_current(cfg) is None
    sent: list[dict[str, Any]] = []
    assert (
        reply.handle_stop(
            {"last_assistant_message": "local answer"},
            cfg,
            report=lambda m: sent.append(m) or {"ok": True},
        )
        is None
    )
    assert sent == []


def test_receipts_and_replies_work_with_generated_config_without_gate(
    env: Any, tmp_path: Path
) -> None:
    import tomllib

    from rh_cli.channel import agent_config_text
    from rh_friend.verify import handle

    core, client, _, _ = env
    phone = Phone()
    pair(core, client, phone)
    cfg = from_dict(
        tomllib.loads(agent_config_text(core.config, tmux="tmux", ask=tmp_path / "ask"))
    )
    assert cfg.gate is None
    sent = signed(client, phone, "POST", "/v1/friend", OP_SEND, "normal", body("Hello"))
    sid = sent.json()["id"]
    out = handle({"prompt": f"⟦rh:{sid}⟧", "prompt_id": "p"}, cfg, project_dir=str(cfg.project_dir))
    assert out and out["hookSpecificOutput"]["additionalContext"].endswith("\nHello")
    assert core.store.message(sid).state == "received"
    assert reply.handle_stop({"last_assistant_message": "Hi", "prompt_id": "p"}, cfg)["ok"]
    row = core.store.message(sid)
    assert row.state == "answered" and row.replies[-1].text == "Hi"
