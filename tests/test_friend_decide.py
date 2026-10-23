"""friend.decide / friend.questions: contracts/vectors/friend_decide.json through the real
core, the Friend verifier hook and the Friend gate, plus the gate end to end over the
core's admin socket, the ask CLI and the config.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tomllib
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from openapi_util import check_response
from refclient import Phone
from rh_cli import rhcore
from rh_common.crypto import b64d, sha256_hex
from rh_common.friend import (
    OP_DECIDE,
    OP_QUESTIONS,
    Question,
    action_text,
    check_action,
    parse_decide_body,
    parse_envelope,
    question_sha256,
)
from rh_common.protocol import parse_ts
from rh_core import logfeed
from rh_core.app import Core, create_app
from rh_core.config import dev_config, to_toml
from rh_core.journal import Journal, verify
from rh_core.store import DecisionRow
from rh_friend import ask, gate
from rh_friend.config import (
    ConfigError,
    FriendConfig,
    GateConfig,
    ProtectedRule,
    default_rules,
    from_dict,
)
from rh_friend.verify import handle as verify_handle
from test_core_flow import Admin, env, pair, signed  # noqa: F401  (env is a fixture)
from test_core_vectors import FIX, NOW, seeded_core

VECTORS = Path(__file__).parent.parent / "contracts" / "vectors"
FD = json.loads((VECTORS / "friend_decide.json").read_text(encoding="utf-8"))
FRIEND = json.loads((VECTORS / "friend.json").read_text(encoding="utf-8"))
QUESTION = Question(**FD["question"])


def ids(vs: list[dict[str, Any]]) -> list[str]:
    return [v["name"] for v in vs]


def events(core: Core) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for f in sorted(core.config.journal_dir.glob("*.jsonl"))
        for line in f.read_text().splitlines()
    ]


@pytest.fixture
def core(short_dir: Path) -> Iterator[Core]:
    c = seeded_core(short_dir)
    c.store.add_question(QUESTION)
    yield c
    c.store.close()


# --- build vectors ---------------------------------------------------------------------------


def test_build_vectors() -> None:
    b = FD["build"]
    for key in ("question", "question_unicode"):
        assert question_sha256(b[key]["text"]) == b[key]["expected_sha256"]
    assert action_text(b["action"]["tool"], b["action"]["input"]) == b["action"]["expected_action"]
    assert check_action(b["action"]["expected_action"])
    for v in b["decide_body"]:
        d = parse_decide_body(v["expected_body_text"].encode("utf-8"))
        assert d.decision == v["decision"] and d.key_level == v["key_level"]
        assert d.id == QUESTION.id and d.action == QUESTION.action
        assert d.question_sha256 == question_sha256(QUESTION.text)


# --- core -------------------------------------------------------------------------------------


@pytest.mark.parametrize("v", FD["core"], ids=ids(FD["core"]))
def test_core_vector(core: Core, v: dict[str, Any]) -> None:
    client = TestClient(create_app(core, admin_socket=False))
    body = b64d(v["body_b64"])
    r = client.post("/v1/friend/decide", headers=v["headers"], content=body)
    expect = v["expect"]
    spooled = sorted(core.config.inbox_dir.glob("*.json")) if core.config.inbox_dir.exists() else []
    if expect["result"] == "reject":
        assert r.status_code == expect["status"], r.text
        assert r.json()["error"]["code"] == expect["code"]
        assert spooled == []
        assert core.store.question(QUESTION.id) == (QUESTION, "open")
        return
    assert r.status_code == 200, r.text
    doc = r.json()
    check_response("/v1/friend/decide", "post", 200, doc)
    decision = parse_decide_body(body)
    assert doc["id"] == expect["spool_id"]
    assert doc["question_id"] == QUESTION.id and doc["decision"] == decision.decision
    assert [p.stem for p in spooled] == [expect["spool_id"]]
    env_ = parse_envelope(spooled[0].read_bytes())
    assert env_.auth == v["headers"]["X-RH-Auth"] and env_.body == body
    assert core.store.question(QUESTION.id) == (QUESTION, "answered")
    row = core.store.decision(expect["spool_id"])
    assert row is not None and row.decision == decision.decision and row.used_at is None
    assert row.key == ("critical" if decision.decision == "allow" else "normal")
    assert any(
        e["event"] == "friend.decision" and e["id"] == expect["spool_id"] for e in events(core)
    )


def test_second_answer_to_the_same_question_is_refused(core: Core) -> None:
    client = TestClient(create_app(core, admin_socket=False))
    allow = next(v for v in FD["core"] if v["name"] == "allow-critical-ok")
    deny = next(v for v in FD["core"] if v["name"] == "deny-normal-ok")
    assert (
        client.post(
            "/v1/friend/decide", headers=allow["headers"], content=b64d(allow["body_b64"])
        ).status_code
        == 200
    )
    # The fixture nonce is spent now; give the deny its own fresh nonce record.
    from rh_common.protocol import NonceRecord, parse_auth

    obj = parse_auth(deny["headers"]["X-RH-Auth"])[0]
    core.store.consume_nonce(obj.nonce)  # already used by the allow; make sure
    core.store.put_nonce(
        obj.nonce + "x", NonceRecord(device=obj.device, expires=NOW + timedelta(30))
    )
    r = client.post("/v1/friend/decide", headers=deny["headers"], content=b64d(deny["body_b64"]))
    assert r.status_code == 401 and r.json()["error"]["code"] == "nonce_used"


def test_withdrawn_question_cannot_be_decided(core: Core) -> None:
    client = TestClient(create_app(core, admin_socket=False))
    assert core.withdraw(QUESTION.id) is True
    assert core.withdraw(QUESTION.id) is False
    v = next(v for v in FD["core"] if v["name"] == "allow-critical-ok")
    r = client.post("/v1/friend/decide", headers=v["headers"], content=b64d(v["body_b64"]))
    assert r.status_code == 400 and r.json()["error"]["code"] == "bad_request"
    assert "withdrawn" in r.json()["error"]["message"]


# --- live flow: ask, list, decide, rows ----------------------------------------------------


def test_questions_endpoint_and_rows(env: Any) -> None:
    core, client, clock, _ = env
    phone = Phone()
    pair(core, client, phone)
    r = signed(client, phone, "GET", "/v1/friend/questions", OP_QUESTIONS, "normal")
    assert r.status_code == 200 and r.json()["questions"] == []
    q = core.ask("Resume the agent?", action_text("Bash", {"command": "kill -CONT 1"}))
    r = signed(client, phone, "GET", "/v1/friend/questions", OP_QUESTIONS, "normal")
    doc = r.json()
    check_response("/v1/friend/questions", "get", 200, doc)
    assert doc["questions"] == [q.to_api()]
    rows = signed(
        client, phone, "POST", "/v1/data", "data.get", "normal", b'{"ids":["rh.questions"]}'
    ).json()["values"]["rh.questions"]
    check_response(
        "/v1/data", "post", 200, {"values": {"rh.questions": rows}, "server_time": q.asked_at}
    )
    assert rows["value"] == [
        {
            "id": q.id,
            "title": "Resume the agent?",
            "subtitle": "Friend asks · Bash",
            "status": {"state": "warn", "text": "waiting"},
            "at": q.asked_at,
        }
    ]
    assert (
        signed(client, phone, "GET", "/v1/friend/questions", "status", "normal").status_code == 401
    )


def decide_body(
    q: Question, decision: str, *, digest: str | None = None, action: str | None = None
) -> bytes:
    doc = {
        "action": action if action is not None else q.action,
        "decision": decision,
        "id": q.id,
        "question_sha256": digest if digest is not None else question_sha256(q.text),
        "to": "Friend",
    }
    return json.dumps(doc, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def friend_cfg(core: Core, tmp: Path, *, window: int = 120) -> FriendConfig:
    from rh_common.crypto import b64e, public_x963

    project = tmp / "project"
    project.mkdir(exist_ok=True)
    return from_dict(
        {
            "project_dir": str(project),
            "inbox_dir": str(core.config.inbox_dir),
            "devices_file": str(core.config.devices_path),
            "core_key": b64e(public_x963(core.key)),
            "seen_file": str(tmp / "seen.jsonl"),
            "rejected_log": str(tmp / "rejected.jsonl"),
            "gate": {
                "admin_socket": str(core.config.admin_socket),
                "decide_window_s": window,
                "log": str(tmp / "gate.jsonl"),
                "protected": [
                    {"name": "kill", "tools": ["Bash"], "field": "command", "match": [r"\bkill\b"]}
                ],
            },
        }
    )


def test_gate_end_to_end_over_the_admin_socket(env: Any, tmp_path: Path) -> None:
    core, client, clock, _ = env
    phone = Phone()
    pair(core, client, phone)
    cfg = friend_cfg(core, tmp_path)
    tool_input = {"command": "kill -CONT 4242", "description": "resume"}
    event = {"tool_name": "Bash", "tool_input": tool_input, "hook_event_name": "PreToolUse"}
    project = str(cfg.project_dir)

    # 1. Protected call without a decision: blocked.
    out = gate.handle(event, cfg, project_dir=project, now=clock)
    assert out.blocked and out.code == "no_decision"
    # Another tool call is not protected; another project is left alone.
    assert (
        gate.handle(
            {"tool_name": "Bash", "tool_input": {"command": "ls"}}, cfg, project_dir=project
        ).kind
        == "none"
    )
    assert gate.handle(event, cfg, project_dir=str(tmp_path)).kind == "none"

    # 2. Friend asks (admin socket), the phone allows with the critical key.
    admin = Admin(core.config.admin_socket)
    admin.send(
        {"cmd": "friend.ask", "text": "Resume pid 4242?", "action": action_text("Bash", tool_input)}
    )
    asked = admin.recv()
    admin.close()
    assert asked["ok"] is True
    q = Question(
        id=asked["id"], text=asked["text"], action=asked["action"], asked_at=asked["asked_at"]
    )
    r = signed(
        client, phone, "POST", "/v1/friend/decide", OP_DECIDE, "critical", decide_body(q, "allow")
    )
    assert r.status_code == 200, r.text
    sid = r.json()["id"]
    # The verifier labels the delivered pointer as a decision.
    delivered = verify_handle({"prompt": f"⟦rh:{sid}⟧"}, cfg, project_dir=project, now=clock)
    assert delivered is not None and "decision" not in delivered
    ctx = delivered["hookSpecificOutput"]["additionalContext"]
    assert (
        "· decide]" in ctx
        and ctx.splitlines()[1].startswith("allow · question")
        and q.action in ctx
    )

    # 3. The gate lets exactly that call through once.
    out = gate.handle(event, cfg, project_dir=project, now=clock)
    assert out.kind == "allow" and out.decision_id == sid, out
    assert "allow ⟦rh:" in (out.label or "")
    again = gate.handle(event, cfg, project_dir=project, now=clock)
    assert again.blocked and again.code == "already_used"
    # A call that differs by one character has no decision.
    other = {**event, "tool_input": {**tool_input, "command": "kill -CONT 4243"}}
    assert gate.handle(other, cfg, project_dir=project, now=clock).code == "no_decision"

    # 4. Deny with the normal key: blocked as denied.
    q2 = core.ask("Again?", q.action)
    r = signed(
        client, phone, "POST", "/v1/friend/decide", OP_DECIDE, "normal", decide_body(q2, "deny")
    )
    assert r.status_code == 200, r.text
    out = gate.handle(event, cfg, project_dir=project, now=clock)
    assert out.blocked and out.code == "denied"

    # 5. Allow, then wait past the window: blocked as expired.
    q3 = core.ask("Once more?", q.action)
    r = signed(
        client, phone, "POST", "/v1/friend/decide", OP_DECIDE, "critical", decide_body(q3, "allow")
    )
    assert r.status_code == 200, r.text
    clock.offset += timedelta(seconds=121)
    out = gate.handle(event, cfg, project_dir=project, now=clock)
    assert out.blocked and out.code == "expired"
    clock.offset -= timedelta(seconds=121)
    # Still unused in the core: the gate never asked it to spend an expired one.
    row = core.store.decision(r.json()["id"])
    assert row is not None and row.used_at is None

    # Wrong key level for a decision is refused by the core before anything is spooled.
    q4 = core.ask("Normal key?", q.action)
    r = signed(
        client, phone, "POST", "/v1/friend/decide", OP_DECIDE, "normal", decide_body(q4, "allow")
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "wrong_key_level"
    r = signed(
        client, phone, "POST", "/v1/friend/decide", OP_DECIDE, "critical", decide_body(q4, "deny")
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "wrong_key_level"
    assert core.store.question(q4.id) == (q4, "open")

    # Logs: blocks in the rejected log, every verdict in the gate log; the journal chain holds.
    rejected = [json.loads(line) for line in cfg.rejected_log.read_text().splitlines()]
    assert [e["code"] for e in rejected] == [
        "no_decision",
        "already_used",
        "no_decision",
        "denied",
        "expired",
    ]
    assert cfg.gate is not None and cfg.gate.log is not None
    results = [json.loads(line)["result"] for line in cfg.gate.log.read_text().splitlines()]
    assert results.count("allow") == 1 and results.count("block") == 5
    assert verify(core.config.journal_dir) == []
    kinds = {e["event"] for e in events(core)}
    assert {
        "friend.question",
        "friend.decision",
        "friend.decision.used",
        "friend.decision.refused",
    } <= kinds


def test_gate_with_the_core_down(env: Any, tmp_path: Path) -> None:
    core, client, clock, _ = env
    phone = Phone()
    pair(core, client, phone)
    cfg = friend_cfg(core, tmp_path)
    tool_input = {"command": "kill -CONT 1"}
    q = core.ask("?", action_text("Bash", tool_input))
    r = signed(
        client, phone, "POST", "/v1/friend/decide", OP_DECIDE, "critical", decide_body(q, "allow")
    )
    assert r.status_code == 200
    import dataclasses

    down = dataclasses.replace(
        cfg, gate=dataclasses.replace(cfg.gate, admin_socket=tmp_path / "nope.sock")
    )
    out = gate.handle(
        {"tool_name": "Bash", "tool_input": tool_input},
        down,
        project_dir=str(cfg.project_dir),
        now=clock,
    )
    assert out.blocked and out.code == "core_unreachable"
    # Nothing was spent: with the core back the same decision still works.
    out = gate.handle(
        {"tool_name": "Bash", "tool_input": tool_input},
        cfg,
        project_dir=str(cfg.project_dir),
        now=clock,
    )
    assert out.kind == "allow"


def test_two_gates_racing_for_one_decision(env: Any, tmp_path: Path) -> None:
    core, client, clock, _ = env
    phone = Phone()
    pair(core, client, phone)
    cfg = friend_cfg(core, tmp_path)
    tool_input = {"command": "kill -CONT 7"}
    q = core.ask("?", action_text("Bash", tool_input))
    assert (
        signed(
            client,
            phone,
            "POST",
            "/v1/friend/decide",
            OP_DECIDE,
            "critical",
            decide_body(q, "allow"),
        ).status_code
        == 200
    )
    import threading

    results: list[gate.Outcome] = []
    event = {"tool_name": "Bash", "tool_input": tool_input}

    def run() -> None:
        results.append(gate.handle(event, cfg, project_dir=str(cfg.project_dir), now=clock))

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert sorted(o.kind for o in results) == ["allow", "block", "block", "block"]
    assert {o.code for o in results if o.blocked} == {"already_used"}


# --- envelope vectors (the verifier) ----------------------------------------------------------


def verifier_config(tmp: Path) -> FriendConfig:
    inbox = tmp / "inbox"
    inbox.mkdir(exist_ok=True)
    devices = tmp / "devices.json"
    devices.write_text(FRIEND["devices"]["valid"], encoding="utf-8")
    return from_dict(
        {
            "project_dir": str(tmp / "project"),
            "inbox_dir": str(inbox),
            "devices_file": str(devices),
            "core_key": FD["core_pub_x963_b64"],
            "seen_file": str(tmp / "seen.jsonl"),
            "rejected_log": str(tmp / "rejected.jsonl"),
            "window_s": FD["verify_window_s"],
        }
    )


@pytest.mark.parametrize("v", FD["envelopes"], ids=ids(FD["envelopes"]))
def test_envelope_vector(tmp_path: Path, v: dict[str, Any]) -> None:
    cfg = verifier_config(tmp_path)
    sid = v["pointer"][len("⟦rh:") : -1]
    (cfg.inbox_dir / f"{sid}.json").write_text(v["envelope"], encoding="utf-8")
    now = parse_ts(v["now"])
    out = verify_handle(
        {"prompt": v["pointer"]}, cfg, project_dir=str(cfg.project_dir), now=lambda: now
    )
    assert out is not None
    if v["expect"]["result"] == "accept":
        ctx = out["hookSpecificOutput"]["additionalContext"]
        assert ctx.startswith("[RH ✔ owner · Мой iPhone · ") and " · decide]\n" in ctx
        assert ctx.splitlines()[1].startswith(f"{v['expect']['decision']} · question ")
        assert ctx.endswith("\n" + v["expect"]["action"])
        assert "decision" not in out
        # Delivered once: the same pointer again is a replay.
        again = verify_handle(
            {"prompt": v["pointer"]}, cfg, project_dir=str(cfg.project_dir), now=lambda: now
        )
        assert (
            again is not None and again["decision"] == "block" and "(replayed)" in again["reason"]
        )
    else:
        assert out["decision"] == "block"
        assert f"({v['expect']['code']})" in out["reason"]


# --- gate vectors ------------------------------------------------------------------------------


class FakeSpend:
    """friend.decision.use as the core answers it, from a vector's `core` state."""

    def __init__(self, state: dict[str, Any] | None) -> None:
        self.state = None if state is None else {k: dict(v) for k, v in state.items()}

    def __call__(self, decision_id: str, action: str, digest: str) -> dict[str, Any]:
        if self.state is None:
            raise gate.CoreUnreachable("down")
        row = self.state.get(decision_id)
        if row is None:
            return {"ok": False, "error": "not_found", "message": "no decision"}
        if action != QUESTION.action or digest != question_sha256(QUESTION.text):
            return {"ok": False, "error": "mismatch", "message": "mismatch"}
        if row["decision"] != "allow":
            return {"ok": False, "error": "denied", "message": "denied"}
        if row["used"]:
            return {"ok": False, "error": "already_used", "message": "already used"}
        row["used"] = True
        return {"ok": True, "id": decision_id}


def gate_config(tmp: Path, rules: tuple[ProtectedRule, ...] = default_rules()) -> FriendConfig:
    cfg = verifier_config(tmp)
    import dataclasses

    return dataclasses.replace(
        cfg,
        gate=GateConfig(
            admin_socket=tmp / "admin.sock",
            protected=rules,
            decide_window_s=FD["decide_window_s"],
            log=tmp / "gate.jsonl",
        ),
    )


@pytest.mark.parametrize("v", FD["gate"], ids=ids(FD["gate"]))
def test_gate_vector(tmp_path: Path, v: dict[str, Any]) -> None:
    cfg = gate_config(tmp_path)
    for sid, text in v["envelopes"].items():
        (cfg.inbox_dir / f"{sid}.json").write_text(text, encoding="utf-8")
    now = parse_ts(v["now"])
    out = gate.handle(
        {"tool_name": v["tool"], "tool_input": v["input"]},
        cfg,
        project_dir=str(cfg.project_dir),
        now=lambda: now,
        spend=FakeSpend(v["core"]),
    )
    expect = v["expect"]
    if expect["result"] == "none":
        assert out.kind == "none"
        assert not cfg.rejected_log.exists()
    elif expect["result"] == "allow":
        assert out.kind == "allow" and out.decision_id == expect["decision"], out
        log = [
            json.loads(line)
            for line in (cfg.gate.log if cfg.gate else Path()).read_text().splitlines()
        ]
        assert log[-1]["result"] == "allow" and log[-1]["decision"] == expect["decision"]
    else:
        assert out.blocked and out.code == expect["code"], out
        log = [json.loads(line) for line in cfg.rejected_log.read_text().splitlines()]
        assert log[-1]["code"] == expect["code"] and log[-1]["hook"] == "gate"


def test_gate_crash_blocks(tmp_path: Path) -> None:
    cfg = gate_config(tmp_path)
    v = next(v for v in FD["gate"] if v["name"] == "valid-allow")
    for sid, text in v["envelopes"].items():
        (cfg.inbox_dir / f"{sid}.json").write_text(text, encoding="utf-8")

    def boom(*args: Any) -> dict[str, Any]:
        raise RuntimeError("bug")

    out = gate.handle(
        {"tool_name": v["tool"], "tool_input": v["input"]},
        cfg,
        project_dir=str(cfg.project_dir),
        now=lambda: parse_ts(v["now"]),
        spend=boom,
    )
    assert out.blocked and out.code == "error" and "RuntimeError" in (out.detail or "")


def test_gate_without_gate_table_blocks_protected_calls_only(tmp_path: Path) -> None:
    cfg = verifier_config(tmp_path)  # no [gate]
    out = gate.handle(
        {"tool_name": "Bash", "tool_input": {"command": "ls"}},
        cfg,
        project_dir=str(cfg.project_dir),
    )
    assert out.blocked and out.code == "no_gate_config"


# --- the hook process ----------------------------------------------------------------------------


def write_toml(cfg: FriendConfig, path: Path, *, rules: bool = True) -> None:
    assert cfg.gate is not None
    lines = [
        f"{k} = {json.dumps(str(val))}"
        for k, val in (
            ("project_dir", cfg.project_dir),
            ("inbox_dir", cfg.inbox_dir),
            ("devices_file", cfg.devices_file),
            ("core_key", FD["core_pub_x963_b64"]),
            ("seen_file", cfg.seen_file),
            ("rejected_log", cfg.rejected_log),
        )
    ]
    lines += [
        "[gate]",
        f"admin_socket = {json.dumps(str(cfg.gate.admin_socket))}",
        f"decide_window_s = {cfg.gate.decide_window_s}",
    ]
    if rules:
        lines += [
            "[[gate.protected]]",
            'name = "kill"',
            'tools = ["Bash"]',
            'field = "command"',
            r"match = ['\bkill\b']",
        ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_gate(
    toml: Path, event: Any, project: Path, *extra: str
) -> subprocess.CompletedProcess[str]:
    env_ = {**os.environ, "CLAUDE_PROJECT_DIR": str(project)}
    return subprocess.run(
        [sys.executable, "-m", "rh_friend.gate", "--config", str(toml), *extra],
        input=event if isinstance(event, str) else json.dumps(event),
        capture_output=True,
        text=True,
        env=env_,
    )


def test_hook_process_end_to_end(tmp_path: Path) -> None:
    cfg = gate_config(tmp_path)
    cfg.project_dir.mkdir(exist_ok=True)
    toml = tmp_path / "friend.toml"
    write_toml(cfg, toml)
    protected = {"tool_name": "Bash", "tool_input": {"command": "kill -CONT 1"}}
    # Not protected: silent exit 0. Protected, no decision: exit 2 with the reason on stderr.
    r = run_gate(toml, {"tool_name": "Bash", "tool_input": {"command": "ls"}}, cfg.project_dir)
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
    r = run_gate(toml, protected, cfg.project_dir)
    assert r.returncode == 2 and "blocked (no_decision)" in r.stderr and r.stdout == ""
    # Another project (by --project before the config, and by the config alone): nothing.
    r = run_gate(toml, protected, tmp_path, "--project", str(cfg.project_dir))
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
    r = run_gate(toml, protected, tmp_path)
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")
    # Broken input or a missing config: blocked (fail closed).
    r = run_gate(toml, "not json", cfg.project_dir)
    assert r.returncode == 2 and "unreadable_input" in r.stderr
    r = run_gate(tmp_path / "nope.toml", protected, cfg.project_dir)
    assert r.returncode == 2 and "blocked (config)" in r.stderr
    # --project that disagrees with the config: blocked.
    r = run_gate(toml, protected, cfg.project_dir, "--project", str(cfg.project_dir))
    assert r.returncode == 2 and "no_decision" in r.stderr
    other = tmp_path / "other"
    other.mkdir()
    r = run_gate(toml, protected, other, "--project", str(other))
    assert r.returncode == 2 and "project_dir differ" in r.stderr


def test_hook_process_allows_with_a_label(tmp_path: Path, short_dir: Path) -> None:
    """The real socket path: a tiny fake core answers friend.decision.use."""
    import dataclasses
    import socket
    import threading

    cfg = gate_config(tmp_path)
    assert cfg.gate is not None
    # macOS caps Unix socket paths at 104 bytes: the socket lives in the short directory.
    cfg = dataclasses.replace(
        cfg, gate=dataclasses.replace(cfg.gate, admin_socket=short_dir / "a.sock")
    )
    cfg.project_dir.mkdir(exist_ok=True)
    v = next(v for v in FD["gate"] if v["name"] == "valid-allow")
    for sid, text in v["envelopes"].items():
        (cfg.inbox_dir / f"{sid}.json").write_text(text, encoding="utf-8")
    assert cfg.gate is not None
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(cfg.gate.admin_socket))
    server.listen(1)
    got: list[dict[str, Any]] = []

    def serve() -> None:
        conn, _ = server.accept()
        with conn:
            f = conn.makefile("rw", encoding="utf-8")
            got.append(json.loads(f.readline()))
            f.write(json.dumps({"ok": True, "id": got[0]["id"]}) + "\n")
            f.flush()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    toml = tmp_path / "friend.toml"
    write_toml(cfg, toml)
    # The gate's clock is real; the vector's envelope was signed at the fixture's NOW.
    # Only the signature path is under test here: widen the window.
    toml.write_text(
        toml.read_text().replace("decide_window_s = 120", "decide_window_s = 100000000000")
    )
    r = run_gate(toml, {"tool_name": v["tool"], "tool_input": v["input"]}, cfg.project_dir)
    t.join(5)
    server.close()
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse" and "allow ⟦rh:" in out["additionalContext"]
    assert got and got[0]["cmd"] == "friend.decision.use" and got[0]["action"] == QUESTION.action


# --- ask CLI ----------------------------------------------------------------------------


def test_ask_cli(env: Any, tmp_path: Path, capsys: Any) -> None:
    core, client, clock, _ = env
    cfg = friend_cfg(core, tmp_path)
    toml = tmp_path / "friend.toml"
    write_toml(cfg, toml)
    assert ask.main(["--config", str(toml), "--list"]) == 0
    assert "no open questions" in capsys.readouterr().out
    rc = ask.main(["--config", str(toml), "--question", "Resume pid 1?", "--bash", "kill -CONT 1"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "asked: " in out and '"command": "kill -CONT 1"' in out
    qid = out.split("asked: ")[1].split()[0]
    questions = core.store.open_questions()
    assert [q.id for q in questions] == [qid]
    assert questions[0].action == action_text("Bash", {"command": "kill -CONT 1"})
    rc = ask.main(
        [
            "--config",
            str(toml),
            "--question",
            "Edit?",
            "--tool",
            "Edit",
            "--input",
            '{"file_path": "/x", "old_string": "a", "new_string": "b"}',
        ]
    )
    assert rc == 0 and len(core.store.open_questions()) == 2
    assert ask.main(["--config", str(toml), "--list"]) == 0
    assert qid in capsys.readouterr().out
    assert ask.main(["--config", str(toml), "--withdraw", qid]) == 0
    assert [q.id for q in core.store.open_questions()] != [qid]
    assert ask.main(["--config", str(toml), "--withdraw", qid]) == 1
    capsys.readouterr()
    # Bad input is refused before anything reaches the core.
    with pytest.raises(SystemExit):
        ask.main(
            ["--config", str(toml), "--question", "x", "--tool", "Bash", "--input", "{not json"]
        )
    assert ask.main(["--config", str(toml), "--question", "  ", "--bash", "ls"]) == 1


def test_ask_cli_without_core(tmp_path: Path, capsys: Any) -> None:
    cfg = gate_config(tmp_path)
    toml = tmp_path / "friend.toml"
    write_toml(cfg, toml)
    assert ask.main(["--config", str(toml), "--question", "x", "--bash", "ls"]) == 2
    assert "not running" in capsys.readouterr().err


# --- config, friend-config, store, log feed ------------------------------------------------------


def test_gate_config_rejects_bad_rules(tmp_path: Path) -> None:
    base = verifier_config(tmp_path)
    good: dict[str, Any] = {
        "project_dir": str(base.project_dir),
        "inbox_dir": str(base.inbox_dir),
        "devices_file": str(base.devices_file),
        "core_key": FD["core_pub_x963_b64"],
        "seen_file": str(base.seen_file),
        "rejected_log": str(base.rejected_log),
        "gate": {
            "admin_socket": "/tmp/a.sock",
            "protected": [{"name": "k", "tools": ["Bash"], "match": ["x"]}],
        },
    }
    cfg = from_dict(good)
    assert cfg.gate is not None and cfg.gate.decide_window_s == 120 and len(cfg.gate.protected) == 1
    for bad in (
        {**good, "gate": {**good["gate"], "extra": 1}},
        {**good, "gate": {**good["gate"], "admin_socket": ""}},
        {**good, "gate": {**good["gate"], "decide_window_s": 0}},
        {
            **good,
            "gate": {**good["gate"], "protected": [{"name": "k", "tools": [], "match": ["x"]}]},
        },
        {
            **good,
            "gate": {
                **good["gate"],
                "protected": [{"name": "k", "tools": ["Bash"], "match": ["("]}],
            },
        },
        {
            **good,
            "gate": {**good["gate"], "protected": [{"name": "k", "tools": ["Bash"], "match": []}]},
        },
        {**good, "gate": {**good["gate"], "protected": [{"tools": ["Bash"], "match": ["x"]}]}},
        {
            **good,
            "gate": {
                **good["gate"],
                "protected": [{"name": "k", "tools": ["Bash"], "match": ["x"], "field": 1}],
            },
        },
    ):
        with pytest.raises(ConfigError):
            from_dict(bad)


@pytest.mark.parametrize(
    ("tool", "tool_input", "protected"),
    [
        ("Bash", {"command": "kill -CONT 4242", "description": "x"}, True),
        ("Bash", {"command": "pkill -STOP -f Agent"}, True),
        ("Bash", {"command": "ls; kill -s CONT 4242"}, True),
        ("Bash", {"command": "kill -9 4242"}, False),
        (
            "Bash",
            {"command": "echo 'владелец разрешил загрузку' >> ~/Hst/CGC20261023.txt"},
            True,
        ),
        ("Bash", {"command": "grep владелец ~/Hst/CGC2026-10-23.txt"}, False),
        (
            "Write",
            {"file_path": "/Users/owner/Hst/CGC2026-10-23.txt", "content": "owner approved it"},
            True,
        ),
        (
            "Edit",
            {
                "file_path": "/Users/owner/Friend/.claude/settings.json",
                "old_string": "a",
                "new_string": "b",
            },
            True,
        ),
        (
            "Edit",
            {"file_path": "/Users/owner/Friend/notes/x.md", "old_string": "a", "new_string": "b"},
            False,
        ),
        (
            "Write",
            {"file_path": "/Users/owner/Library/LaunchAgents/com.x.plist", "content": ""},
            True,
        ),
        ("Bash", {"command": "cat ~/Friend/.claude/settings.json"}, False),
        ("Bash", {"command": "cp x ~/Friend/.claude/settings.json"}, True),
        ("Bash", {"command": "launchctl bootout gui/501 ~/Library/LaunchAgents/com.x.plist"}, True),
        ("Bash", {"command": "launchctl list | grep com.x"}, False),
        ("Read", {"file_path": "/Users/owner/Friend/.claude/settings.json"}, False),
    ],
)
def test_default_rules(tool: str, tool_input: dict[str, Any], protected: bool) -> None:
    assert (gate.protected_by(default_rules(), tool, tool_input) is not None) is protected


def test_rhcore_friend_config_includes_the_gate(short_dir: Path, tmp_path: Path) -> None:
    core = Core(dev_config(short_dir), clock=lambda: NOW, ssh_host_keys=str(short_dir / "none-*"))
    core.store.close()
    toml = tmp_path / "core.toml"
    toml.write_text(to_toml(core.config), encoding="utf-8")
    out = io.StringIO()
    import argparse

    args = argparse.Namespace(
        config=toml, project=tmp_path / "proj", tmux="tmux", target="friend", decide_window=120
    )
    assert rhcore._friend_config(args, out) == 0
    cfg = from_dict(tomllib.loads(out.getvalue()))
    assert cfg.gate is not None
    assert cfg.gate.admin_socket == core.config.admin_socket
    assert cfg.gate.decide_window_s == 120 and cfg.gate.log == (
        tmp_path / "proj" / "log" / "rh_gate.jsonl"
    )
    assert [r.name for r in cfg.gate.protected] == [r.name for r in default_rules()]
    assert gate.protected_by(cfg.gate.protected, "Bash", {"command": "kill -CONT 1"})


def test_store_spends_a_decision_once() -> None:
    from rh_core.store import Store

    s = Store(":memory:")
    s.add_question(QUESTION)
    row = DecisionRow(
        id="b" * 32,
        question_id=QUESTION.id,
        device="d" * 32,
        key="critical",
        decision="allow",
        question_sha256=question_sha256(QUESTION.text),
        action=QUESTION.action,
        signed_at="2026-10-19T12:00:00Z",
        accepted_at="2026-10-19T12:00:01Z",
        used_at=None,
    )
    assert s.answer_question(row) is True
    assert s.answer_question(row) is False  # the question is closed
    assert s.open_questions() == []
    assert s.use_decision(row.id, now=NOW) is True
    assert s.use_decision(row.id, now=NOW) is False
    assert s.decision(row.id) is not None and s.decision(row.id).used_at == "2026-10-19T12:00:00Z"
    s.close()


def test_core_use_decision_checks_everything(core: Core) -> None:
    sid = "c" * 32
    core.store.put_decision(
        DecisionRow(
            id=sid,
            question_id=QUESTION.id,
            device=FIX["devices"][0]["id"],
            key="critical",
            decision="allow",
            question_sha256=question_sha256(QUESTION.text),
            action=QUESTION.action,
            signed_at=FIX["now"],
            accepted_at=FIX["now"],
            used_at=None,
        )
    )
    digest = question_sha256(QUESTION.text)
    assert (
        core.use_decision("0" * 32, action=QUESTION.action, question_sha256_=digest)["error"]
        == "not_found"
    )
    assert (
        core.use_decision(sid, action=QUESTION.action + " ", question_sha256_=digest)["error"]
        == "mismatch"
    )
    assert (
        core.use_decision(sid, action=QUESTION.action, question_sha256_="0" * 64)["error"]
        == "mismatch"
    )
    ok = core.use_decision(sid, action=QUESTION.action, question_sha256_=digest)
    assert ok["ok"] is True and ok["question_id"] == QUESTION.id
    assert (
        core.use_decision(sid, action=QUESTION.action, question_sha256_=digest)["error"]
        == "already_used"
    )
    assert sha256_hex(QUESTION.action.encode()) in {e.get("action_sha256") for e in events(core)}


def test_log_feed_shows_friend_events(tmp_path: Path) -> None:
    journal = Journal(tmp_path)
    journal.append("friend.message", device="a" * 32, id="b" * 32)
    journal.append("friend.question", id="q" * 32)
    journal.append(
        "friend.decision",
        device="a" * 32,
        id="d" * 32,
        question_id="q" * 32,
        decision="allow",
        key="critical",
    )
    journal.append("friend.decision.used", id="d" * 32, question_id="q" * 32)
    journal.append("friend.decision.refused", id="d" * 32, reason="already_used")
    journal.append("friend.question.withdrawn", id="q" * 32)
    entries, _ = logfeed.page(tmp_path, names=lambda d: "Мой iPhone")
    assert [(e["kind"], e["title"]) for e in reversed(entries)] == [
        ("chat", "Message to Friend from Мой iPhone"),
        ("approval", "Friend asks for a decision"),
        ("approval", "Allowed Friend's action (Мой iPhone)"),
        ("approval", "Friend used a decision"),
        ("approval", "Friend's decision refused: already_used"),
        ("approval", "Friend withdrew a question"),
    ]
    approvals, _ = logfeed.page(tmp_path, names=lambda d: None, filter="approvals")
    assert len(approvals) == 5


def test_admin_socket_friend_commands_validate(env: Any) -> None:
    core, client, clock, _ = env
    admin = Admin(core.config.admin_socket)
    admin.send({"cmd": "friend.ask", "text": "", "action": "{}"})
    assert admin.recv()["error"] == "bad_request"
    admin.close()
    admin = Admin(core.config.admin_socket)
    admin.send({"cmd": "friend.decision.use", "id": "x"})
    assert admin.recv()["error"] == "bad_request"
    admin.close()
    admin = Admin(core.config.admin_socket)
    admin.send(
        {"cmd": "friend.decision.use", "id": "0" * 32, "action": "{}", "question_sha256": "0" * 64}
    )
    assert admin.recv()["error"] == "not_found"
    admin.close()
    admin = Admin(core.config.admin_socket)
    admin.send({"cmd": "friend.question.withdraw", "id": "0" * 32})
    assert admin.recv()["error"] == "not_found"
    admin.close()


_ = Callable  # typing import kept for readers of the fixtures above
