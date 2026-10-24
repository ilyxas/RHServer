# Friend gate: signed decisions for protected actions (friend slice 2)

"friend" is the name of the mechanism, after the agent that designed it and first worked on
it; it has nothing to do with the channel's current agent.

What it gives: a protected tool call of the channel agent's session runs only after the owner
allowed exactly that call from the iPhone with a fresh Face ID within the last two minutes.
The model's beliefs do not matter; the gate decides, and the core keeps the count.

The channel has **one** agent at a time, **any** agent: `[channel] agent` in the core config
is the only place its name is set, and the owner switches it with `rhcore channel set`
(see "Switching the agent" below and docs/any_single_agent.md).

**What it is: a seat belt, not a sandbox.** Everything runs under one macOS user today, so
the files the gate relies on (friend.toml, the device list, the core's key and database,
the hook entry in settings.json) belong to the same user the agent's session runs as, and a
protected action can be spelled in a way the rules do not recognise (another path, a
script, Python). The gate catches the obvious spelling and makes the session ask; it does
not make the action impossible. The real guarantee comes with separate users (stage 7):
the dangerous actions are then done by the core under `_rhcore` on a signed decision, and
the agent's user has no right to do them directly. Until then, read "Known limitations" below.

**Main rule: the gate never paralyses the session.** Its first step for every tool call is
a local match against the protected rules; only a matching call goes further. An
unprotected call is never blocked by the core being down, the socket missing, a broken
config or a missing `CLAUDE_PROJECT_DIR`; a protected call is blocked by any of those. A
crash of the gate on an unprotected call is a bug (`tests/test_friend_decide.py`,
`test_unprotected_calls_never_reach_the_core_or_fail`, `test_hook_process_never_blocks_unprotected_calls`).

## Pieces

| Where | What |
|---|---|
| `rh-friend-ask` (the agent's Mac user) | puts a question + the exact action into the core over the admin socket |
| core, `GET /v1/friend/questions` | the phone lists open questions (`text`, `action` in full); `status.channel` names the agent asking |
| phone | shows text and action; **Allow** signs `friend.decide` with the critical key (fresh Face ID), **Deny** with the normal key |
| core, `POST /v1/friend/decide` | checks signature, key level per decision, body (`to` = the channel agent), that the question is open and the hash/action match; records the decision, spools the envelope, closes the question |
| bridge + `rh-friend-verify` | the pointer `⟦rh:<id>⟧` reaches the agent's session; the verifier labels it `[RH ✔ … · decide]`; an envelope addressed to another agent is blocked (`wrong_recipient`) |
| `rh-friend-gate` (PreToolUse hook) | for a protected call: re-checks every decide envelope's signature itself, takes the **newest** decision for exactly this action (a deny wins a tie); a deny blocks; a fresh allow with the critical key is spent in the core (`friend.decision.use`, first use wins) and only then the call goes through; otherwise exit 2 |

The newest decision counts. A Deny after an unused Allow blocks; a new question about the
same action voids the unused Allows for it (the core marks them `superseded`, journal
`friend.decision.voided`). The core re-checks everything itself when a decision is spent:
the action and question, the key level (allow = critical), freshness by the phone's `ts`
and by its own `accepted_at` (`[channel] decide_window_s` in core.toml, default 120 s), that
it was not superseded, and that it was not used. Every refusal is journaled
(`friend.decision.refused` with `reason` and `action_sha256`). Every `friend.*` record names
the agent (`agent`).

The action is canonical JSON (RFC 8785) `{"input": <tool_input>, "tool": "<tool name>"}`:
the whole tool input as Claude Code hands it to the hook. One changed character is a
different action. So ask with the exact input you will run and run it unchanged. Claude
Code's Bash tool sends a `description` with the command, so `rh-friend-ask --bash` requires
`--description` (the text the call will carry); for other fields (timeout) use `--tool Bash
--input '{...}'` with the full object.

Asking is never protected: a Bash call that runs exactly `<path>/rh-friend-ask <args>` (the
program named by `[gate] ask`, by its full path, one command, no shell operators) passes the
gate whatever the question text says, so a question about CGC or settings does not need
an answer before it can be asked. Anything more than that one command is matched as usual.

Rules see file paths resolved: `file_path`, `notebook_path` and `path` in the tool input are
made absolute against the call's `cwd` (and `~`) before matching, so a relative
`"CLAUDE.md"` is the file it names. The action text keeps the input as given.

Limits: an action is at most 65 536 characters and a question 8000 (the contract); the
admin socket takes lines up to 4 MiB, so anything the contract allows fits with UTF-8 and
JSON escaping to spare. One character over the contract is `bad_request` from the core,
not a closed socket.

## The owner's messages: state and the agent's replies (friend slice 3, core side)

The core keeps every accepted `friend.send` with its text and a state the phone reads
through `POST /v1/friend/messages` (contract 0.6.0): `accepted` (the core has it) →
`received` (the verifier delivered it) → `waiting` (the agent asked a decision since) →
`answered` (the final reply is in `replies`); `rejected` (the verifier blocked it) and
`superseded` (a newer message from the owner) end a message without an answer. A new
message supersedes every earlier one the agent still owed an answer to. The same `id`
sent again by the same device returns the first message's answer (a retry, not a
second message; the same `id` with another body is refused). Texts, both ways, are
`chat.message` entries in the Log (filter chat); the journal record carries the hash of the
text and the ids, the text itself is in the store, where the owner can delete it later
without breaking the journal chain (a deleted text shows as such in the Log).

The agent side reports facts over the admin socket; none of them is a permission, and
none is signed: any process running as the agent's user can send them. The phone shows
them as the agent's report (the contract says so), not as verified; what is verified stays
what it was: the owner's signature on the way in, the core's on the way out.

| Command | Who sends it | Effect |
|---|---|---|
| `friend.received {id, prompt_id}` | `rh-friend-verify` after a successful check (slice 3, agent side) | `accepted` → `received` |
| `friend.rejected {id, code, detail}` | `rh-friend-verify` when it blocks the pointer | → `rejected` |
| `friend.reply {in_reply_to, text, prompt_id, progress}` | the Stop hook (`rh-friend-reply`) with the turn's last assistant message; `--progress` by the agent itself | final: → `answered`, or → `waiting` when an open question was asked after the message arrived; progress: a reply, state unchanged |

The `kind` the phone signs (`question`, default, or `task`) and `re` (the message a
"make it a task" follows up) are stored and shown; the agent-side verifier labels the
message with its kind and the gate enforces it (agent side, slice 3). `[channel]
match_prompt_id = true` makes the core refuse a reply whose `prompt_id` is not the one the
verifier recorded for the message; it stays off until the live check that Claude Code's
Stop hook carries the same `prompt_id` as UserPromptSubmit.

## Configuration

The core config names the agent; nothing else does:

```toml
# core.toml
[agents]
team_file = "<the file whose 'Команда' list names the agents>"   # no default

[channel]
agent = "<id from the team file>"       # required; 1–32 of A-Za-z0-9_-
project_dir = "<the agent's folder>"    # required; the hooks act only there
target = "<tmux session>"               # required; the bridge types here, never derived
# inbox_dir = "<data_dir>/inbox"        # defaults
# devices_file = "<data_dir>/devices.json"
# decide_window_s = 120
```

A core without `[channel]` does not start; an old `[friend]` table is refused with a
pointer here. An id missing from the team file is shown as the id itself, with a
`friend.channel.warning` in the journal; the core still starts (only `channel set` refuses
such an id). The channel agent gets an `agents.status` rule (process `claude`, cwd =
`project_dir`) unless `[[agents.rule]]` configures one with its id; an agent that is not a
Claude Code session (Codex, Grok, an app) needs that explicit rule, or it shows as stopped
while it runs.

The agent-side config (`friend.toml`: verifier, bridge, gate) is derived from it:
`rhcore friend-config --owner-names '<name>|<Name>'` prints the whole file, `agent`,
`project_dir`, `[bridge] target`, the `[gate]` table and the default protected rules
included. `--project` is only a check against `[channel] project_dir`. Paths not given
default into the project: `state/rh_seen.jsonl`, `log/rh_rejected.jsonl`,
`state/rh_bridge.json`, `log/rh_gate.jsonl`.

Rules: a call is protected when any rule matches; a rule names `tools`, optionally a `field`
of `tool_input`, and regexes that must all be found (`re.search`, DOTALL; `ignore_case`
optional). Defaults:

1. `kill` / `pkill` / `killall` with CONT or STOP (resuming or pausing a process), wherever
   the word stands: after a path (`/bin/kill`), `command`, `xargs`, `bash -c "…"`, a space
   or a newline; by name (`-CONT`, `-s SIGSTOP`) or number (`-17`, `-18`, `-19`, `-s 19`);
2. the same from a script on the command line: `os.kill(`, `signal.SIGCONT`/`SIGSTOP`,
   `"kill", "-CONT"` in an argument list;
3. a record that the owner allowed something, in a CGC file (Bash, Write, Edit);
4. editing rules or access settings (`.claude/`, `CLAUDE.md`, `settings(.local).json`,
   LaunchAgents/Daemons, managed settings, `friend.toml`, `core.toml`, `.ssh/`,
   `authorized_keys`, `sudoers`) with an editing tool (paths resolved against `cwd`) or from
   the shell (`>`, `tee`, `sed -i`, `cp`, `mv`, `rm`, `ln`, `chmod`, `chown`, `truncate`,
   `install`, `patch`, `launchctl`, `defaults write`, `python`, `perl`, `ruby`, `node`,
   `swift`, `osascript`, `sh -c`).

Regexes run with DOTALL and MULTILINE. `decide_window_s` (from `[channel]`) is how old an
`allow` may be when the gate spends it, by the signed `ts`; the core applies the same window
on its side. `log` records every verdict on a protected call; blocks also go to
`rejected_log`. `ask` is the full path of `rh-friend-ask` (written by `rhcore friend-config`).

## Switching the agent

```sh
rhcore channel set --agent <id> --project <the agent's folder> --target <tmux session> \
    --core-label <core LaunchAgent label> [--bridge-label <bridge LaunchAgent label>]
```

(`$RH_CORE_LABEL` / `$RH_BRIDGE_LABEL` stand in for the labels.) In order:

1. Checks, nothing written yet: the id's form; the id is in the team file and no other
   member differs from it only in case (the id takes part in paths; the Mac's file system
   ignores case); the project folder exists; the tmux session `--target` exists.
2. Writes `[channel]` into core.toml (every other line kept; an old `[friend]` is dropped and
   its `inbox_dir`, `devices_file`, `decide_window_s` carry over) and the agent-side config
   next to it, after reading both back; each old file is kept as `*.bak-<time>`. The owner's
   `[[gate.protected]]` rules are kept as written (`--owner-names` writes the defaults instead).
   The new agent's bridge state is seeded with the envelopes already in the inbox, so its
   first start does not type the history into the new session.
3. Restarts the core (`launchctl kickstart -k`) and waits until the running core reports
   `channel.agent` = the new id over the admin socket; otherwise it is an error, not "done".
   On start the core withdraws the previous agent's open questions and voids its unused
   allows (journal `friend.channel.changed` with the ids; Log: "Channel agent changed").
4. Restarts the bridge when `--bridge-label` is given.
5. Prints what is left to the owner: the verify and gate hooks in the new agent's
   `.claude/settings.json` (an edit the gate protects, so the owner does it), and removing
   them from the previous agent's project.

The app needs nothing: the next `status` brings the new `channel.agent` and `title`, and
messages and decisions are addressed to it. Old envelopes stay in the inbox; the previous
agent's seen/rejected/gate logs stay in its project.

After a switch the previous agent's session gets no ✔ for a new message and cannot run a
protected action: the bridge no longer types into its tmux session; its hooks still say
`--project <previous folder>` while the agent-side config now names the new folder, so the
verifier fails closed (no ✔) and the gate blocks every protected call (`config`), while
unprotected calls run as before; its unused allows are voided in the core
(`tests/test_channel.py`).

## Known limitations (what the rules do not catch)

Protected means "the owner is asked", not "impossible". Under one user these still run
without a question, by design of a regex seat belt; they are closed by stage 7, not by more
regexes:

- a protected action inside a file that is then executed (`python3 script.py`, `sh run.sh`,
  a Makefile, a cron or launchd job written elsewhere);
- indirection the regex cannot follow: a variable (`S=CONT; kill -$S 1`), `eval`, `base64 -d
  | sh`, `xargs -I{}` with the signal in the input, `printf` into a file, an alias or a
  function defined earlier in the same shell;
- a tool call through an MCP server or another agent process (desktop-commander
  `start_process`, a terminal the session already holds), which never passes this hook;
- a shell edit of a settings file by a relative path that does not contain the file name
  (`cd <project>/.claude && cat > s.json && mv s.json settings.json` is caught by the
  `mv … settings.json` segment; `cd … && cat > "$F"` is not);
- renaming the ask program or putting another binary at its path: the exemption is by full
  path, so this takes a protected action (a write under the venv) or a free one (a copy
  elsewhere and a changed `[gate] ask`, which is a protected edit of friend.toml);
- anything the owner's user may do that the rules do not name at all (network, deleting
  files, git push): the rules are a list, not a policy.

A reviewer's or operator's new bypass is added to the rules when it is an obvious spelling
of a protected action; otherwise it goes here.

## Install (project settings of the agent's session; no sudo)

Prerequisites: the core and bridge LaunchAgents, RHServer installed into its venv
(`uv sync`), the agent's tmux session running.

1. Give the core its channel. On an install from before `[channel]`, add to core.toml the
   team file and the channel (or let `rhcore channel set` write the channel, step 1 of
   "Switching the agent" does the checks):

   ```toml
   [agents]
   team_file = "<the agent's team file>"

   [channel]
   agent = "<id>"
   project_dir = "<folder>"
   target = "<tmux session>"
   inbox_dir = "<data_dir>/friend-inbox"   # only to keep the slice-1/2 inbox folder
   ```

   The inbox default moved from `<data_dir>/friend-inbox` to `<data_dir>/inbox`. Keep
   `inbox_dir` pointing at the old folder while the running bridge and its state file use it;
   if you move to the new default, regenerate the agent-side config and restart the bridge
   in the same step.

2. Regenerate the agent-side config (keep a copy of the old one):

   ```sh
   cd ~/Development/RemoteHands/RHServer
   cp "$HOME/Library/Application Support/RemoteHands/friend.toml" "$HOME/Library/Application Support/RemoteHands/friend.toml.bak-$(date +%Y%m%d-%H%M%S)"
   uv run rhcore friend-config --config "$HOME/Library/Application Support/RemoteHands/core.toml" \
       --tmux /opt/homebrew/bin/tmux \
       --owner-names '<how CGC records name you, e.g. Name|Имя>' \
       > "$HOME/Library/Application Support/RemoteHands/friend.toml"
   ```

   Compare with the backup: `agent` is new; the rules are the defaults (copy your own back
   if you edited them).

3. Restart the core (it migrates the database to schema 4 and binds the channel) and the
   bridge, then check that it names the agent:

   ```sh
   launchctl kickstart -k gui/$(id -u)/<label of the core LaunchAgent>
   launchctl kickstart -k gui/$(id -u)/<label of the bridge LaunchAgent>
   uv run rhcore status --config "$HOME/Library/Application Support/RemoteHands/core.toml"
   ```

4. Add the hooks in `<project_dir>/.claude/settings.json` (`onFailure` and `timeout` are
   required for the gate, see docs/decisions/004):

   ```json
   "PreToolUse": [
     {
       "hooks": [
         {
           "type": "command",
           "command": "\"/Users/<user>/Development/RemoteHands/RHServer/.venv/bin/rh-friend-gate\" --config \"/Users/<user>/Library/Application Support/RemoteHands/friend.toml\" --project \"<project_dir>\"",
           "timeout": 30,
           "onFailure": "block"
         }
       ]
     }
   ]
   ```

   Editing this file is itself a protected action for the agent's session, so the owner
   edits it (or the agent does it before the gate is active). Then restart the agent's
   session (hook changes are picked up at start).

5. Check: `claude --version` ≥ 2.1.295; in the agent's session ask for `ls` (not protected,
   runs) and for `kill -CONT 1` (protected, blocked with `no_decision`).

### Rollback (one command, from the phone over SSH)

Before the owner is away, the way back must be tested live. It needs Remote Login (System
Settings → General → Sharing → Remote Login) or Tailscale SSH on the Mac, and an SSH app on
the phone (Termius, Blink) reaching the Mac's Tailscale name. The command restores the
settings file from before the hooks were added and restarts the agent's session, which is
how hook changes take effect:

```sh
P=<project_dir>
cp $P/.claude/settings.json $P/.claude/settings.json.bak-gate-$(date +%Y%m%d-%H%M%S) \
  && cp $P/.claude/settings.json.bak-rh $P/.claude/settings.json \
  && tmux kill-session -t <target>; <the agent's own autostart>
```

`settings.json.bak-rh` is the copy made before the verify hook was installed; it has no
hooks at all, so this removes both hooks at once (the core and bridge keep running and are
harmless without the hooks: the pointer arrives as plain text). The copy taken first keeps
the gated settings for putting them back.

## Live acceptance (owner on the Mac, phone in hand)

Run it with an agent id other than the mechanism's namesake on a test tmux session, then
with the real agent.

1. The agent tries a protected test call without asking, e.g. Bash `kill -CONT 99999`
   → blocked; `<project_dir>/log/rh_rejected.jsonl` ends with `"code": "no_decision"`.
2. The agent asks: `rh-friend-ask --question "<why>" --bash "kill -CONT 99999"` (or
   `--tool/--input` with the exact input). The phone's Chat tab shows the question, the
   asking agent's name and the action in full; Home → Needs Attention counts it.
   **Allow** + Face ID. The agent runs exactly that call → passes; the session shows
   `[RH ✔ owner · <iPhone> · <time> · allow ⟦rh:…⟧]`; `<project_dir>/log/rh_gate.jsonl` has
   `"result": "allow"`.
3. The agent repeats the same call → blocked, `already_used`.
4. The agent asks again, the owner taps **Deny** (no Face ID) → blocked, `denied`.
5. The agent asks, the owner allows, wait over two minutes, the agent runs → blocked,
   `expired`; the core journal has no `friend.decision.used` for it.
6. The core off (`launchctl bootout gui/$(id -u)/<core label>`): the agent reads files,
   answers a signed message from the phone with ✔ (the verifier needs no core), its
   monitors run; a protected call → blocked, `core_unreachable` (or `no_decision` when
   nothing was allowed). Start the core again (`launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/<core>.plist`).
7. The agent asks, the owner allows; the agent asks again about the same action, the owner
   denies → the agent runs the call → blocked, `denied`; the core journal has
   `friend.decision.voided` for the allow. (Also: allow, then a new question alone → `superseded`.)
8. Fail closed: temporarily point the hook's `command` to a missing path → any protected
   call is blocked with `failed; blocking because onFailure is "block"`; an unprotected
   call still runs; restore the path.
9. Rollback: run the one command above from the phone; the agent restarts without hooks; a
   message from the phone arrives as plain text (no ✔); put the gated settings back.
10. Switch: the agent asks, the owner allows and does not use it; `rhcore channel set` to
    another agent → the journal has `friend.channel.changed` with the question and the
    allow; the previous session gets no ✔ for new messages and its protected call is
    blocked; the app's Chat shows the new agent's name.

Independent trail: the core journal (`…/RemoteHands/data/journal/<date>.jsonl`): `friend.question`,
`friend.question.refused`, `friend.decision` (device, key, decision), `friend.decision.used`,
`friend.decision.refused` (every refusal, with `reason`), `friend.decision.voided`,
`friend.channel.changed`, `friend.channel.warning`; each names the `agent`.
The Log tab lists them under filter **approvals**.

## Managed install (prepared, not done: needs sudo, the owner's step)

Moves the trust anchors out of the agent user's reach so no agent can turn the gate off.
Same shape as the slice-1 plan for the verifier.

```sh
# as an administrator
sudo mkdir -p "/Library/Application Support/ClaudeCode" /usr/local/etc/remotehands
sudo cp "$HOME/Library/Application Support/RemoteHands/friend.toml" /usr/local/etc/remotehands/friend.toml
sudo chown root:wheel /usr/local/etc/remotehands /usr/local/etc/remotehands/friend.toml
sudo chmod 755 /usr/local/etc/remotehands; sudo chmod 644 /usr/local/etc/remotehands/friend.toml
# devices.json must also be owned by root or _rhcore (the core exports it; point core.toml
# [channel] devices_file at a root-owned directory the core user may write, or copy it on
# every pairing/revoke). Then in /Library/Application Support/ClaudeCode/managed-settings.json:
#   hooks.UserPromptSubmit: rh-friend-verify --config /usr/local/etc/remotehands/friend.toml
#                            --project <project_dir> --require-protected
#   hooks.PreToolUse:       rh-friend-gate   --config /usr/local/etc/remotehands/friend.toml
#                            --project <project_dir> --require-protected
#                            with "timeout": 30, "onFailure": "block"
# Both hooks exit 0 at once for any other project (CLAUDE_PROJECT_DIR check before the config).
# A managed install pins one project: switching the agent means the owner updates it too.
```

`--require-protected` makes both hooks refuse when the config or the device list (or any
directory above them) is writable by the hook's user. Open point for the managed step: the
device list is written by the core as the agent's user today; under `_rhcore` (stage 7) it is
not, and `--require-protected` passes. Until then the managed install protects the hook
entry and the config, not the device list.
