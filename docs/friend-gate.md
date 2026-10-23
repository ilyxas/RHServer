# Friend gate: signed decisions for protected actions (friend slice 2)

What it gives: a protected tool call of the Friend session runs only after the owner allowed
exactly that call from the iPhone with a fresh Face ID within the last two minutes. The
model's beliefs do not matter; the gate decides, and the core keeps the count.

**What it is: a seat belt, not a sandbox.** Everything runs under one macOS user today, so
the files the gate relies on (friend.toml, the device list, the core's key and database,
the hook entry in settings.json) belong to the same user the Friend session runs as, and a
protected action can be spelled in a way the rules do not recognise (another path, a
script, Python). The gate catches the obvious spelling and makes the session ask; it does
not make the action impossible. The real guarantee comes with separate users (stage 7):
the dangerous actions are then done by the core under `_rhcore` on a signed decision, and
the Friend user has no right to do them directly. Until then, read "Known limitations" below.

**Main rule: the gate never paralyses the session.** Its first step for every tool call is
a local match against the protected rules; only a matching call goes further. An
unprotected call is never blocked by the core being down, the socket missing, a broken
config or a missing `CLAUDE_PROJECT_DIR`; a protected call is blocked by any of those. A
crash of the gate on an unprotected call is a bug (`tests/test_friend_decide.py`,
`test_unprotected_calls_never_reach_the_core_or_fail`, `test_hook_process_never_blocks_unprotected_calls`).

## Pieces

| Where | What |
|---|---|
| `rh-friend-ask` (Friend's Mac user) | puts a question + the exact action into the core over the admin socket |
| core, `GET /v1/friend/questions` | the phone lists open questions (`text`, `action` in full) |
| phone | shows text and action; **Allow** signs `friend.decide` with the critical key (fresh Face ID), **Deny** with the normal key |
| core, `POST /v1/friend/decide` | checks signature, key level per decision, body, that the question is open and the hash/action match; records the decision, spools the envelope, closes the question |
| bridge + `rh-friend-verify` | the pointer `⟦rh:<id>⟧` reaches the Friend session; the verifier labels it `[RH ✔ … · decide]` |
| `rh-friend-gate` (PreToolUse hook) | for a protected call: re-checks every decide envelope's signature itself, takes the **newest** decision for exactly this action (a deny wins a tie); a deny blocks; a fresh allow with the critical key is spent in the core (`friend.decision.use`, first use wins) and only then the call goes through; otherwise exit 2 |

The newest decision counts. A Deny after an unused Allow blocks; a new question about the
same action voids the unused Allows for it (the core marks them `superseded`, journal
`friend.decision.voided`). The core re-checks everything itself when a decision is spent:
the action and question, the key level (allow = critical), freshness by the phone's `ts`
and by its own `accepted_at` (`[friend] decide_window_s` in core.toml, default 120 s), that
it was not superseded, and that it was not used. Every refusal is journaled
(`friend.decision.refused` with `reason` and `action_sha256`).

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

## Configuration (`friend.toml`)

`rhcore friend-config --project ~/Friend --owner-names '<name>|<Name>'` prints the whole file, the `[gate]` table and the
default protected rules included. Rules: a call is protected when any rule matches; a rule
names `tools`, optionally a `field` of `tool_input`, and regexes that must all be found
(`re.search`, DOTALL; `ignore_case` optional). Defaults:

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

Regexes run with DOTALL and MULTILINE. `decide_window_s` (default 120) is how old an `allow`
may be when the gate spends it, by the signed `ts`; the core applies the same window on its
side. `log` records every verdict on a protected call; blocks also go to `rejected_log`.
`ask` is the full path of `rh-friend-ask` (written by `rhcore friend-config`).

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
  (`cd ~/Friend/.claude && cat > s.json && mv s.json settings.json` is caught by the
  `mv … settings.json` segment; `cd … && cat > "$F"` is not);
- renaming the ask program or putting another binary at its path: the exemption is by full
  path, so this takes a protected action (a write under the venv) or a free one (a copy
  elsewhere and a changed `[gate] ask`, which is a protected edit of friend.toml);
- anything the owner's user may do that the rules do not name at all (network, deleting
  files, git push): the rules are a list, not a policy.

A reviewer's or operator's new bypass is added to the rules when it is an obvious spelling
of a protected action; otherwise it goes here.

## Install for the live test (project settings of the Friend session; no sudo)

Prerequisites: slice 1 running (the core and bridge LaunchAgents, the verify hook in
`~/Friend/.claude/settings.json`), RHServer at this branch installed into its venv (`uv sync`).

1. Regenerate `friend.toml` so it has `[gate]` (keep a copy of the old one):

   ```sh
   cd ~/Development/RemoteHands/RHServer
   cp "$HOME/Library/Application Support/RemoteHands/friend.toml" "$HOME/Library/Application Support/RemoteHands/friend.toml.bak-slice1"
   uv run rhcore friend-config --config "$HOME/Library/Application Support/RemoteHands/core.toml" \
       --project ~/Friend --tmux /opt/homebrew/bin/tmux --target friend \
       --owner-names '<how CGC records name you, e.g. Name|Имя>' \
       > "$HOME/Library/Application Support/RemoteHands/friend.toml"
   ```

   Compare with the backup: only the `[gate]` part is new.

2. Restart the core so it creates the new tables and serves `friend.questions` / `friend.decide`:

   ```sh
   launchctl kickstart -k gui/$(id -u)/<label of the core LaunchAgent>
   tail -3 "$HOME/Library/Application Support/RemoteHands/log/core.log"
   ```

3. Add the gate next to the verify hook in `~/Friend/.claude/settings.json` (`onFailure`
   and `timeout` are required, see docs/decisions/004):

   ```json
   "PreToolUse": [
     {
       "hooks": [
         {
           "type": "command",
           "command": "\"/Users/<user>/Development/RemoteHands/RHServer/.venv/bin/rh-friend-gate\" --config \"/Users/<user>/Library/Application Support/RemoteHands/friend.toml\" --project \"/Users/<user>/Friend\"",
           "timeout": 30,
           "onFailure": "block"
         }
       ]
     }
   ]
   ```

   Editing this file is itself a protected action for the Friend session, so the owner edits
   it (or Friend does it before the gate is active). Then restart the Friend session (hook
   changes are picked up at start; the owner confirms this on the first run).

4. Check: `claude --version` ≥ 2.1.295; in the Friend session ask for `ls` (not protected,
   runs) and for `kill -CONT 1` (protected, blocked with `no_decision`).

### Rollback (one command, from the phone over SSH)

Before the owner is away, the way back must be tested live. It needs Remote Login (System
Settings → General → Sharing → Remote Login) or Tailscale SSH on the Mac, and an SSH app on
the phone (Termius, Blink) reaching the Mac's Tailscale name. The command restores the
settings file from before the hooks were added and restarts the Friend session, which is how
hook changes take effect:

```sh
cp ~/Friend/.claude/settings.json ~/Friend/.claude/settings.json.bak-gate-$(date +%Y%m%d-%H%M%S) \
  && cp ~/Friend/.claude/settings.json.bak-rh ~/Friend/.claude/settings.json \
  && tmux kill-session -t friend; ~/Friend/bin/friend_autostart.sh
```

`settings.json.bak-rh` is the copy made before the verify hook was installed (slice 1); it
has no hooks at all, so this removes both hooks at once (the core and bridge keep running
and are harmless without the hooks: the pointer arrives as plain text). The copy taken
first keeps the gated settings for putting them back.

## Live acceptance (owner on the Mac, phone in hand)

1. Friend tries a protected test call without asking, e.g. Bash `kill -CONT 99999`
   → blocked; `~/Friend/log/rh_rejected.jsonl` ends with `"code": "no_decision"`.
2. Friend asks: `rh-friend-ask --question "<why>" --bash "kill -CONT 99999"` (or `--tool/--input`
   with the exact input). The phone's Chat tab shows the question and the action in full;
   Home → Needs Attention counts it. **Allow** + Face ID. Friend runs exactly that call →
   passes; the session shows `[RH ✔ owner · <iPhone> · <time> · allow ⟦rh:…⟧]`;
   `~/Friend/log/rh_gate.jsonl` has `"result": "allow"`.
3. Friend repeats the same call → blocked, `already_used`.
4. Friend asks again, the owner taps **Deny** (no Face ID) → blocked, `denied`.
5. Friend asks, the owner allows, wait over two minutes, Friend runs → blocked, `expired`;
   the core journal has no `friend.decision.used` for it.
6. The core off (`launchctl bootout gui/$(id -u)/<core label>`): Friend reads files, answers
   a signed message from the phone with ✔ (the verifier needs no core), its monitors run;
   a protected call → blocked, `core_unreachable` (or `no_decision` when nothing was
   allowed). Start the core again (`launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/<core>.plist`).
7. Friend asks, the owner allows; Friend asks again about the same action, the owner denies
   → Friend runs the call → blocked, `denied`; the core journal has `friend.decision.voided`
   for the allow. (Also: allow, then a new question alone → `superseded`.)
8. Fail closed: temporarily point the hook's `command` to a missing path → any protected
   call is blocked with `failed; blocking because onFailure is "block"`; an unprotected
   call still runs; restore the path.
9. Rollback: run the one command above from the phone; Friend restarts without hooks; a
   message from the phone arrives as plain text (no ✔); put the gated settings back.

Independent trail: the core journal (`…/RemoteHands/data/journal/<date>.jsonl`): `friend.question`,
`friend.question.refused`, `friend.decision` (device, key, decision), `friend.decision.used`,
`friend.decision.refused` (every refusal, with `reason`), `friend.decision.voided`.
The Log tab lists them under filter **approvals**.

## Managed install (prepared, not done: needs sudo, the owner's step)

Moves the trust anchors out of the Friend user's reach so no agent can turn the gate off.
Same shape as the slice-1 plan for the verifier.

```sh
# as an administrator
sudo mkdir -p "/Library/Application Support/ClaudeCode" /usr/local/etc/remotehands
sudo cp "$HOME/Library/Application Support/RemoteHands/friend.toml" /usr/local/etc/remotehands/friend.toml
sudo chown root:wheel /usr/local/etc/remotehands /usr/local/etc/remotehands/friend.toml
sudo chmod 755 /usr/local/etc/remotehands; sudo chmod 644 /usr/local/etc/remotehands/friend.toml
# devices.json must also be owned by root or _rhcore (the core exports it; point core.toml
# [friend] devices_file at a root-owned directory the core user may write, or copy it on
# every pairing/revoke). Then in /Library/Application Support/ClaudeCode/managed-settings.json:
#   hooks.UserPromptSubmit: rh-friend-verify --config /usr/local/etc/remotehands/friend.toml
#                            --project /Users/<user>/Friend --require-protected
#   hooks.PreToolUse:       rh-friend-gate   --config /usr/local/etc/remotehands/friend.toml
#                            --project /Users/<user>/Friend --require-protected
#                            with "timeout": 30, "onFailure": "block"
# Both hooks exit 0 at once for any other project (CLAUDE_PROJECT_DIR check before the config).
```

`--require-protected` makes both hooks refuse when the config or the device list (or any
directory above them) is writable by the hook's user. Open point for the managed step: the
device list is written by the core as the Friend user today; under `_rhcore` (stage 7) it is
not, and `--require-protected` passes. Until then the managed install protects the hook
entry and the config, not the device list.
