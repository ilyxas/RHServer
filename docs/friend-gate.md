# Friend gate: signed decisions for protected actions (friend slice 2)

What it gives: the Friend session physically cannot run a protected tool call unless the
owner allowed exactly that call from the iPhone with a fresh Face ID within the last two
minutes. The model's beliefs do not matter; the gate decides.

## Pieces

| Where | What |
|---|---|
| `rh-friend-ask` (Friend's Mac user) | puts a question + the exact action into the core over the admin socket |
| core, `GET /v1/friend/questions` | the phone lists open questions (`text`, `action` in full) |
| phone | shows text and action; **Allow** signs `friend.decide` with the critical key (fresh Face ID), **Deny** with the normal key |
| core, `POST /v1/friend/decide` | checks signature, key level per decision, body, that the question is open and the hash/action match; records the decision, spools the envelope, closes the question |
| bridge + `rh-friend-verify` | the pointer `⟦rh:<id>⟧` reaches the Friend session; the verifier labels it `[RH ✔ … · decide]` |
| `rh-friend-gate` (PreToolUse hook) | for a protected call: re-checks every decide envelope's signature itself, keeps fresh `allow`s for exactly this action, asks the core to spend one (`friend.decision.use`, first use wins) and only then lets the call through; otherwise exit 2 |

The action is canonical JSON (RFC 8785) `{"input": <tool_input>, "tool": "<tool name>"}`:
the whole tool input as Claude Code hands it to the hook. One changed character is a
different action. So ask with the exact input you will run (for Bash that includes
`description` if you will pass one), and run it unchanged.

## Configuration (`friend.toml`)

`rhcore friend-config --project ~/Friend --owner-names '<name>|<Name>'` prints the whole file, the `[gate]` table and the
default protected rules included. Rules: a call is protected when any rule matches; a rule
names `tools`, optionally a `field` of `tool_input`, and regexes that must all be found
(`re.search`, DOTALL; `ignore_case` optional). Defaults:

1. `kill` / `pkill` / `killall` with CONT or STOP (resuming or pausing a process);
2. a record that the owner allowed something, in a CGC file (Bash, Write, Edit);
3. editing rules or access settings (`.claude/`, `CLAUDE.md`, LaunchAgents/Daemons, managed settings, `friend.toml`, `core.toml`, `.ssh/`, `authorized_keys`, `sudoers`) with an editing tool or from the shell.

`decide_window_s` (default 120) is how old an `allow` may be when the gate spends it, by the
signed `ts`. `log` records every verdict; blocks also go to `rejected_log`.

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
6. Fail closed: temporarily point the hook's `command` to a missing path → any protected
   call is blocked with `failed; blocking because onFailure is "block"`; restore the path.

Independent trail: the core journal (`…/RemoteHands/data/journal/<date>.jsonl`): `friend.question`,
`friend.decision` (device, key, decision), `friend.decision.used`, `friend.decision.refused`.
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
