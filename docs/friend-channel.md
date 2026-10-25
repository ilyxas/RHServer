# RemoteHands: messages into an existing agent session

The phone is a remote input to the configured agent's existing tmux session. The agent
keeps its role, conversation and normal tool permissions. RH does not decide whether an
utterance is a question or a task, or whether a task has finished.

## Runtime

1. The core verifies the signed request, stores it and spools the original envelope.
2. The bridge sends one Escape, waits 300 ms, types `⟦rh:id⟧` literally and presses Enter.
3. `rh-friend-verify` re-verifies the phone signature, recipient, freshness and replay
   ledger. The agent receives the verified-origin label and the owner's original text.
4. The verifier reports receipt and remembers the message id / prompt id for replying.
5. `rh-friend-reply` on Stop sends the turn's last answer to the phone. Explicit
   `rh-friend-reply --progress TEXT` is still available. Failed reply delivery is queued
   locally and retried on the next verify/Stop or with `--flush`.

Only UserPromptSubmit and Stop are part of this installation. There is no RH PreToolUse
hook, command allowlist, question-mode timer or automatic promotion to a task. The
existing agent's own permissions and instructions remain in force.

Pairing, device keys, the signed device list, pinned key, nonce checks, signature checks,
revocation and exact signed envelope bytes are unchanged.

## What the states mean

`accepted` means the core stored the message; `received` means the verifier reported
receipt; `answered` means an answer was stored; `rejected` means the verifier refused it.
These are delivery states, not a task scheduler. A new message never cancels or closes
an earlier one. An unanswered earlier message stays received/accepted. A final response
means a turn ended, not that the owner's entire task is complete. Approval questions do
not infer a waiting state by their timestamp.

The optional signed `kind` and `re` fields are retained for older clients and history.
They do not change permissions. Existing clients may still show Question/Task and
"Make it a task"; these controls no longer select an execution mode. A later client
change should remove them and use delivery wording instead of "is working".

Reply correlation is local to the most recent verified phone message. When both hooks
supply prompt ids, an old Stop cannot answer a newer message. A normal local prompt
clears the phone reply target so its unrelated answer is not attached to an older phone
message; it does not change any permissions or close that message in the core. Missing
prompt ids retain the existing latest-message fallback; test the actual hook version
before relying on attribution during rapid interruptions. An interrupted turn need not
emit Stop, so the phone may never receive an answer to that earlier message.

## Configuration

`rhcore friend-config --config <core.toml>` generates the pinned agent config from the
core's existing `[channel]`. It includes:

```toml
# agent, project_dir, inbox_dir, devices_file and pinned core_key are generated above
admin_socket = "/absolute/path/to/data/admin.sock"
report_timeout_s = 2

[bridge]
tmux = "/absolute/path/to/tmux"
target = "friend"
interrupt = true
```

Receipts and replies use the top-level `admin_socket`, independently of any gate. Older
configs with only `[gate].admin_socket` continue to work as a compatibility fallback.
Legacy `question_tools`, `question_bash` and `question_ttl_s` settings are ignored.
The reply state file contains correlation, not permission state.

## Move an existing installation (explicit operator step)

Do not edit or switch the checkout used by running editable installs to deploy a review.
Use a reviewed, fixed revision and restart services as an explicit deployment operation.
This change does not install itself or edit Claude/launchd settings.

1. Back up the existing agent TOML and the Claude settings files you will edit.
2. Generate the new config to a temporary file. Compare pinned key, agent, project,
   inbox, device list and tmux target with the old file before replacing it. Preserve
   deliberate path overrides and `require_protected` if used. Pair again is not needed.
3. In the selected project's `.claude/settings.json`, retain one UserPromptSubmit
   command for `rh-friend-verify` and one Stop command for `rh-friend-reply`, both using
   the same absolute config and project paths. For example:

   ```json
   {
     "hooks": {
       "UserPromptSubmit": [{"hooks": [{
         "type": "command",
         "command": "\"/fixed/install/bin/rh-friend-verify\" --config \"/absolute/agent.toml\" --project \"/absolute/project\"",
         "timeout": 30,
         "onFailure": "block"
       }]}],
       "Stop": [{"hooks": [{
         "type": "command",
         "command": "\"/fixed/install/bin/rh-friend-reply\" --config \"/absolute/agent.toml\" --project \"/absolute/project\"",
         "timeout": 10
       }]}]
     }
   }
   ```

   Merge these entries, do not overwrite unrelated settings. Remove only RH
   `rh-friend-gate` entries from effective PreToolUse hooks. Check user/project/local
   and managed settings for duplicate RH entries; leave unrelated hooks and permission
   policies untouched. Do not install duplicate verify hooks (the replay ledger is shared).
4. Restart core/bridge and the agent session with the reviewed version. Keep the existing
   pairing, database, seen ledger and bridge delivery state; do not replay the inbox.

## Focused live acceptance

- Idle agent: a signed message reaches that same session with its verified label.
- Running agent: a message requests interruption, arrives, and its answer reaches Chat.
- Follow-up "how is it going?": the prior message is not marked cancelled or superseded.
- Both legacy kind values deliver the same text without introducing tool restrictions.
- With no RH PreToolUse entry, `git status`, `git -C <repo> status` and loops are subject
  only to the agent's ordinary permissions, not to RH question-mode classification.
- Unavailable core at Stop: reply is queued; restore core and flush it.
- Rapid messages: check prompt ids and verify answers are not attached to another message.
- Permission prompt / unfinished local draft: observe delivery before relying on remote
  interruption unattended. Escape may dismiss a permission prompt. The bridge cannot
  prove that every child process stopped or that a terminal draft was safely preserved.

The bridge implements a priority input attempt using the existing tmux sequence, not an
OS process-kill or rollback guarantee. It never interprets "stop" or other natural text;
the agent handles the owner's intent exactly as in the terminal.
