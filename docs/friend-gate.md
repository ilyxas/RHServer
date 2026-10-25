# Optional legacy action gate

The standard channel is described in [friend-channel.md](friend-channel.md). It needs
only UserPromptSubmit (`rh-friend-verify`) and Stop (`rh-friend-reply`). Do not install
`rh-friend-gate` to enable messages or replies.

The existing `rh-friend-ask`, `friend.questions`, `friend.decide` and `rh-friend-gate`
remain for installations that explicitly use signed, single-call action approvals.
Pairing and signature verification are unchanged. This separate mechanism is not a
question/task mode and no longer reads `rh_current.json` to classify tool calls.

An explicitly installed gate applies `[[gate.protected]]`, verifies a fresh critical-key
Allow for the exact canonical tool call, and spends it once via the core. The newest
valid decision takes precedence; the core enforces freshness, matching and single use.
Legacy gate configuration is still accepted; channel switching preserves explicitly
configured rules. A newly generated channel config creates no gate or protected rules.

Removing the RH PreToolUse hook removes these RH tool-call checks. It does not remove
phone-message authentication, the agent's native permission checks or unrelated hooks.
Do this as an explicit operator migration, not by silently editing running settings.

Regex rules remain heuristic: a shell script can hide effects and a read-only command
can match a protected spelling. They do not provide OS isolation. See the historical
hook failure discussion in [decision 004](decisions/004-pretooluse-onfailure.md).

For a deliberate legacy installation, `[gate]` still accepts `admin_socket`,
`decide_window_s`, `ask`, `log`, `report_timeout_s` and `[[gate.protected]]` tables.
Old `question_tools`, `question_bash` and `question_ttl_s` are ignored. Receipt/reply
transport should use the top-level `admin_socket`; `[gate].admin_socket` is a fallback
for old configs only.

## Install (optional, explicit operator action)

Start with the working signed channel and back up the agent TOML and the effective Claude
settings you will edit. No new pairing is needed. Use a fixed reviewed installation path.
The hook failure settings below follow [decision 004](decisions/004-pretooluse-onfailure.md),
which records the Claude Code version requirement for `onFailure: "block"`; verify the
installed CLI meets it before enabling the gate.

1. Add `[gate]` to the same agent TOML. `admin_socket` is required. At least one
   `[[gate.protected]]` rule is needed to protect anything; each rule requires a name,
   tools and non-empty match patterns. `decide_window_s` defaults to 120 seconds;
   `ask` should name the exact installed executable. This harmless test rule protects
   only the shown command; it is not a general security policy:

   ```toml
   [gate]
   admin_socket = "/absolute/path/to/data/admin.sock"
   decide_window_s = 120
   ask = "/fixed/install/bin/rh-friend-ask"

   [[gate.protected]]
   name = "gate acceptance probe"
   tools = ["Bash"]
   field = "command"
   match = ['^printf RH_GATE_TEST$']
   ```

2. Merge this entry into the selected project's `.claude/settings.json`; preserve the
   existing verify and Stop hooks and unrelated settings. Check global/local/managed
   settings for duplicate RH entries. Do not overwrite the complete settings file:

   ```json
   {
     "hooks": {
       "PreToolUse": [{"hooks": [{
         "type": "command",
         "command": "\"/fixed/install/bin/rh-friend-gate\" --config \"/absolute/agent.toml\" --project \"/absolute/project\"",
         "timeout": 30,
         "onFailure": "block"
       }]}]
     }
   }
   ```

3. Restart the agent session. In that session, call Bash with command
   `printf RH_GATE_TEST` and description `gate acceptance probe`: without a decision it
   must be blocked. Ask using the configured executable:

   ```sh
   /fixed/install/bin/rh-friend-ask --config /absolute/agent.toml \
     --question "Allow the harmless gate probe once?" \
     --bash "printf RH_GATE_TEST" --description "gate acceptance probe"
   ```

   Allow on the phone, then retry exactly the same tool input, including description
   and any other fields: it must pass once, and the next attempt must be refused.
   Ask again and Deny: it must block. Ask again and Allow, wait over 120 seconds:
   it must block. Check the rejection log and core decision-use events.
4. In a disposable test session, temporarily point the hook command to a missing
   executable and confirm the probe is blocked by hook failure. Restore the path
   and restart that session. This verifies the installed host's failure handling.

To remove or roll back the gate, remove only its PreToolUse entry from every settings
scope where it was installed, or restore the backed-up entry. Preserve UserPromptSubmit,
Stop and unrelated permission settings, then restart the session. Keep the top-level
`admin_socket` for receipts/replies; if an old config relies on `[gate].admin_socket`,
move that value to the top level before deleting the table. Verify that signed messages
and replies still work without the gate. No service, database or pairing reset is needed.

## Known limitations

Regexes are a seat belt, not a sandbox. They classify spelling, not effects: reading a
settings file through Python can be blocked; executing a script can hide a protected
action. Tool parameters must match the signed action exactly. A decision label alone
never authorizes a different call.

The gate covers calls observed by this Claude Code hook, not every process or external
tool on the Mac. Config, code and trust anchors writable by the agent's user do not
provide an independent OS boundary. `onFailure: "block"` can also block otherwise
unprotected calls when the hook cannot start; it cannot classify a call while broken.
These limitations remain even if the harmless acceptance probe succeeds.

The earlier full installation and managed-install discussion is retained in
[the pre-simplification document at 89bbc22](https://github.com/ilyxas/RHServer/blob/89bbc222d36790aece1796a65380bb3d3c623554/docs/friend-gate.md).
Its question-mode and automatic message-state sections are historical and superseded by
[decision 008](decisions/008-no-question-mode.md).
