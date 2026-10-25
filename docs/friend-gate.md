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

The gate asks by itself. When a protected call has no usable Allow (none yet, expired,
already used or voided), the hook records the question in the core (`Gate: <rule>
(<tool>: <description>)` above the exact call), waits up to `[gate] wait_s` (default
580 s) for the phone's answer and then lets the call through once or blocks it. No
answer in time: the question is withdrawn and the call is blocked. A Deny signed within
`decide_window_s` blocks a repeat of the same call at once, without asking again. While
the hook waits it leaves `.gate-wait` in the inbox, and the bridge does not type the
answer into the session: the Escape before a typed line would cancel the very call the
hook holds. `wait_s = 0` turns asking off; `rh-friend-ask` still asks ahead of a call.

The default rules protect pausing or resuming a process (`kill -STOP/-CONT`, `os.kill`)
and Write/Edit of settings and rules files by `file_path`. Rules for the shell's
`command` with `code_only = true` look at the shell code only: quoted text and heredoc
bodies are data and are skipped, except a `-c`/`-e` script, a command substitution in
`"…"` or an unquoted heredoc, and a heredoc fed to an interpreter. Two rules were removed
on 2026-10-26 because they fired on mentions rather than actions: records in CGC, and the
shell naming a settings file next to `>`, `python3`, `cp`… anywhere in the command.
Legacy gate configuration is still accepted; channel switching preserves explicitly
configured rules. A newly generated channel config creates no gate or protected rules.

Removing the RH PreToolUse hook removes these RH tool-call checks. It does not remove
phone-message authentication, the agent's native permission checks or unrelated hooks.
Do this as an explicit operator migration, not by silently editing running settings.

Regex rules remain heuristic: a shell script can hide effects and a read-only command
can match a protected spelling. They do not provide OS isolation. See the historical
hook failure discussion in [decision 004](decisions/004-pretooluse-onfailure.md).

For a deliberate legacy installation, `[gate]` still accepts `admin_socket`,
`decide_window_s`, `wait_s`, `ask`, `log`, `report_timeout_s` and `[[gate.protected]]`
tables.
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
         "timeout": 600,
         "onFailure": "block"
       }]}]
     }
   }
   ```

   `timeout` must be longer than `[gate] wait_s` (580 s by default), or the host ends the
   wait first and `onFailure` blocks the call before the owner's answer arrives.

3. In the agent session (a running session picks up hook changes), call Bash with command
   `printf RH_GATE_TEST` and description `gate acceptance probe`: the phone shows the
   question `Gate: gate acceptance probe (Bash: gate acceptance probe)`. Allow: the call
   runs. Call it again: a new question; Deny: it is blocked, and an immediate repeat is
   blocked without a question. Call it again later and do not answer: blocked after
   `wait_s`, the question withdrawn. Check the rejection log and core decision-use events.
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

Regexes are a seat belt, not a sandbox. They classify spelling, not effects: executing a
script can hide a protected action, and `code_only` is a rough reading of the shell, not
a parser. Tool parameters must match the signed action exactly. A decision label alone
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
