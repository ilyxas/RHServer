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
