# PR draft: simplify the signed agent channel

## Before

The signed phone channel also controlled the agent's Question/Task mode. Tool allowlists,
a mode TTL and local typing affected permissions. Receipt/reply transport depended on
`[gate]`; accepting a new message superseded earlier open messages, and open approval
questions inferred a waiting state.

## After

RH delivers the owner's verified text into the existing agent session, using the existing
priority tmux input sequence, and returns the agent's answer to the phone. Standard setup
uses UserPromptSubmit (verify) and Stop (reply), with no RH PreToolUse hook. The owner
explicitly approved this scope in decision 008.

Question/Task no longer changes permissions. A new message does not cancel earlier work.
An answer is a delivered response, not a claim that the whole task finished. The separate
signed-action gate remains available only by explicit installation.

## How

- Remove question-mode classification, command/tool lists, TTL and mode hints.
- Keep only reply correlation in `rh_current.json`; local input detaches that correlation.
- Configure receipt/reply transport via top-level `admin_socket`, with the old gate socket
  as a compatibility fallback. Generated configs no longer create a gate by default.
- Stop inferring `superseded` on new input or `waiting` from unrelated approval questions.
- Reject a late Stop when its supplied prompt id differs from the current reply target.
- Update channel setup, optional gate installation, decision 008 and the UML diagrams.

## Contract changes

0.6.1 changes the contract descriptions only; wire schemas, signed request/response
encodings, signature checks and test-vector bytes are unchanged. `kind` and `re` remain
accepted and stored as compatibility metadata, without selecting a tool policy. The
OpenAPI text, changelog and manifest bytes do change and RHClient must resync contracts.
No client wire-model or signing-code change is needed for that sync. Client UX changes
are a separate follow-up in RHClient PR14.

## Unchanged

Pairing, Secure Enclave/key levels, signature and replay verification, device revocation,
original signed envelopes, the bridge's Escape/pause/pointer/Enter sequence, native agent
permissions, and the signed-action decision mechanism. No live install, deployment or
RHClient code changes are included.

## Validation

The implementation passed 597 tests on macOS, plus ruff, formatting, mypy and contract
manifest checks. The same 597-pass result was independently reported in the follow-up
review. The final documentation/docstring follow-up is checked separately; these results
are not a claim that the live flow was tested.

## Not verified / known behavior

- Full live iPhone → tmux → answer flow on this branch has not been verified by the
  implementation author; timing and prompt-id behavior need live acceptance.
- A message whose turn is interrupted can remain `received` indefinitely if no reply
  arrives. No timeout closes it. The client should present this as “Delivered”, not as
  evidence of ongoing work; that wording is a separate RHClient PR14 change after merge
  and contract sync, not functionality already delivered here.
- Keyboard input before the phone message's answer clears the local reply target, so
  the phone will not automatically receive that local turn's answer. The stored earlier
  message is not cancelled.
- Missing prompt ids retain the latest-message fallback. Rapid interruptions, permission
  prompts and partially typed terminal input still require live testing.
- Existing clients retain Question/Task and “Make it a task” until their separate UI
  update. These controls no longer select server-side permissions.
- Installing or removing the optional gate, including its host's `onFailure` behavior,
  has not been exercised by this documentation follow-up.
