# Component charts

High/middle-level UML (Mermaid) of the packages in `src/`: what each one is, what it
imports and how the running parts talk to each other. Module internals are left out.

| Chart | Shows |
|---|---|
| [packages.md](packages.md) | Package and module dependencies (static imports) |
| [runtime.md](runtime.md) | Running processes, their channels and files (deployment view) |
| [seq-pairing.md](seq-pairing.md) | Pairing a phone (`rhcore pair`) |
| [seq-friend-send.md](seq-friend-send.md) | Phone message → agent session (`friend.send`) |
| [seq-friend-reply.md](seq-friend-reply.md) | Agent's answer → phone (Stop hook, `friend.reply`) |
| [message-states.md](message-states.md) | Delivery states of an owner's message |
| [seq-friend-decide.md](seq-friend-decide.md) | Optional legacy gate: question → signed decision → gated tool call |

The standard channel ([friend-channel.md](../friend-channel.md)) is two hooks in the
agent's session: UserPromptSubmit (`rh-friend-verify`) and Stop (`rh-friend-reply`).
There is no question/task mode: the signed `kind` is compatibility metadata only.
The PreToolUse gate is optional and not part of a standard install
([friend-gate.md](../friend-gate.md)).

Packages:

- **rh_common** — pure shared code: P-256 crypto, JCS (RFC 8785), the signed request
  protocol, the Friend envelope formats. No I/O, no imports from other packages.
- **rh_core** — the core service: HTTP/WebSocket API for the phone, SQLite registry,
  journal, pairing, admin socket, data sources.
- **rh_cli** — command line: `rhcore` (serve, pair, devices, journal, dev mode,
  friend-config, channel set) and `rhpage` (stub).
- **rh_friend** — agent side, runs outside the core: tmux bridge, UserPromptSubmit
  verifier, Stop reply hook, admin socket client; the optional legacy gate and
  `rh-friend-ask`.
- **rh_agent** — placeholder for the agent host (stage 3); only an entry point today.
