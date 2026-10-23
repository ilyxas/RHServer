# Component charts

High/middle-level UML (Mermaid) of the packages in `src/`: what each one is, what it
imports and how the running parts talk to each other. Module internals are left out.

| Chart | Shows |
|---|---|
| [packages.md](packages.md) | Package and module dependencies (static imports) |
| [runtime.md](runtime.md) | Running processes, their channels and files (deployment view) |
| [seq-friend-send.md](seq-friend-send.md) | Phone message → Friend session (`friend.send`) |
| [seq-friend-decide.md](seq-friend-decide.md) | Question → signed decision → gated tool call (`friend.ask` / `friend.decide`) |
| [seq-pairing.md](seq-pairing.md) | Pairing a phone (`rhcore pair`) |

Packages:

- **rh_common** — pure shared code: P-256 crypto, JCS (RFC 8785), the signed request
  protocol, the Friend envelope formats. No I/O, no imports from other packages.
- **rh_core** — the core service: HTTP/WebSocket API for the phone, SQLite registry,
  journal, pairing, admin socket, data sources.
- **rh_cli** — command line: `rhcore` (serve, pair, devices, dev mode, friend-config) and
  `rhpage` (stub).
- **rh_friend** — Friend side, runs outside the core: tmux bridge, UserPromptSubmit
  verifier, PreToolUse gate, `rh-friend-ask`.
- **rh_agent** — placeholder for the agent host (stage 3); only an entry point today.
