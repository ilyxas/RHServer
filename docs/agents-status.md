# agents.status: team and status rules

`agents.status` (SPEC §5.4) lists the team from the team file and gives each member one of `working`, `idle`, `monitoring`, `stopped`, `unknown`. The rules were approved by the owner (stage 2, drafted by the iOS agent and agreed with Friend).

Everything that names the owner's agents, folders or the owner lives in the **local** core config (`~/Library/Application Support/RemoteHands/core.toml`), never in this repository.

## Team

The team is the bullet list under the first heading that starts with `Команда`, up to the next heading of the same level:

```markdown
## Команда (идентификаторы)

- **Owner** — the only one whose word decides.
- **Agent-Alpha** — builds the render pipeline.
```

The file is read on every `data.get`, so edits show up at once. Ids in `skip` are people, not agents.

## Rules

A rule finds the agent's process by **program name** (process name, executable basename or `argv[0]` basename: a natively installed `claude` runs as `…/versions/<version>` through a `claude` symlink) and **working directory**, never by app: one app (Claude, ChatGPT) hosts several sessions.

| Situation | Status |
|---|---|
| no rule for the agent | `unknown` |
| no matching process | `stopped` |
| process, newest transcript changed within `working_within_s` (60) | `working` |
| process, otherwise (or no transcripts) | `idle` |
| `when_running` set: replaces working / idle while the transcript changed within `stale_after_s` (always, without it) | e.g. `monitoring` |
| `when_running` set, transcript older than `stale_after_s` | `idle` |

`transcripts` is a glob. For `process = "claude"` with a `cwd` it defaults to Claude Code's own folder `~/.claude/projects/<slug>/*.jsonl`, where the slug is the cwd with every character other than a letter or digit replaced by `-`. So no user name is written into the config.

## Example (placeholders)

```toml
[agents]
team_file = "~/Friend/CLAUDE.md"
skip = ["Owner"]

[[agents.rule]]
id = "Friend"
process = "claude"
cwd = "~/Friend"
when_running = "monitoring"
stale_after_s = 4200        # no activity for 70 min: idle (no permanent monitoring task)

[[agents.rule]]
id = "Agent-Alpha"
process = "claude"
cwd = "~/Development/Project"

[[agents.rule]]
id = "RemoteHands"
process = "rh-agent"        # stage 3; stopped until then

[[agents.rule]]
id = "Desktop-Agent"
process = "DesktopApp"      # presence only: idle / stopped
```

Agents that run in the cloud and leave no local trace get no rule and stay `unknown` (owner's decision; the core does not read CGC for them).

## Limits

- The core reads other processes' working directories as the owner's user. Under `_rhcore` (stage 7) this needs a solution; to be raised before stage 7.
- A session that writes no transcript (or writes it elsewhere) shows as `idle` while its process runs.
