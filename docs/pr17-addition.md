## Owner approval (review 2026-10-23 19:41Z)

Approved with additions:

1. `rhcore channel set` restarts the core itself and checks that `status.channel` reports the new name; otherwise it is an error, not "done".
2. The team file never stops the core at start: an id missing from it is shown as the id itself, with a warning in the journal. The "id is in the team file" check is done only by `channel set`.
3. The tmux target is stored explicitly, not derived from the id; `channel set` checks that the tmux session exists.
4. Live test: after a switch the previous agent gets no ✔ and cannot run a protected action.
5. The question card in the app shows the asking agent's name clearly.
6. One line in `docs/friend-gate.md`: "friend" is the name of the mechanism, after the agent that designed it and first worked on it; it has nothing to do with the channel's current agent.

Decisions 1–3 (section 9): as recommended — `status.channel`, `rhcore channel set` with voiding, required `[channel].agent` without a default.
Decision 4, PR order: (a) contract + vectors, (b) core + schema 4 + `channel set`, (c) agent side + docs — merged into **one server PR**; (d) iOS sync + strings + tests — a separate PR.
