# Optional legacy gate: friend.ask / friend.decide

Not part of the standard channel. Only for an installation that explicitly adds the
`rh-friend-gate` PreToolUse hook ([friend-gate.md](../friend-gate.md)). It no longer
reads the message note: there is no question mode, only `[[gate.protected]]` rules.

```mermaid
sequenceDiagram
    autonumber
    participant Model as Friend model
    participant Ask as rh-friend-ask
    participant Gate as rh-friend-gate
    participant Admin as rh-core admin socket
    participant Core as rh-core (app + store)
    participant Inbox as inbox dir
    participant App as RH app (iPhone)
    actor Owner

    Model->>Ask: question + exact tool call
    Ask->>Admin: friend.ask {text, action}
    Admin->>Core: store open question, journal
    App->>Core: GET /v1/friend/questions
    Core-->>App: questions (signed)
    App->>Owner: question and the full action
    Owner->>App: Allow (critical key, Face ID) / Deny
    App->>Core: POST /v1/friend/decide (signed)
    Core->>Core: verify, key level fits verdict,<br/>answers an open question
    Core->>Inbox: spool decision envelope
    Core-->>App: 200 (signed)

    Model->>Gate: PreToolUse (tool + input)
    alt call matches no [gate] rule
        Gate-->>Model: silent, normal permission flow
    else protected
        Gate->>Inbox: decide envelopes for this action
        Gate->>Gate: re-check signatures, newest wins,<br/>deny wins a tie, allow within decide window
        alt fresh allow
            Gate->>Admin: friend.decision.use {id, action}
            Admin->>Core: spend once (first use wins)
            Admin-->>Gate: ok / already used
            Gate-->>Model: run, with label [RH ✔ … allow]
        else deny / none / expired / used / core down
            Gate-->>Model: block (exit 2), rejected log
        end
    end
```
