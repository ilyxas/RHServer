# friend.send: phone message to the Friend session

```mermaid
sequenceDiagram
    autonumber
    actor Owner
    participant App as RH app (iPhone)
    participant Core as rh-core (app)
    participant Inbox as inbox dir
    participant Bridge as rh-friend-bridge
    participant Tmux as Friend tmux session
    participant Verify as rh-friend-verify
    participant Model as Friend model

    Owner->>App: types message, Face ID
    App->>Core: POST /v1/challenge
    Core-->>App: nonce (signed)
    App->>Core: POST /v1/friend (signed object)
    Core->>Core: verify signature, nonce, device, Tailscale peer
    Core->>Core: journal
    Core->>Inbox: spool envelope exactly as received
    Core-->>App: 200 (signed)
    Bridge->>Inbox: new envelope
    Bridge->>Tmux: send-keys "⟦rh:id⟧" + Enter
    Tmux->>Verify: UserPromptSubmit (pointer)
    Verify->>Inbox: load envelope by id
    Verify->>Verify: re-check phone signature against<br/>device list signed by pinned core key, freshness
    alt valid
        Verify-->>Model: text + label [RH ✔ owner · device · time]
    else invalid
        Verify-->>Tmux: block input, append to rejected log
    end
    Note over Verify,Model: any other input is labelled [unsigned]
```
